// SPDX-License-Identifier: MIT
// Copyright(c) 2024 Darek Stojaczyk

use anyhow::anyhow;
use anyhow::Result;
use async_proc::select;
use futures::FutureExt;
use futures::StreamExt;
use log::debug;
use log::error;
use log::info;
use log::warn;
use packet::pkt_common::*;
use packet::pkt_global::*;
use packet::*;

use crate::async_for_each;
use crate::gms::world::GlobalWorldHandler;
use crate::gms::GlobalDbHandler;
use crate::registry::BorrowRegistry;
use crate::registry::Entry;

use super::Connection;

pub struct GlobalLoginHandler {
    pub conn: Connection,
    pub notify_user_counts: bool,
}
crate::impl_registry_entry!(
    GlobalLoginHandler,
    RefData = pkt_common::Connect,
    data = .conn,
    borrow_ref = .conn.conn_ref
);

impl std::fmt::Display for GlobalLoginHandler {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.conn)
    }
}

impl GlobalLoginHandler {
    pub fn new(conn: Connection) -> Self {
        Self {
            conn,
            notify_user_counts: false,
        }
    }

    pub async fn handle(&mut self) -> Result<()> {
        let conn_ref = self.conn.conn_ref.clone();
        let service = &conn_ref.data;

        #[rustfmt::skip]
        self.conn.stream
            .send(&pkt_common::ConnectAck {
                bytes: BoundVec(vec![
                    0xfa, 0, 0, 0, 0, 0, 0, 0,
                    ServiceID::GlobalMgrSvr as u8, 0, 0, 0, 0,
                    service.world_id, service.channel_id, 0, 0, 0, 0, 0x1,
                ]),
            })
            .await.unwrap();

        self.conn
            .stream
            .send(&ChangeServerState {
                server_id: service.world_id,
                channel_id: service.channel_id,
                state: ServerStateEnum::Disabled,
            })
            .await
            .unwrap();

        loop {
            select! {
                p = self.conn.stream.recv().fuse() => {
                    let p = p.map_err(|e| {
                        anyhow!("{self}: Failed to recv a packet: {e}")
                    })?;
                    match p {
                        Packet::ClientVersionNotify(p) => {
                            info!("{self}: Version: {}, Magickey: {:#x}", p.version, p.magickey);
                        }
                        Packet::NotifyUserCount(_) => {
                            self.notify_user_counts = true;
                        }
                        Packet::SystemMessage(p) => {
                            self.handle_system_message(p).await.unwrap();
                        }
                        Packet::RoutePacket(p) => {
                            self.conn.handle_route_packet(p).await.unwrap();
                        }
                        Packet::SetLoginInstance(p) => {
                            self.handle_login_stt(p).await.unwrap();
                        }
                        Packet::MultipleLoginDisconnectRequest(p) => {
                            self.handle_already_connected_prompt(p).await.unwrap();
                        }
                        _ => {
                            warn!("{self}: Got unexpected packet: {p:?}");
                        }
                    }
                }
                _ = self.conn.conn_ref.borrower.wait_to_lend().fuse() => {
                    self.lend_self().await;
                }
            }

            if self.notify_user_counts {
                self.update_user_count().await.unwrap();
                self.notify_user_counts = false;
            }
        }
    }

    pub async fn update_user_count(&mut self) -> Result<()> {
        // Gather the channels
        // TODO: group those into game servers; for now we assume only 1 server
        let mut groups = Vec::new();

        let conns = BorrowRegistry::borrow_multiple::<GlobalWorldHandler>(
            self.conn.listener.connections.refs.iter(),
        );
        async_for_each!(mut conn in conns => {
            if let Some(group) = conn.group_node() {
                groups.push(group);
            }
        });

        // Tell each WorldSvr about the other channels
        // (perhaps for the "Switch Channel" functionality?)
        let world_srv_state = WorldServerState {
            unk1: 1, // FIXME: server id
            groups: groups.clone().into(),
        };

        let conns = BorrowRegistry::borrow_multiple::<GlobalWorldHandler>(
            self.conn.listener.connections.refs.iter(),
        );
        async_for_each!(mut conn in conns => {
            if let Err(e) = conn.conn.stream.send(&world_srv_state).await {
                error!(
                    "{self}: Failed to send WorldServerState to {}: {e}",
                    conn.conn
                );
            }
        });

        let mut servers = vec![];
        if !groups.is_empty() {
            servers.push(LoginServerNode {
                id: 1,
                stype: 16,
                unk1: 0,
                groups: groups.into(),
            });
        }

        /*
        servers.push(LoginServerNode {
            id: 0x80,
            stype: 0,
            unk1: 0,
            groups: Vec::new().into(),
        });
        */

        if let Err(e) = self
            .conn
            .stream
            .send(&LoginServerState {
                servers: servers.into(),
                trailing: vec![0; 1024].into(),
            })
            .await
        {
            error!("{self}: Failed to send LoginServerState: {e}");
        }

        Ok(())
    }

    pub async fn handle_system_message(&mut self, p: SystemMessage) -> Result<()> {
        let resp = SystemMessageForwarded { data: p };

        let conns = BorrowRegistry::borrow_multiple::<GlobalWorldHandler>(
            self.conn.listener.connections.refs.iter(),
        );
        async_for_each!(mut conn in conns => {
            if let Err(e) = conn.conn.stream.send(&resp).await {
                error!(
                    "{self}: Failed to forward SystemMessage to {}: {e}",
                    conn.conn
                );
            }
        });

        self.conn.stream.send(&resp).await.unwrap();
        Ok(())
    }

    pub async fn handle_login_stt(&mut self, p: SetLoginInstance) -> Result<()> {
        debug!("{self}: New login! {p:?}");

        let conns = BorrowRegistry::borrow_multiple::<GlobalDbHandler>(
            self.conn.listener.connections.refs.iter(),
        );
        async_for_each!(mut conn in conns => {
            if let Err(e) = conn.conn.stream.send(&p).await {
                error!(
                    "{self}: Failed to send SetLoginInstance to {}: {e}",
                    conn.conn
                );
            }
        });

        Ok(())
    }

    pub async fn handle_already_connected_prompt(
        &mut self,
        p: MultipleLoginDisconnectRequest,
    ) -> Result<()> {
        let resp = MultipleLoginDisconnectResponse {
            unk1: p.unk1,
            unk2: p.unk2,
        };
        let conns = BorrowRegistry::borrow_multiple::<GlobalWorldHandler>(
            self.conn.listener.connections.refs.iter(),
        );
        async_for_each!(mut conn in conns => {
            if let Err(e) = conn.conn.stream.send(&resp).await {
                error!(
                    "{self}: Failed to send MultipleLoginDisconnectResponse to {}: {e}",
                    conn.conn
                );
            }
        });

        if let Err(e) = self.conn.stream.send(&resp).await {
            error!("{self}: Failed to send MultipleLoginDisconnectResponse to Self: {e}");
        }

        let resp = pkt_global::SetLoginInstance {
            unk1: p.unk1,
            unk2: p.unk2,
            unk3: 0,
            unk4: Arr::default(),
            unk6: Arr::default(),
            unk7: 0x14,
            unk8: Default::default(),
            unk9: Arr::default(),
        };

        let conns = BorrowRegistry::borrow_multiple::<GlobalDbHandler>(
            self.conn.listener.connections.refs.iter(),
        );
        async_for_each!(mut conn in conns => {
            if let Err(e) = conn.conn.stream.send(&resp).await {
                error!(
                    "{self}: Failed to send MultipleLoginDisconnectResponse to {}: {e}",
                    conn.conn
                );
            }
        });

        Ok(())
    }
}
