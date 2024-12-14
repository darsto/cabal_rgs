// SPDX-License-Identifier: MIT
// Copyright(c) 2024 Darek Stojaczyk

use std::net::TcpStream;
use std::sync::Arc;

use anyhow::anyhow;
use anyhow::Result;
use async_proc::select;
use futures::FutureExt;
use log::error;
use log::info;
use log::warn;
use packet::pkt_common::*;
use packet::pkt_global::*;
use packet::*;
use smol::Async;

use crate::packet_stream::IPCPacketStream;
use crate::registry::BorrowRef;
use crate::registry::Entry;

use super::Listener;

pub struct GlobalLoginHandler {
    pub listener: Arc<Listener>,
    pub stream: IPCPacketStream<Async<TcpStream>>,
    pub conn_ref: Arc<BorrowRef<Self, pkt_common::Connect>>,
    pub notify_user_counts: bool,
}
crate::impl_registry_entry!(
    GlobalLoginHandler,
    RefData = pkt_common::Connect,
    borrow_ref = .conn_ref
);

impl std::fmt::Display for GlobalLoginHandler {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "GlobalLoginHandler")
    }
}

impl GlobalLoginHandler {
    pub fn new(
        listener: Arc<Listener>,
        stream: IPCPacketStream<Async<TcpStream>>,
        conn_ref: Arc<BorrowRef<Self, pkt_common::Connect>>,
    ) -> Self {
        Self {
            listener,
            stream,
            conn_ref,
            notify_user_counts: false,
        }
    }

    pub async fn handle(&mut self) -> Result<()> {
        let conn_ref = self.conn_ref.clone();
        let service = &conn_ref.data;

        #[rustfmt::skip]
        self.stream
            .send(&pkt_common::ConnectAck {
                bytes: BoundVec(vec![
                    0xfa, 0, 0, 0, 0, 0, 0, 0,
                    ServiceID::GlobalMgrSvr as u8, 0, 0, 0, 0,
                    service.world_id, service.channel_id, 0, 0, 0, 0, 0x1,
                ]),
            })
            .await.unwrap();

        self.stream
            .send(&ChangeServerState {
                server_id: service.world_id,
                channel_id: service.channel_id,
                state: ServerStateEnum::Disabled,
            })
            .await
            .unwrap();

        loop {
            select! {
                p = self.stream.recv().fuse() => {
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
                            let listener = self.listener.clone();
                            self.lend_self_until(async {
                                super::handle_route_packet(&listener, p).await
                            }).await?;
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
                _ = self.conn_ref.borrower.wait_to_lend().fuse() => {
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

        for conn_ref in self.listener.worlds.cloned().into_iter() {
            let mut conn = conn_ref.borrow().await.unwrap();
            if let Some(group) = conn.group_node() {
                groups.push(group);
            }
        }

        // Tell each WorldSvr about the other channels
        // (perhaps for the "Switch Channel" functionality?)
        let world_srv_state = WorldServerState {
            unk1: 1, // FIXME: server id
            groups: groups.clone().into(),
        };

        for conn_ref in self.listener.worlds.cloned().into_iter() {
            let mut conn = conn_ref.borrow().await.unwrap();
            if let Err(e) = conn.stream.send(&world_srv_state).await {
                error!("{self}: Failed to send WorldServerState to {}: {e}", &*conn);
            }
        }

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

        for conn_ref in self.listener.worlds.cloned().into_iter() {
            let mut conn = conn_ref.borrow().await.unwrap();
            if let Err(e) = conn.stream.send(&resp).await {
                error!("{self}: Failed to forward SystemMessage to {}: {e}", &*conn);
            }
        }

        self.stream.send(&resp).await.unwrap();
        Ok(())
    }

    pub async fn handle_login_stt(&mut self, p: SetLoginInstance) -> Result<()> {
        for conn_ref in self.listener.db.first().iter() {
            let mut conn = conn_ref.borrow().await.unwrap();
            if let Err(e) = conn.stream.send(&p).await {
                error!("{self}: Failed to send SetLoginInstance to {}: {e}", &*conn);
            }
        }

        Ok(())
    }

    pub async fn handle_already_connected_prompt(
        &mut self,
        p: MultipleLoginDisconnectRequest,
    ) -> Result<()> {
        let resp = MultipleLoginDisconnectResponse {
            user_id: p.user_id,
            login_idx: p.login_idx,
        };
        for conn_ref in self.listener.worlds.cloned().into_iter() {
            let mut conn = conn_ref.borrow().await.unwrap();
            if let Err(e) = conn.stream.send(&resp).await {
                error!(
                    "{self}: Failed to send MultipleLoginDisconnectResponse to {}: {e}",
                    &*conn
                );
            }
        }

        if let Err(e) = self.stream.send(&resp).await {
            error!("{self}: Failed to send MultipleLoginDisconnectResponse to Self: {e}");
        }

        let resp = pkt_global::SetLoginInstance {
            user_id: p.user_id,
            login_idx: p.login_idx,
            unk3: 0,
            unk4: Arr::default(),
            login: 0,
            unk6: Arr::default(),
            unk7: 0x14,
            unk8: Default::default(),
            unk9: Arr::default(),
        };

        for conn_ref in self.listener.db.cloned().into_iter() {
            let mut conn = conn_ref.borrow().await.unwrap();
            if let Err(e) = conn.stream.send(&resp).await {
                error!(
                    "{self}: Failed to send MultipleLoginDisconnectResponse to {}: {e}",
                    &*conn
                );
            }
        }

        Ok(())
    }
}
