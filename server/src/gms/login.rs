// SPDX-License-Identifier: MIT
// Copyright(c) 2024 Darek Stojaczyk

use std::pin::pin;

use anyhow::anyhow;
use anyhow::bail;
use anyhow::Result;
use futures::FutureExt;
use futures::StreamExt;
use log::{error, trace};
use packet::pkt_common::*;
use packet::pkt_global::*;
use packet::*;

use crate::gms::world::GlobalWorldHandler;

use super::Connection;

pub struct GlobalLoginHandler {
    pub conn: Box<Connection>,
    pub notify_user_counts: bool,
}

impl std::fmt::Display for GlobalLoginHandler {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.conn)
    }
}

impl GlobalLoginHandler {
    pub fn new(conn: Box<Connection>) -> Self {
        Self {
            conn,
            notify_user_counts: false,
        }
    }

    pub async fn handle(&mut self) -> Result<()> {
        let conn_ref = self.conn.conn_ref.as_ref().unwrap().clone();
        let service = &conn_ref.service;

        #[rustfmt::skip]
        self.conn.stream
            .send(&Payload::ConnectAck(pkt_common::ConnectAck {
                bytes: BoundVec(vec![
                    0xfa, 0, 0, 0, 0, 0, 0, 0,
                    ServiceID::GlobalMgrSvr as u8, 0, 0, 0, 0,
                    service.world_id, service.channel_id, 0, 0, 0, 0, 0x1,
                ]),
            }))
            .await.unwrap();

        self.conn
            .stream
            .send(&Payload::ChangeServerState(ChangeServerState {
                server_id: service.world_id,
                channel_id: service.channel_id,
                state: ServerStateEnum::Disabled,
            }))
            .await.unwrap();

        loop {
            futures::select! {
                p = self.conn.stream.recv().fuse() => {
                    let p = p.map_err(|e| {
                        anyhow!("{self}: Failed to recv a packet: {e}")
                    })?;
                    match p {
                        Payload::NotifyUserCount(_) => {
                            self.notify_user_counts = true;
                        }
                        Payload::SystemMessage(p) => {
                            self.handle_system_message(p).await.unwrap();
                        }
                        Payload::RoutePacket(p) => {
                            self.handle_route_packet(p).await.unwrap();
                        }
                        _ => {
                            trace!("{self}: Got packet: {p:?}");
                        }
                    }
                }
                _ = conn_ref.borrower.wait_to_lend().fuse() => {
                    conn_ref.borrower.lend(&mut self.conn).unwrap().await
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
        // TODO: group those into servers; for now we assume only 1 server
        let mut groups = Vec::new();
        while let Some(conn) = //
            pin!(self.conn.iter_handlers::<GlobalWorldHandler>())
                .next()
                .await
        {
            if let Some(group) = conn.group_node() {
                groups.push(group);
            }
        }

        // Tell each WorldSvr about the other channels
        // (perhaps for the "Switch Channel" functionality?)
        let world_srv_state = Payload::ServerState(
            WorldServerState {
                unk1: 1, // FIXME: server id
                groups: groups.clone().into(),
            }
            .try_into()
            .unwrap(),
        );
        while let Some(mut conn) = //
            pin!(self.conn.iter_handlers::<GlobalWorldHandler>())
                .next()
                .await
        {
            if let Err(e) = conn.conn.stream.send(&world_srv_state).await {
                error!(
                    "{self}: Failed to send WorldServerState to {}: {e}",
                    conn.conn
                );
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

        servers.push(LoginServerNode {
            id: 0x80,
            stype: 0,
            unk1: 0,
            groups: Vec::new().into(),
        });

        if let Err(e) = self
            .conn
            .stream
            .send(&Payload::ServerState(
                LoginServerState {
                    servers: servers.into(),
                    trailing: vec![0; 1024].into(),
                }
                .try_into()
                .unwrap(),
            ))
            .await
        {
            error!("{self}: Failed to send LoginServerState: {e}");
        }

        Ok(())
    }

    pub async fn handle_system_message(&mut self, p: SystemMessage) -> Result<()> {
        let resp = Payload::SystemMessageForwarded(SystemMessageForwarded { data: p });

        while let Some(mut conn) = //
            pin!(self.conn.iter_handlers::<GlobalWorldHandler>())
                .next()
                .await
        {
            if let Err(e) = conn.conn.stream.send(&resp).await {
                error!(
                    "{self}: Failed to forward SystemMessage to {}: {e}",
                    conn.conn
                );
            }
        }

        self.conn.stream.send(&resp).await.unwrap();
        Ok(())
    }

    pub async fn handle_route_packet(&mut self, p: RoutePacket) -> Result<()> {
        let route_hdr = &p.droute_hdr.route_hdr;

        let Some(conn_ref) = self.conn.listener.conn_refs.iter().find(|conn_ref| {
            let s = &conn_ref.service;
            s.world_id == route_hdr.server_id && s.channel_id == route_hdr.group_id
        }) else {
            bail!("{self}: Can't find a conn to route to: {route_hdr:?}");
        };

        let psize = std::mem::size_of_val(&p);
        let mut bytes = Vec::with_capacity(psize + Header::SIZE);
        let hdr = Header::new(route_hdr.origin_main_cmd, (psize + Header::SIZE) as u16);
        let len = Payload::encode_into_std_write(&p, &mut bytes)
            .map_err(|e| anyhow!("{self}: Failed to reencode packet {e}: {p:?}"))?;
        let target_payload = Payload::decode(&hdr, &bytes)
            .map_err(|e| anyhow!("{self}: Failed to decode target packet {e}: {p:?}"))?;
        assert_eq!(len, psize);

        let mut target_conn = conn_ref
            .borrower
            .request_borrow()
            .await
            .map_err(|e| anyhow!("{self}: request_borrow() failed: {e}"))?;

        target_conn
            .stream
            .send(&target_payload)
            .await
            .map_err(|e| {
                anyhow!(
                    "{self}: Failed to forward RoutePacket to {}: {e}",
                    &*target_conn
                )
            })?;

        Ok(())
    }
}
