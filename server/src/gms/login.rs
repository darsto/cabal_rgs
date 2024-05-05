// SPDX-License-Identifier: MIT
// Copyright(c) 2024 Darek Stojaczyk

use std::pin::pin;

use anyhow::anyhow;
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
    pub conn: Connection,
    pub notify_user_counts: bool,
}

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

    pub async fn handle(mut self) -> Result<()> {
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
            .await?;

        self.conn
            .stream
            .send(&Payload::ChangeServerState(ChangeServerState {
                server_id: service.world_id,
                channel_id: service.channel_id,
                state: ServerStateEnum::Disabled,
            }))
            .await?;

        let lender = conn_ref.borrower.inner::<Self>();
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
                            self.handle_system_message(p).await?;
                        }
                        _ => {
                            trace!("{self}: Got packet: {p:?}");
                        }
                    }
                }
                _ = lender.wait_to_lend().fuse() => {
                    lender.lend(&mut self).unwrap().await
                }
            }

            if self.notify_user_counts {
                self.update_user_count().await?;
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
                error!("Failed to send WorldServerState to {}: {e}", conn.conn);
            }
        }

        if let Err(e) = self
            .conn
            .stream
            .send(&Payload::ServerState(
                LoginServerState {
                    servers: vec![LoginServerNode {
                        id: 1,
                        stype: 16,
                        unk1: 0,
                        groups: groups.clone().into(),
                    }]
                    .into(),
                    trailing: Vec::new().into(),
                }
                .try_into()
                .unwrap(),
            ))
            .await
        {
            error!("{self} Failed to send LoginServerState: {e}");
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
                error!("Failed to forward SystemMessage to {}: {e}", conn.conn);
            }
        }

        self.conn.stream.send(&resp).await?;
        Ok(())
    }
}
