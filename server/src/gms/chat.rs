// SPDX-License-Identifier: MIT
// Copyright(c) 2024 Darek Stojaczyk

use anyhow::{anyhow, bail, Result};
use futures::FutureExt;
use log::trace;
use packet::pkt_common::ServiceID;
use packet::*;

use super::Connection;

pub struct GlobalChatHandler {
    pub conn: Box<Connection>,
}

impl std::fmt::Display for GlobalChatHandler {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.conn)
    }
}

impl GlobalChatHandler {
    pub fn new(conn: Box<Connection>) -> Self {
        Self { conn }
    }

    pub async fn handle(&mut self) -> Result<()> {
        let conn_ref = self.conn.conn_ref.as_ref().unwrap().clone();
        let service = &conn_ref.service;

        #[rustfmt::skip]
        self.conn.stream
            .send(&Payload::ConnectAck(pkt_common::ConnectAck {
                bytes: BoundVec(vec![
                    0xff, 0xff, 0xff, 0x7f, 0, 0xff, 0, 0xff,
                    ServiceID::GlobalMgrSvr as u8, 0, 0, 0, 0,
                    service.world_id, service.channel_id, 0, 0, 0, 0, 0x1,
                ]),
            }))
            .await.unwrap();

        let p = self.conn.stream.recv().await.unwrap();
        let Payload::RegisterChatSvr(_) = p else {
            bail!("{self}: Expected RegisterChatSvr packet, got {p:?}");
        };

        loop {
            futures::select! {
                p = self.conn.stream.recv().fuse() => {
                    let p = p.map_err(|e| {
                        anyhow!("{self}: Failed to recv a packet: {e}")
                    })?;
                    trace!("{self}: Got packet: {p:?}");
                }
                _ = conn_ref.borrower.wait_to_lend().fuse() => {
                    conn_ref.borrower.lend(&mut self.conn).unwrap().await
                }
            }
        }
    }
}
