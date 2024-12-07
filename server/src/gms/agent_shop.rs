// SPDX-License-Identifier: MIT
// Copyright(c) 2024 Darek Stojaczyk

use anyhow::{anyhow, Result};
use async_proc::select;
use futures::FutureExt;
use log::warn;
use packet::pkt_common::*;
use packet::*;

use crate::registry::Entry;

use super::Connection;

pub struct GlobalAgentShopHandler {
    pub conn: Connection,
}
crate::impl_registry_entry!(
    GlobalAgentShopHandler,
    RefData = pkt_common::Connect,
    data = .conn,
    borrow_ref = .conn.conn_ref
);

impl GlobalAgentShopHandler {
    pub fn new(conn: Connection) -> Self {
        Self { conn }
    }

    pub async fn handle(&mut self) -> Result<()> {
        let conn_ref = self.conn.conn_ref.clone();
        let service = &conn_ref.data;

        #[rustfmt::skip]
        self.conn.stream
            .send(&pkt_common::ConnectAck {
                bytes: BoundVec(vec![
                    0xff, 0xff, 0xff, 0x7f, 0, 0xff, 0, 0xff,
                    ServiceID::GlobalMgrSvr as u8, 0, 0, 0, 0,
                    service.world_id, service.channel_id, 0, 0, 0, 0, 0x1,
                ]),
            })
            .await.unwrap();

        // There should be nothing else to do for now (until we start using AgentShop maybe?)

        loop {
            select! {
                p = self.conn.stream.recv().fuse() => {
                    let p = p.map_err(|e| {
                        anyhow!("{self}: Failed to recv a packet: {e}")
                    })?;
                    warn!("{self}: Got unexpected packet: {p:?}");
                }
                _ = self.conn.conn_ref.borrower.wait_to_lend().fuse() => {
                    self.lend_self().await;
                }
            }
        }
    }
}

impl std::fmt::Display for GlobalAgentShopHandler {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.conn)
    }
}
