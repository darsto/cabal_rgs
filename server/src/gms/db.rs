// SPDX-License-Identifier: MIT
// Copyright(c) 2024 Darek Stojaczyk

use std::time::Duration;

use anyhow::{anyhow, bail, Result};
use async_proc::select;
use futures::{FutureExt, StreamExt};
use log::warn;
use packet::pkt_common::*;
use packet::*;
use smol::Timer;

use crate::registry::Entry;

use super::Connection;

pub struct GlobalDbHandler {
    pub conn: Connection,
    pub dung_inst_cnt: Option<pkt_global::AdditionalDungeonInstanceCount>,
}
crate::impl_registry_entry!(
    GlobalDbHandler,
    pkt_common::Connect,
    .conn,
    .conn.conn_ref
);

impl GlobalDbHandler {
    pub fn new(conn: Connection) -> Self {
        Self {
            conn,
            dung_inst_cnt: Some(pkt_global::AdditionalDungeonInstanceCount { unk1: 1, unk2: 0 }),
        }
    }

    pub async fn handle(&mut self) -> Result<()> {
        let p = self
            .conn
            .stream
            .recv()
            .await
            .map_err(|e| anyhow!("{self}: Failed to receive the first packet: {e:?}"))?;
        let Packet::ConnectAck(ack) = p else {
            bail!("{self}: Expected ConnectAck packet, got {p:?}");
        };
        assert_eq!(ack.bytes.len(), 20);
        assert_eq!(ack.bytes[8], ServiceID::DBAgent as u8);

        let mut interval_10s = Timer::interval(Duration::from_secs(10));
        loop {
            select! {
                p = self.conn.stream.recv().fuse() => {
                    let p = p.map_err(|e| {
                        anyhow!("{self}: Failed to recv a packet: {e}")
                    })?;
                    match p {
                        Packet::AdditionalDungeonInstanceCount(_) => {
                            // carry on
                        }
                        _ => {
                            warn!("{self}: Got unexpected packet: {p:?}");
                        }
                    }
                }
                _ = interval_10s.next().fuse() => {
                    if let Some(dung_inst_cnt) = &self.dung_inst_cnt {
                        self.conn.stream
                        .send(&dung_inst_cnt.clone())
                        .await.unwrap();
                    }
                }
                _ = self.conn.conn_ref.borrower.wait_to_lend().fuse() => {
                    self.lend_self().await;
                }
            }
        }
    }
}

impl std::fmt::Display for GlobalDbHandler {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.conn)
    }
}
