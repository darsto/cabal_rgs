// SPDX-License-Identifier: MIT
// Copyright(c) 2024 Darek Stojaczyk

use std::sync::atomic::{AtomicUsize, Ordering};

use anyhow::anyhow;
use anyhow::Result;
use async_proc::select;
use futures::FutureExt;
use log::warn;
use packet::pkt_common::*;
use packet::pkt_global::*;
use packet::*;

use crate::registry::Entry;

use super::Connection;

pub struct UserConnHandler {
    pub conn: Connection,
}
crate::impl_registry_entry!(
    UserConnHandler,
    usize,
    .conn,
    .conn.conn_ref
);

impl std::fmt::Display for UserConnHandler {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.conn)
    }
}

impl UserConnHandler {
    pub fn new(conn: Connection) -> Self {
        Self { conn }
    }

    pub async fn handle(&mut self) -> Result<()> {
        #[rustfmt::skip]
        self.conn.stream
            .send(&ConnectAck {
                bytes: BoundVec(vec![
                    0x50, 0, 0, 0, 0, 0, 0, 0,
                    ServiceID::GlobalMgrSvr as u8, 0, 0, 0, 0,
                    0, 0, 0, 0, 0, 0, 0x1,
                ]),
            })
            .await.unwrap();

        loop {
            select! {
                p = self.conn.stream.recv().fuse() => {
                    let p = p.map_err(|e| {
                        anyhow!("{self}: Failed to recv a packet: {e}")
                    })?;
                    match p {
                        Packet::ProfilePathRequest(p) => {
                            self.handle_profile_path(p).await.unwrap();
                        }
                        Packet::SetLoginInstance(_) => {
                            // there's nothing to do
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
        }
    }

    async fn handle_profile_path(&mut self, p: ProfilePathRequest) -> Result<()> {
        static COUNTER: AtomicUsize = AtomicUsize::new(0);
        assert_eq!(p.unk1, 0);
        self.conn
            .stream
            .send(&ProfilePathResponse {
                unk1: 5 + COUNTER.fetch_add(1, Ordering::Relaxed) as u32, // TODO: test with more than 2 channels
                scp_id1: 4,
                scp_path1: Arr::from("Data/Item.scp".as_bytes()),
                scp_id2: 2,
                scp_path2: Arr::from("Data/Mobs.scp".as_bytes()),
                scp_id3: 1,
                scp_path3: Arr::from("Data/Warp.scp".as_bytes()),
            })
            .await
    }
}
