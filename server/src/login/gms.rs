// SPDX-License-Identifier: MIT
// Copyright(c) 2024 Darek Stojaczyk

use std::{net::TcpStream, sync::Arc, time::Duration};

use anyhow::{anyhow, bail, Result};
use async_proc::select;
use futures::{FutureExt, StreamExt};
use log::warn;
use packet::pkt_common::*;
use packet::*;
use pkt_global::NotifyUserCount;
use smol::{Async, Timer};

use crate::{
    packet_stream::IPCPacketStream,
    registry::{BorrowRef, Entry},
};

use super::Listener;

pub struct GmsHandler {
    listener: Arc<Listener>,
    conn_ref: Arc<BorrowRef<()>>,
    stream: IPCPacketStream<Async<TcpStream>>,
}
crate::impl_registry_entry!(
    GmsHandler,
    RefData = (),
    data = .listener,
    borrow_ref = .conn_ref
);

impl GmsHandler {
    pub fn new(
        listener: Arc<Listener>,
        stream: IPCPacketStream<Async<TcpStream>>,
        conn_ref: Arc<BorrowRef<()>>,
    ) -> Self {
        Self {
            listener,
            stream,
            conn_ref,
        }
    }

    pub async fn handle(&mut self) -> Result<()> {
        let p = self
            .stream
            .recv()
            .await
            .map_err(|e| anyhow!("{self}: Failed to receive the first packet: {e:?}"))?;
        let Packet::ConnectAck(ack) = p else {
            bail!("{self}: Expected ConnectAck packet, got {p:?}");
        };
        assert_eq!(ack.bytes.len(), 20);
        assert_eq!(ack.bytes[8], ServiceID::GlobalMgrSvr as u8);

        // TODO send the version packet, altho our GMS doesn't need it

        let mut interval_10s = Timer::interval(Duration::from_secs(10));
        loop {
            select! {
                p = self.stream.recv().fuse() => {
                    let p = p.map_err(|e| {
                        anyhow!("{self}: Failed to recv a packet: {e}")
                    })?;
                    warn!("{self}: Got unexpected packet: {p:?}");
                }
                _ = interval_10s.next().fuse() => {
                    self.stream.send(&NotifyUserCount {
                            server_id: 0x80,
                        channel_id: 1,
                        ..Default::default()
                })
                        .await.unwrap();
                }
                _ = self.conn_ref.borrower.wait_to_lend().fuse() => {
                    self.lend_self().await;
                }
            }
        }
    }
}

impl std::fmt::Display for GmsHandler {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Gms")
    }
}
