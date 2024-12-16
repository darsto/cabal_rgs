// SPDX-License-Identifier: MIT
// Copyright(c) 2024 Darek Stojaczyk

use std::{net::TcpStream, sync::Arc};

use anyhow::{anyhow, bail, Result};
use async_proc::select;
use futures::FutureExt;
use log::warn;
use packet::pkt_common::*;
use packet::*;
use pkt_login::RequestClientVersion;
use smol::Async;

use crate::{
    packet_stream::IPCPacketStream,
    registry::{BorrowRef, Borrowable},
};

use super::Listener;

pub struct GlobalDbHandler {
    pub listener: Arc<Listener>,
    pub stream: IPCPacketStream<Async<TcpStream>>,
    pub conn_ref: Arc<BorrowRef<Self, ()>>,
}
crate::impl_borrowable!(
    GlobalDbHandler,
    RefData = (),
    borrow_ref =.conn_ref
);

impl GlobalDbHandler {
    pub fn new(
        listener: Arc<Listener>,
        stream: IPCPacketStream<Async<TcpStream>>,
        conn_ref: Arc<BorrowRef<Self, ()>>,
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
        assert_eq!(ack.bytes[8], ServiceID::DBAgent as u8);

        self.stream.send(&RequestClientVersion {}).await?;
        let p = self
            .stream
            .recv()
            .await
            .map_err(|e| anyhow!("{self}: Failed to recv a packet: {e:?}"))?;
        let Packet::ClientVersionNotify(p) = p else {
            bail!("{self}: Expected ClientVersionNotify packet, got {p:?}");
        };

        println!("{self}: ver={p:?}");

        // TODO send the version to GMS

        loop {
            select! {
                p = self.stream.recv().fuse() => {
                    let p = p.map_err(|e| {
                        anyhow!("{self}: Failed to recv a packet: {e}")
                    })?;
                    warn!("{self}: Got unexpected packet: {p:?}");
                }
                _ = self.conn_ref.borrower.wait_to_lend().fuse() => {
                    self.lend_self().await;
                }
            }
        }
    }
}

impl std::fmt::Display for GlobalDbHandler {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "GlobalDb")
    }
}
