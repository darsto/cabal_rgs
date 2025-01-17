// SPDX-License-Identifier: MIT
// Copyright(c) 2024 Darek Stojaczyk

use std::{net::TcpStream, sync::Arc};

use anyhow::{anyhow, bail, Result};
use async_proc::select;
use futures::FutureExt;
use log::warn;
use packet::pkt_common::ServiceID;
use packet::*;
use smol::Async;

use super::Listener;
use crate::{
    packet_stream::IPCPacketStream,
    registry::{BorrowRef, Borrowable},
};

pub struct GlobalChatHandler {
    pub _listener: Arc<Listener>,
    pub stream: IPCPacketStream<Async<TcpStream>>,
    pub conn_ref: Arc<BorrowRef<Self, pkt_common::Connect>>,
}
crate::impl_borrowable!(
    GlobalChatHandler,
    RefData = pkt_common::Connect,
    borrow_ref = .conn_ref
);

impl GlobalChatHandler {
    pub fn new(
        listener: Arc<Listener>,
        stream: IPCPacketStream<Async<TcpStream>>,
        conn_ref: Arc<BorrowRef<Self, pkt_common::Connect>>,
    ) -> Self {
        Self {
            _listener: listener,
            stream,
            conn_ref,
        }
    }

    pub async fn handle(&mut self) -> Result<()> {
        let conn_ref = self.conn_ref.clone();
        let service = &conn_ref.data;

        #[rustfmt::skip]
        self.stream
            .send(&pkt_common::ConnectAck {
                bytes: BoundVec(vec![
                    0xff, 0xff, 0xff, 0x7f, 0, 0xff, 0, 0xff,
                    ServiceID::GlobalMgrSvr as u8, 0, 0, 0, 0,
                    service.server_id, service.channel_id, 0, 0, 0, 0, 0x1,
                ]),
            })
            .await.unwrap();

        let p = self.stream.recv().await.unwrap();
        let Packet::RegisterChatSvr(_) = p else {
            bail!("{self}: Expected RegisterChatSvr packet, got {p:?}");
        };

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

impl std::fmt::Display for GlobalChatHandler {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "GlobalChatHandler")
    }
}
