// SPDX-License-Identifier: MIT
// Copyright(c) 2024 Darek Stojaczyk

use std::{net::TcpStream, sync::Arc, time::Duration};

use anyhow::{anyhow, bail, Result};
use async_proc::select;
use futures::{FutureExt, StreamExt};
use log::warn;
use packet::pkt_common::*;
use packet::*;
use pkt_global::{LoginServerNode, LoginServerState, NotifyUserCount};
use smol::{Async, Timer};

use crate::{
    packet_stream::IPCPacketStream,
    registry::{BorrowRef, Entry},
};

use super::Listener;

pub struct GmsHandler {
    pub listener: Arc<Listener>,
    pub conn_ref: Arc<BorrowRef<()>>,
    pub stream: IPCPacketStream<Async<TcpStream>>,
    pub world_servers: Vec<LoginServerNode>,
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
            world_servers: Vec::new(),
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
                    self.handle_packet(p).await?;
                }
                _ = interval_10s.next().fuse() => {
                    self.stream.send(&NotifyUserCount {
                        server_id: 0x80,
                        channel_id: 1,
                        ..Default::default()
                    }).await.unwrap();
                }
                _ = self.conn_ref.borrower.wait_to_lend().fuse() => {
                    self.lend_self().await;
                }
            }
        }
    }

    pub async fn handle_packet(&mut self, p: Packet) -> Result<()> {
        match p {
            Packet::ServerState(p) => {
                let s = LoginServerState::deserialize_no_hdr(&p.bytes)
                    .map_err(|_| anyhow!("{self}: Malformed LoginServerState packet"))?;
                self.update_world_server_list(s.servers.0);
            }
            Packet::MultipleLoginDisconnectResponse(_) => {
                // nothing to do
            }
            Packet::ChangeServerState(_) => {
                // nothing to do
            }
            Packet::VerifyLinks(p) => {
                let auth_key = p.auth_key; // client key

                // send server list to appropriate client
                // send back VerifyLinksResult with:
                // DuplexRouteHeader:
                //   resp_process_id=0, resp_world_id=0x16, resp_group_id=1, resp_server_id=0x80, unk3=4
                // unk1: 4?? 6??
                // unk2: 1
            }
            _ => {
                warn!("{self}: Got unexpected packet: {p:?}");
            }
        };

        Ok(())
    }

    fn update_world_server_list(&mut self, servers: Vec<LoginServerNode>) {
        if !Self::world_server_list_eq(&self.world_servers, &servers) {
            self.world_servers = servers;
        }
    }

    fn world_server_list_eq(a: &[LoginServerNode], b: &[LoginServerNode]) -> bool {
        if a.len() != b.len() {
            return false;
        }

        for (a, b) in a.iter().zip(b.iter()) {
            if a.id != b.id {
                return false;
            }

            if a.groups.len() != b.groups.len() {
                return false;
            }

            for (a, b) in a.groups.iter().zip(b.groups.iter()) {
                if a.id != b.id {
                    return false;
                }
            }
        }

        true
    }
}

impl std::fmt::Display for GmsHandler {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Gms")
    }
}
