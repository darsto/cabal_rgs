// SPDX-License-Identifier: MIT
// Copyright(c) 2023 Darek Stojaczyk

use crate::executor;
use crate::packet_stream::{IPCPacketStream, Service};
use crate::registry::{BorrowRef, BorrowRegistry};
use clap::Args;
use log::{error, info, trace};

use std::fmt::Display;
use std::net::TcpStream;
use std::os::fd::AsRawFd;
use std::sync::Weak;
use std::{net::TcpListener, sync::Arc};

use anyhow::Result;
use smol::Async;

#[derive(Args, Debug)]
pub struct EventArgs {}

pub struct Listener {
    me: Weak<Listener>,
    tcp_listener: Async<TcpListener>,
    connections: BorrowRegistry<Connection, usize>,
    _args: Arc<crate::args::Config>,
}

impl Listener {
    pub fn new(tcp_listener: Async<TcpListener>, args: &Arc<crate::args::Config>) -> Arc<Self> {
        Arc::new_cyclic(|me| Self {
            me: me.clone(),
            tcp_listener,
            connections: BorrowRegistry::new(16),
            _args: args.clone(),
        })
    }

    pub async fn listen(self: &mut Arc<Self>) -> Result<()> {
        info!(
            "Listener: started on {}",
            self.tcp_listener.get_ref().local_addr()?
        );

        loop {
            let (stream, _) = self.tcp_listener.accept().await?;

            let conn_ref = self
                .connections
                .add_borrower(stream.as_raw_fd() as usize)
                .unwrap();

            // Give the connection handler its own background task
            let listener = self.me.upgrade().unwrap();
            executor::spawn_local(async move {
                let stream = IPCPacketStream::from_host(Service::EventMgr, stream)
                    .await
                    .unwrap();

                let conn = Connection {
                    stream,
                    listener,
                    conn_ref,
                };
                let id = conn.stream.other_id.clone();

                info!("Listener: {id} connected");
                if let Err(err) = conn.handle().await {
                    error!("Listener: {id} error: {err}");
                } else {
                    info!("Listener: closing {id}");
                }
            })
            .detach();
            // for now the tasks are just dropped, but we might want to
            // wait for them in the future (or send a special shutdown
            // message in each connection)
        }
    }
}

pub struct Connection {
    pub stream: IPCPacketStream<Async<TcpStream>>,
    pub listener: Arc<Listener>,
    pub conn_ref: Arc<BorrowRef<Connection, usize>>,
}
crate::impl_registry_entry!(
    Connection,
    RefData = usize,
    borrow_ref =.conn_ref
);

impl Display for Connection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.stream.fmt(f)
    }
}

impl Connection {
    pub async fn handle(mut self) -> Result<()> {
        let other_conn = packet::pkt_common::Connect::from(self.stream.other_id);
        self.stream
            .send(&packet::pkt_event::ConnectAck {
                unk1: 0x0,
                unk2: [0x00, 0xff, 0x00, 0xff, 0xf5, 0x00, 0x00, 0x00, 0x00],
                world_id: other_conn.world_id,
                channel_id: other_conn.channel_id,
                unk3: 0x0,
                unk4: 0x1,
            })
            .await?;

        loop {
            let p = self.stream.recv().await?;
            trace!("{self}: Got packet: {p:?}");
        }
    }
}
