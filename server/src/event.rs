// SPDX-License-Identifier: MIT
// Copyright(c) 2023 Darek Stojaczyk

use crate::packet_stream::PacketStream;
use crate::registry::{BorrowRef, BorrowRegistry};
use crate::{executor, impl_registry_entry};
use clap::Parser;
use futures::io::BufReader;
use log::{error, info, trace};
use packet::*;

use std::any::TypeId;
use std::fmt::Display;
use std::net::TcpStream;
use std::os::fd::AsRawFd;
use std::sync::Weak;
use std::{net::TcpListener, sync::Arc};

use anyhow::{bail, Result};
use smol::Async;

#[derive(Parser, Debug)]
pub struct EventArgs {}

pub struct Listener {
    me: Weak<Listener>,
    tcp_listener: Async<TcpListener>,
    connections: BorrowRegistry<usize>,
    _args: Arc<crate::args::Config>,
}

impl Listener {
    pub fn new(tcp_listener: Async<TcpListener>, args: &Arc<crate::args::Config>) -> Arc<Self> {
        Arc::new_cyclic(|me| Self {
            me: me.clone(),
            tcp_listener,
            connections: BorrowRegistry::new("EventMgr", 16),
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
                .add_borrower(TypeId::of::<Connection>(), stream.as_raw_fd() as usize)
                .unwrap();

            let conn = Connection {
                id: stream.as_raw_fd(),
                stream: PacketStream::new_buffered(stream.as_raw_fd(), stream),
                listener: self.me.upgrade().unwrap(),
                conn_ref,
            };

            // Give the connection handler its own background task
            executor::spawn_local(async move {
                let id = conn.id;
                info!("Listener: new connection #{id}");
                if let Err(err) = conn.handle().await {
                    error!("Listener: connection #{id} error: {err}");
                }
                info!("Listener: closing connection #{id}");
            })
            .detach();
            // for now the tasks are just dropped, but we might want to
            // wait for them in the future (or send a special shutdown
            // message in each connection)
        }
    }
}

pub struct Connection {
    pub id: i32,
    pub stream: PacketStream<BufReader<Async<TcpStream>>>,
    pub listener: Arc<Listener>,
    pub conn_ref: Arc<BorrowRef<usize>>,
}
impl_registry_entry!(Connection, usize, .stream, .conn_ref);

impl Display for Connection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "EventMgr Conn #{}", self.id)
    }
}

impl Connection {
    pub async fn handle(mut self) -> Result<()> {
        let p = self.stream.recv().await?;
        let Payload::Connect(hello) = &p else {
            bail!("{self}: Expected Connect packet, got {p:?}");
        };
        let world_id = hello.world_id;
        let channel_id = hello.channel_id;
        trace!("{self}: Got hello: {p:?}");

        let ack = packet::pkt_event::ConnectAck {
            unk1: 0x0,
            unk2: [0x00, 0xff, 0x00, 0xff, 0xf5, 0x00, 0x00, 0x00, 0x00],
            world_id,
            channel_id,
            unk3: 0x0,
            unk4: 0x1,
        };
        self.stream
            .send(&Payload::ConnectAck(ack.try_into()?))
            .await?;

        loop {
            let p = self.stream.recv().await?;
            trace!("{self}: Got packet: {p:?}");
        }
    }
}
