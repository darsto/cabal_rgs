// SPDX-License-Identifier: MIT
// Copyright(c) 2023 Darek Stojaczyk

use crate::packet_stream::PacketStream;
use crate::ThreadLocalExecutor;
use log::{error, info, trace};
use packet::*;

use std::fmt::Display;
use std::net::TcpStream;
use std::os::fd::AsRawFd;
use std::{net::TcpListener, sync::Arc};

use anyhow::{bail, Result};
use smol::Async;

#[derive(clap::Parser, Debug, Default)]
pub struct Args {}

pub struct Listener {
    tcp_listener: Async<TcpListener>,
    _args: Arc<crate::args::Config>,
}

impl Listener {
    pub fn new(tcp_listener: Async<TcpListener>, args: Arc<crate::args::Config>) -> Self {
        Self {
            tcp_listener,
            _args: args,
        }
    }

    pub async fn listen(&mut self) -> Result<()> {
        info!(
            "Listener: started on {}",
            self.tcp_listener.get_ref().local_addr()?
        );

        loop {
            let (stream, _) = self.tcp_listener.accept().await?;

            let conn = Connection {
                id: stream.as_raw_fd(),
                stream: PacketStream::new(stream.as_raw_fd(), stream),
            };

            // Give the connection handler its own background task
            ThreadLocalExecutor::get()
                .unwrap()
                .spawn(async move {
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
    pub stream: PacketStream<Async<TcpStream>>,
}

impl Display for Connection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Conn #{}", self.id)
    }
}

impl Connection {
    pub async fn handle(mut self) -> Result<()> {
        let p = self.stream.recv().await?;
        let Payload::Connect(hello) = &p else {
            bail!("{self}: Expected Connect packet, got {p:?}");
        };
        let hello = packet::event_mgr::Connect::try_from(hello)?;
        let world_id = hello.world_id;
        let channel_id = hello.channel_id;
        trace!("{self}: Got hello: {p:?}");

        let ack = packet::event_mgr::ConnectAck {
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
