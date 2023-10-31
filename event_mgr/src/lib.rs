// SPDX-License-Identifier: MIT
// Copyright(c) 2023 Darek Stojaczyk

pub mod packet_stream;

use packet::*;
use packet_stream::PacketStream;

use std::net::{TcpListener, TcpStream};
use std::os::fd::AsRawFd;

use anyhow::{bail, Result};
use clap::Parser;
use smol::io::{AsyncReadExt, AsyncWriteExt};
use smol::Async;

#[derive(Parser, Debug, Default)]
#[command(author, version, about, long_about = None)]
pub struct Args {}

pub struct Listener {
    tcp_listener: Async<TcpListener>,
    _args: Args,
}

impl Listener {
    pub fn new(tcp_listener: Async<TcpListener>, args: Args) -> Self {
        Self {
            tcp_listener,
            _args: args,
        }
    }

    pub async fn listen(&mut self) -> Result<()> {
        println!("Listening on {}", self.tcp_listener.get_ref().local_addr()?);

        loop {
            let (stream, _) = self.tcp_listener.accept().await?;

            let conn = Connection {
                id: stream.as_raw_fd(),
                stream: PacketStream::new(stream),
            };

            // Give the connection handler its own background task
            smol::spawn(async move {
                let id = conn.id;
                println!("New connection #{id}");
                if let Err(err) = conn.handle().await {
                    eprintln!("Connection #{id} error: {err}");
                }
                println!("Closing connection #{id}");
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
    pub stream: PacketStream,
}

impl Connection {
    pub async fn handle(mut self) -> Result<()> {
        let p = self.stream.recv().await?;
        let Payload::Connect(hello) = &p else {
            bail!("Expected Connect packet, got {p:?}");
        };

        let world_id = hello.world_id;
        let channel_id = hello.channel_id;

        println!("Got hello: {p:?}");
        println!("Sending Ack ...");

        let ack = Payload::ConnectAck(common::ConnectAck {
            unk1: 0x0,
            unk2: [0x00, 0xff, 0x00, 0xff, 0xf5, 0x00, 0x00, 0x00, 0x00],
            world_id,
            channel_id,
            unk3: 0x0,
            unk4: 0x1,
        });
        self.stream.send(&ack).await?;

        loop {
            let p = self.stream.recv().await?;
            println!("Got packet: {p:?}");
        }
    }
}
