// SPDX-License-Identifier: MIT
// Copyright(c) 2024 Darek Stojaczyk

use crate::executor;
use crate::packet_stream::{PacketStream, StreamConfig};
use crate::registry::{BorrowRef, BorrowRegistry};
use clap::Args;
use futures::io::BufReader;
use log::{error, info};
use user::UserConnHandler;

use core::any::TypeId;
use std::fmt::Display;
use std::net::TcpStream;
use std::os::fd::{AsFd, AsRawFd};
use std::sync::Weak;
use std::{net::TcpListener, sync::Arc};

use anyhow::Result;
use smol::Async;

mod user;

/// LoginSvr replacement
#[derive(Args, Debug, Default)]
#[command(about, long_about, verbatim_doc_comment)]
pub struct LoginArgs {}
pub struct Listener {
    me: Weak<Listener>,
    tcp_listener: Async<TcpListener>,
    connections: BorrowRegistry<usize>,
    args: Arc<crate::args::Config>,
}

impl std::fmt::Display for Listener {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_fmt(format_args!(
            "GMS:{}",
            self.tcp_listener.get_ref().local_addr().unwrap().port()
        ))
    }
}

impl Listener {
    pub fn new(tcp_listener: Async<TcpListener>, args: &Arc<crate::args::Config>) -> Arc<Self> {
        Arc::new_cyclic(|me| Self {
            me: me.clone(),
            tcp_listener,
            connections: BorrowRegistry::new("GMS", 16),
            args: args.clone(),
        })
    }

    pub async fn listen(&self) -> Result<()> {
        info!(
            "Listener: started on {}",
            self.tcp_listener.get_ref().local_addr()?
        );
        let _gmsargs = self
            .args
            .services
            .iter()
            .find_map(|s| {
                if let crate::args::Service::Gms(args) = s {
                    Some(args)
                } else {
                    None
                }
            })
            .unwrap();

        loop {
            let (stream, _) = self.tcp_listener.accept().await.unwrap();
            let listener = self.me.upgrade().unwrap();
            // Give the connection handler its own background task
            executor::spawn_local(async move {
                info!("Listener: new connection ...");

                let id = stream.as_fd().as_raw_fd();
                let stream = PacketStream::new(
                    BufReader::with_capacity(65536, stream),
                    StreamConfig {
                        self_name: "LoginSvr".into(),
                        other_name: "User".into(),
                        serialize_checksum: false,
                        deserialize_checksum: true,
                    },
                );

                info!("Listener: {id} connected");
                if let Err(err) = listener.handle_new_conn(stream).await {
                    error!("Listener: {id} error: {err}");
                }
                info!("Listener: closing {id}");
                // TODO remove handle?
            })
            .detach();
        }
    }

    async fn handle_new_conn(
        self: Arc<Listener>,
        stream: PacketStream<BufReader<Async<TcpStream>>>,
    ) -> Result<()> {
        let conn_ref = self
            .connections
            .add_borrower(TypeId::of::<UserConnHandler>(), 0)
            .unwrap();
        let conn = Connection {
            conn_ref,
            listener: self.clone(),
            stream,
        };
        UserConnHandler::new(conn).handle().await
    }
}

struct Connection {
    conn_ref: Arc<BorrowRef<usize>>,
    listener: Arc<Listener>,
    stream: PacketStream<BufReader<Async<TcpStream>>>,
}

impl Display for Connection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.stream.fmt(f)
    }
}
