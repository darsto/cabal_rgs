// SPDX-License-Identifier: MIT
// Copyright(c) 2024 Darek Stojaczyk

use crate::executor;
use crate::packet_stream::{IPCPacketStream, PacketStream, Service, StreamConfig};
use crate::registry::{BorrowRef, BorrowRegistry};
use clap::Args;
use db::GlobalDbHandler;
use gms::GmsHandler;
use log::{error, info};
use packet::{pkt_global, Packet};
use user::UserConnHandler;

use core::any::TypeId;
use std::fmt::Display;
use std::net::{IpAddr, TcpStream};
use std::os::fd::{AsFd, AsRawFd};
use std::sync::atomic::AtomicU32;
use std::sync::{OnceLock, Weak};
use std::{net::TcpListener, sync::Arc};

use anyhow::{bail, Context, Result};
use smol::Async;

mod db;
mod gms;
mod user;

/// LoginSvr replacement
#[derive(Args, Debug, Default)]
#[command(about, long_about, verbatim_doc_comment)]
pub struct LoginArgs {}
pub struct Listener {
    me: Weak<Listener>,
    tcp_listener: Async<TcpListener>,
    globaldb: OnceLock<Arc<BorrowRef<()>>>,
    gms: OnceLock<Arc<BorrowRef<()>>>,
    connections: BorrowRegistry<u32>,
    args: Arc<crate::args::Config>,
    pub verify_links_unique_idx: AtomicU32,
}

impl std::fmt::Display for Listener {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_fmt(format_args!(
            "LoginSvr:{}",
            self.tcp_listener.get_ref().local_addr().unwrap().port()
        ))
    }
}

impl Listener {
    pub fn new(tcp_listener: Async<TcpListener>, args: &Arc<crate::args::Config>) -> Arc<Self> {
        Arc::new_cyclic(|me| Self {
            me: me.clone(),
            tcp_listener,
            globaldb: OnceLock::new(),
            gms: OnceLock::new(),
            connections: BorrowRegistry::new("LoginSvr", 16),
            args: args.clone(),
            verify_links_unique_idx: AtomicU32::new(1),
        })
    }

    pub async fn listen(&self) -> Result<()> {
        info!(
            "Listener: started on {}",
            self.tcp_listener.get_ref().local_addr()?
        );
        let _loginargs = self
            .args
            .services
            .iter()
            .find_map(|s| {
                if let crate::args::Service::Login(args) = s {
                    Some(args)
                } else {
                    None
                }
            })
            .unwrap();

        self.connect_to_globaldb().await;
        self.connect_to_gms().await;

        loop {
            let (stream, _) = self.tcp_listener.accept().await.unwrap();
            let listener = self.me.upgrade().unwrap();
            // Give the connection handler its own background task
            executor::spawn_local(async move {
                info!("Listener: new user connection ...");

                let id = stream.as_fd().as_raw_fd();
                let stream = PacketStream::new(
                    stream,
                    StreamConfig {
                        self_name: "LoginSvr".into(),
                        other_name: "User".into(),
                        serialize_checksum: false,
                        deserialize_checksum: true,
                        encode_tx: true,
                        decode_rx: true,
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
        mut stream: PacketStream<Async<TcpStream>>,
    ) -> Result<()> {
        let peer_addr = stream
            .stream
            .get_ref()
            .peer_addr()
            .context("can't obtain user ip address")?;
        let IpAddr::V4(ip) = peer_addr.ip() else {
            bail!("{self}: Not an IPv4 connection");
        };

        let p = stream.recv().await.unwrap();
        let Packet::C2SConnect(p) = p else {
            bail!("{self}: Expected C2SConnect packet, got {p:?}");
        };
        let auth_key = p.auth_key;

        let conn_ref = self
            .connections
            .add_borrower(TypeId::of::<UserConnHandler>(), auth_key)
            .unwrap();
        let conn = Connection {
            conn_ref,
            listener: self.clone(),
            stream,
        };
        let mut handler = UserConnHandler::new(conn, ip, auth_key);
        let result = handler.handle().await;
        if result.is_err() {
            let _ = handler.send_diconnect();
        }
        result
    }

    async fn connect_to_globaldb(&self) {
        let db_stream = Async::<TcpStream>::connect(([127, 0, 0, 1], 38180))
            .await
            .unwrap();

        let listener = self.me.upgrade().unwrap();
        // Give the connection handler its own background task
        executor::spawn_local(async move {
            let stream = IPCPacketStream::from_conn(Service::LoginSvr, Service::DBAgent, db_stream)
                .await
                .unwrap();

            let conn_ref = BorrowRef::new(TypeId::of::<GlobalDbHandler>(), ());
            listener.globaldb.set(conn_ref.clone()).unwrap();

            let ret = GlobalDbHandler::new(listener, stream, conn_ref)
                .handle()
                .await;

            info!("Listener: DB connection closed => {ret:?}");
            // TODO: reconnect?
        })
        .detach();
    }

    async fn connect_to_gms(&self) {
        let stream = Async::<TcpStream>::connect(([127, 0, 0, 1], 38170))
            .await
            .unwrap();

        let listener = self.me.upgrade().unwrap();
        // Give the connection handler its own background task
        executor::spawn_local(async move {
            let stream = IPCPacketStream::from_conn(
                Service::LoginSvr,
                Service::GlobalMgrSvr { id: 0 },
                stream,
            )
            .await
            .unwrap();

            let conn_ref = BorrowRef::new(TypeId::of::<GmsHandler>(), ());
            listener.gms.set(conn_ref.clone()).unwrap();

            let ret = GmsHandler::new(listener, stream, conn_ref).handle().await;

            info!("Listener: GMS connection closed => {ret:?}");
            // TODO: reconnect?
        })
        .detach();
    }
}

struct Connection {
    conn_ref: Arc<BorrowRef<u32>>,
    listener: Arc<Listener>,
    stream: PacketStream<Async<TcpStream>>,
}

impl Display for Connection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.stream.fmt(f)
    }
}
