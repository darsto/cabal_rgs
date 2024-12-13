// SPDX-License-Identifier: MIT
// Copyright(c) 2024 Darek Stojaczyk

use crate::executor;
use crate::locked_vec::LockedVec;
use crate::packet_stream::{IPCPacketStream, PacketStream, Service, StreamConfig};
use crate::registry::{BorrowRef, BorrowRegistry};
use clap::Args;
use db::GlobalDbHandler;
use gms::GmsHandler;
use log::{error, info};
use packet::Packet;
use user::UserConnHandler;

use std::net::{IpAddr, TcpStream};
use std::os::fd::{AsFd, AsRawFd};
use std::sync::atomic::{AtomicU16, Ordering};
use std::sync::Weak;
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
    globaldb: LockedVec<Arc<BorrowRef<GlobalDbHandler, ()>>>,
    gms: LockedVec<Arc<BorrowRef<GmsHandler, ()>>>,
    connections: BorrowRegistry<UserConnHandler, ()>,
    args: Arc<crate::args::Config>,
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
            globaldb: LockedVec::new(),
            gms: LockedVec::new(),
            connections: BorrowRegistry::new(65536),
            args: args.clone(),
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

        let conn_ref = self.connections.register(()).unwrap();
        let mut handler =
            UserConnHandler::new(self.clone(), stream, conn_ref, ip, auth_key);
        let result = handler.handle().await;
        if result.is_err() {
            let _ = handler.send_diconnect();
        }
        self.connections.unregister(&handler.conn_ref);
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

            let conn_ref = BorrowRef::new(());
            listener.globaldb.push(conn_ref.clone());

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

            let conn_ref = BorrowRef::new(());
            listener.gms.push(conn_ref.clone());

            let ret = GmsHandler::new(listener, stream, conn_ref).handle().await;

            info!("Listener: GMS connection closed => {ret:?}");
            // TODO: reconnect?
        })
        .detach();
    }
}
