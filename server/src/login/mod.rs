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

use std::collections::hash_map::Entry;
use std::collections::HashMap;
use std::net::{IpAddr, TcpStream};
use std::os::fd::{AsFd, AsRawFd};
use std::sync::{Mutex, Weak};
use std::time::Duration;
use std::{net::TcpListener, sync::Arc};

use anyhow::{bail, Context, Result};
use smol::{Async, Timer};

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
    authenticated_connections: Mutex<HashMap<u32, u16>>,
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
            authenticated_connections: Mutex::new(HashMap::new()),
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

        // If the TCP send buffer is sufficiently small, a malicious connection could
        // be stuck on send(), so cut it short here
        let _ = stream
            .stream
            .get_ref()
            .set_write_timeout(Some(Duration::from_secs(10)));

        let conn_ref = self.connections.register(()).unwrap();
        let mut handler = UserConnHandler::new(self.clone(), stream, conn_ref, ip, auth_key);
        // TODO: add timeout - the user should not linger forever while choosing the channel
        let result = handler.handle().await;
        if result.is_err() && !handler.force_terminate {
            let _ = handler.handle_disconnect().await;
        }
        self.connections.unregister(&handler.conn_ref);
        result
    }

    async fn connect_to_globaldb(&self) {
        let listener = self.me.upgrade().unwrap();

        let conn_ref = BorrowRef::new(());
        listener.globaldb.push(conn_ref.clone());

        // Give the connection handler its own background task
        executor::spawn_local(async move {
            loop {
                let Ok(db_stream) = Async::<TcpStream>::connect(([127, 0, 0, 1], 38180)).await
                else {
                    Timer::after(Duration::from_secs(2)).await;
                    continue;
                };

                info!("Listener: DB connection established");
                let stream =
                    IPCPacketStream::from_conn(Service::LoginSvr, Service::DBAgent, db_stream)
                        .await
                        .unwrap();

                let ret = GlobalDbHandler::new(listener.clone(), stream, conn_ref.clone())
                    .handle()
                    .await;

                info!("Listener: DB connection closed => {ret:?}");
            }
        })
        .detach();
    }

    async fn connect_to_gms(&self) {
        let listener = self.me.upgrade().unwrap();

        let conn_ref = BorrowRef::new(());
        listener.gms.push(conn_ref.clone());

        // Give the connection handler its own background task
        executor::spawn_local(async move {
            loop {
                let Ok(stream) = Async::<TcpStream>::connect(([127, 0, 0, 1], 38170)).await else {
                    Timer::after(Duration::from_secs(2)).await;
                    continue;
                };

                info!("Listener: GMS connection established");
                let stream = IPCPacketStream::from_conn(
                    Service::LoginSvr,
                    Service::GlobalMgrSvr { id: 0 },
                    stream,
                )
                .await
                .unwrap();

                let ret = GmsHandler::new(listener.clone(), stream, conn_ref.clone())
                    .handle()
                    .await;
                info!("Listener: GMS connection closed => {ret:?}");
            }
        })
        .detach();
    }

    pub async fn set_authenticated_connection_idx(&self, user_id: u32, conn_idx: u16) {
        println!("setting {conn_idx} as authenticated connection for user {user_id}");
        let mut authenticated_connections = self.authenticated_connections.lock().unwrap();
        let prev_conn_idx = authenticated_connections.insert(user_id, conn_idx);
        drop(authenticated_connections);
        if let Some(prev_conn_idx) = prev_conn_idx {
            println!("terminating previous connection {prev_conn_idx} for user {user_id}");
            let prev_conn_ref = self.connections.refs.get(prev_conn_idx);
            // connection could've just dropped
            if let Some(prev_conn_ref) = prev_conn_ref {
                // Note: we might be waiting for a long time if the previous connection is
                // stuck inside send() (because i.e. the client is not responding). This will
                // only affect the current connection (for the same user), so not a problem
                if let Ok(mut prev_conn) = prev_conn_ref.borrow().await {
                    prev_conn.force_terminate = true;
                }
            }
        }
    }

    pub fn unset_authenticated_connection_idx(&self, user_id: u32, conn_idx: u16) {
        if let Ok(mut authenticated_connections) = self.authenticated_connections.lock() {
            match authenticated_connections.entry(user_id) {
                Entry::Vacant(_) => {}
                Entry::Occupied(e) => {
                    if *e.get() == conn_idx {
                        e.remove_entry();
                    }
                }
            }
        }
    }
}
