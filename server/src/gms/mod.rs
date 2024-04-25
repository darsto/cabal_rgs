// SPDX-License-Identifier: MIT
// Copyright(c) 2023 Darek Stojaczyk

use crate::packet_stream::PacketStream;
use crate::ThreadLocalExecutor;
use borrow_mutex::BorrowMutex;
use clap::Parser;
use log::{error, info, trace};
use packet::pkt_common::ServiceID;
use packet::*;

use std::fmt::Display;
use std::net::TcpStream;
use std::os::fd::AsRawFd;
use std::sync::{OnceLock, RwLock, Weak};
use std::{net::TcpListener, sync::Arc};

use anyhow::{bail, Result};
use smol::Async;

/// GlobalMgrSvr replacement
#[derive(Parser, Debug, Default)]
#[command(about, long_about, verbatim_doc_comment)]
pub struct GmsArgs {}

pub struct Listener {
    me: Weak<Listener>,
    tcp_listener: Async<TcpListener>,
    connections: RwLock<Vec<Arc<ConnectionHandle>>>,
    args: Arc<crate::args::Config>,
}

impl Listener {
    pub fn new(tcp_listener: Async<TcpListener>, args: &Arc<crate::args::Config>) -> Arc<Self> {
        Arc::new_cyclic(|me| Self {
            me: me.clone(),
            tcp_listener,
            connections: RwLock::new(Vec::new()),
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
            let (stream, _) = self.tcp_listener.accept().await?;

            let handle = Arc::new(ConnectionHandle {
                id: stream.as_raw_fd(),
                service: OnceLock::new(),
                borrower: BorrowMutex::new(),
            });
            self.connections.write().unwrap().push(handle.clone());

            let mut conn = Connection {
                handle,
                listener: self.me.upgrade().unwrap(),
                stream: PacketStream::new(stream.as_raw_fd(), stream),
            };

            // Give the connection handler its own background task
            ThreadLocalExecutor::get()
                .unwrap()
                .spawn(async move {
                    let id = conn.handle.id;
                    info!("Listener: new connection #{id}");
                    if let Err(err) = conn.handle_initial().await {
                        error!("Listener: connection #{id} error: {err}");
                    }
                    info!("Listener: closing connection #{id}");
                    // TODO remove handle?
                })
                .detach();
        }
    }
}

struct Connection {
    pub handle: Arc<ConnectionHandle>,
    pub listener: Arc<Listener>,
    pub stream: PacketStream<Async<TcpStream>>,
}

#[derive(Debug, Default)]
struct ConnectionHandle {
    pub id: i32,
    pub service: OnceLock<pkt_common::Connect>,
    pub borrower: BorrowMutex<16, Connection>,
}

impl Display for Connection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if let Some(service) = self.handle.service.get() {
            write!(f, "Conn {}", service)
        } else {
            write!(f, "Conn #{}", self.handle.id)
        }
    }
}

impl Connection {
    pub async fn handle_initial(&mut self) -> Result<()> {
        let p = self.stream.recv().await?;
        let Payload::Connect(connect) = p else {
            bail!("{self}: Expected Connect packet, got {p:?}");
        };
        self.handle
            .service
            .set(connect)
            .expect("connection handle was already initialized");
        let service = self.handle.service.get().unwrap();

        #[rustfmt::skip]
        let connect_ack_bytes: Vec<u8> = match service.id {
            ServiceID::ChatNode | ServiceID::AgentShop => [
                0xff, 0xff, 0xff, 0x7f, 0, 0xff, 0, 0xff,
                ServiceID::GlobalMgrSvr as u8, 0, 0, 0, 0,
                service.world_id, service.channel_id, 0, 0, 0, 0, 0x1,
            ]
            .into(),
            ServiceID::LoginSvr => [
                0xfa, 0, 0, 0, 0, 0, 0, 0,
                ServiceID::GlobalMgrSvr as u8, 0, 0, 0, 0,
                service.world_id, service.channel_id, 0, 0, 0, 0, 0x1,
            ]
            .into(),
            ServiceID::WorldSvr => [
                0x50, 0, 0, 0, 0, 0, 0, 0,
                ServiceID::GlobalMgrSvr as u8, 0, 0, 0, 0,
                service.world_id, service.channel_id, 0, 0, 0, 0, 0x1,
            ]
            .into(),
            _ => {
                bail!("Unexpected connection from service {service:?}");
            }
        };

        self.stream
            .send(&Payload::ConnectAck(pkt_common::ConnectAck {
                bytes: BoundVec(connect_ack_bytes),
            }))
            .await?;

        loop {
            let p = self.stream.recv().await?;
            trace!("{self}: Got packet: {p:?}");
        }
    }
}
