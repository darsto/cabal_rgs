// SPDX-License-Identifier: MIT
// Copyright(c) 2024 Darek Stojaczyk

use crate::atomic_append_vec::AtomicAppendVec;
use crate::packet_stream::PacketStream;
use crate::ThreadLocalExecutor;
use borrow_mutex::{BorrowMutex, BorrowMutexGuardArmed};
use clap::Parser;
use futures::Stream;
use genmatch::*;
use log::{error, info};
use packet::pkt_common::ServiceID;
use packet::*;

use std::any::TypeId;
use std::fmt::Display;
use std::net::TcpStream;
use std::os::fd::AsRawFd;
use std::sync::Weak;
use std::{net::TcpListener, sync::Arc};

use anyhow::{anyhow, bail, Result};
use smol::Async;

mod chat;
use chat::GlobalChatHandler;
mod login;
use login::GlobalLoginHandler;
mod agent_shop;
use agent_shop::GlobalAgentShopHandler;
mod world;
use world::GlobalWorldHandler;

/// GlobalMgrSvr replacement
#[derive(Parser, Debug, Default)]
#[command(about, long_about, verbatim_doc_comment)]
pub struct GmsArgs {}

pub struct Listener {
    me: Weak<Listener>,
    tcp_listener: Async<TcpListener>,
    conn_refs: AtomicAppendVec<Arc<ConnectionRef>>,
    args: Arc<crate::args::Config>,
}

impl Listener {
    pub fn new(tcp_listener: Async<TcpListener>, args: &Arc<crate::args::Config>) -> Arc<Self> {
        Arc::new_cyclic(|me| Self {
            me: me.clone(),
            tcp_listener,
            conn_refs: AtomicAppendVec::with_capacity(16),
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

            let conn = Box::new(Connection {
                id: stream.as_raw_fd(),
                conn_ref: None,
                listener: self.me.upgrade().unwrap(),
                stream: PacketStream::new(stream.as_raw_fd(), stream),
                handler: None,
            });

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
                    // TODO remove handle?
                })
                .detach();
        }
    }
}

struct Connection {
    id: i32,
    conn_ref: Option<Arc<ConnectionRef>>,
    listener: Arc<Listener>,
    stream: PacketStream<Async<TcpStream>>,
    handler: Option<ConnectionHandler>,
}

const BORROW_MUTEX_SIZE: usize = 16;

#[genmatch]
enum ConnectionHandler {
    ChatNode(GlobalChatHandler),
    LoginSvr(GlobalLoginHandler),
    AgentShop(GlobalAgentShopHandler),
    WorldSvr(GlobalWorldHandler),
}

macro_rules! try_cast {
    ($target: expr, $type_a: path, $type_b: path) => {{
        if TypeId::of::<$type_a>() == TypeId::of::<$type_b>() {
            // SAFETY: it's the exact same type
            Some(unsafe { std::mem::transmute($target) })
        } else {
            None
        }
    }};
}

impl ConnectionHandler {
    #[genmatch_self(ConnectionHandler)]
    pub fn conn(&self) -> &Connection {
        &inner.conn
    }

    #[genmatch_self(ConnectionHandler)]
    pub fn try_inner_mut<H: 'static>(&mut self) -> Option<&mut H> {
        try_cast!(inner, H, EnumStructType)
    }

    pub fn inner_mut<H: 'static>(&mut self) -> &mut H {
        self.try_inner_mut().unwrap()
    }

    pub fn handler_service<T: 'static>() -> ServiceID {
        let t_id = TypeId::of::<T>();
        if t_id == TypeId::of::<GlobalChatHandler>() {
            ServiceID::ChatNode
        } else if t_id == TypeId::of::<GlobalLoginHandler>() {
            ServiceID::LoginSvr
        } else if t_id == TypeId::of::<GlobalAgentShopHandler>() {
            ServiceID::AgentShop
        } else if t_id == TypeId::of::<GlobalWorldHandler>() {
            ServiceID::WorldSvr
        } else {
            ServiceID::None
        }
    }
}

#[derive(Debug)]
struct ConnectionRef {
    service: pkt_common::Connect,
    borrower: BorrowMutex<BORROW_MUTEX_SIZE, Connection>,
}

impl Display for Connection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if let Some(handle) = &self.conn_ref {
            write!(f, "Conn #{} ({})", self.id, handle.service)
        } else {
            write!(f, "Conn #{}", self.id)
        }
    }
}

#[macro_export]
macro_rules! init_start_handler {
    ($conn:ident, $handler_type:expr, $handler_struct:ident) => {{
        let conn_ref = $conn.conn_ref.as_ref().unwrap().clone();
        let listener = $conn.listener.clone();
        let conn_ptr: *mut Connection = $conn.as_mut();

        let handler = $handler_type($handler_struct::new($conn));
        let handler = unsafe { &mut *conn_ptr }.handler.insert(handler);

        listener.conn_refs.push(conn_ref).unwrap();
        handler.inner_mut::<$handler_struct>().handle()
    }};
}

impl Connection {
    async fn handle(mut self: Box<Connection>) -> Result<()> {
        let p = self.stream.recv().await.map_err(|e| anyhow!("{self}: Failed to receive the first packet: {e:?}"))?;
        let Payload::Connect(service) = p else {
            bail!("{self}: Expected Connect packet, got {p:?}");
        };

        if let Some(conn) = self.listener.conn_refs.iter().find(|conn| {
            let s = &conn.service;
            s.id == service.id
                && s.world_id == service.world_id
                && s.channel_id == service.channel_id
        }) {
            bail!(
                "{self}: Received multiple connections from the same service: {service:?}, previous: {:?}",
                &conn.service
            );
        }

        self.conn_ref = Some(Arc::new(ConnectionRef {
            service,
            borrower: BorrowMutex::new(),
        }));

        let service = self.service();
        match service.id {
            ServiceID::ChatNode => {
                init_start_handler!(self, ConnectionHandler::ChatNode, GlobalChatHandler).await
            }
            ServiceID::LoginSvr => {
                init_start_handler!(self, ConnectionHandler::LoginSvr, GlobalLoginHandler).await
            }
            ServiceID::AgentShop => {
                init_start_handler!(self, ConnectionHandler::AgentShop, GlobalAgentShopHandler)
                    .await
            }
            ServiceID::WorldSvr => {
                init_start_handler!(self, ConnectionHandler::WorldSvr, GlobalWorldHandler).await
            }
            _ => {
                bail!("{self}: Unexpected connection from service {service:?}");
            }
        }
    }

    fn service(&self) -> &pkt_common::Connect {
        &self.conn_ref.as_ref().unwrap().service
    }

    fn iter_handlers<H: 'static>(&self) -> impl Stream<Item = BorrowMutexGuardArmed<'_, H>> {
        let self_handle = self.conn_ref.as_ref().unwrap();
        let iter = self.listener.conn_refs.iter();
        futures::stream::unfold(iter, move |mut iter| async move {
            while let Some(next) = iter.next() {
                if next.service.id != ConnectionHandler::handler_service::<H>() {
                    continue;
                }
                assert!(!Arc::ptr_eq(next, self_handle));
                if let Ok(conn) = next.borrower.request_borrow().await {
                    return Some((
                        BorrowMutexGuardArmed::map(conn, |conn| {
                            conn.handler.as_mut().unwrap().try_inner_mut::<H>().unwrap()
                        }),
                        iter,
                    ));
                }
            }
            None
        })
    }
}
