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

use core::any::{Any, TypeId};
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
            let listener = self.me.upgrade().unwrap();
            // Give the connection handler its own background task
            ThreadLocalExecutor::get()
                .unwrap()
                .spawn(async move {
                    let id = stream.as_raw_fd();
                    info!("Listener: new connection #{id}");
                    if let Err(err) = listener.handle_new_conn(id, stream).await {
                        error!("Listener: connection #{id} error: {err}");
                    }
                    info!("Listener: closing connection #{id}");
                    // TODO remove handle?
                })
                .detach();
        }
    }

    async fn handle_new_conn(self: Arc<Listener>, id: i32, stream: Async<TcpStream>) -> Result<()> {
        let mut stream = PacketStream::new(stream.as_raw_fd(), stream);
        let p = stream
            .recv()
            .await
            .map_err(|e| anyhow!("{self}: Failed to receive the first packet: {e:?}"))?;
        let Payload::Connect(service) = p else {
            bail!("{self}: Expected Connect packet, got {p:?}");
        };

        if let Some(conn) = self.conn_refs.iter().find(|conn| {
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

        let conn_ref = Arc::new(ConnectionRef {
            service,
            borrower: BorrowMutex::new(),
        });
        let conn = Connection {
            id,
            conn_ref,
            listener: self.clone(),
            stream,
        };
        // TODO: introduce `from_inner` inside the genmatch crate
        let mut handler = match conn.conn_ref.service.id {
            ServiceID::ChatNode => ConnectionHandler::ChatNode(GlobalChatHandler::new(conn)),
            ServiceID::LoginSvr => ConnectionHandler::LoginSvr(GlobalLoginHandler::new(conn)),
            ServiceID::AgentShop => ConnectionHandler::AgentShop(GlobalAgentShopHandler::new(conn)),
            ServiceID::WorldSvr => ConnectionHandler::WorldSvr(GlobalWorldHandler::new(conn)),
            service_id => {
                bail!("{self}: Unexpected connection from service {service_id:?}");
            }
        };

        handler.handle().await
    }
}

struct Connection {
    id: i32,
    conn_ref: Arc<ConnectionRef>,
    listener: Arc<Listener>,
    stream: PacketStream<Async<TcpStream>>,
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
    pub fn conn_mut(&mut self) -> &mut Connection {
        &mut inner.conn
    }

    #[genmatch_self(ConnectionHandler)]
    pub fn try_inner_mut<H: 'static>(&mut self) -> Option<&mut H> {
        try_cast!(inner, H, EnumStructType)
    }

    pub fn inner_mut<H: 'static>(&mut self) -> &mut H {
        self.try_inner_mut().unwrap()
    }

    #[genmatch_self(ConnectionHandler)]
    pub async fn handle(&mut self) -> Result<()> {
        inner.handle().await
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

trait ConnectionHandler2: AsAny + std::fmt::Display {
    fn conn(&self) -> &Connection;
    fn conn_mut(&mut self) -> &mut Connection;
}

trait AsAny: Any {
    fn as_any(&self) -> &dyn Any;
    fn as_any_mut(&mut self) -> &mut dyn Any;
}

impl<T: Any> AsAny for T {
    fn as_any(&self) -> &dyn Any {
        self
    }
    fn as_any_mut(&mut self) -> &mut dyn Any {
        self
    }
}

#[macro_export]
macro_rules! impl_connection_handler {
    ($handler:ident) => {
        impl $crate::gms::ConnectionHandler2 for $handler {
            fn conn(&self) -> &Connection {
                &self.conn
            }
            fn conn_mut(&mut self) -> &mut Connection {
                &mut self.conn
            }
        }
    };
}

#[derive(Debug)]
struct ConnectionRef {
    service: pkt_common::Connect,
    borrower: BorrowMutex<BORROW_MUTEX_SIZE, dyn ConnectionHandler2>,
}

impl Display for Connection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Conn #{} ({})", self.id, self.conn_ref.service)
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
    fn service(&self) -> &pkt_common::Connect {
        &self.conn_ref.service
    }

    fn iter_handlers<H: 'static>(&self) -> impl Stream<Item = BorrowMutexGuardArmed<'_, H>> {
        let self_handle = &self.conn_ref;
        let iter = self.listener.conn_refs.iter();
        futures::stream::unfold(iter, move |mut iter| async move {
            while let Some(next) = iter.next() {
                if next.service.id != ConnectionHandler::handler_service::<H>() {
                    continue;
                }
                assert!(!Arc::ptr_eq(next, self_handle));
                if let Ok(handler) = next.borrower.request_borrow().await {
                    return Some((
                        BorrowMutexGuardArmed::map(handler, |handler| {
                            handler.as_any_mut().downcast_mut::<H>().unwrap()
                        }),
                        iter,
                    ));
                }
            }
            None
        })
    }
}
