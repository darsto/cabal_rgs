// SPDX-License-Identifier: MIT
// Copyright(c) 2024 Darek Stojaczyk

use crate::atomic_append_vec::AtomicAppendVec;
use crate::packet_stream::PacketStream;
use crate::ThreadLocalExecutor;
use borrow_mutex::{BorrowMutex, BorrowMutexGuardArmed, BorrowMutexGuardUnarmed};
use clap::Parser;
use futures::Stream;
use log::{error, info};
use packet::pkt_common::ServiceID;
use packet::*;

use std::any::TypeId;
use std::fmt::Display;
use std::net::TcpStream;
use std::os::fd::AsRawFd;
use std::sync::Weak;
use std::{net::TcpListener, sync::Arc};

use anyhow::{bail, Result};
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

            let conn = Connection {
                id: stream.as_raw_fd(),
                conn_ref: None,
                listener: self.me.upgrade().unwrap(),
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
}

impl Default for Connection {
    fn default() -> Self {
        unimplemented!();
    }
}

const BORROW_MUTEX_SIZE: usize = 16;
#[derive(Debug)]
enum ConnectionHandlerBorrower {
    ChatNode(BorrowMutex<BORROW_MUTEX_SIZE, GlobalChatHandler>),
    LoginSvr(BorrowMutex<BORROW_MUTEX_SIZE, GlobalLoginHandler>),
    AgentShop(BorrowMutex<BORROW_MUTEX_SIZE, GlobalAgentShopHandler>),
    WorldSvr(BorrowMutex<BORROW_MUTEX_SIZE, GlobalWorldHandler>),
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

impl ConnectionHandlerBorrower {
    pub fn try_inner<H: 'static>(&self) -> Option<&BorrowMutex<16, H>> {
        match self {
            Self::ChatNode(inner) => {
                try_cast!(inner, H, GlobalChatHandler)
            }
            Self::LoginSvr(inner) => {
                try_cast!(inner, H, GlobalLoginHandler)
            }
            Self::AgentShop(inner) => {
                try_cast!(inner, H, GlobalAgentShopHandler)
            }
            Self::WorldSvr(inner) => {
                try_cast!(inner, H, GlobalWorldHandler)
            }
        }
    }

    #[inline]
    pub fn inner<H: 'static>(&self) -> &BorrowMutex<16, H> {
        self.try_inner().unwrap()
    }

    #[inline]
    pub fn request_borrow<H: 'static>(&self) -> BorrowMutexGuardUnarmed<'_, BORROW_MUTEX_SIZE, H> {
        self.inner::<H>().request_borrow()
    }
}

#[derive(Debug)]
struct ConnectionRef {
    service: pkt_common::Connect,
    borrower: ConnectionHandlerBorrower,
}

impl Display for Connection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if let Some(handle) = &self.conn_ref {
            write!(f, "Conn {}", handle.service)
        } else {
            write!(f, "Conn #{}", self.id)
        }
    }
}

impl Connection {
    async fn handle(mut self) -> Result<()> {
        let p = self.stream.recv().await?;
        let Payload::Connect(service) = p else {
            bail!("{self}: Expected Connect packet, got {p:?}");
        };

        let borrower = match service.id {
            ServiceID::ChatNode => ConnectionHandlerBorrower::ChatNode(BorrowMutex::new()),
            ServiceID::LoginSvr => ConnectionHandlerBorrower::LoginSvr(BorrowMutex::new()),
            ServiceID::AgentShop => ConnectionHandlerBorrower::AgentShop(BorrowMutex::new()),
            ServiceID::WorldSvr => ConnectionHandlerBorrower::WorldSvr(BorrowMutex::new()),
            _ => {
                bail!("Unexpected connection from service {service:?}");
            }
        };

        if let Some(conn) = self.listener.conn_refs.iter().find(|conn| {
            let s = &conn.service;
            s.id == service.id
                && s.world_id == service.world_id
                && s.channel_id == service.channel_id
        }) {
            bail!(
                "Received multiple connections from the same service: {service:?}, previous: {:?}",
                &conn.service
            );
        }

        self.conn_ref = Some(Arc::new(ConnectionRef { service, borrower }));
        self.listener
            .conn_refs
            .push(self.conn_ref.as_ref().unwrap().clone())
            .unwrap();
        let service = self.service();

        match service.id {
            ServiceID::ChatNode => GlobalChatHandler::new(self).handle().await,
            ServiceID::LoginSvr => GlobalLoginHandler::new(self).handle().await,
            ServiceID::AgentShop => GlobalAgentShopHandler::new(self).handle().await,
            ServiceID::WorldSvr => GlobalWorldHandler::new(self).handle().await,
            _ => {
                bail!("Unexpected connection from service {service:?}");
            }
        }
    }

    fn service(&self) -> &pkt_common::Connect {
        &self.conn_ref.as_ref().unwrap().service
    }

    fn iter_handlers<T: 'static>(
        &self,
    ) -> impl Stream<Item = BorrowMutexGuardArmed<'_, T>> {
        let self_handle = self.conn_ref.as_ref().unwrap();
        let iter = self.listener.conn_refs.iter();
        futures::stream::unfold(iter, move |mut iter| async move {
            if let Some(next) = iter.next() {
                if let Some(borrower) = next.borrower.try_inner::<T>() {
                    assert!(!Arc::ptr_eq(next, self_handle));
                    if let Ok(borrow) = borrower.request_borrow().await {
                        return Some((borrow, iter));
                    }
                }
            }
            None
        })
    }
}
