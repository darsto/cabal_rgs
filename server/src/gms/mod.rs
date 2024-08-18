// SPDX-License-Identifier: MIT
// Copyright(c) 2024 Darek Stojaczyk

use crate::atomic_append_vec::AtomicAppendVec;
use crate::executor;
use crate::packet_stream::PacketStream;
use borrow_mutex::{BorrowGuardArmed, BorrowMutex};
use clap::Parser;
use futures::Stream;
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
mod db;
use db::*;

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

        let db_conn = Async::<TcpStream>::connect(([127, 0, 0, 1], 38180))
            .await
            .unwrap();
        let listener = self.me.upgrade().unwrap();
        // Give the connection handler its own background task
        smol::spawn(async move {
            let id = db_conn.as_raw_fd();
            let service = pkt_common::Connect {
                id: ServiceID::GlobalMgrSvr,
                world_id: 0x80,
                channel_id: 0,
                unk2: 0,
            };
            let stream = PacketStream::from_conn(id, db_conn, service.clone())
                .await
                .unwrap();
            let conn_ref = Arc::new(ConnectionRef {
                service: pkt_common::Connect {
                    id: ServiceID::DBAgent,
                    ..service
                },
                borrower: BorrowMutex::new(),
            });
            listener.conn_refs.push(conn_ref.clone()).unwrap();
            let conn = Connection {
                id,
                conn_ref,
                listener,
                stream,
            };
            let ret = GlobalDbHandler::new(conn).handle().await;

            info!("Listener: DB connection closed #{id} => {ret:?}");
            // TODO: reconnect?
        })
        .detach();

        loop {
            let (stream, _) = self.tcp_listener.accept().await.unwrap();
            let listener = self.me.upgrade().unwrap();
            // Give the connection handler its own background task
            executor::spawn_local(async move {
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
        let stream = PacketStream::from_host(stream.as_raw_fd(), stream)
            .await
            .unwrap();
        let service = &stream.service;
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
            service: service.clone(),
            borrower: BorrowMutex::new(),
        });
        self.conn_refs.push(conn_ref.clone()).unwrap();
        let conn = Connection {
            id,
            conn_ref,
            listener: self.clone(),
            stream,
        };
        match conn.conn_ref.service.id {
            ServiceID::ChatNode => GlobalChatHandler::new(conn).handle().await,
            ServiceID::LoginSvr => GlobalLoginHandler::new(conn).handle().await,
            ServiceID::AgentShop => GlobalAgentShopHandler::new(conn).handle().await,
            ServiceID::WorldSvr => GlobalWorldHandler::new(conn).handle().await,
            service_id => {
                bail!("{self}: Unexpected connection from service {service_id:?}");
            }
        }
    }
}

struct Connection {
    id: i32,
    conn_ref: Arc<ConnectionRef>,
    listener: Arc<Listener>,
    stream: PacketStream<Async<TcpStream>>,
}

impl Display for Connection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Conn #{} ({})", self.id, self.conn_ref.service)
    }
}

const BORROW_MUTEX_SIZE: usize = 16;

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
    } else if t_id == TypeId::of::<GlobalDbHandler>() {
        ServiceID::DBAgent
    } else {
        ServiceID::None
    }
}

#[allow(dead_code)]
trait ConnectionHandler: AsAny + Send + std::fmt::Display {
    fn conn(&self) -> &Connection;
    fn conn_mut(&mut self) -> &mut Connection;
}

#[allow(dead_code)]
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
        impl $crate::gms::ConnectionHandler for $handler {
            fn conn(&self) -> &Connection {
                &self.conn
            }
            fn conn_mut(&mut self) -> &mut Connection {
                &mut self.conn
            }
        }
        impl $handler {
            #[allow(dead_code)]
            async fn lend_self_until<T>(&mut self, future: impl futures::Future<Output = T>) -> T {
                let conn_ref = self.conn().conn_ref.clone();
                let mut future = core::pin::pin!(future.fuse());
                loop {
                    futures::select! {
                        ret = future => {
                            return ret;
                        }
                        _ = conn_ref.borrower.wait_to_lend().fuse() => {
                            conn_ref.borrower.lend(self as &mut dyn ConnectionHandler).unwrap().await;
                        }
                    }
                }
            }
        }
    };
}

/// Hopefuly we'll see async for loops in stable rust one day
#[macro_export]
macro_rules! async_for_each {
    ($item:ident in $iter:expr => $b:block) => {
        {
            let mut iter = core::pin::pin!($iter);
            while let Some($item) = iter.next().await $b
        }
    };
    (mut $item:ident in $iter:expr => $b:block) => {
        {
            let mut iter = core::pin::pin!($iter);
            while let Some(mut $item) = iter.next().await $b
        }
    };
}

#[derive(Debug)]
struct ConnectionRef {
    service: pkt_common::Connect,
    borrower: BorrowMutex<BORROW_MUTEX_SIZE, dyn ConnectionHandler>,
}

impl ConnectionRef {
    fn iter_handlers<'a, H: 'static + Send>(
        self: &'a Arc<Self>,
        conn_refs: impl Iterator<Item = &'a Arc<ConnectionRef>>,
    ) -> impl Stream<Item = BorrowGuardArmed<'a, H>> {
        futures::stream::unfold(conn_refs, move |mut iter| async {
            while let Some(next) = iter.next() {
                if next.service.id != handler_service::<H>() {
                    continue;
                }
                assert!(!Arc::ptr_eq(next, self));
                if let Ok(handler) = next.borrower.request_borrow().await {
                    return Some((
                        BorrowGuardArmed::map(handler, |handler| {
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

impl Connection {
    fn service(&self) -> &pkt_common::Connect {
        &self.conn_ref.service
    }

    fn iter_handlers<H: 'static + Send>(&self) -> impl Stream<Item = BorrowGuardArmed<'_, H>> {
        self.conn_ref.iter_handlers(self.listener.conn_refs.iter())
    }

    pub async fn handle_route_packet(&mut self, p: pkt_global::RoutePacket) -> Result<()> {
        let route_hdr = p.droute_hdr.route_hdr.clone();

        let Some(conn_ref) = self.listener.conn_refs.iter().find(|conn_ref| {
            let s = &conn_ref.service;
            // original GMS routes IDs 1,1 to WorldSvr1,channel1, not ChatNode or AgentShop
            // I yet have to see a packet routed to ChatNode/AgentShop to see how it's done
            (s.id == ServiceID::WorldSvr || s.id == ServiceID::LoginSvr)
                && s.world_id == route_hdr.server_id
                && s.channel_id == route_hdr.group_id
        }) else {
            bail!("{self}: Can't find a conn to route to: {route_hdr:?}");
        };

        let mut bytes = Vec::with_capacity(4096);
        let p = Payload::RoutePacket(p);
        let len = p
            .encode(&mut bytes)
            .map_err(|e| anyhow!("{self}: Failed to reencode packet {e}: {p:?}"))?;

        let mut target_hdr = Header::decode(&bytes[0..Header::SIZE])?;
        target_hdr.id = route_hdr.origin_main_cmd;
        let target_payload = Payload::decode(&target_hdr, &bytes[Header::SIZE..len])
            .map_err(|e| anyhow!("{self}: Failed to decode target packet {e}: {p:?}"))?;

        let mut target_conn = conn_ref
            .borrower
            .request_borrow()
            .await
            .map_err(|e| anyhow!("{self}: request_borrow() failed: {e}"))?;

        target_conn
            .conn_mut()
            .stream
            .send(&target_payload)
            .await
            .map_err(|e| {
                anyhow!(
                    "{self}: Failed to forward RoutePacket to {}: {e}",
                    &*target_conn
                )
            })?;

        Ok(())
    }
}
