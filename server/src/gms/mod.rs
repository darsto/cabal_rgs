// SPDX-License-Identifier: MIT
// Copyright(c) 2024 Darek Stojaczyk

use crate::executor;
use crate::packet_stream::{IPCPacketStream, Service};
use crate::registry::{BorrowRef, BorrowRegistry};
use clap::Args;
use log::{error, info};
use packet::pkt_common::ServiceID;
use packet::*;
use pkt_common::Connect;
use pkt_global::CustomIdPacket;

use core::any::TypeId;
use std::fmt::Display;
use std::net::TcpStream;
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
#[derive(Args, Debug, Default)]
#[command(about, long_about, verbatim_doc_comment)]
pub struct GmsArgs {}

pub struct Listener {
    me: Weak<Listener>,
    tcp_listener: Async<TcpListener>,
    connections: BorrowRegistry<pkt_common::Connect>,
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

        let db_stream = Async::<TcpStream>::connect(([127, 0, 0, 1], 38180))
            .await
            .unwrap();

        let listener = self.me.upgrade().unwrap();
        // Give the connection handler its own background task
        executor::spawn_local(async move {
            let stream = IPCPacketStream::from_conn(
                Service::GlobalMgrSvr { id: 0x80 },
                Service::DBAgent,
                db_stream,
            )
            .await
            .unwrap();

            let conn_ref = listener
                .connections
                .add_borrower(TypeId::of::<GlobalDbHandler>(), stream.other_id.into())
                .unwrap();

            let conn = Connection {
                conn_ref,
                listener,
                stream,
            };
            let ret = GlobalDbHandler::new(conn).handle().await;

            info!("Listener: DB connection closed => {ret:?}");
            // TODO: reconnect?
        })
        .detach();

        loop {
            let (stream, _) = self.tcp_listener.accept().await.unwrap();
            let listener = self.me.upgrade().unwrap();
            // Give the connection handler its own background task
            executor::spawn_local(async move {
                info!("Listener: new connection ...");

                let stream = IPCPacketStream::from_host(Service::GlobalMgrSvr { id: 0x80 }, stream)
                    .await
                    .unwrap();
                let id = stream.other_id.clone();

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
        stream: IPCPacketStream<Async<TcpStream>>,
    ) -> Result<()> {
        let id = Connect::from(stream.other_id);
        if let Some(conn) = self.connections.refs.iter().find(|conn| {
            let s = &conn.data;
            s.service == id.service && s.world_id == id.world_id && s.channel_id == id.channel_id
        }) {
            bail!(
                    "{self}: Received multiple connections from the same service: {id:?}, previous: {:?}",
                    &conn.data
                );
        }

        let conn_ref = self
            .connections
            .add_borrower(
                match id.service {
                    ServiceID::ChatNode => TypeId::of::<GlobalChatHandler>(),
                    ServiceID::LoginSvr => TypeId::of::<GlobalLoginHandler>(),
                    ServiceID::AgentShop => TypeId::of::<GlobalAgentShopHandler>(),
                    ServiceID::WorldSvr => TypeId::of::<GlobalWorldHandler>(),
                    service_id => {
                        bail!("{self}: Unexpected connection from service {service_id:?}");
                    }
                },
                id.clone(),
            )
            .unwrap();
        let conn = Connection {
            conn_ref,
            listener: self.clone(),
            stream,
        };
        match conn.conn_ref.data.service {
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
    conn_ref: Arc<BorrowRef<pkt_common::Connect>>,
    listener: Arc<Listener>,
    stream: IPCPacketStream<Async<TcpStream>>,
}

impl Display for Connection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.stream.fmt(f)
    }
}

impl Connection {
    fn service(&self) -> &pkt_common::Connect {
        &self.conn_ref.data
    }

    pub async fn handle_route_packet(&mut self, p: pkt_global::RoutePacket) -> Result<()> {
        let route_hdr = &p.droute_hdr.route_hdr;

        let Some(conn_ref) = self.listener.connections.refs.iter().find(|conn_ref| {
            let s = &conn_ref.data;
            // original GMS routes IDs 1,1 to WorldSvr1,channel1, not ChatNode or AgentShop
            // I yet have to see a packet routed to ChatNode/AgentShop to see how it's done
            (s.service == ServiceID::WorldSvr || s.service == ServiceID::LoginSvr)
                && s.world_id == route_hdr.server_id
                && s.channel_id == route_hdr.group_id
        }) else {
            bail!("{self}: Can't find a conn to route to: {route_hdr:?}");
        };

        let mut target_conn = conn_ref
            .borrower
            .request_borrow()
            .await
            .map_err(|e| anyhow!("{self}: request_borrow() failed: {e}"))?;

        target_conn
            .data_mut()
            .downcast_mut::<Connection>()
            .unwrap()
            .stream
            .send(&CustomIdPacket {
                id: route_hdr.origin_main_cmd,
                data: p,
            })
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
