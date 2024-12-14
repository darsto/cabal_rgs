// SPDX-License-Identifier: MIT
// Copyright(c) 2024 Darek Stojaczyk

use crate::executor;
use crate::locked_vec::LockedVec;
use crate::packet_stream::{IPCPacketStream, Service};
use crate::registry::BorrowRef;
use borrow_mutex::BorrowGuardArmed;
use clap::Args;
use log::{error, info};
use packet::pkt_common::ServiceID;
use packet::*;
use pkt_common::Connect;
use pkt_global::CustomIdPacket;

use std::net::TcpStream;
use std::sync::Weak;
use std::time::Duration;
use std::{net::TcpListener, sync::Arc};

use anyhow::{anyhow, bail, Result};
use smol::{Async, Timer};

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
    args: Arc<crate::args::Config>,
    tcp_listener: Async<TcpListener>,
    worlds: LockedVec<Arc<BorrowRef<GlobalWorldHandler, pkt_common::Connect>>>,
    db: LockedVec<Arc<BorrowRef<GlobalDbHandler, ()>>>,
    login: LockedVec<Arc<BorrowRef<GlobalLoginHandler, pkt_common::Connect>>>,
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
            args: args.clone(),
            tcp_listener,
            worlds: LockedVec::new(),
            db: LockedVec::new(),
            login: LockedVec::new(),
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

        let listener = self.me.upgrade().unwrap();

        let conn_ref = BorrowRef::new(());
        listener.db.push(conn_ref.clone());

        // Give the connection handler its own background task
        executor::spawn_local(async move {
            loop {
                let Ok(db_stream) = Async::<TcpStream>::connect(([127, 0, 0, 1], 38180)).await
                else {
                    Timer::after(Duration::from_secs(2)).await;
                    continue;
                };

                info!("Listener: DB connection established");
                let stream = IPCPacketStream::from_conn(
                    Service::GlobalMgrSvr { id: 0x80 },
                    Service::DBAgent,
                    db_stream,
                )
                .await
                .unwrap();

                let ret = GlobalDbHandler::new(listener.clone(), stream, conn_ref.clone())
                    .handle()
                    .await;
                info!("Listener: DB connection closed => {ret:?}");
            }
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
        let listener = self.clone();

        match id.service {
            ServiceID::ChatNode => {
                GlobalChatHandler::new(listener, stream, BorrowRef::new(id.clone()))
                    .handle()
                    .await
            }
            ServiceID::AgentShop => {
                GlobalAgentShopHandler::new(listener, stream, BorrowRef::new(id.clone()))
                    .handle()
                    .await
            }
            ServiceID::WorldSvr => {
                let conn_ref = BorrowRef::new(id.clone());
                self.worlds.push(conn_ref.clone());
                GlobalWorldHandler::new(listener, stream, conn_ref)
                    .handle()
                    .await
            }
            ServiceID::LoginSvr => {
                let conn_ref = BorrowRef::new(id.clone());
                self.login.push(conn_ref.clone());
                GlobalLoginHandler::new(listener, stream, conn_ref)
                    .handle()
                    .await
            }
            service_id => {
                bail!("{self}: Unexpected connection from service {service_id:?}");
            }
        }
    }
}

pub async fn handle_route_packet(
    listener: &Arc<Listener>,
    p: pkt_global::RoutePacket,
) -> Result<()> {
    let route_hdr = p.droute_hdr.route_hdr.clone();

    // original GMS routes IDs 1,1 to WorldSvr1,channel1, not ChatNode or AgentShop
    // I yet have to see a packet routed to ChatNode/AgentShop to see how it's done
    let logins = listener.login.cloned();
    let worlds = listener.worlds.cloned();

    enum EitherRef {
        Login(Arc<BorrowRef<GlobalLoginHandler, pkt_common::Connect>>),
        World(Arc<BorrowRef<GlobalWorldHandler, pkt_common::Connect>>),
    }

    let login_ref = logins.into_iter().find(|conn_ref| {
        let s = &conn_ref.data;
        s.world_id == route_hdr.server_id && s.channel_id == route_hdr.group_id
    });
    let world_ref = worlds.into_iter().find(|conn_ref| {
        let s = &conn_ref.data;
        s.world_id == route_hdr.server_id && s.channel_id == route_hdr.group_id
    });
    let Some(target_ref) = login_ref
        .map(|l| EitherRef::Login(l))
        .or(world_ref.map(|w| EitherRef::World(w)))
    else {
        bail!("Can't find a conn to route to: {route_hdr:?}");
    };

    let mut target_stream = match &target_ref {
        EitherRef::Login(login_ref) => {
            BorrowGuardArmed::map(login_ref.borrow().await.unwrap(), |m| &mut m.stream)
        }
        EitherRef::World(world_ref) => {
            BorrowGuardArmed::map(world_ref.borrow().await.unwrap(), |m| &mut m.stream)
        }
    };

    target_stream
        .send(&CustomIdPacket {
            id: route_hdr.origin_main_cmd,
            data: p,
        })
        .await
        .map_err(|e| anyhow!("Failed to forward RoutePacket to {route_hdr:?}: {e}",))?;

    Ok(())
}
