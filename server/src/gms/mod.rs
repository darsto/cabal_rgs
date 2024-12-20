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
    db: Arc<BorrowRef<GlobalDbHandler, ()>>,
    login: Arc<BorrowRef<GlobalLoginHandler, ()>>,
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
            db: BorrowRef::new(()),
            login: BorrowRef::new(()),
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

        self.connect_to_globaldb();

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
                let mut handler = GlobalWorldHandler::new(listener, stream, conn_ref);
                let ret = handler.handle().await;
                let mut worlds = self.worlds.lock_write();
                let world_idx = worlds
                    .iter()
                    .position(|w| Arc::ptr_eq(w, &handler.conn_ref))
                    .unwrap();
                worlds.remove(world_idx);
                ret
            }
            ServiceID::LoginSvr => {
                GlobalLoginHandler::new(listener, stream, self.login.clone())
                    .handle()
                    .await
            }
            service_id => {
                bail!("{self}: Unexpected connection from service {service_id:?}");
            }
        }
    }

    fn connect_to_globaldb(&self) {
        let listener = self.me.upgrade().unwrap();
        let conn_ref = self.db.clone();

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
    }
}

pub async fn handle_route_packet(
    listener: &Arc<Listener>,
    p: pkt_global::RoutePacket,
) -> Result<()> {
    let route_hdr = p.droute_hdr.route_hdr.clone();

    let login_route = Connect::from(Service::LoginSvr);
    let worlds = listener.worlds.cloned();

    let mut target_stream = {
        // original GMS routes IDs 1,1 to WorldSvr1,channel1, not ChatNode or AgentShop
        // I yet have to see a packet routed to ChatNode/AgentShop to see how it's done
        // And yes, LoginSvr route is switched up, it's found by server 1, channel 0x80,
        // despite the Connect packet saying the opposite
        if route_hdr.channel_id == login_route.server_id
            && route_hdr.server_id == login_route.channel_id
        {
            let login_ref = &listener.login;
            BorrowGuardArmed::map(login_ref.borrow().await.unwrap(), |m| &mut m.stream)
        } else {
            let world_ref = worlds.iter().find(|conn_ref| {
                let s = &conn_ref.data;
                s.server_id == route_hdr.channel_id && s.channel_id == route_hdr.server_id
            });

            let Some(world_ref) = world_ref else {
                bail!("Can't find a conn to route to: {route_hdr:?}");
            };

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
