// SPDX-License-Identifier: MIT
// Copyright(c) 2024 Darek Stojaczyk

use crate::executor;
use crate::locked_vec::LockedVec;
use crate::packet_stream::{IPCPacketStream, Service};
use crate::registry::{BorrowRef, BorrowRegistry};
use clap::Args;
use futures::StreamExt;
use log::{error, info};
use packet::*;
use pkt_common::ServiceID;
use pkt_party::*;
use state::{PartyState, State};

use std::fmt::Display;
use std::net::TcpStream;
use std::sync::Weak;
use std::time::{Duration, Instant};
use std::{net::TcpListener, sync::Arc};

use anyhow::{bail, Result};
use smol::{Async, Timer};

mod state;

#[derive(Args, Debug)]
pub struct PartyArgs {}

// The gist of a party server is to keep state of all players on
// multiple channels / servers. There's barely any processing, so
// be strictly single threaded and don't worry about Mutex contention
pub struct Listener {
    me: Weak<Listener>,
    tcp_listener: Async<TcpListener>,
    worlds: BorrowRegistry<WorldConnection, ()>,
    servers: LockedVec<Server>,
    args: Arc<crate::args::Config>,
}

struct Server {
    id: u8,
    state: State,
    /// Indices inside [`Listener::worlds`]
    worlds: Vec<u16>,
}

static CHARACTER_OFFLINE_KICK_TIMEOUT: Duration = Duration::from_secs(5 * 60);

impl Listener {
    pub fn new(tcp_listener: Async<TcpListener>, args: &Arc<crate::args::Config>) -> Arc<Self> {
        Arc::new_cyclic(|me| Self {
            me: me.clone(),
            tcp_listener,
            worlds: BorrowRegistry::new(128),
            servers: LockedVec::with_capacity(1),
            args: args.clone(),
        })
    }

    pub async fn listen(self: &mut Arc<Self>) -> Result<()> {
        info!(
            "Listener: started on {}",
            self.tcp_listener.get_ref().local_addr()?
        );

        self.start_offline_grooming();

        loop {
            let (stream, _) = self.tcp_listener.accept().await?;
            let conn_ref = self.worlds.register(()).unwrap();

            // Give the connection handler its own background task
            let listener = self.me.upgrade().unwrap();
            executor::spawn_local(async move {
                info!("Listener: new connection ...");

                let stream = IPCPacketStream::from_host(Service::Party, stream)
                    .await
                    .unwrap();

                let id = stream.other_id.clone();
                let Service::WorldSvr { server, channel } = id.clone() else {
                    error!("Listener: expected WorldSvr connection, got {id}. Closing");
                    listener.worlds.unregister(&conn_ref);
                    return;
                };

                if let Err(e) = listener.register_world(server, channel, &conn_ref) {
                    error!("Listener: {e}. Closing");
                    listener.worlds.unregister(&conn_ref);
                    return;
                };

                info!("Listener: {id} connected");
                let mut conn = WorldConnection::new(listener, stream, conn_ref, server, channel);
                if let Err(err) = conn.handle().await {
                    error!("Listener: {id} error: {err}");
                } else {
                    info!("Listener: closing {id}");
                }
                conn.listener
                    .unregister_world(server, channel, &conn.conn_ref);
            })
            .detach();
        }
    }

    fn register_world(
        &self,
        server: u8,
        channel: u8,
        conn_ref: &BorrowRef<WorldConnection, ()>,
    ) -> Result<()> {
        let mut servers = self.servers.lock_write();
        let server_idx = match servers.iter().position(|s| s.id == server) {
            Some(idx) => idx,
            None => {
                let idx = servers.len();
                servers.push(Server {
                    id: server,
                    state: State::new(),
                    worlds: Vec::new(),
                });
                idx
            }
        };
        if servers[server_idx].worlds.contains(&conn_ref.idx) {
            bail!("Duplicate WorldSvr connection. Server {server}, channel {channel}");
        }
        servers[server_idx].worlds.push(conn_ref.idx);
        Ok(())
    }

    fn unregister_world(
        &self,
        server: u8,
        _channel: u8,
        conn_ref: &BorrowRef<WorldConnection, ()>,
    ) {
        let mut servers = self.servers.lock_write();
        let server_idx = servers.iter().position(|s| s.id == server).unwrap();
        let world_idx = servers[server_idx]
            .worlds
            .iter()
            .position(|idx| *idx == conn_ref.idx)
            .unwrap();
        servers[server_idx].worlds.remove(world_idx);
        self.worlds.unregister(conn_ref);
    }

    fn start_offline_grooming(&self) {
        let listener = self.me.upgrade().unwrap();
        executor::spawn_local(async move {
            let mut interval_10s = Timer::interval(Duration::from_secs(10));
            loop {
                interval_10s.next().await;
                let now = Instant::now();
                let mut to_remove = Vec::with_capacity(8);

                let mut servers = listener.servers.lock_write();
                for server in servers.iter_mut() {
                    for char in server.state.iter_characters() {
                        if char.timeout_date.is_some_and(|d| d >= now) {
                            to_remove.push((server.id, char.data.char_id));
                        }
                    }
                }

                // TODO process to_remove, send messages to appropriate WorldSvrs
            }
        }).detach();
    }
}

pub struct WorldConnection {
    listener: Arc<Listener>,
    stream: IPCPacketStream<Async<TcpStream>>,
    conn_ref: Arc<BorrowRef<WorldConnection, ()>>,
    server: u8,
    channel: u8,
}
crate::impl_borrowable!(
    WorldConnection,
    RefData = (),
    borrow_ref = .conn_ref
);

impl WorldConnection {
    pub fn new(
        listener: Arc<Listener>,
        stream: IPCPacketStream<Async<TcpStream>>,
        conn_ref: Arc<BorrowRef<Self, ()>>,
        server: u8,
        channel: u8,
    ) -> Self {
        Self {
            listener,
            stream,
            conn_ref,
            server,
            channel,
        }
    }

    pub async fn handle(&mut self) -> Result<()> {
        let server_idx = self
            .listener
            .servers
            .lock_read()
            .iter()
            .position(|s| s.id == self.server)
            .unwrap();

        self.stream
            .send(&packet::pkt_party::ConnectAck {
                unk1: [0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0x00, 0xff],
                service_id: ServiceID::Party.into(),
                unk2: 0,
                server_id: self.server,
                channel_id: self.channel,
                unk3: 0,
                unk4: 1,
            })
            .await?;

        macro_rules! server_guard {
            () => {
                &mut self.listener.servers.lock_write()[server_idx]
            };
        }

        loop {
            let p = self.stream.recv().await?;
            match p {
                Packet::ClientConnect(p) => {
                    let char_id = p.char_id;
                    server_guard!().state.add_character(self.channel, p);
                    self.stream
                        .send(&ClientConnect {
                            char_id: char_id,
                            padding: vec![0u8; 370].into(),
                            ..Default::default()
                        })
                        .await?;
                }
                Packet::PartyInvite(p) => {
                    if let Some(char) = server_guard!().state.get_character(p.inviter_id) {
                        char.data.level = p.inviter_level;
                    }
                    self.stream.send(&p).await?;
                }
                Packet::PartyInviteAck(p) => {
                    if let Some(char) = server_guard!().state.get_character(p.invitee_id) {
                        char.data.level = p.invitee_level;
                    }

                    self.stream.send(&p).await?;
                }
                Packet::PartyInviteResult(p) => {
                    let party_stats = {
                        let server = server_guard!();
                        server.state.get_character(p.invitee_id).map(|c| {
                            c.data.level = p.invitee_level;
                        });
                        match p.accepted {
                            1 => server
                                .state
                                .add_to_party(p.inviter_id, p.invitee_id)
                                .map(|party| PartyStats {
                                    tgt_char_id: 0,
                                    party_id: party.id,
                                    leader_id: party.leader_id,
                                    unk2: [0; 5],
                                    unk4: 1,
                                    unk5: 1,
                                    chars: party
                                        .players
                                        .into_iter()
                                        .filter_map(|id| {
                                            let p = server.state.get_character(id)?;
                                            Some(PartyCharacterStat {
                                                id: p.data.char_id,
                                                level: p.data.level,
                                                unk8: 0,
                                                unk9: 1,
                                                class: p.data.class,
                                                unk11: 1,
                                                name_len: p.data.name_len,
                                                name: p.data.name.clone(),
                                                unk12: 0,
                                            })
                                        })
                                        .collect::<Vec<_>>()
                                        .into(),
                                    padding: Default::default(),
                                }),
                            _ => None,
                        }
                    };

                    let accepted = party_stats.is_some();
                    self.stream
                        .send(&PartyInviteResultAck {
                            invitee_id: p.invitee_id,
                            accepted: if accepted { 1 } else { 0 },
                            unk1: if accepted { 0 } else { 1 },
                        })
                        .await?;

                    self.stream.send(&p).await?;

                    if let Some(mut party_stats) = party_stats {
                        // notify about new char in the existing party
                        if party_stats.chars.len() > 2 {
                            let invitee = party_stats
                                .chars
                                .iter()
                                .find(|c| c.id == p.invitee_id)
                                .unwrap();
                            self.stream
                                .send(&PartyMemeberAdd {
                                    party_id: party_stats.party_id,
                                    char: invitee.clone(),
                                })
                                .await?;
                        }

                        // send full stats to the characters new in party
                        let new_char_ids: &[u32] = match party_stats.chars.len() {
                            2 => &[p.inviter_id, p.invitee_id],
                            _ => &[p.invitee_id],
                        };
                        for char_id in new_char_ids {
                            party_stats.tgt_char_id = *char_id;
                            self.stream.send(&party_stats).await?;
                        }
                    }
                }
                Packet::PartyLeave(p) => {
                    let result = server_guard!().state.remove_from_party(p.char_id);
                    self.stream.send(&p).await?;

                    match result {
                        Some((removed_party_id, PartyState::Disbanded { last_player_idx }))
                            if removed_party_id == p.party_id =>
                        {
                            if let Some(last_player_idx) = last_player_idx {
                                server_guard!().state.remove_from_party(last_player_idx);
                            }

                            self.stream
                                .send(&PartyClear {
                                    party_id: p.party_id,
                                })
                                .await?;
                        }
                        _ => {}
                    }

                    self.stream
                        .send(&PartyLeaveAck {
                            char_id: p.char_id,
                            party_id: p.party_id,
                        })
                        .await?;
                }
                Packet::ClientDisconnect(p) => {
                    if let Some(char) = server_guard!().state.get_character(p.char_id) {
                        char.channel = None;
                        char.timeout_date = Some(Instant::now() + CHARACTER_OFFLINE_KICK_TIMEOUT);
                    }
                }
                _ => {
                    //trace!("{self}: Got packet: {p:?}");
                }
            }
        }
    }
}

impl Display for WorldConnection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.stream.fmt(f)
    }
}
