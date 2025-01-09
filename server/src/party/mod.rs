// SPDX-License-Identifier: MIT
// Copyright(c) 2024 Darek Stojaczyk

use crate::executor;
use crate::locked_vec::LockedVec;
use crate::packet_stream::{IPCPacketStream, Service};
use crate::registry::{BorrowRef, BorrowRegistry};
use clap::Args;
use futures::{StreamExt, TryFutureExt};
use log::{error, info};
use packet::*;
use pkt_common::ServiceID;
use pkt_party::*;
use state::{PartyState, State};

use std::collections::hash_map::Entry;
use std::collections::HashMap;
use std::fmt::Display;
use std::net::TcpStream;
use std::sync::Weak;
use std::time::{Duration, Instant};
use std::{net::TcpListener, sync::Arc};

use anyhow::{bail, Result};
use smol::{Async, Timer};

mod state;

/// PartySvr replacement
#[derive(Args, Debug)]
#[command(about, long_about, verbatim_doc_comment, disable_help_flag = true)]
pub struct PartyArgs {}

// The gist of a party server is to keep state of all players on
// multiple channels / servers. There's barely any processing, so
// be strictly single threaded and don't worry about Mutex contention
pub struct Listener {
    me: Weak<Listener>,
    tcp_listener: Async<TcpListener>,
    worlds: BorrowRegistry<WorldConnection, ()>,
    servers: LockedVec<Server>,
    _args: Arc<crate::args::Config>,
}

struct Server {
    id: u8,
    state: State,
    /// Indices inside [`Listener::worlds`], indexed by channel id
    worlds: HashMap<u8, u16>,
}

static CHARACTER_OFFLINE_KICK_TIMEOUT: Duration = Duration::from_secs(10 * 60);

impl Listener {
    pub fn new(tcp_listener: Async<TcpListener>, args: &Arc<crate::args::Config>) -> Arc<Self> {
        Arc::new_cyclic(|me| Self {
            me: me.clone(),
            tcp_listener,
            worlds: BorrowRegistry::new(128),
            servers: LockedVec::with_capacity(1),
            _args: args.clone(),
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

                let id = stream.other_id;
                let Service::WorldSvr { server, channel } = id else {
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
                    worlds: HashMap::new(),
                });
                idx
            }
        };
        match servers[server_idx].worlds.entry(channel) {
            Entry::Vacant(e) => {
                e.insert(conn_ref.idx);
            }
            Entry::Occupied(_) => {
                bail!("Duplicate WorldSvr connection. Server {server}, channel {channel}");
            }
        }
        Ok(())
    }

    fn unregister_world(&self, server: u8, channel: u8, conn_ref: &BorrowRef<WorldConnection, ()>) {
        let mut servers = self.servers.lock_write();
        let server_idx = servers.iter().position(|s| s.id == server).unwrap();
        let removed_conn_ref_idx = servers[server_idx].worlds.remove(&channel).unwrap();
        assert_eq!(removed_conn_ref_idx, conn_ref.idx);
        self.worlds.unregister(conn_ref);
    }

    fn start_offline_grooming(&self) {
        let listener = self.me.upgrade().unwrap();
        executor::spawn_local(async move {
            let mut interval_10s = Timer::interval(Duration::from_secs(10));
            loop {
                interval_10s.next().await;
                let now = Instant::now();

                enum Action {
                    Kick { char_id: u32, party_id: u32 },
                    Disband { party_id: u32 },
                }

                let actions: Vec<(u16, Action)> = listener
                    .servers
                    .lock_write()
                    .iter_mut()
                    .flat_map(|server| {
                        let mut chars_to_remove = Vec::new();
                        for char in server.state.iter_characters() {
                            if char.timeout_date.is_some_and(|d| d >= now) {
                                chars_to_remove.push(char.data.char_id);
                            }
                        }

                        chars_to_remove.into_iter().flat_map(|char_id| {
                            let Some((party_id, action)) = server.state.remove_character(char_id)
                            else {
                                return vec![];
                            };

                            match action {
                                PartyState::Disbanded { last_player_idx } => {
                                    let last_player_idx = last_player_idx.unwrap();
                                    let last_player_world_id = server
                                        .state
                                        .get_character(last_player_idx)
                                        .and_then(|last_player| {
                                            last_player.channel.and_then(|channel| {
                                                server.worlds.get(&channel).cloned()
                                            })
                                        });
                                    server.state.remove_from_party(last_player_idx);
                                    if let Some(last_player_world_id) = last_player_world_id {
                                        vec![(last_player_world_id, Action::Disband { party_id })]
                                    } else {
                                        vec![]
                                    }
                                }
                                PartyState::Normal => {
                                    let party_chars =
                                        server.state.get_party(party_id).unwrap().players.clone();
                                    let world_ids = party_chars.into_iter().filter_map(|char_id| {
                                        let channel_id =
                                            server.state.get_character(char_id).unwrap().channel?;
                                        server.worlds.get(&channel_id)
                                    });
                                    world_ids
                                        .map(|world_id| {
                                            (*world_id, Action::Kick { char_id, party_id })
                                        })
                                        .collect()
                                }
                            }
                        })
                    })
                    .collect();

                for (world_id, action) in actions {
                    let Some(world) = listener.worlds.refs.get(world_id) else {
                        continue;
                    };

                    let _ = world
                        .borrow()
                        .and_then(|mut world| async move {
                            match action {
                                Action::Kick { char_id, party_id } => {
                                    let _ = world
                                        .stream
                                        .send(&PartyInviteLeaveOtherType {
                                            char_id,
                                            party_id,
                                            unk1: 1,
                                        })
                                        .await;
                                }
                                Action::Disband { party_id } => {
                                    let _ = world.stream.send(&PartyClear { party_id }).await;
                                }
                            }
                            Ok(())
                        })
                        .await;
                }
            }
        })
        .detach();
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
                            char_id,
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
                    let party_stats =
                        {
                            let server = server_guard!();
                            if let Some(c) = server.state.get_character(p.invitee_id) {
                                c.data.level = p.invitee_level;
                            }
                            match p.accepted {
                                1 => server.state.add_to_party(p.inviter_id, p.invitee_id).map(
                                    |party| PartyStats {
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
                                                    channel_id: p.channel.unwrap_or(0),
                                                    class: p.data.class,
                                                    unk11: 1,
                                                    name_len: p.data.name_len,
                                                    name: p.data.name,
                                                    unk12: 0,
                                                })
                                            })
                                            .collect::<Vec<_>>()
                                            .into(),
                                        padding: Default::default(),
                                    },
                                ),
                                _ => None,
                            }
                        };

                    let accepted = party_stats.is_some();
                    self.stream
                        .send(&PartyInviteResultAck {
                            invitee_id: p.invitee_id,
                            invitee_channel_id: if accepted { p.invitee_channel_id } else { 0 },
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
