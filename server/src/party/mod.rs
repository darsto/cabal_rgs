// SPDX-License-Identifier: MIT
// Copyright(c) 2024 Darek Stojaczyk

use crate::executor;
use crate::locked_vec::LockedVec;
use crate::packet_stream::{IPCPacketStream, Service};
use crate::registry::{BorrowRef, BorrowRegistry, Borrowable};
use async_proc::select;
use clap::Args;
use futures::{FutureExt, StreamExt, TryFutureExt};
use log::{error, info};
use packet::*;
use pkt_common::ServiceID;
use pkt_party::*;
use state::State;

use std::collections::hash_map::Entry;
use std::collections::{HashMap, HashSet};
use std::fmt::Display;
use std::net::TcpStream;
use std::sync::Weak;
use std::time::{Duration, Instant};
use std::{net::TcpListener, sync::Arc};

use anyhow::{anyhow, bail, Result};
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

static CHARACTER_OFFLINE_KICK_TIMEOUT_SECS: u64 = 10 * 60;

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

                #[derive(Debug)]
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
                            if char.disconnect_time.is_some_and(|d| {
                                now.duration_since(d).as_secs()
                                    >= CHARACTER_OFFLINE_KICK_TIMEOUT_SECS
                            }) {
                                println!("Marking character {} for removal", char.data.char_id);
                                chars_to_remove.push(char.data.char_id);
                            }
                        }

                        chars_to_remove.into_iter().flat_map(|char_id: u32| {
                            let Some(party) = server.state.remove_character(char_id) else {
                                return vec![];
                            };

                            let party_id = party.id;
                            let world_ids = party
                                .players
                                .iter()
                                .filter_map(|char_id| {
                                    let channel_id =
                                        server.state.get_character(*char_id).unwrap().channel?;
                                    server.worlds.get(&channel_id)
                                })
                                .cloned()
                                .collect::<HashSet<u16>>();
                            world_ids
                                .iter()
                                .flat_map(|world_id| {
                                    if party.players.len() >= 2 {
                                        vec![(*world_id, Action::Kick { char_id, party_id })]
                                    } else {
                                        vec![
                                            (*world_id, Action::Kick { char_id, party_id }),
                                            (*world_id, Action::Disband { party_id }),
                                        ]
                                    }
                                })
                                .collect()
                        })
                    })
                    .collect();

                for (world_id, action) in actions {
                    println!("Party offline timer: world_id={world_id} {action:?}");
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
    server_idx: usize,
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
        let server_idx = listener
            .servers
            .lock_read()
            .iter()
            .position(|s| s.id == server)
            .unwrap();

        Self {
            listener,
            stream,
            conn_ref,
            server,
            channel,
            server_idx,
        }
    }

    pub async fn handle(&mut self) -> Result<()> {
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

        loop {
            select! {
                p = self.stream.recv().fuse() => {
                    let p = p.map_err(|e| {
                        anyhow!("{self}: Failed to recv a packet: {e}")
                    })?;
                    self.handle_packet(p).await?;
                }
                _ = self.conn_ref.borrower.wait_to_lend().fuse() => {
                    self.lend_self().await;
                }
            }
        }
    }

    async fn handle_packet(&mut self, p: Packet) -> Result<()> {
        macro_rules! server_guard {
            () => {
                &mut self.listener.servers.lock_write()[self.server_idx]
            };
        }
        match p {
            Packet::ClientConnect(p) => {
                let p = ClientConnectReq::deserialize_no_hdr(&p.bytes)?;
                let char_id = p.char_id;

                let (mut party_stats, world_ids) = {
                    let server = server_guard!();
                    let party_id = server.state.add_character(self.channel, p);
                    let party =
                        party_id.and_then(|party_id| server.state.get_party(party_id).cloned());

                    let stats = party.map(|party| PartyStats {
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
                    });

                    let world_ids = stats
                        .iter()
                        .flat_map(|stats| stats.chars.iter())
                        .flat_map(|char_stat| {
                            let channel = char_stat.channel_id;
                            server.worlds.get(&channel).cloned()
                        })
                        .collect::<HashSet<u16>>();

                    (stats, world_ids)
                };

                // note that original PartySvr doesn't send the packets we do here,
                // and the character remains "offline". Extraneous PartyMemberAdd
                // fixes this. As a side effect, other party members get message
                // "[Name] has joined your party", but it does no harm.
                if let Some(party_stats) = &mut party_stats {
                    let cur_world_idx = self.conn_ref.idx;
                    let listener = self.listener.clone();
                    self.lend_self_until(async {
                        for world_idx in world_ids {
                            if world_idx == cur_world_idx {
                                // no need to notify the channel we've connected to
                                continue;
                            }
                            let Some(world) = listener.worlds.refs.get(world_idx) else {
                                continue;
                            };
                            let Ok(mut world) = world.borrow().await else {
                                continue;
                            };

                            for char in party_stats.chars.iter() {
                                if char.channel_id == world.channel {
                                    party_stats.tgt_char_id = char.id;
                                    let _ = world
                                        .stream
                                        .send(&PartyMemberAdd {
                                            party_id: party_stats.party_id,
                                            char: party_stats
                                                .chars
                                                .iter()
                                                .find(|c| c.id == char_id)
                                                .cloned()
                                                .unwrap(),
                                        })
                                        .await;
                                }
                            }
                        }
                    })
                    .await;
                }

                let party_stats_resp = ClientConnectResp {
                    char_id,
                    has_party: party_stats.is_some().into(),
                    party_stats: party_stats
                        .map(|mut s| {
                            s.tgt_char_id = 0;
                            s
                        })
                        .unwrap_or_default(),
                    ..Default::default()
                };
                self.stream.send(&party_stats_resp).await?;
            }
            Packet::PartyInvite(p) => {
                println!("PartyInvite");
                let invitee_world_idx = {
                    let server = server_guard!();
                    if let Some(inviter) = server.state.get_character(p.inviter_id) {
                        inviter.data.level = p.inviter_level;
                    }

                    server
                        .state
                        .get_character(p.invitee_id)
                        .and_then(|c| c.channel)
                        .and_then(|channel| server.worlds.get(&channel))
                        .cloned()
                }
                .unwrap_or(self.conn_ref.idx);

                println!("invitee_world_idx={invitee_world_idx}");

                let listener = self.listener.clone();
                self.lend_self_until(async {
                    println!("lending self");
                    let Some(world) = listener.worlds.refs.get(invitee_world_idx) else {
                        println!("return 1");
                        return;
                    };
                    let Ok(mut world) = world.borrow().await else {
                        println!("return 1");
                        return;
                    };
                    println!("sending");
                    let _ = world.stream.send(&p).await;
                    println!("sent");
                })
                .await;
                println!("all done");
            }
            Packet::PartyInviteCancel(p) => {
                let invitee_world_idx = {
                    let server = server_guard!();
                    server
                        .state
                        .get_character(p.invitee_id)
                        .and_then(|c| c.channel)
                        .and_then(|channel| server.worlds.get(&channel))
                        .cloned()
                }
                .unwrap_or(self.conn_ref.idx);

                let listener = self.listener.clone();
                self.lend_self_until(async {
                    let Some(world) = listener.worlds.refs.get(invitee_world_idx) else {
                        return;
                    };
                    let Ok(mut world) = world.borrow().await else {
                        return;
                    };

                    let _ = world.stream.send(&p).await;
                })
                .await;

                let _ = self
                    .stream
                    .send(&PartyInviteCancelAck {
                        inviter_id: p.inviter_id,
                        unk1: 1,
                    })
                    .await;
            }
            Packet::PartyInviteAck(p) => {
                let inviter_world_idx = {
                    let server = server_guard!();
                    if let Some(invitee) = server.state.get_character(p.invitee_id) {
                        invitee.data.level = p.invitee_level;
                    }

                    server
                        .state
                        .get_character(p.inviter_id)
                        .and_then(|c| c.channel)
                        .and_then(|channel| server.worlds.get(&channel))
                        .cloned()
                }
                .unwrap_or(self.conn_ref.idx);

                let listener = self.listener.clone();
                self.lend_self_until(async {
                    let Some(world) = listener.worlds.refs.get(inviter_world_idx) else {
                        return;
                    };
                    let Ok(mut world) = world.borrow().await else {
                        return;
                    };

                    let _ = world.stream.send(&p).await;
                })
                .await;
            }
            Packet::PartyInviteResult(p) => {
                let (mut party_stats, world_ids) = {
                    let server = server_guard!();
                    if let Some(c) = server.state.get_character(p.invitee_id) {
                        c.data.level = p.invitee_level;
                    }
                    let stats = match p.accepted {
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
                            }),
                        _ => None,
                    };

                    let world_ids = stats
                        .iter()
                        .flat_map(|stats| stats.chars.iter())
                        .map(|stat| stat.channel_id)
                        .chain(std::iter::once(p.inviter_channel_id))
                        .flat_map(|channel| server.worlds.get(&channel).cloned())
                        .collect::<HashSet<u16>>();

                    (stats, world_ids)
                };

                let accepted = party_stats.is_some();
                let _ = self
                    .stream
                    .send(&PartyInviteResultAck {
                        invitee_id: p.invitee_id,
                        invitee_channel_id: if accepted { p.invitee_channel_id } else { 0 },
                        unk1: if accepted { 0 } else { 1 },
                    })
                    .await;

                let listener = self.listener.clone();
                self.lend_self_until(async {
                    for world_idx in world_ids {
                        let Some(world) = listener.worlds.refs.get(world_idx) else {
                            continue;
                        };
                        let Ok(mut world) = world.borrow().await else {
                            continue;
                        };

                        if world.channel == p.inviter_channel_id {
                            let _ = world.stream.send(&p).await;
                        }

                        if let Some(party_stats) = party_stats.as_mut() {
                            // notify about new char in the existing party
                            if party_stats.chars.len() > 2 {
                                let new_char = party_stats.chars.iter().last().unwrap();
                                let _ = world
                                    .stream
                                    .send(&PartyMemberAdd {
                                        party_id: party_stats.party_id,
                                        char: new_char.clone(),
                                    })
                                    .await;
                            }

                            // send full stats to (potentially) new characters in party
                            if p.invitee_channel_id == world.channel {
                                party_stats.tgt_char_id = p.invitee_id;
                                let _ = world.stream.send(party_stats).await;
                            }
                            if p.inviter_channel_id == world.channel {
                                party_stats.tgt_char_id = p.inviter_id;
                                let _ = world.stream.send(party_stats).await;
                            }
                        }
                    }
                })
                .await;
            }
            Packet::PartyMemberStatsChange(p) => {
                let world_ids = {
                    let server = server_guard!();

                    if let Some(char) = server.state.get_character(p.char_id) {
                        char.data.level = p.level;
                    }
                    let party = server.state.get_party(p.party_id).cloned();

                    party
                        .iter()
                        .flat_map(|party| party.players.iter())
                        .flat_map(|char_id| {
                            let char = server.state.get_character(*char_id)?;
                            let channel = char.channel?;
                            server.worlds.get(&channel).cloned()
                        })
                        .collect::<HashSet<u16>>()
                };

                let listener = self.listener.clone();
                self.lend_self_until(async {
                    for world_idx in world_ids {
                        let Some(world) = listener.worlds.refs.get(world_idx) else {
                            continue;
                        };
                        let Ok(mut world) = world.borrow().await else {
                            continue;
                        };

                        let _ = world.stream.send(&p).await;
                    }
                })
                .await;
            }
            Packet::PartyLeave(p) => {
                let mut new_leader_id = None;
                let (party, world_ids) = {
                    let Some(mut party) = server_guard!().state.remove_from_party(p.char_id) else {
                        self.stream.send(&p).await?;
                        return Ok(());
                    };
                    let server = server_guard!();
                    let world_ids = party
                        .players
                        .iter()
                        .flat_map(|char_id| {
                            let char = server.state.get_character(*char_id)?;
                            let channel = char.channel?;
                            server.worlds.get(&channel).cloned()
                        })
                        .collect::<HashSet<u16>>();

                    if party.players.len() == 1 {
                        let last_player_idx = party.players[0];
                        server.state.remove_from_party(last_player_idx);
                    } else if !party.players.is_empty() && p.char_id == party.leader_id {
                        let org_party = server.state.get_party(p.party_id).unwrap();
                        org_party.leader_id = org_party.players[0];
                        new_leader_id = Some(org_party.leader_id);
                        party.leader_id = org_party.leader_id;
                    }

                    (party, world_ids)
                };

                let listener = self.listener.clone();
                self.lend_self_until(async {
                    for world_idx in world_ids {
                        let Some(world) = listener.worlds.refs.get(world_idx) else {
                            continue;
                        };
                        let Ok(mut world) = world.borrow().await else {
                            continue;
                        };

                        let _ = world.stream.send(&p).await;

                        if party.players.len() < 2 {
                            let _ = world
                                .stream
                                .send(&PartyClear {
                                    party_id: p.party_id,
                                })
                                .await;
                        } else if let Some(new_leader_id) = new_leader_id {
                            let _ = world
                                .stream
                                .send(&PartyLeaderChange {
                                    old_leader_id: p.char_id,
                                    party_id: p.party_id,
                                    new_leader_id,
                                })
                                .await;
                        }
                    }
                })
                .await;

                self.stream
                    .send(&PartyLeaveAck {
                        char_id: p.char_id,
                        party_id: p.party_id,
                    })
                    .await?;
            }
            Packet::ClientDisconnect(mut p) => {
                let mut new_leader_id = None;
                let world_ids = (|| {
                    let mut server_guard = self.listener.servers.lock_write();
                    let server = &mut server_guard[self.server_idx];
                    let char = server.state.get_character(p.char_id)?;
                    char.channel = None;

                    let party_id = char.party?;
                    char.disconnect_time = Some(Instant::now());
                    p.party_id = party_id;

                    let party = server.state.get_party(party_id).unwrap();
                    if !party.players.is_empty() && p.char_id == party.leader_id {
                        party.leader_id = party
                            .players
                            .iter()
                            .cloned()
                            .find(|c| *c != p.char_id)
                            .unwrap();
                        new_leader_id = Some(party.leader_id);
                    }
                    let party = party.clone();

                    Some(
                        party
                            .players
                            .iter()
                            .flat_map(|char_id| {
                                let char = server.state.get_character(*char_id)?;
                                let channel = char.channel?;
                                server.worlds.get(&channel).cloned()
                            })
                            .collect::<HashSet<u16>>(),
                    )
                })()
                .unwrap_or_default();

                let listener = self.listener.clone();
                self.lend_self_until(async {
                    for world_idx in world_ids {
                        let Some(world) = listener.worlds.refs.get(world_idx) else {
                            continue;
                        };
                        let Ok(mut world) = world.borrow().await else {
                            continue;
                        };

                        let _ = world.stream.send(&p).await;

                        if let Some(new_leader_id) = new_leader_id {
                            let _ = world
                                .stream
                                .send(&PartyLeaderChange {
                                    old_leader_id: p.char_id,
                                    party_id: p.party_id,
                                    new_leader_id,
                                })
                                .await;
                        }
                    }
                })
                .await;
            }
            Packet::PartyLeaderChange(mut p) => {
                let world_ids = (|| {
                    let mut server_guard = self.listener.servers.lock_write();
                    let server = &mut server_guard[self.server_idx];
                    let party_id = server.state.get_character(p.old_leader_id)?.party?;
                    let party = server.state.get_party(party_id).cloned().unwrap();

                    p.party_id = party.id;

                    Some(
                        party
                            .players
                            .iter()
                            .flat_map(|char_id| {
                                let char = server.state.get_character(*char_id)?;
                                let channel = char.channel?;
                                server.worlds.get(&channel).cloned()
                            })
                            .collect::<HashSet<u16>>(),
                    )
                })()
                .unwrap_or_default();

                let listener = self.listener.clone();
                self.lend_self_until(async {
                    for world_idx in world_ids {
                        let Some(world) = listener.worlds.refs.get(world_idx) else {
                            continue;
                        };
                        let Ok(mut world) = world.borrow().await else {
                            continue;
                        };

                        let _ = world.stream.send(&p).await;
                    }
                })
                .await;

                self.stream
                    .send(&PartyLeaderChangeAck {
                        old_leader_id: p.old_leader_id,
                        unk1: 1,
                    })
                    .await?;
            }
            _ => {
                //trace!("{self}: Got packet: {p:?}");
            }
        }

        Ok(())
    }
}

impl Display for WorldConnection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.stream.fmt(f)
    }
}
