use std::{
    collections::{hash_map::Entry, HashMap},
    time::Instant,
};

use crossbeam_queue::ArrayQueue;
use log::info;
use packet::pkt_party::ClientConnectReq;

pub struct State {
    chars: HashMap<u32, CharacterState>,
    parties: PartyMap,
}

pub struct CharacterState {
    pub data: ClientConnectReq,
    pub channel: Option<u8>,
    pub disconnect_time: Option<Instant>,
    pub party: Option<u32>,
}

#[derive(Debug, Clone)]
pub struct Party {
    pub id: u32,
    pub leader_id: u32,
    pub players: Vec<u32>,
}

impl State {
    pub fn new() -> Self {
        Self {
            chars: HashMap::new(),
            parties: PartyMap::new(),
        }
    }

    pub fn add_character(&mut self, channel: u8, data: ClientConnectReq) -> Option<u32> {
        match self.chars.entry(data.char_id) {
            Entry::Vacant(e) => {
                info!("Added character {} on channel {channel}", data.char_id);
                e.insert(CharacterState {
                    data,
                    channel: Some(channel),
                    disconnect_time: None,
                    party: None,
                });
                None
            }
            Entry::Occupied(mut e) => {
                info!("Updated character {} on channel {channel}", data.char_id);
                let char = e.get_mut();
                char.channel = Some(channel);
                char.disconnect_time = None;
                char.data = data;
                char.party
            }
        }
    }

    pub fn get_character(&mut self, char_id: u32) -> Option<&mut CharacterState> {
        self.chars.get_mut(&char_id)
    }

    pub fn iter_characters(&mut self) -> impl Iterator<Item = &CharacterState> {
        self.chars.values()
    }

    pub fn add_to_party(&mut self, inviter_id: u32, invitee_id: u32) -> Option<Party> {
        info!("Creating party for {inviter_id} and {invitee_id}");

        // Invitee can be already in party, and then they effectively
        // become the inviter
        let inviter_party_id = self.chars.get_mut(&inviter_id)?.party;
        let invitee_party_id = self.chars.get_mut(&invitee_id)?.party;

        let party = match inviter_party_id.or(invitee_party_id) {
            None => {
                let party = self.parties.new_party(inviter_id, invitee_id).unwrap();
                info!("Created party {}", party.id);
                party
            }
            Some(party_id) => {
                let party: &mut Party = self.parties.get_mut(party_id).unwrap();
                if !party.players.contains(&inviter_id) {
                    // TODO hashset?
                    party.players.push(inviter_id);
                    info!("Added {inviter_id} to party {}", party.id);
                }
                if !party.players.contains(&invitee_id) {
                    // TODO hashset?
                    party.players.push(invitee_id);
                    info!("Added {invitee_id} to party {}", party.id);
                }
                party
            }
        };

        let party = party.clone();
        let invitee = self.chars.get_mut(&invitee_id).unwrap();
        invitee.party = Some(party.id);
        let inviter = self.chars.get_mut(&inviter_id).unwrap();
        inviter.party = Some(party.id);
        Some(party)
    }

    #[allow(dead_code)]
    pub fn get_party(&mut self, party_id: u32) -> Option<&mut Party> {
        self.parties.get_mut(party_id)
    }

    pub fn remove_from_party(&mut self, char_id: u32) -> Option<Party> {
        info!("Removing character {char_id} from party");
        let char = self.chars.get_mut(&char_id)?;
        let party_id = char.party?;
        char.party = None;
        info!("Removed character {char_id} from party");
        self.parties.remove_from_party(party_id, char_id)
    }

    // Can happen due to timeout after being offline for too long
    pub fn remove_character(&mut self, char_id: u32) -> Option<Party> {
        info!("Removing character {char_id}");
        let char = self.chars.remove(&char_id)?;
        let party_id = char.party?;
        self.parties.remove_from_party(party_id, char_id)
    }
}

pub struct PartyMap {
    parties: HashMap<u32, Party>,
    avail_indices: ArrayQueue<u16>,
}

impl PartyMap {
    fn new() -> Self {
        // WorldSvr is glitchy with party ID 0
        let party_avail_indices = ArrayQueue::new(u16::MAX as usize);
        for i in 1..=u16::MAX {
            let _ = party_avail_indices.push(i);
        }

        Self {
            parties: HashMap::new(),
            avail_indices: party_avail_indices,
        }
    }

    fn new_party(&mut self, leader_id: u32, invitee_id: u32) -> Option<&mut Party> {
        let idx = self.avail_indices.pop()?;
        let entry = self.parties.entry(idx as _);
        Some(entry.or_insert(Party {
            id: idx as _,
            leader_id,
            players: vec![leader_id, invitee_id],
        }))
    }

    fn get_mut(&mut self, id: u32) -> Option<&mut Party> {
        self.parties.get_mut(&id)
    }

    fn remove_from_party(&mut self, party_id: u32, char_id: u32) -> Option<Party> {
        let mut entry = match self.parties.entry(party_id as _) {
            Entry::Occupied(e) => e,
            Entry::Vacant(_) => {
                // party removed in the meantime - assume the other side
                // is handling the party removal
                return None;
            }
        };
        if let Some(player_idx) = entry.get_mut().players.iter().position(|id| *id == char_id) {
            entry.get_mut().players.remove(player_idx);
        }
        if entry.get_mut().players.len() >= 2 {
            return Some(entry.get_mut().clone());
        }

        let party = entry.remove();
        self.avail_indices.push(party_id as _).unwrap();
        Some(party)
    }
}
