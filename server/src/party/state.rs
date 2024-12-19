use std::{collections::{hash_map::Entry, HashMap}, time::Instant};

use crossbeam_queue::ArrayQueue;
use packet::pkt_party::ClientConnect;

pub struct State {
    chars: HashMap<u32, CharacterState>,
    parties: PartyMap,
}

pub struct CharacterState {
    pub data: ClientConnect,
    pub channel: Option<u8>,
    pub timeout_date: Option<Instant>,
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

    pub fn add_character(&mut self, channel: u8, data: ClientConnect){
        match self.chars.entry(data.char_id) {
            Entry::Vacant(e) => {
                e.insert(CharacterState {
                    data,
                    channel: Some(channel),
                    timeout_date: None,
                    party: None,
                });
            }
            Entry::Occupied(mut e) => {
                let char = e.get_mut();
                char.channel = Some(channel);
                char.data = data;
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
        let inviter = self.chars.get_mut(&inviter_id)?;
        let party = match inviter.party {
            None => {
                let party = self.parties.new_party(inviter.data.char_id, invitee_id).unwrap();
                inviter.party = Some(party.id);
                party
            }
            Some(party_id) => {
                self.parties.get_mut(party_id).unwrap()
            }
        };

        let party = party.clone();
        let Some(invitee) = self.chars.get_mut(&invitee_id) else {
            // need to remove the party if we have just created it
            let _ = self.parties.remove_from_party(party.id, invitee_id);
            return None;
        };
        invitee.party = Some(party.id);
        Some(party)
    }

    pub fn get_party(&mut self, party_id: u32) -> Option<&mut Party> {
        self.parties.get_mut(party_id)
    }

    pub fn remove_from_party(&mut self, char_id: u32) -> Option<(u32, PartyState)> {
        let char = self.chars.get_mut(&char_id)?;
        let party_id = char.party?;
        char.party = None;
        self.parties.remove_from_party(party_id, char_id).map(|state| {
            (party_id, state)
        })
    }

    // Can happen due to timeout after being offline for too long
    pub fn remove_character(&mut self, char_id: u32) -> Option<(u32, PartyState)> {
        let char = self.chars.remove(&char_id)?;
        let party_id = char.party?;
        self.parties.remove_from_party(party_id, char_id).map(|state| {
            (party_id, state)
        })
    }
}

pub struct PartyMap {
    parties: HashMap<u32, Party>,
    avail_indices: ArrayQueue<u16>,
}

impl PartyMap {
    fn new() -> Self {
        let party_avail_indices = ArrayQueue::new(1 + u16::MAX as usize);
        for i in 0..u16::MAX {
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

    fn remove_from_party(&mut self, party_id: u32, char_id: u32) -> Option<PartyState> {
        let mut entry = match self.parties.entry(party_id as _) {
            Entry::Occupied(e) => e,
            Entry::Vacant(_) => {
                // party removed in the meantime - assume the other side
                // is handling the party removal
                return None;
            }
        };
        let Some(player_idx) = entry.get_mut().players.iter().position(|id| *id == char_id) else {
            // player removed in the meantime, but the party continues to exist
            return Some(PartyState::Normal);
        };
        entry.get_mut().players.remove(player_idx);
        if entry.get_mut().players.len() >= 2 {
            return Some(PartyState::Normal);
        }

        let party = entry.remove();
        let last_player_idx = party.players.first().cloned();
        self.avail_indices.push(party_id as _).unwrap();
        Some(PartyState::Disbanded { last_player_idx })
    }
}

pub enum PartyState {
    Normal,
    Disbanded {
        last_player_idx: Option<u32>
    },
}
