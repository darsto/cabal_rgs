// SPDX-License-Identifier: MIT
// Copyright(c) 2023 Darek Stojaczyk

use crate::assert_def_packet_size;
use packet_proc::packet;

#[packet(0x6)]
pub struct ConnectAck {
    unk1: [u8; 8],  // hardcoded to [0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0x00, 0xff]
    service_id: u8, // 0xf7 - partysvr
    unk2: u32,      // 0
    server_id: u8,
    channel_id: u8,
    unk3: u32, // 0
    unk4: u8,  // 1
}
assert_def_packet_size!(ConnectAck, 20);

#[packet(0xbce)]
pub struct ClientConnect {
    char_id: u32,    // 0x18?
    channel_id: u32, // ?? 1
    unk3: u8,        // 0 maybe gender?
    class: u8,
    level: u32, // 0xc8
    name_len: u8,
    name: [u8; 16],
    padding: BoundVec<0, u8>, // zeroes
}
// ^ response: first u32, then zeroes for a total pkt len 411
assert_def_packet_size!(ClientConnect, 31);

#[packet(0xbbb)]
pub struct PartyInvite {
    unk1: u8, // 1
    invitee_name_len: u8,
    invitee_name: [u8; 16],
    invitee_id: u32,
    invitee_channel_id: u8, // 1
    inviter_id: u32,
    inviter_channel_id: u8, // 1
    inviter_class: u8,
    unk7: u8, // 3, 0??
    inviter_level: u32,
    unk9: u32, // 0
    inviter_name_len: u8,
    inviter_name: [u8; 16],
}
assert_def_packet_size!(PartyInvite, 55);
// ^ response: same pkt

#[packet(0xbbc)]
pub struct PartyInviteAck {
    inviter_id: u32,        // 8
    inviter_channel_id: u8, // 1
    invitee_id: u32,
    invitee_channel_id: u8, // 1
    invitee_class: u8,      // 2, 4
    invitee_level: u32,
    invitee_name_len: u8,
    invitee_name: [u8; 16],
    unk7: u8,
}
assert_def_packet_size!(PartyInviteAck, 33);
// ^ response: same pkt

#[packet(0xbbd)]
pub struct PartyInviteResult {
    inviter_id: u32,
    inviter_channel_id: u8, // 1
    accepted: u32,          // 1 accept, 0 reject
    invitee_id: u32,
    invitee_channel_id: u8, // 1
    invitee_class: u8,      // 2, 4, ??
    unk5: u8,               // 0
    invitee_level: u32,
    invitee_name_len: u8,
    invitee_name: [u8; 16],
}
assert_def_packet_size!(PartyInviteResult, 37);
// ^ response: 0xbbe + same pkt (+ 2x 0xbbf ?)

#[packet(0xbbe)]
pub struct PartyInviteResultAck {
    invitee_id: u32, // 0x18
    accepted: u8,    // 1 accept, 0 reject
    unk1: u8,        // ?? 0 accept, 1 on reject
}

#[packet(0xbbf)]
pub struct PartyStats {
    tgt_char_id: u32, // sent to this party player
    party_id: u32,    // 1, 2
    leader_id: u32,
    unk2: [u8; 5], // 0
    unk4: u8,      // 1
    unk5: u8,      // 1
    chars: BoundVec<4, PartyCharacterStat>,
    padding: BoundVec<0, u8>,
}
assert_def_packet_size!(PartyStats, 296);

#[packet]
pub struct PartyCharacterStat {
    id: u32, // ??
    level: u32,
    unk8: u32,  // 0
    unk9: u8,   // 1
    class: u8,  // 3, 6, class?
    unk11: u32, // 1
    name_len: u8,
    name: [u8; 16],
    unk12: u32, // 0 - maybe mercenary count?
}

#[packet(0xbc0)]
pub struct PartyMemeberAdd {
    party_id: u32,
    char: PartyCharacterStat,
}

#[packet(0xbc1)]
pub struct PartyInviteCancel {
    unk: BoundVec<0, u8>,
}

#[packet(0xbc2)]
pub struct PartyInviteCancelAck {
    unk: BoundVec<0, u8>,
}

#[packet(0xbc3)]
pub struct PartyInviteLeaveOtherType {
    unk: BoundVec<0, u8>,
}

#[packet(0xbc4)]
pub struct PartyLeave {
    char_id: u32,
    party_id: u32,
}
// ^ response: 0xbc4, 0xbd3, ... and bc5

#[packet(0xbc5)]
pub struct PartyLeaveAck {
    char_id: u32,
    party_id: u32,
}

#[packet(0xbc6)]
pub struct PartyKickout {
    p1_id: u32,
    party_id: u32, // 1
    p2_id: u32,
}
// ^ response: same pkt + 0xbd3

#[packet(0xbc7)]
pub struct PartyKickoutAck {
    p1_id: u32,
    party_id: u32, // 1
}

#[packet(0xbc8)]
pub struct PartyLeaderChange {
    p1_id: u32,
    unk1: u32, // 0, 1
    p2_id: u32,
}
// ^ response: same pkt + 0xbc9

#[packet(0xbc9)]
pub struct PartyLeaderChangeAck {
    p1_id: u32,
    unk1: u32, // 0
}

#[packet(0xbca)]
pub struct PartyAuthChange {
    p1_id: u32,
    unk1: u32, // 1
    unk2: u32, // 1
}
// ^ response: same pkt + 0xbcb

#[packet(0xbcb)]
pub struct PartyAuthChangeAck {
    p1_id: u32,
    unk1: u32, // 1
}

#[packet(0xbcc)]
pub struct PartyLootingChange {
    p1_id: u32,
    unk1: u32, // 1
    unk2: u32, // 3
    unk3: u32, // 1, 2
}
// ^ response: same pkt + 0xbcd

#[packet(0xbcd)]
pub struct PartyLootingChangeAck {
    p1_id: u32,
    unk1: u32, // 1
}

#[packet(0xbcf)]
pub struct ClientDisconnect {
    char_id: u32,
    unk1: u32,
    unk2: u32,
}

#[packet(0xbd1)]
pub struct PartyMemberDungeonCheck {
    unk: BoundVec<0, u8>,
}

#[packet(0xbd2)]
pub struct PartyMessage {
    unk: BoundVec<0, u8>,
}

#[packet(0xbd3)]
pub struct PartyClear {
    party_id: u32,
}

#[packet(0xbd0)]
pub struct PartyMemberStatsChange {
    unk: BoundVec<0, u8>,
}

#[packet(0xbd4)]
pub struct IPCInstantWarAutoParty {
    unk: BoundVec<0, u8>,
}

#[packet(0xbd8)]
pub struct PartySearchRegist {
    unk: BoundVec<0, u8>,
}

#[packet(0xbd9)]
pub struct PartySearchRegistCancel {
    unk: BoundVec<0, u8>,
}

#[packet(0xbda)]
pub struct PartySearchList {
    unk: BoundVec<0, u8>,
}

#[packet(0xbdb)]
pub struct PartySearchChange {
    unk: BoundVec<0, u8>,
}

#[packet(0xbdc)]
pub struct PartySearchRegistAutoCancel {
    unk: BoundVec<0, u8>,
}

#[packet(0xbdd)]
pub struct PartySearchRegistStats {
    unk: BoundVec<0, u8>,
}

#[packet(0xbe8)]
pub struct OathInfoRegist {
    unk: BoundVec<0, u8>,
}

#[packet(0xc05)]
pub struct AssistantSummon {
    unk: BoundVec<0, u8>,
}

#[packet(0xc06)]
pub struct AssistantSummonCancel {
    unk: BoundVec<0, u8>,
}

#[packet(0xc0f)]
pub struct SavedSingleDungeonSet {
    unk: BoundVec<0, u8>,
}

#[packet(0xc10)]
pub struct SavedSingleDungeonClear {
    unk: BoundVec<0, u8>,
}
