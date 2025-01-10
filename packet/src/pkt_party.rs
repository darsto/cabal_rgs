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
    bytes: BoundVec<0, u8>,
}
// ^ response: first u32, then zeroes for a total pkt len 411
//assert_def_packet_size!(ClientConnect, 31);

#[packet(0xbce)]
pub struct ClientConnectReq {
    char_id: u32,    // 0x18?
    channel_id: u32, // ?? 1
    unk3: u8,        // 0 maybe gender?
    class: u8,
    level: u32, // 0xc8
    name_len: u8,
    name: [u8; 16],
}

#[packet(0xbce)]
pub struct ClientConnectResp {
    char_id: u32,
    has_party: u32,
    party_stats: PartyStats, // tgt_char_id == 0
    bytes: BoundVec<0, u8>,
}

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
    invitee_channel_id: u8,    // 0 on reject
    unk1: u8,        // ?? 0 accept, 1 on reject, maybe 2 on timeout reject?
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

#[packet]
pub struct PartyCharacterStat {
    id: u32, // ??
    level: u32,
    unk8: u32,  // 0
    channel_id: u8,   // 1
    class: u8,  // 3, 6, class?
    unk11: u32, // 1
    name_len: u8,
    name: [u8; 16],
    unk12: u32, // 0 - maybe mercenary count?
}

#[packet(0xbc0)]
pub struct PartyMemberAdd {
    party_id: u32,
    char: PartyCharacterStat,
}

#[packet(0xbc1)]
pub struct PartyInviteCancel {
    invitee_id: u32,
    invitee_channel_id: u8,
    inviter_id: u32,
    inviter_channel_id: u8,
}

#[packet(0xbc2)]
pub struct PartyInviteCancelAck {
    inviter_id: u32,
    unk1: u32, // 1
}

#[packet(0xbc3)]
pub struct PartyInviteLeaveOtherType {
    char_id: u32,
    party_id: u32,
    unk1: u8, // 1 - leave type?
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
    kicker_char_id: u32,
    party_id: u32, // 1
    kicked_char_id: u32,
}
// ^ response: same pkt + 0xbd3 + at last 0xbc7

#[packet(0xbc7)]
pub struct PartyKickoutAck {
    kicker_char_id: u32,
    party_id: u32, // 1
}

#[packet(0xbc8)]
pub struct PartyLeaderChange {
    old_leader_id: u32,
    party_id: u32, // 0 in received packet
    new_leader_id: u32,
}
// ^ response: same pkt + 0xbc9

#[packet(0xbc9)]
pub struct PartyLeaderChangeAck {
    old_leader_id: u32,
    unk1: u32, // 1?
}

#[packet(0xbca)]
pub struct PartyAuthChange {
    leader_id: u32,
    party_id: u32, // 0 in received packet
    invite_leader_only: u32, // 0 -> anyone can invite, 1 -> leader only
}
// ^ response: same pkt + 0xbcb

#[packet(0xbcb)]
pub struct PartyAuthChangeAck {
    p1_id: u32,
    unk1: u32, // 1
}

#[packet(0xbcc)]
pub struct PartyLootingChange {
    leader_id: u32,
    party_id: u32, // 1, 4 -> party id?
    looting_type: u32, // 1 -> free looting, 2 -> turns, 3 -> leader only
    bound_item_looting_type: u32, // 1 -> dice rolling, 2 -> no dice rolling
}
// ^ response: same pkt + 0xbcd

#[packet(0xbcd)]
pub struct PartyLootingChangeAck {
    leader_id: u32,
    unk1: u32, // 1
}

#[packet(0xbcf)]
pub struct ClientDisconnect {
    char_id: u32,
    party_id: u32, // 0 in received packet
    unk2: u32, // 0
}

#[packet(0xbd1)]
pub struct PartyMemberDungeonCheck {
    unk: BoundVec<0, u8>,
}

#[packet(0xbd2)]
pub struct PartyMessage {
    player_id: u32,
    party_id: u32,
    remaining_bytes: u16,
    msg_num_bytes: u16, // remaining_bytes - 5?
    msg_unk1: [u8; 3], // 0xfe 0xfe 0xa0
    msg_bytes: BoundVec<0, u8>, // usually followed by three 0 bytes
}

#[packet(0xbd3)]
pub struct PartyClear {
    party_id: u32,
}

#[packet(0xbd0)]
pub struct PartyMemberStatsChange {
    char_id: u32,
    party_id: u32, // 1
    unk2: u8, // 1
    level: u32,
    unk3: [u8; 21], // zeroes
}

#[packet(0xbd4)]
pub struct IPCInstantWarAutoParty {
    unk: BoundVec<0, u8>,
}

#[packet(0xbd8)]
pub struct PartySearchRegist {
    unk: BoundVec<0, u8>,
}

#[packet]
pub struct PartySearchRegistReq {
    leader_id: u32,
    leader_level: u32,
    unk1: u8, // 2 - channel id? player cnt?
    unk2: u8, // 2 - ^
    leader_name_len: u8,
    leader_name: [u8; 16],
    max_party_size: u8, // 4
    promo_msg: [u8; 32],
    unk4: [u8; 8], // zeroes
}

#[packet]
pub struct PartySearchRegistResp {
    leader_id: u32,
    unk1: u8, // 0
}

#[packet(0xbd9)]
pub struct PartySearchRegistCancel {
    unk: BoundVec<0, u8>,
}

#[packet(0xbda)]
pub struct PartySearchList {
    bytes: BoundVec<0, u8>,
}

#[packet]
pub struct PartySearchListReq {
    char_id: u32,
}

#[packet]
pub struct PartySearchListResp {
    char_id: u32,
    parties: BoundVec<4, PartySearchListParty>,
}

#[packet]
pub struct PartySearchListParty {
    leader_id: u32,
    leader_level: u32,
    unk1: u8, // 2 - channel id? player cnt?
    unk2: u8, // 2 - ^
    leader_name_len: u8,
    leader_name: [u8; 16],
    max_party_size: u8, // 4
    promo_msg: [u8; 32],
    unk4: [u8; 8], // zeroes
    party_size: u32, // 3
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
    party_id: u32,
    unk1: u32, // 1
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
