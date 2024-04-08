// SPDX-License-Identifier: MIT
// Copyright(c) 2024 Darek Stojaczyk

use packet_proc::packet;

use crate::{assert_def_packet_size, BoundVec};

#[packet(0x50)]
pub struct RegisterChatSvr {
    server_id: u8,  // 1?
    channel_id: u8, // 1?
    chattype: u8,   // always 0xfa = chatnode
    unk1: u8,       // 0?
    port: u16,      // e.g. 0x94e9 = 38121
}
assert_def_packet_size!(RegisterChatSvr, 6);

pub enum ServerStateEnum {
    Disabled = 0x0, // can't connect
    Green = 0x1,    // low population
    Orange = 0x2,   // medium population
    Red = 0x3,      // population full
}

#[packet(0x62)]
pub struct ChangeServerState {
    server_id: u8,
    channel_id: u8,
    state: u32,
}
assert_def_packet_size!(ChangeServerState, 6);

#[packet(0x63)]
pub struct ChangeChannelType {
    server_id: u8,
    channel_id: u8,
    state: u32,
}

#[packet(0xc3e)]
pub struct ClientVersionNotify {
    version: u32,  // can be zero (-> ignore?)
    magickey: u32, // ^
}
assert_def_packet_size!(ClientVersionNotify, 8);

#[packet(0xbd5)]
pub struct DailyQuestResetTime {
    unk1: u32, // unix timestamp, unknown timezone
    unk2: u32, // usually 0
}
assert_def_packet_size!(DailyQuestResetTime, 8);

#[packet(0xbec)]
pub struct AdditionalDungeonInstanceCount {
    unk1: u32, // 1/0? usually 0
    unk2: u32, // actual count?
}
assert_def_packet_size!(AdditionalDungeonInstanceCount, 8);

#[packet]
pub struct RouteHeader {
    origin_main_cmd: u16,
    server_id: u8,
    group_id: u8,
    world_id: u8,
    process_id: u8, // ?? 0?
}

#[packet(0x15)]
pub struct SystemMessage {
    route_hdr: RouteHeader,
    unk0: u32,    // 0?
    unk1: u16,    // 0?
    unk2: u32,    // 1?
    msg_type: u8, // 0,1,2,3? or 9...
    aux: BoundVec<1, u8>,
    // there might be 1 trailing byte
    trailing: BoundVec<0, u8>,
}
assert_def_packet_size!(SystemMessage, 0x1d - 1 - Header::SIZE);

#[packet(0x16)]
pub struct SystemMessageResult {
    data: SystemMessage,
}

#[packet(0x34)]
pub struct NotifyUserCount {
    server_id: u8,
    channel_id: u8,
    ip: [u8; 4],
    port: u16,
    // certain indices are special, haven't figured this out yet
    user_count: Arr<u16, 200>,
    unk: [u8; 18],
}
assert_def_packet_size!(NotifyUserCount, 0x1b4 - Header::SIZE);
// [2024-03-03T13:23:57.930Z TRACE server::proxy] Conn #9: Got up packet(0x34): Unknown(Unknown { id: 52, data: BoundVec([128, 1,  0, 0, 0,   0,   0,   0, 0, 0, 1) })
// [2024-03-03T13:23:54.118Z TRACE server::proxy] Conn #15: Got up packet(0x34): Unknown(Unknown { id: 52, data: BoundVec([1,   2, 10, 2, 0, 143, 224, 148, 0, 0, 0) })
// [2024-03-03T13:23:52.074Z TRACE server::proxy] Conn #13: Got up packet(0x34): Unknown(Unknown { id: 52, data: BoundVec([1,   1, 10, 2, 0, 143, 223, 148, 0, 0, 1) })

#[packet(0x35)]
pub struct ServerState {
    servers: BoundVec<1, ServerNode>,
    // the packet is usually sized way more than needed
    trailing: BoundVec<0, u8>,
}

// must be 7 bytes!
#[packet]
pub struct ServerNode {
    id: u8,
    stype: u8, // usually 0x10 (set in globalmgrsvr ini)
    unk1: u32,
    groups: BoundVec<1, GroupNode>,
}
assert_def_packet_size!(ServerNode, 7);

// must be 0x25 bytes
#[packet]
pub struct GroupNode {
    id: u8,
    unk0: u16, // 1 later on
    unk1: u32,
    unk2: u32,
    unk3: u32,
    unk4: u32,
    unk5: u16,
    unk6: u16,
    unk7: u16, //0xff later on
    unk8: u16, // 0x50 max players (set in globalmgrsvr ini)
    ip: u32,   // 8f00020a
    port: u16, // 0x94df
    unk9: u32, // 0x5
}
assert_def_packet_size!(GroupNode, 37);

#[packet(0x2f6)]
pub struct ProfilePathRequest {
    unk1: u32, // hardcoded 0
}

#[packet(0x2f7)]
pub struct ProfilePathResponse {
    unk1: u32, // usually 0x6, but worldsvr doesn't seem to parse it

    scp_id1: u8, // 0x4 = item.scp; 0x2 = mobs.scp; 0x1 = warp.scp
    scp_path1: Arr<u8, 0x100>,
    scp_id2: u8,
    scp_path2: Arr<u8, 0x100>,
    scp_id3: u8,
    scp_path3: Arr<u8, 0x100>,
}
assert_def_packet_size!(ProfilePathResponse, 0x311 - Header::SIZE);

#[packet]
pub struct DuplexRouteHeader {
    route_hdr: RouteHeader,
    unk1: u32,           // 2?
    unk2: u16,           // 0?
    unk3: u16,           // 0?
    resp_server_id: u8,  // 0x80?
    resp_group_id: u8,   // 0x1?
    resp_world_id: u8,   // 0?
    resp_process_id: u8, // 0?
}

#[packet(0x1a)]
pub struct RoutePacket {
    droute_hdr: DuplexRouteHeader, // desired msg id non 0,
    // 0x17 - special handling, no server_id/group_id checked
    data: BoundVec<0, u8>,
}

#[packet(0xc3f)]
pub struct ShutdownStatsSet {
    unk1: u32, // always 0?
}

#[packet(0xc76)]
pub struct ChannelOptionSync {
    unk1: u16, // 0?
    unk2: u16, // 255?
    unk3: u32, // [80, 0, 0, 0]? only the low 2 bytes are read -> 0
    unk4: u32, // 5
}

#[packet(0x17)]
pub struct VerifyLinks {
    droute_hdr: DuplexRouteHeader,
    unk: BoundVec<0, u8>,
}

#[packet(0x18)]
pub struct VerifyLinksResult {
    droute_hdr: DuplexRouteHeader,
    unk1: u32, // 8?
    unk2: u8,  // 226?
}

#[packet(0x1c)]
pub struct SetLoginInstance {
    user_id: u32,
    unk1: u8, // 105?
    login_time_mins: u32,
    unk2: BoundVec<0, u8>,
}

#[packet(0x2dc)]
pub struct SubPasswordCheckRequest {
    unk1: u32, // 1?
    ip: [u8; 17],
    unk2: u32,          // 0x101?
    login_counter: u32, // 0x8? 0x9? 0x10?
    unk4: u32,          // 0x0?
}

#[packet(0x2dd)]
pub struct SubPasswordCheckResponse {
    unk1: u32,          // 1?
    auth_needed: u32,   // 0 or 1
    zeroes: [u8; 17],   // always zeroes...
    unk2: u32,          // 0x65820101? next pass timestamp?
    login_counter: u32, // 0x8? 0x9? 0x10?
    unk4: u32,          // 0x0?
}
assert_def_packet_size!(SubPasswordCheckResponse, 0x2f - Header::SIZE);

#[packet(0xc7c)]
pub struct MultipleLoginDisconnectRequest {
    unk1: u32,
    unk2: u32,
}
// broadcasted to all world servers

#[packet(0xc7d)]
pub struct MultipleLoginDisconnectResponse {
    unk1: u32,
    unk2: u32,
}

#[cfg(test)]
mod tests {
    use super::*;
    use bincode::config;

    #[test]
    fn test_decode() {
        let buf = [
            0x1, 0x1, 0x10, 0x0, 0x0, 0x0, 0x0, 0x1, 0x1, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
            0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0xff, 0x50,
            0x0, 0xa, 0x2, 0x0, 0x8f, 0xdf, 0x94, 0x5, 0x0, 0x0, 0x0, 0x80, 0x0, 0x0, 0x0, 0x0,
            0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
            0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
            0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
            0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
            0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
            0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
            0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
            0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
            0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
            0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
            0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
            0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
            0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
            0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
            0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
            0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
            0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
            0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
            0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
            0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
            0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
            0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
            0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
            0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
            0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
            0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
            0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
            0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
            0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
            0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
            0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
            0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
            0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
            0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
            0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
            0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
            0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
            0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
            0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
            0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
            0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
            0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
            0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
            0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
            0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
            0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
            0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
            0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
            0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
            0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
            0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
            0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
            0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
            0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
            0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
            0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
            0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
            0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
            0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
            0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
        ];
        let (data, len) =
            bincode::decode_from_slice::<ServerState, _>(&buf, config::legacy()).unwrap();
        println!("len={len}, {:?}", data);
    }
}

/*

> @annotate-cfg [clamp = [7, 54]]
> @annotate-cfg [rangeFn = { start = 8 + start * 3 - 1; end = 8 + end * 3 - 2 }]

max 0x4000 for the packet

server:

gm -> 50538
0000   e2 b7 38 04 00 00 00 00 35 00 01 01 10 00 00 00   ..8.....5.......
> @annotate [10-11] num of servers = 1
> @annotate [11-12] server id
> @annotate [12-13] server type?
> @annotate [13-16] unk0
0010   00 01 01 00 00 00 00 00 00 00 00 00 00 00 00 00   ................
> @annotate [0-1] [default3] unk0
> @annotate [1-2] server -> num groups
> @annotate [2-3] group id (local_7c)
> @annotate [3-5] unk0
> @annotate [5-9] unk1 (memcpied)
> @annotate [9-13] unk2
> @annotate [13-16] unk3
0020   00 00 00 00 00 00 00 00 00 00 00 50 00 0a 02 00   ...........P....
> @annotate [0-1] [default5] unk3
> @annotate [1-5] unk4
> @annotate [5-7] unk5
> @annotate [7-9] unk6 (grp offset 0x15)
> @annotate [9-11] unk7
> @annotate [11-13] unk8
> @annotate [13-16] unk9
0030   8f df 94 05 00 00 00 80 00 00 00 00 00 00 00 00   ................
> @annotate [0-1] [default6] unk9
> @annotate [1-3] unk10
> @annotate [3-7] unk11


0000   e2 b7 13 04 00 00 00 00 35 00 00 80 00 00 00 00   ........5.......
> @annotate [0-2] magic
> @annotate [2-4] pktlen
> @annotate [4-8] unk (0)
> @annotate [8-10] pktid
0010   00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00   ................
0020   00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00   ................
0030   00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00   ................


0000   e2 b7 30 00 00 00 00 00 35 00 01 01 00 00 00 00   ..0.....5.......
> @annotate [0-2] magic
> @annotate [2-4] pktlen
> @annotate [4-8] unk (0)
> @annotate [8-10] pktid
> @annotate [10-11] servers_count = 1
> @annotate [11-12] server1 id = 1
> @annotate [12-13] server1 type = 0
0010   00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00   ................
0020   00 00 00 00 50 00 0a 02 00 8f df 94 05 00 00 00   ....P...........

gm -> 50538
0000   e2 b7 38 04 00 00 00 00 35 00 01 01 10 00 00 00   ..8.....5.......
0010   00 01 01 00 00 00 00 00 00 00 00 00 00 00 00 00   ................
0020   00 00 00 00 00 00 00 00 00 00 00 50 00 0a 02 00   ...........P....
0030   8f df 94 05 00 00 00 80 00 00 00 00 00 00 00 00   ................

*/
