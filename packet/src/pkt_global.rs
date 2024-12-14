// SPDX-License-Identifier: MIT
// Copyright(c) 2024 Darek Stojaczyk

use num_enum::{IntoPrimitive, TryFromPrimitive};
use packet_proc::{packet, PacketEnum};

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

#[derive(Debug, Clone, Copy, Default, PartialEq, TryFromPrimitive, IntoPrimitive, PacketEnum)]
#[repr(u32)]
pub enum ServerStateEnum {
    #[default]
    Disabled = 0x0, // can't connect
    Green = 0x1,  // low population
    Orange = 0x2, // medium population
    Red = 0x3,    // population full
}

#[packet(0x62)]
pub struct ChangeServerState {
    server_id: u8,
    channel_id: u8,
    state: ServerStateEnum,
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
    next_daily_reset_time: u32, // unix timestamp, unknown timezone
    unk2: u32,                  // usually 0
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

/*
[2024-08-13T15:30:12.906Z DEBUG server::packet_stream] Conn None: Decoded packet: RoutePacket(RoutePacket { droute_hdr: DuplexRouteHeader { route_hdr: RouteHeader { origin_main_cmd: 23, server_id: 1, group_id: 1, world_id: 0, process_id: 0 }, unk1: 2, unk2: 0, unk3: 0, resp_server_id: 128, resp_group_id: 1, resp_world_id: 0, resp_process_id: 0 }, data: BoundVec([204, 94, 0, 0, 1, 0, 0, 0, 131, 1, 0, 0, 10, 2, 0, 206, 208, 191, 11, 0, 0, 0, 0, 0, 0, 0, 0, 0, 5, 0, 0, 0, 235, 129, 63, 120, 87, 10, 0, 0, 144, 113, 122, 71, 0, 0, 0, 0, 144, 113, 122, 71, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 7, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 97, 100, 109, 105, 110, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]) })

[2024-08-13T15:30:12.913Z TRACE server::proxy] Conn #15: Got up packet(0x1a): RoutePacket(RoutePacket { droute_hdr: DuplexRouteHeader { route_hdr: RouteHeader { origin_main_cmd: 24, server_id: 128, group_id: 1, world_id: 0, process_id: 0 }, unk1: 2, unk2: 0, unk3: 0, resp_server_id: 1, resp_group_id: 1, resp_world_id: 0, resp_process_id: 0 }, data: BoundVec([8, 0, 0, 0, 226]) })


*/

#[packet(0x15)]
pub struct SystemMessage {
    route_hdr: RouteHeader,
    unk0: u32,    // 0?
    unk1: u16,    // 0?
    unk2: u32,    // 1? user id
    msg_type: u8, // 0,1,2,3? or 9...
    aux: BoundVec<1, u8>,
    // there might be 1 trailing byte in case aux is empty
    trailing: BoundVec<0, u8>,
}
assert_def_packet_size!(SystemMessage, 0x1d - 1 - Header::SIZE);
/*


> @annotate-cfg [clamp = [7, 54]]
> @annotate-cfg [rangeFn = { start = 8 + start * 3 - 1; end = 8 + end * 3 - 2 }]

req:
0040                                             00 00   l..J............
> @annotate [14-16] origin_main_cmd
0050   00 00 00 00 00 00 00 00 00 00 01 00 00 00 01 00   ................
> @annotate [0-4] RouteHeader
> @annotate [4-8] unk0
> @annotate [8-10] unk1
> @annotate [10-14] unk2
> @annotate [14-15] msg_type
> @annotate [15-16] aux len (0)
0060   00                                                .
> @annotate [0-1] a trailing byte

resp (0x16)
0000   00 00 00 00 00 00 00 00 00 00 00 00 01 00 00 00   ................
0010   01 00 00                                          ...


*/

#[packet(0x16)]
pub struct SystemMessageForwarded {
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
// [2024-03-03T13:23:57.930Z TRACE server::proxy] Conn #9: Got up packet(0x34): Unknown(Unknown { id: 52, data: BoundVec( [128, 1,  0, 0, 0,   0,   0,   0, 0, 0, 1) })
// [2024-03-03T13:23:54.118Z TRACE server::proxy] Conn #15: Got up packet(0x34): Unknown(Unknown { id: 52, data: BoundVec([1,   2, 10, 2, 0, 143, 224, 148, 0, 0, 0) })
// [2024-03-03T13:23:52.074Z TRACE server::proxy] Conn #13: Got up packet(0x34): Unknown(Unknown { id: 52, data: BoundVec([1,   1, 10, 2, 0, 143, 223, 148, 0, 0, 1) })

#[packet(0x35)]
pub struct ServerState {
    bytes: BoundVec<0, u8>,
}

#[packet(0x35)]
pub struct LoginServerState {
    servers: BoundVec<1, LoginServerNode>,
    // the packet is usually sized way more than needed
    trailing: BoundVec<0, u8>,
}

#[packet(0x35)]
pub struct WorldServerState {
    unk1: u8, // 1 - server id?
    groups: BoundVec<0, GroupNode>,
}

#[packet]
pub struct LoginServerNode {
    id: u8,    // 1 - server id?
    stype: u8, // usually 0x10 (set in globalmgrsvr ini)
    unk1: u32, // 0
    groups: BoundVec<1, GroupNode>,
}
assert_def_packet_size!(LoginServerNode, 0x7);

// must be 0x25 bytes
#[packet]
pub struct GroupNode {
    id: u8,
    unk0: u16,
    unk1: u32,
    unk2: u32,
    unk3: u32,
    unk4: u32,
    unk5: u16,
    unk6: u16,
    unk7: u16,        // 0xff00 later on
    max_players: u16, // 0x50 max players (set in globalmgrsvr ini)
    ip: [u8; 4],      // 8f00020a
    port: u16,        // 0x94df
    state: u32,       // 0x5
}
assert_def_packet_size!(GroupNode, 37);
/*
0000   01 01 00 00 00 00 00 00 00 00 00 00 00 00 00 00   ................
> @annotate [0-1] unk1
> @annotate [1-2] GroupNode starts: id
> @annotate [2-4] unk0
> @annotate [4-8] unk1
> @annotate [8-12] unk2
> @annotate [12-16] unk3
0010   00 00 00 00 00 00 00 00 00 00 50 00 0a 02 00 8f   ..........P.....
> @annotate [0-4] unk4
> @annotate [4-6] unk5
> @annotate [6-8] unk6
> @annotate [8-10] unk7
> @annotate [10-12] max_players
> @annotate [12-16] ip
0020   df 94 05 00 00 00                                 ......
> @annotate [0-2] port
> @annotate [2-6] state

*/

#[packet(0x2f6)]
pub struct ProfilePathRequest {
    unk1: u32, // hardcoded 0
}

#[packet(0x2f7)]
pub struct ProfilePathResponse {
    unk1: u32, // either 0x5 or 0x6, but worldsvr doesn't seem to parse it, just checks != 0

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
    unique_idx: u32,     // 2? 6?
    to_idx: u16,         // 0?
    fm_idx: u16,         // 0? 4?
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

/// Wrapper to serialize given Payload under a different packet ID
#[packet]
pub struct CustomIdPacket<T: Payload> {
    id: u16,
    data: T,
}
impl<T: Payload> crate::Payload for CustomIdPacket<T> {
    fn id(&self) -> u16 {
        self.id
    }

    fn serialize_no_hdr(&self, dst: &mut Vec<u8>) -> Result<usize, PayloadSerializeError> {
        self.data.serialize_no_hdr(dst)
    }

    fn deserialize_no_hdr(_data: &[u8]) -> Result<Self, PayloadDeserializeError> {
        unimplemented!()
    }
}

/*
[2024-08-13T15:30:12.914Z TRACE server::packet_stream] Conn None: sent pkt: RoutePacket(RoutePacket { droute_hdr: DuplexRouteHeader { route_hdr: RouteHeader { origin_main_cmd: 24, server_id: 128, group_id: 1, world_id: 0, process_id: 0 }, unk1: 2, unk2: 0, unk3: 0, resp_server_id: 1, resp_group_id: 1, resp_world_id: 0, resp_process_id: 0 }, data: BoundVec([8, 0, 0, 0, 226]) })
[2024-08-13T15:30:12.914Z DEBUG server::packet_stream] Conn None: Decoded packet: VerifyLinksResult(VerifyLinksResult { droute_hdr: DuplexRouteHeader { route_hdr: RouteHeader { origin_main_cmd: 24, server_id: 128, group_id: 1, world_id: 0, process_id: 0 }, unk1: 2, unk2: 0, unk3: 0, resp_server_id: 1, resp_group_id: 1, resp_world_id: 0, resp_process_id: 0 }, unk1: 8, unk2: 226 })

*/

#[packet(0xc3f)]
pub struct ShutdownStatsSet {
    unk1: u32, // always 0?
}

#[packet(0xc76)]
pub struct ChannelOptionSync {
    unk1: u16, // 0?
    unk2: u16, // 65280?
    unk3: u32, // [0x50, 0, 0, 0]? only the low 2 bytes are read -> 0x50
    unk4: u32, // 5
}

#[packet(0x17)]
pub struct VerifyLinks {
    droute_hdr: DuplexRouteHeader,
    auth_key: u32,
    user_id: u32,
    unk_user_id: u32,
    user_ip: [u8; 4],
    resident_num: u32,         // d0 bf 0b 00 ??
    unk2: u32,                 // zero
    unk3: u32,                 // zero
    premium_service_type: u32, // 5
    premium_expire_time: u32,  // eb 81 3f 78
    unk4: u32,                 // ResponseAuthAccount.unk21
    unk5: u32,                 // ResponseAuthAccount.unk22; 0x477a7190 ?
    unk6: u32,                 // ResponseAuthAccount.unk23
    unk7: u32,                 // ResponseAuthAccount.unk24; 0x477a7190 ?
    unk8: [u32; 3],
    unk9: u32, // 1
    unk10: [u32; 4],
    unk11: u32, // ? 0x665
    unk12: Arr<u8, 285>,
    username: Arr<u8, 33>,
}
assert_def_packet_size!(VerifyLinks, 424);

#[packet(0x18)]
pub struct VerifyLinksResult {
    droute_hdr: DuplexRouteHeader,
    user_idx: u32, // 8?
    status: u8,    // 226?
}
assert_def_packet_size!(VerifyLinksResult, 0x21 - Header::SIZE);

#[packet(0x2dc)]
pub struct SubPasswordCheckRequest {
    unk1: u32, // 1?
    ip: [u8; 17],
    unk2: u16,          // 0x101?
    unk3: u16,          // 0x0? 0x9000?
    login_counter: u32, // 0x8? 0x9? 0x10?
    unk4: u32,          // 0x0?
}

#[packet(0x2dd)]
pub struct SubPasswordCheckResponse {
    unk1: u32,          // 1?
    auth_needed: u32,   // 0 or 1
    zeroes: [u8; 17],   // always zeroes...
    unk2: u16,          // 0x101? from req
    unk3: u16,          // 0x4152? hardcoded?
    login_counter: u32, // 0x8? 0x9? 0x10? from req
    unk4: u32,          // 0x0? from req
}
assert_def_packet_size!(SubPasswordCheckResponse, 0x2f - Header::SIZE);

#[packet(0xc7c)]
pub struct MultipleLoginDisconnectRequest {
    unk1: u32, // user id?
    unk2: u32, // group id? login counter??
}
// broadcasted to all world servers

#[packet(0xc7d)]
pub struct MultipleLoginDisconnectResponse {
    unk1: u32,
    unk2: u32,
}

#[packet(0x1c)]
pub struct SetLoginInstance {
    user_id: u32,        // 1? user id?
    unk_idx: u32,        // ??
    unk3: u8,            // hardcoded 0? logged in time in mins?
    unk4: Arr<u8, 33>,   // username? sometimes junk. Always null-terminated
    login: u8,           // 1 - login, 0 - logout
    unk6: Arr<u8, 28>,   // hardcoded zeroes
    unk7: u8,            // hardcoded 0x14 (off 71)
    unk8: [u8; 9],       // hardcoded zeroes
    unk9: Arr<u8, 0xf0>, // zeroes? uninitialized
}
assert_def_packet_size!(SetLoginInstance, 0x14b - Header::SIZE);

/*
0000   01 00 00 00 3c 01 00 00 00 61 64 6d 69 6e 00 00   ....<....admin..
> @annotate [0-4] unk1
> @annotate [4-8] unk2
> @annotate [8-9] unk3
> @annotate [9-16] unk4
0010   00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00   ................
> @annotate [0-16] unk4
0020   00 00 00 00 00 00 00 00 00 00 01 00 00 00 00 00   ................
> @annotate [0-6] unk4
> @annotate [6-10] unk4?
> @annotate [10-16] unk6
0030   00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00   ................
> @annotate [0-16] unk6
0040   00 00 00 00 00 00 00 14 00 00 00 00 00 00 00 00   ................
> @annotate [0-7] unk6
> @annotate [7-8] unk8
> @annotate [8-16] unk9
0050   00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00   ................
> @annotate [0-1] unk9
0060   00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00   ................
0070   00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00   ................
0080   00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00   ................
0090   00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00   ................
00a0   00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00   ................
00b0   00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00   ................
00c0   00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00   ................
00d0   00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00   ................
00e0   00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00   ................
00f0   00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00   ................
0100   00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00   ................
0110   00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00   ................
0120   00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00   ................
0130   00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00   ................
0140   00                                                .




0000   01 00 00 00 71 01 00 00 00 08 c0 48 1e 08 08 fa   ....q......H....
> @annotate [0-4] user id
> @annotate [4-8] unk2
> @annotate [8-9] unk3
> @annotate [9-16] unk4
0010   f1 f6 f2 3d 0b 08 28 7e 8d 09 20 54 1e 08 38 04   ...=..(~.. T..8.
> @annotate [0-16] unk4
0020   00 00 00 00 00 00 c0 48 1e 08 00 00 00 00 00 00   .......H........
> @annotate [0-6] unk4
> @annotate [6-10] unk4?
0030   00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00   ................
0040   00 00 00 00 00 00 00 14 00 00 00 00 00 00 00 00   ................
0050   00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00   ................
0060   00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00   ................
0070   00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00   ................
0080   00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00   ................
0090   00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00   ................
00a0   00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00   ................
00b0   00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00   ................
00c0   00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00   ................
00d0   00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00   ................
00e0   00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00   ................
00f0   00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00   ................
0100   00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00   ................
0110   00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00   ................
0120   00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00   ................
0130   00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00   ................
0140   00                                                .


*/

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

    #[test]
    fn test_decode_2() {
        let buf = b"\xe2\xb7\x1d\x00\x00\x00\x00\x00\x15\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00\x09\x00\x00";
        let data = Packet::deserialize(buf, true).unwrap();
        println!("{:?}", data);

        let buf = b"\xe2\xb7\x1d\x00\x00\x00\x00\x00\x16\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00\x01\x00\x00";
        let data = Packet::deserialize(buf, true).unwrap();
        println!("{:?}", data);

        let mut buf = [
            0xe2, 0xb7, 0xb2, 0x1, 0x0, 0x0, 0x0, 0x0, 0x1a, 0x0, 0x17, 0x0, 0x1, 0x1, 0x0, 0x0,
            0x2, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x80, 0x1, 0x0, 0x0, 0x50, 0x43, 0x0, 0x0, 0x1,
            0x0, 0x0, 0x0, 0x8c, 0x1, 0x0, 0x0, 0xa, 0x2, 0x0, 0xce, 0xd0, 0xbf, 0xb, 0x0, 0x0,
            0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x5, 0x0, 0x0, 0x0, 0xeb, 0x81, 0x3f, 0x78, 0x5e,
            0xa, 0x0, 0x0, 0x90, 0x71, 0x7a, 0x47, 0x0, 0x0, 0x0, 0x0, 0x90, 0x71, 0x7a, 0x47, 0x0,
            0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x1, 0x0, 0x0, 0x0, 0x0, 0x0,
            0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x65, 0x6, 0x0,
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
            0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x61, 0x64, 0x6d,
            0x69, 0x6e, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
            0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
        ];
        let data = Packet::deserialize(&buf, true).unwrap();
        //println!("{:?}", data);

        buf[8] = 0x17;
        let data = Packet::deserialize(&buf, true).unwrap();
        println!("{:x?}", data);
    }
}

/*

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
