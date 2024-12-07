// SPDX-License-Identifier: MIT
// Copyright(c) 2024 Darek Stojaczyk

use num_enum::{IntoPrimitive, TryFromPrimitive};
use packet_proc::{packet, PacketEnum};
use pkt_global::LoginServerNode;

use crate::{assert_def_packet_size, BoundVec};

#[packet(0x65)]
pub struct C2SConnect {
    auth_key: u32
}
assert_def_packet_size!(C2SConnect, 4);

#[packet(0x65)]
pub struct S2CConnect {
    xor_seed_2: u32,
    auth_key: u32,
    user_idx: u16,
    xor_key_idx: u16,
}
assert_def_packet_size!(S2CConnect, 12);

#[packet(0x7a)]
pub struct C2SCheckVersion {
    client_version: u32,
    unk1: u32, // 0
    unk2: u32, // 0
    unk3: u32, // 0
}
assert_def_packet_size!(C2SCheckVersion, 16);

#[packet(0x7a)]
pub struct S2CCheckVersion {
    server_version: u32,
    server_magic_key: u32,
    unk2: u32, // 0
    unk3: u32, // 0
}
assert_def_packet_size!(S2CCheckVersion, 16);

#[packet(0x7d2)]
pub struct C2SEnvironment {
    username: Arr<u8, 33>,
}
assert_def_packet_size!(C2SEnvironment, 33);

#[packet(0x7d2)]
pub struct S2CEnvironment {
    unk1: Arr<u8, 0x100e>, // zeroes, related to image auth
    unk2: u16, // 0x14c8? junk?
    unk3: u8, // 0?
}
assert_def_packet_size!(S2CEnvironment, 4113);

#[packet(0x7d1)]
pub struct C2SRequestRsaPubKey;
assert_def_packet_size!(C2SRequestRsaPubKey, 0);

#[packet(0x7d1)]
pub struct S2CRsaPubKey {
    unk1: u8,
    pub_key_num_bytes: u16,
    pub_key: BoundVec<0, u8>,
}

#[packet(0x67)]
pub struct C2SAuthAccount {
    unk1: u8, // 0?
    unk2: u8, // 1?
    encoded_pass: Arr<u8, 256>,
}
assert_def_packet_size!(C2SAuthAccount, 258);

#[packet(0x67)]
pub struct S2CAuthAccount {
    unk1: u8, // 0x20
    unk2: u32, // 1
    unk3: [u8; 3], // 01 2f 03
    unk4: [u8; 8], // zeroes
    unk5: u32, //  5
    unk6: u32, // 0x783f81eb
    unk7: u8,
    unk8: u32,
    unk9: [u8; 8],
    unk10: Arr<u8, 33>, // string? always null terminated
    unk11: u8, // 1
    unk12: u8, // 3
}
assert_def_packet_size!(S2CAuthAccount, 72);

#[packet(0x67)]
pub struct S2CServerList {
    servers: BoundVec<1, LoginServerNode>,
}

#[packet(0x80)]
pub struct S2CUrlList {
    urls_num_bytes: u16,
    urls: BoundVec<0, BoundVec<4, u8>>,
}

#[packet(0x78)]
pub struct S2CSystemMessage {
    msg_type: u8,
    data1: u8,
    data2: u8,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, TryFromPrimitive, IntoPrimitive, PacketEnum)]
#[repr(u8)]
pub enum SystemMessageType {
    #[default]
    Unknown,
    ForceLogin = 0x1,
    DisconnectDualLogin = 0x2,
    DisconnectShutdown = 0x3,
    Login = 0x9,
}

#[packet(0x66)]
pub struct C2SVerifyLinks {
    unk: BoundVec<0, u8>,
}

#[packet(0x66)]
pub struct S2CVerifyLinks {
    unk: BoundVec<0, u8>,
}

#[packet(0xc3d)]
pub struct RequestClientVersion;

#[packet(0x1e)]
pub struct RequestAuthAccount {
    server_id: u8, // 0x80?
    channel_id: u8, // 1?
    user_idx: u16, // 0?
    ip: [u8; 4],
    username: Arr<u8, 33>,
    password: Arr<u8, 97>,
    zero: u8,
}
assert_def_packet_size!(RequestAuthAccount, 139);

#[packet(0x1f)]
pub struct ResponseAuthAccount {
    server_id: u8, // 0x80?
    channel_id: u8, // 1?
    user_idx: u16, // 0?
    ip: [u8; 4],
    username: Arr<u8, 33>,
    user_num: u32, // 1?
    login_idx: u8, // 0?
    result: u8, // 0x20 - ok
    /*
    0x20 - ok
    0x21 - failed
    0x22 - already logged in?
    0x23 - outofservice
    0x24 - time expired?
    0x25 - ip blocked
    0x26 - id blocked
    0x27 - free id?
    0x28 - onlycafe?
    0x29 - preregist?
    0x2a - withdrawl?
    0x2b - passlock?
    0x2c - failedgash?
    0x2d - antiaddict stuff
    0x2e - antiaddict stuff
     */
    resident_num: u32, // d0 bf 0b 0 ??
    unk5: u32, // 0
    service_type: u32, // 5
    service_expire_time: u32, // eb 81 3f 78
    pcbang_remaining_time: u32, // 0?
    unkkey: Arr<u8, 33>,
    unk9: u8, // 0
    pcpoint: u32, // 0
    unk10: u8, // 1
    unk11: u8, // 0
    unk12: u32, // 1
    unk13: u32, // 0
    unk14: u32, // 0
    unk15: u32, // 0
    unk16: u32, // 0
    unk17: u8, // 0
    unk18: Arr<u8, 32>, // 0?
    unk19: u8, // 0
    unk20: u32, // 0
    unk21: u32, // 0
    unk22: u32, // 0
    unk23: u32, // 0
    unk24: u32, // 0
    unk25: u32, // 0
    unk26: u32, // 0x18c - login counter??
    unk27: u16, // 0x301
}
assert_def_packet_size!(ResponseAuthAccount, 191);

/*
> @annotate-cfg [clamp = [7, 54]]
> @annotate-cfg [rangeFn = { start = 8 + start * 3 - 1; end = 8 + end * 3 - 2 }]


0000                                             80 01   6PV3............
> @annotate [14-15] server_id
> @annotate [15-16] channel_id
0010   00 00 0a 02 00 ce 61 64 6d 69 6e 00 00 00 00 00   ......admin.....
> @annotate [0-2] user_idx
> @annotate [2-6]  ip
0020   00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00   ................
0030   00 00 00 00 00 00 00 01 00 00 00 00 20 d0 bf 0b   ............ ...
> @annotate [7-11] user_num
> @annotate [11-12] login_idx ??
> @annotate [12-13] result ??
> @annotate [13-16] resident_num
0040   00 00 00 00 00 05 00 00 00 eb 81 3f 78 00 00 00   ...........?x...
> @annotate [0-1] resident_num
> @annotate [1-5] unk5
> @annotate [5-9] unk6
> @annotate [9-13] unk7
> @annotate [13-16] unk8
0050   00 41 35 31 32 30 36 35 33 41 41 37 33 34 36 44   .A5120653AA7346D
> @annotate [0-1] unk8
> @annotate [1-16]
0060   35 38 34 41 46 30 30 36 39 36 44 35 36 46 37 31   584AF00696D56F71
> @annotate [0-16]
0070   45 00 00 00 00 00 00 01 00 01 00 00 00 00 00 00   E...............
0080   00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00   ................
0090   00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00   ................
00a0   00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00   ................
00b0   00 00 00 5e 0a 00 00 90 71 7a 47 00 00 00 00 90   ...^....qzG.....
00c0   71 7a 47 00 00 00 00 8c 01 00 00 01 03            qzG..........





0000   e2 b7 c9 00 00 00 00 00 1f 00 80 01 00 00 0a 02   ................
0010   00 ce 61 64 6d 69 6e 00 00 00 00 00 00 00 00 00   ..admin.........
0020   00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00   ................
0030   00 00 00 01 00 00 00 00 20 d0 bf 0b 00 00 00 00   ........ .......
0040   00 05 00 00 00 eb 81 3f 78 00 00 00 00 41 35 31   .......?x....A51
> @annotate [1-5] service kind
> @annotate [5-9] service expire time
> @annotate [9-13] pcbang remaining time
0050   32 30 36 35 33 41 41 37 33 34 36 44 35 38 34 41   20653AA7346D584A
0060   46 30 30 36 39 36 44 35 36 46 37 31 45 00 00 00   F00696D56F71E...
> @annotate [13-14] always null terminated
> @annotate [15-16] pcpoint
0070   00 00 00 01 00 01 00 00 00 00 00 00 00 00 00 00   ................
> @annotate [4-5]
> @annotate [0-3] pcpoint
> @annotate [5-9] unk
> @annotate [9-13] unk
> @annotate [13-16]
0080   00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00   ................
> @annotate [0-1]
> @annotate [1-5]
> @annotate [5-9]
> @annotate [9-10]
0090   00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00   ................
00a0   00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 5e   ...............^
> @annotate [10-11]
> @annotate [11-15]
> @annotate [15-16]
00b0   0a 00 00 90 71 7a 47 00 00 00 00 90 71 7a 47 00   ....qzG.....qzG.
> @annotate [15-16]
> @annotate [11-15] unk
> @annotate [0-3]
> @annotate [7-11]
> @annotate [3-7]
00c0   00 00 00 8c 01 00 00 01 03                        .........
> @annotate [0-3]
> @annotate [7-9]
> @annotate [3-7] login counter



 */