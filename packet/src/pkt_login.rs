// SPDX-License-Identifier: MIT
// Copyright(c) 2024 Darek Stojaczyk

use num_enum::{IntoPrimitive, TryFromPrimitive};
use packet_proc::{packet, PacketEnum};
use pkt_global::LoginServerNode;

use crate::{assert_def_packet_size, BoundVec};

#[packet(0x65)]
pub struct C2SConnect {
    auth_key: u32,
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
    unk2: u16,             // 0x14c8? junk?
    unk3: u8,              // 0?
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
    status: u8,      // 0x20
    user_id: u32,     // ?? 1
    unk2: u8, // 1
    unk3: u8, // 2f ?? age => when 0, "only users that are age 18 or older can join the server"
    char_count: u8,
    unk4: u64, // 0
    premium_service_type: u32,     //  5
    premium_expire_time: u32,     // 0x783f81eb
    unk7: u8,
    sub_password_exists: u64,
    language: u32,
    unkkey: Arr<u8, 33>,     // string? always null terminated
    characters: BoundVec<0, u8>, // u8 pairs of (server_id, char_id) on successfull login, or [0]
}
assert_def_packet_size!(S2CAuthAccount, 70);

#[packet(0x79)]
pub struct S2CServerList {
    servers: BoundVec<1, LoginServerNode>,
}

#[packet(0x80)]
pub struct S2CUrlList {
    urls_num_bytes: u16,
    urls_num_bytes2: u16,
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
    unk1: u32, // some key, 0x4350
    unique_idx: u16, // 0 ?? some unknown user idx
    server_id: u8, // 1
    group_id: u8, // 1
    magic_key: u32
}
assert_def_packet_size!(C2SVerifyLinks, 12);

#[packet(0x66)]
pub struct S2CVerifyLinks {
    unk: BoundVec<0, u8>,
}

#[packet(0xc3d)]
pub struct RequestClientVersion;

#[packet(0x1e)]
pub struct RequestAuthAccount {
    server_id: u8,  // 0x80?
    channel_id: u8, // 1?
    user_idx: u16,  // 0?
    ip: [u8; 4],
    username: Arr<u8, 33>,
    password: Arr<u8, 97>,
    zero: u8,
}
assert_def_packet_size!(RequestAuthAccount, 139);

#[packet(0x1f)]
pub struct ResponseAuthAccount {
    server_id: u8,  // 0x80?
    channel_id: u8, // 1?
    db_user_idx: u16,  // idx inside db agent; for VerifyLinks message
    ip: [u8; 4],
    username: Arr<u8, 33>,
    user_id: u32, // 1?
    login_idx_existing: u8, // 0; 1 when result 0x22
    result: u8,    // 0x20 - ok
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
    resident_num: u32,          // d0 bf 0b 0 ??
    unk5: u32,                  // 0
    premium_service_type: u32,          // 5
    premium_expire_time: u32,   // eb 81 3f 78
    pcbang_remaining_time: u32, // 0?
    unkkey: Arr<u8, 33>,
    unk9: u8,               // 0
    pcpoint: u32,           // 0
    unk10: u8,              // 1
    unk11: u8,              // 0
    unk12: u32,             // 1
    unk13: u32,             // 0
    unk14: u32,             // 0
    unk15: u32,             // 0
    unk16: u32,             // 0
    unk17: u8,              // 0
    unk18: Arr<u8, 32>,     // 0?
    unk19: u8,              // 0
    unk20: u32,             // 0
    unk21: u32,             // 0xa5e - some counter
    unk22: u32,             // 0x477a7190
    unk23: u32,             // 0
    unk24: u32,             // 0x477a7190
    unk25: u32,             // 0
    login_idx: u32,         // total login count
    characters: BoundVec<0, u8>, // i.e. [1, 3] on successful login (server idx1, character idx3), or [0]
}
assert_def_packet_size!(ResponseAuthAccount, 189);

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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_decode_2() {
        let buf = [
            0xE2, 0xB7, 0x4E, 0x00, 0x67, 0x00, 0x20, 0x01, 0x00, 0x00, 0x00, 0x01, 0x2F, 0x01,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x05, 0x00, 0x00, 0x00, 0xEB, 0x81,
            0x3F, 0x78, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x41, 0x35, 0x31, 0x32, 0x30, 0x36, 0x35, 0x33, 0x41, 0x41, 0x37, 0x33, 0x34,
            0x36, 0x44, 0x35, 0x38, 0x34, 0x41, 0x46, 0x30, 0x30, 0x36, 0x39, 0x36, 0x44, 0x35,
            0x36, 0x46, 0x37, 0x31, 0x45, 0x00, 0x01, 0x03,
        ];
        let data = S2CAuthAccount::deserialize_no_hdr(&buf[6..]).unwrap();
        println!("{:?}", data);
    }
}

#[packet(0x6d)]
pub struct C2SForceLogin {
    do_disconnect: u32, // 0 or 1
    unk1: u8,           // 1 ?? not processed by loginsvr
}
assert_def_packet_size!(C2SForceLogin, 5);

#[packet(0x6d)]
pub struct S2CForceLogin {
    unk1: u8, // hardcoded 1
}
