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
