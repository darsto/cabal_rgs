// SPDX-License-Identifier: MIT
// Copyright(c) 2023 Darek Stojaczyk

use crate::{assert_def_packet_size, UnboundVec};
use packet_proc::packet;

#[packet(0x5)]
pub struct Connect {
    unk1: u8, // 0xa1?
    world_id: u8,
    channel_id: u8,
    unk2: u8,
}
assert_def_packet_size!(Connect, 4);
packet_alias!(Connect, common::Connect);

#[packet(0x6)]
pub struct ConnectAck {
    unk1: u32,     // 0x0?
    unk2: [u8; 8], // hardcoded to [0x00, 0xff, 0x00, 0xff, 0xf5, 0x00, 0x00, 0x00]
    unk3: u8,
    unk4: u8,
    unk5: u32, // hardcoded to 0x0
    unk6: u8,  // hardcoded to 0x1
}
packet_alias!(ConnectAck, common::ConnectAck);
assert_def_packet_size!(ConnectAck, 19);

#[packet(0x305)]
pub struct EncryptKey2Request {
    key_split_point: u32, // xored with 0x1f398ab3. usually ends up either 1 or 5
                          // the short key should be split at this index into two parts,
                          // then constructed from those parts in reverse order
}
assert_def_packet_size!(EncryptKey2Request, 14 - Header::SIZE);

#[packet(0x306)]
pub struct EncryptKey2Response {
    key_split_point: u32, // un-xored, usually either 1 or 5
    shortkey: UnboundVec<u8>,
}
assert_def_packet_size!(EncryptKey2Response, 14 - Header::SIZE);

#[packet(0x2f3)]
pub struct KeyAuthRequest {
    unk1: u32,           // 0x0
    unk2: u32,           // 0x0
    netmask: Block,      // expecting "255.255.255.127"
    nation: Block,       // expecting "BRA"
    srchash: [Block; 4], // expecting f2b76e1ee8a92a8ce99a41c07926d3f3
    binbuf: [Block; 4],  // expecting "empty"
    xor_port: u32,       // global db agent port? xored with 0x1f398ab3, ends up 38180
}
assert_def_packet_size!(KeyAuthRequest, 182 - Header::SIZE);

#[packet(0x2f4)]
pub struct KeyAuthResponse {
    unk1: u32,             // 0x1
    xor_unk2: u32,         // xored with 0x1f398ab3, usually ends up 0x03010101
    ip_local: Block,       // plaintext, always null-terminated, usually "127.0.0.1"
    xor_unk3: u8,          // xored with 0xb3, ends up 4
    enc_item: [Block; 16], // ^
    xor_unk4: u8,          // xored with 0xb3, ends up 2
    enc_mobs: [Block; 16], // ^
    xor_unk5: u8,          // xored with 0xb3, ends up 1
    enc_warp: [Block; 16], // ^
    port: u32,             // global db agent port? 38180
}
assert_def_packet_size!(KeyAuthResponse, 809 - Header::SIZE);

// The same packet ID used by request and response.
// Possibly an oversight in original design
#[packet(0x30c)]
pub struct ESYM {
    bytes: UnboundVec<u8>,
}

#[packet(0x30c)]
pub struct ESYMRequest {
    unk1: u32,              // 0x0
    nation: NulltermString, // usually BRA
    srchash: NulltermString,
}
packet_alias!(ESYMRequest, ESYM);

#[packet(0x30c)]
pub struct ESYMResponse {
    unk1: u32,     // 0x0
    filesize: u32, // 0x0
    esym: UnboundVec<u8>,
}
packet_alias!(ESYMResponse, ESYM);
