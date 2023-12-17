// SPDX-License-Identifier: MIT
// Copyright(c) 2023 Darek Stojaczyk

use crate::assert_def_packet_size;
use packet_proc::packet;

#[packet(0x5)]
pub struct Connect {
    unk1: u8, // 0xa1?
    world_id: u8,
    channel_id: u8,
    unk2: u8, // hardcoded 0x0
}
assert_def_packet_size!(Connect, 4);

#[packet(0x6)]
pub struct ConnectAck {
    unk1: u32,     // 0x0?
    unk2: [u8; 8], // hardcoded to [0x00, 0xff, 0x00, 0xff, 0xf5, 0x00, 0x00, 0x00]
    world_id: u8,
    channel_id: u8,
    unk3: u32, // hardcoded to 0x0
    unk4: u8,  // hardcoded to 0x1
}
assert_def_packet_size!(ConnectAck, 19);

#[packet(0x0)]
pub struct Unknown {
    bytes: UnboundVec<u8>,
}
