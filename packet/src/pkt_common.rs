// SPDX-License-Identifier: MIT
// Copyright(c) 2023 Darek Stojaczyk

use num_derive::FromPrimitive;
use packet_proc::packet;

use crate::BoundVec;

#[packet(0x0)]
pub struct Unknown {
    id: u16,
    data: UnknownPayload,
}
pub type UnknownPayload = BoundVec<0, u8>;

#[packet(0x5)]
pub struct Connect {
    unk1: u8, // source ServiceID
    world_id: u8,
    channel_id: u8,
    unk2: u8, // hardcoded 0x0
}

#[derive(Debug, PartialEq, FromPrimitive)]
#[repr(u8)]
pub enum ServiceID {
    WorldSvr = 0xa1,
    LoginSvr = 0xc3,
    DBAgent = 0xd4,
    AgentShop = 0xe9,
    EventNgr = 0xf5,
    GlobalMgrSvr = 0xf6,
    ChatNode = 0xfa,
    RockNRoll = 0xfd,
}

#[packet(0x6)]
pub struct ConnectAck {
    bytes: BoundVec<0, u8>,
}
