// SPDX-License-Identifier: MIT
// Copyright(c) 2023 Darek Stojaczyk

use num_enum::{IntoPrimitive, TryFromPrimitive};
use packet_proc::{packet, PacketEnum};

use crate::BoundVec;

#[derive(std::fmt::Debug, PartialEq, Clone, Default, bincode::Encode, bincode::Decode)]
pub struct Unknown {
    pub id: u16,
    pub data: UnknownPayload,
}
pub type UnknownPayload = BoundVec<0, u8>;

impl crate::Payload for Unknown {
    fn id(&self) -> u16 {
        self.id
    }
}

#[packet(0x5)]
pub struct Connect {
    service: ServiceID,
    world_id: u8,
    channel_id: u8,
    unk2: u8, // hardcoded 0x0
}

impl std::fmt::Display for Connect {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_fmt(format_args!("{:?}", self.service))?;
        if self.service == ServiceID::WorldSvr {
            f.write_fmt(format_args!("s{}c{}", self.world_id, self.channel_id))?;
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, TryFromPrimitive, IntoPrimitive, PacketEnum)]
#[repr(u8)]
pub enum ServiceID {
    #[default]
    WorldSvr = 0xa1, // 161
    LoginSvr = 0xc3,     // 195
    DBAgent = 0xd4,      // 212
    AgentShop = 0xe9,    // 233
    EventMgr = 0xf5,     // 245
    GlobalMgrSvr = 0xf6, // 246
    ChatNode = 0xfa,     // 250
    RockNRoll = 0xfd,    // 253
}

#[packet(0x6)]
pub struct ConnectAck {
    bytes: BoundVec<0, u8>,
}
