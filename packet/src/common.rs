// SPDX-License-Identifier: MIT
// Copyright(c) 2023 Darek Stojaczyk

use packet_proc::packet;

use crate::BoundVec;

#[packet(0x0)]
pub struct Unknown {
    bytes: BoundVec<0, u8>,
}

#[packet(0x5)]
pub struct Connect {
    bytes: BoundVec<0, u8>,
}

#[packet(0x6)]
pub struct ConnectAck {
    bytes: BoundVec<0, u8>,
}
