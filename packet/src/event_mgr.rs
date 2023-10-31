// SPDX-License-Identifier: MIT
// Copyright(c) 2023 Darek Stojaczyk

use crate::assert_def_packet_size;
use packet_proc::packet;

#[packet(0x2b3)]
pub struct Keepalive {}
assert_def_packet_size!(Keepalive, 0);
