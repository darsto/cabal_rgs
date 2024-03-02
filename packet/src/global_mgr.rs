// SPDX-License-Identifier: MIT
// Copyright(c) 2024 Darek Stojaczyk

use packet_proc::packet;

use crate::{assert_def_packet_size, BoundVec};

// packet 0x35
#[packet(0x35)]
pub struct ServerState {
    servers: BoundVec<1, ServerNode>,
}

// must be 7 bytes!
#[packet]
pub struct ServerNode {
    id: u8,
    stype: u8, // usually 0x10 (set in globalmgrsvr ini)
    unk1: u32,
    groups: BoundVec<1, GroupNode>,
}
assert_def_packet_size!(ServerNode, 7);

// must be 0x25 bytes
#[packet]
pub struct GroupNode {
    id: u8,
    unk0: u16, // 1 later on
    unk1: u32,
    unk2: u32,
    unk3: u32,
    unk4: u32,
    unk5: u16,
    unk6: u16,
    unk7: u16, //0xff later on
    unk8: u16, // 0x50 max players (set in globalmgrsvr ini)
    ip: u32,   // 8f00020a
    port: u16, // 0x94df
    unk9: u32, // 0x5
}
assert_def_packet_size!(GroupNode, 37);

/*

> @annotate-cfg [clamp = [7, 54]]
> @annotate-cfg [rangeFn = { start = 8 + start * 3 - 1; end = 8 + end * 3 - 2 }]

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
