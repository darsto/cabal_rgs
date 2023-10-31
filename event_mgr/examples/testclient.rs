/* SPDX-License-Identifier: MIT
 * Copyright(c) 2023 Darek Stojaczyk
 */

use ::event_mgr::packet_stream::PacketStream;
use packet::*;

use std::{net::TcpStream, time::Duration};

use anyhow::{bail, Result};
use smol::{Async, Timer};

async fn client_test(mut stream: PacketStream) -> Result<()> {
    let world_id = 1;
    let channel_id = 1;

    let hello = Payload::Connect(packet::common::Connect {
        unk1: 0x0,
        world_id,
        channel_id,
        unk2: 0x0,
    });
    stream.send(&hello).await?;

    println!("Sent Hello!");
    println!("Waiting for Ack ...");

    let p = stream.recv().await?;
    let Payload::ConnectAck(ack) = &p else {
        bail!("Expected ConnectAck packet, got {p:?}");
    };

    assert!(ack.unk1 == 0x0);
    assert!(ack.unk2 == [0x00, 0xff, 0x00, 0xff, 0xf5, 0x00, 0x00, 0x00, 0x00]);
    assert!(ack.world_id == world_id);
    assert!(ack.channel_id == channel_id);
    assert!(ack.unk3 == 0x0);
    assert!(ack.unk4 == 0x1);

    println!("Ack received!");

    Ok(())
}

async fn connect_timeout() -> std::io::Result<Async<TcpStream>> {
    let mut attempts = 0;
    loop {
        let conn = Async::<TcpStream>::connect(([127, 0, 0, 1], 38171)).await;
        if conn.is_ok() {
            return conn;
        }

        attempts += 1;
        if attempts > 10 {
            return conn;
        }

        Timer::after(Duration::from_millis(75)).await;
    }
}

fn main() -> Result<()> {
    smol::block_on(async {
        println!("Trying to connect ...");
        let conn = connect_timeout().await?;

        println!("Connected!");
        client_test(PacketStream::new(conn)).await
    })
}
