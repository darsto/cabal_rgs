// SPDX-License-Identifier: MIT
// Copyright(c) 2023 Darek Stojaczyk

use packet::Payload;
use server::packet_stream::PacketStream;

use std::net::{TcpListener, TcpStream};
use std::sync::Arc;
use std::time::Duration;

use anyhow::Result;
use smol::{Async, Timer};

macro_rules! log {
    ($s:literal) => {
        print!("C: ");
        println!($s);
    };
    ($s:literal, $($arg:tt)*) => {
        print!("C: ");
        println!($s, ($arg)*);
    };
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

async fn start_client_test() {
    let mut conn = PacketStream::new(connect_timeout().await.unwrap());

    let world_id = 1;
    let channel_id = 1;

    let hello = packet::event_mgr::Connect {
        unk1: 0x0,
        world_id,
        channel_id,
        unk2: 0x0,
    };
    conn.send(&Payload::Connect(hello.try_into().unwrap()))
        .await
        .unwrap();
    log!("Sent Hello!");
    log!("Waiting for Ack ...");

    let p = conn.recv().await.unwrap();
    let Payload::ConnectAck(ack) = &p else {
        panic!("Expected ConnectAck packet, got {p:?}");
    };
    let ack = packet::event_mgr::ConnectAck::try_from(ack).unwrap();
    assert_eq!(ack.unk1, 0x0);
    assert_eq!(
        ack.unk2,
        [0x00, 0xff, 0x00, 0xff, 0xf5, 0x00, 0x00, 0x00, 0x00]
    );
    assert_eq!(ack.world_id, world_id);
    assert_eq!(ack.channel_id, channel_id);
    assert_eq!(ack.unk3, 0x0);
    assert_eq!(ack.unk4, 0x1);
    log!("Ack received!");
    log!("Sending Keepalive!");

    let keepalive = Payload::Keepalive(packet::event_mgr::Keepalive {});
    conn.send(&keepalive).await.unwrap();
    log!("All sent!");

    // make sure the connection wasn't terminated
    Timer::after(Duration::from_millis(100)).await;
    conn.send(&keepalive).await.unwrap();
}

async fn start_server() -> Result<()> {
    let tcp_listener = Async::<TcpListener>::bind(([127, 0, 0, 1], 38171)) //
        .expect("Cannot bind to 38171");
    let args = Arc::new(server::args::Config::default());

    let mut listener = server::event_mgr::Listener::new(tcp_listener, args);
    listener.listen().await
}

#[test]
fn test_connect() {
    smol::block_on(async {
        let server_t = smol::spawn(start_server());
        let client_f = start_client_test();
        client_f.await;
        server_t.cancel().await;
    });
}
