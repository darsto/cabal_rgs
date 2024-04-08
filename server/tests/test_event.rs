// SPDX-License-Identifier: MIT
// Copyright(c) 2023 Darek Stojaczyk

use log::{info, trace};
use packet::Payload;
use server::packet_stream::PacketStream;
use server::ThreadLocalExecutor;

use std::net::{TcpListener, TcpStream};
use std::os::fd::AsRawFd;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use anyhow::Result;
use smol::{Async, Timer};

/// Log prefix
const PREFIX: &str = "Client";

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
    let stream = connect_timeout().await.unwrap();
    let mut conn = PacketStream::new(stream.as_raw_fd(), stream);

    let world_id = 1;
    let channel_id = 1;

    let hello = packet::pkt_common::Connect {
        unk1: 0x0,
        world_id,
        channel_id,
        unk2: 0x0,
    };
    conn.send(&Payload::Connect(hello.try_into().unwrap()))
        .await
        .unwrap();
    trace!("{PREFIX}: Sent Hello!");
    trace!("{PREFIX}: Waiting for Ack ...");

    let p = conn.recv().await.unwrap();
    let Payload::ConnectAck(ack) = &p else {
        panic!("Expected ConnectAck packet, got {p:?}");
    };
    let ack = packet::pkt_event::ConnectAck::try_from(ack).unwrap();
    assert_eq!(ack.unk1, 0x0);
    assert_eq!(
        ack.unk2,
        [0x00, 0xff, 0x00, 0xff, 0xf5, 0x00, 0x00, 0x00, 0x00]
    );
    assert_eq!(ack.world_id, world_id);
    assert_eq!(ack.channel_id, channel_id);
    assert_eq!(ack.unk3, 0x0);
    assert_eq!(ack.unk4, 0x1);
    trace!("{PREFIX}: Ack received!");
    trace!("{PREFIX}: Sending Keepalive!");

    let keepalive = Payload::Keepalive(packet::pkt_event::Keepalive {});
    conn.send(&keepalive).await.unwrap();

    // make sure the connection wasn't terminated
    Timer::after(Duration::from_millis(100)).await;
    conn.send(&keepalive).await.unwrap();

    info!("{PREFIX}: All done. Exiting");
}

async fn start_server() -> Result<()> {
    let tcp_listener = Async::<TcpListener>::bind(([127, 0, 0, 1], 38171)) //
        .expect("Cannot bind to 38171");

    let mut args = server::args::parse_from_str("-s event");
    args.common.resources_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let mut listener = server::event::Listener::new(tcp_listener, &Arc::new(args));
    listener.listen().await
}

#[test]
fn basic_event_mgr() {
    server::setup_log(true);

    let ex = ThreadLocalExecutor::new().unwrap();
    futures::executor::block_on(ex.run(async {
        let server_t = ex.spawn(start_server());
        let client_f = start_client_test();
        client_f.await;
        server_t.cancel().await;
    }));
}
