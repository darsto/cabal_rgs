// SPDX-License-Identifier: MIT
// Copyright(c) 2023 Darek Stojaczyk

use log::{info, trace};
use packet::pkt_common::Connect;
use packet::{Packet, Payload};
use server::executor;
use server::packet_stream::{IPCPacketStream, Service};

use std::net::{TcpListener, TcpStream};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use anyhow::Result;
use smol::{Async, Timer};

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
    let mut conn = IPCPacketStream::from_conn(
        Service::WorldSvr {
            server: 1,
            channel: 1,
        },
        Service::EventMgr,
        stream,
    )
    .await
    .unwrap();

    trace!("Connected!");
    trace!("Waiting for Ack ...");

    let p = conn.recv().await.unwrap();
    let Packet::ConnectAck(ack) = &p else {
        panic!("Expected ConnectAck packet, got {p:?}");
    };
    let ack = packet::pkt_event::ConnectAck::deserialize_no_hdr(&ack.bytes).unwrap();
    assert_eq!(ack.unk1, 0x0);
    assert_eq!(
        ack.unk2,
        [0x00, 0xff, 0x00, 0xff, 0xf5, 0x00, 0x00, 0x00, 0x00]
    );
    let self_id = Connect::from(conn.self_id);
    assert_eq!(ack.world_id, self_id.world_id);
    assert_eq!(ack.channel_id, self_id.channel_id);
    assert_eq!(ack.unk3, 0x0);
    assert_eq!(ack.unk4, 0x1);
    trace!("Ack received!");
    trace!("Sending Keepalive!");

    conn.send(&packet::pkt_event::Keepalive {}).await.unwrap();

    // make sure the connection wasn't terminated
    Timer::after(Duration::from_millis(100)).await;
    conn.send(&packet::pkt_event::Keepalive {}).await.unwrap();

    info!("All done. Exiting");
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

    executor::run_until(async {
        let server_t = executor::spawn_local(start_server());
        let client_f = start_client_test();
        client_f.await;
        server_t.cancel().await;
    });
}
