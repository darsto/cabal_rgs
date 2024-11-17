// SPDX-License-Identifier: MIT
// Copyright(c) 2023 Darek Stojaczyk

use futures::io::BufReader;
use log::{info, trace};
use packet::pkt_common::ServiceID;
use packet::{Packet, Payload};
use server::packet_stream::{PacketStream, StreamConfig};
use server::{executor, EndpointID};

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
    let mut conn = PacketStream::from_conn(
        EndpointID {
            service: ServiceID::WorldSvr,
            world_id: 1,
            channel_id: 1,
            unk2: 0,
        },
        EndpointID {
            service: ServiceID::EventMgr,
            world_id: 1,
            channel_id: 1,
            unk2: 0,
        },
        BufReader::with_capacity(65536, stream),
        StreamConfig::ipc(),
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
    assert_eq!(ack.world_id, conn.other_id.world_id);
    assert_eq!(ack.channel_id, conn.other_id.channel_id);
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
