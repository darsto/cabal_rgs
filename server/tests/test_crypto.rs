// SPDX-License-Identifier: MIT
// Copyright(c) 2023 Darek Stojaczyk

use aria::{BlockExt, BlockSlice};
use log::{info, trace};
use packet::pkt_common::ServiceID;
use packet::{Block, Payload};
use server::executor;
use server::packet_stream::PacketStream;

use std::net::{TcpListener, TcpStream};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use anyhow::Result;
use smol::{Async, Timer};

async fn connect_timeout() -> std::io::Result<Async<TcpStream>> {
    let mut attempts = 0;
    loop {
        let conn = Async::<TcpStream>::connect(([127, 0, 0, 1], 32001)).await;
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

fn xor_blocks_mut(blocks: &mut [Block]) {
    blocks
        .iter_mut()
        .for_each(|c| c.iter_mut().for_each(|b| *b ^= 0xb3));
}

fn xor_blocks<const N: usize>(mut blocks: [Block; N]) -> [Block; N] {
    xor_blocks_mut(&mut blocks);
    blocks
}

fn xor_block(mut block: Block) -> Block {
    block.iter_mut().for_each(|b| *b ^= 0xb3);
    block
}

async fn start_client_test() {
    let stream = connect_timeout().await.unwrap();
    let mut conn = PacketStream::new_buffered(stream);

    let hello = packet::pkt_common::Connect {
        id: ServiceID::GlobalMgrSvr,
        world_id: 0xfd,
        channel_id: 0x0,
        unk2: 0x0,
    };
    conn.send(&Payload::Connect(hello)).await.unwrap();

    trace!("Sent Hello!");
    trace!("Waiting for Ack ...");

    let p = conn.recv().await.unwrap();
    let Payload::ConnectAck(ack) = p else {
        panic!("Expected ConnectAck packet, got {p:?}");
    };
    let ack = packet::pkt_crypto::ConnectAck::try_from(ack).unwrap();

    assert_eq!(ack.unk1, 0x0);
    assert_eq!(ack.unk2, [0x00, 0xff, 0x00, 0xff, 0x00, 0x00, 0x00, 0x00]);
    assert_eq!(ack.unk3, 0xf6);
    assert_eq!(ack.unk4, 0xf6);
    assert_eq!(ack.unk5, 0x398ab300);
    assert_eq!(ack.unk6, 0x1f);

    trace!("Ack received!");
    trace!("Sending Key Request ...");

    let req = Payload::EncryptKey2Request(packet::pkt_crypto::EncryptKey2Request {
        key_split_point: 0x1 ^ 0x1f398ab3,
    });
    conn.send(&req).await.unwrap();

    trace!("Key Request sent!");
    trace!("Waiting for response ...");

    let p = conn.recv().await.unwrap();
    let Payload::EncryptKey2Response(mut resp) = p else {
        panic!("Expected EncryptKey2Response packet, got {p:?}");
    };

    assert_eq!(resp.key_split_point, 0x1);
    assert_eq!(resp.shortkey.len(), 9);

    resp.shortkey.0.as_mut_slice()[0..8].rotate_right(resp.key_split_point as usize);
    resp.shortkey.iter_mut().for_each(|b| *b ^= 0xb3);
    resp.shortkey.resize(32, 0x0);

    trace!("Response received");
    trace!("Sending Key Auth Request ...");

    let keybuf: [u8; 32] = (&resp.shortkey[0..32]).try_into().unwrap();
    let key = aria::Key::from(keybuf);
    let enckey = key.expand();
    let deckey = aria::DecryptKey::from(enckey.clone());

    let req = packet::pkt_crypto::KeyAuthRequest {
        unk1: 0x0,
        unk2: 0x0,
        netmask: xor_block(enckey.encrypt(Block::new("255.255.255.127"))),
        nation: xor_block(enckey.encrypt(Block::new("127.0.0.1"))),
        srchash: xor_blocks(
            Block::arr_from_slice::<_, 4>("f2b76e1ee8a92a8ce99a41c07926d3f3")
                .map(|b| enckey.encrypt(b)),
        ),
        binbuf: xor_blocks(Block::arr_from_slice::<_, 4>("empty").map(|b| enckey.encrypt(b))),
        xor_port: 38180,
    };
    conn.send(&Payload::KeyAuthRequest(req)).await.unwrap();

    trace!("Key Auth Request sent!");
    trace!("Waiting for response ...");

    let p = conn.recv().await.unwrap();
    let Payload::KeyAuthResponse(mut resp) = p else {
        panic!("Expected KeyAuthResponse packet, got {p:?}");
    };

    assert_eq!(resp.unk1, 0x1);
    resp.xor_unk2 ^= 0x1f398ab3;
    assert_eq!(resp.xor_unk2, 0x03010101);
    assert_eq!(resp.ip_local.try_as_str(), Ok("127.0.0.1"));
    resp.xor_unk3 ^= 0xb3;
    assert_eq!(resp.xor_unk3, 0x4);
    xor_blocks_mut(&mut resp.enc_item);
    resp.enc_item.iter_mut().for_each(|b| deckey.decrypt_mut(b));
    assert_eq!(resp.enc_item.try_as_str(), Ok("Data/Item.scp"));
    resp.xor_unk4 ^= 0xb3;
    assert_eq!(resp.xor_unk4, 0x2);
    xor_blocks_mut(&mut resp.enc_mobs);
    resp.enc_mobs.iter_mut().for_each(|b| deckey.decrypt_mut(b));
    assert_eq!(resp.enc_mobs.try_as_str(), Ok("Data/Mobs.scp"));
    resp.xor_unk5 ^= 0xb3;
    assert_eq!(resp.xor_unk5, 0x1);
    xor_blocks_mut(&mut resp.enc_warp);
    resp.enc_warp.iter_mut().for_each(|b| deckey.decrypt_mut(b));
    assert_eq!(resp.enc_warp.try_as_str(), Ok("Data/Warp.scp"));
    assert_eq!(resp.port, 38180);

    trace!("Response received");
    trace!("Sending ESYM Request ...");

    let req = packet::pkt_crypto::ESYMRequest {
        unk1: 0x0,
        nation: "BRA".into(),
        srchash: "f2b76e1ee8a92a8ce99a41c07926d3f3".into(),
    };
    conn.send(&Payload::ESYM(req.try_into().unwrap()))
        .await
        .unwrap();

    trace!("ESYM Request sent!");
    trace!("Waiting for response ...");

    let p = conn.recv().await.unwrap();
    let Payload::ESYM(resp) = p else {
        panic!("Expected KeyAuthResponse packet, got {p:?}");
    };

    let resp = packet::pkt_crypto::ESYMResponse::try_from(resp).unwrap();
    trace!("ESYM resp length: {}", resp.filesize);
    trace!("Reponse received");

    info!("All done. Exiting");
}

async fn start_server() -> Result<()> {
    let tcp_listener = Async::<TcpListener>::bind(([127, 0, 0, 1], 32001)) //
        .expect("Cannot bind to 32001");
    let mut args = server::args::parse_from_str("-s crypto");
    args.common.resources_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let mut listener = server::crypto::Listener::new(tcp_listener, &Arc::new(args));
    listener.listen().await
}

#[test]
fn basic_crypto_mgr() {
    server::setup_log(true);

    executor::run_until(async {
        let server_t = executor::spawn_local(start_server());
        let client_f = start_client_test();
        client_f.await;
        server_t.cancel().await;
    });
}
