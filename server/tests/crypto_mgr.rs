// SPDX-License-Identifier: MIT
// Copyright(c) 2023 Darek Stojaczyk

use crypto::aesc::BlockUtil;
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

async fn start_client_test() {
    let mut conn = PacketStream::new(connect_timeout().await.unwrap());

    let hello = Payload::Connect(packet::common::Connect {
        unk1: 0xf6,
        world_id: 0xfd,
        channel_id: 0x0,
        unk2: 0x0,
    });
    conn.send(&hello).await.unwrap();

    log!("Sent Hello!");
    log!("Waiting for Ack ...");

    let p = conn.recv().await.unwrap();
    let Payload::ConnectAck(ack) = p else {
        panic!("Expected ConnectAck packet, got {p:?}");
    };

    assert_eq!(ack.unk1, 0x0);
    assert_eq!(
        ack.unk2,
        [0x00, 0xff, 0x00, 0xff, 0x00, 0x00, 0x00, 0x00, 0xf6]
    );
    assert_eq!(ack.world_id, 0xf6);
    assert_eq!(ack.channel_id, 0xf6);
    assert_eq!(ack.unk3, 0x398ab300);
    assert_eq!(ack.unk4, 0x1f);

    log!("Ack received!");
    log!("Sending Key Request!");

    let req = Payload::EncryptKey2Request(packet::crypto_mgr::EncryptKey2Request {
        key_xid: 0x1 ^ 0x1f398ab3,
    });
    conn.send(&req).await.unwrap();

    let p = conn.recv().await.unwrap();
    let Payload::EncryptKey2Response(mut resp) = p else {
        panic!("Expected EncryptKey2Response packet, got {p:?}");
    };

    assert_eq!(resp.key_id, 0x1);
    assert_eq!(resp.shortkey.len(), 9);

    resp.shortkey.iter_mut().for_each(|b| *b ^= 0xb3);

    let mut keybuf = Vec::from(resp.shortkey.0);
    keybuf.resize(32, 0x0);
    let keybuf: [u8; 32] = (&keybuf[0..32]).try_into().unwrap();
    let key = crypto::aesc::Key::from(keybuf);
    let enckey = key.expand(crypto::aesc::NumRounds::R16);
    let deckey = crypto::aesc::DecryptKey::from(enckey.clone());

    let req = Payload::KeyAuthRequest(packet::crypto_mgr::KeyAuthRequest {
        unk1: 0x0,
        unk2: 0x0,
        ip_origin: enckey.encrypt_one(&BlockUtil::one_from_str("255.255.255.127")),
        ip_local: enckey.encrypt_one(&BlockUtil::one_from_str("127.0.0.1")),
        srchash: enckey.encrypt(&BlockUtil::from_str::<4>(
            "f2b76e1ee8a92a8ce99a41c07926d3f3",
        )),
        binbuf: enckey.encrypt(&BlockUtil::from_str::<4>("empty")),
        key_id: resp.key_id,
    });
    conn.send(&req).await.unwrap();

    let p = conn.recv().await.unwrap();
    let Payload::KeyAuthResponse(mut resp) = p else {
        panic!("Expected KeyAuthResponse packet, got {p:?}");
    };

    assert_eq!(resp.unk1, 0x1);
    assert_eq!(resp.xor_unk2, 0x03010101);
    resp.xor_unk2 ^= 0x1f398ab3;
    deckey.mut_decrypt(core::slice::from_mut(&mut resp.ip_local));
    assert_eq!(
        BlockUtil::try_as_utf8_string(core::slice::from_ref(&resp.ip_local)),
        Ok("127.0.0.1")
    );
    resp.xor_unk3 ^= 0xb3;
    assert_eq!(resp.xor_unk3, 0x4);
    deckey.mut_decrypt(&mut resp.enc_item);
    assert_eq!(
        BlockUtil::try_as_utf8_string(&resp.enc_item),
        Ok("Data/Item.scp")
    );
    resp.xor_unk4 ^= 0xb3;
    assert_eq!(resp.xor_unk4, 0x2);
    deckey.mut_decrypt(&mut resp.enc_mobs);
    assert_eq!(
        BlockUtil::try_as_utf8_string(&resp.enc_item),
        Ok("Data/Mobs.scp")
    );
    resp.xor_unk5 ^= 0xb3;
    assert_eq!(resp.xor_unk5, 0x1);
    deckey.mut_decrypt(&mut resp.enc_warp);
    assert_eq!(
        BlockUtil::try_as_utf8_string(&resp.enc_item),
        Ok("Data/Warp.scp")
    );

    assert_eq!(resp.port, 38180);

    log!("All sent!");
}

async fn start_server() -> Result<()> {
    let tcp_listener = Async::<TcpListener>::bind(([127, 0, 0, 1], 32001)) //
        .expect("Cannot bind to 32001");
    let args = Arc::new(server::args::Args::default());

    let mut listener = server::crypto_mgr::Listener::new(tcp_listener, args);
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
