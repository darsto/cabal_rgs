// SPDX-License-Identifier: MIT
// Copyright(c) 2023 Darek Stojaczyk

use crate::packet_stream::PacketStream;
use crypto::aesc::BlockUtil;
use packet::*;

use rand::Rng;
use std::collections::HashMap;
use std::os::fd::AsRawFd;
use std::{net::TcpListener, sync::Arc};

use anyhow::{bail, Context, Result};
use smol::Async;

#[derive(clap::Args, Debug, Default)]
pub struct Args {}

pub struct Listener {
    tcp_listener: Async<TcpListener>,
    _args: Arc<crate::args::Args>,
}

impl Listener {
    pub fn new(tcp_listener: Async<TcpListener>, args: Arc<crate::args::Args>) -> Self {
        Self {
            tcp_listener,
            _args: args,
        }
    }

    pub async fn listen(&mut self) -> Result<()> {
        println!("Listening on {}", self.tcp_listener.get_ref().local_addr()?);

        loop {
            let (stream, _) = self.tcp_listener.accept().await?;

            let conn = Connection {
                id: stream.as_raw_fd(),
                stream: PacketStream::new(stream),
                keys: HashMap::new(),
            };

            // Give the connection handler its own background task
            smol::spawn(async move {
                let id = conn.id;
                println!("New connection #{id}");
                if let Err(err) = conn.handle().await {
                    eprintln!("Connection #{id} error: {err}");
                }
                println!("Closing connection #{id}");
            })
            .detach();
            // for now the tasks are just dropped, but we might want to
            // wait for them in the future (or send a special shutdown
            // message in each connection)
        }
    }
}

fn block_arr_xor(blocks: &mut [crypto::aesc::Block]) {
    blocks
        .iter_mut()
        .for_each(|c| c.iter_mut().for_each(|b| *b ^= 0xb3));
}

pub struct Connection {
    pub id: i32,
    pub stream: PacketStream,
    pub keys: HashMap<u32, crypto::aesc::Key>,
}

impl Connection {
    pub async fn handle_key_req(&mut self, mut req: crypto_mgr::EncryptKey2Request) -> Result<()> {
        req.key_xid ^= 0x1f398ab3;
        println!("key req key_id = {}", req.key_xid);

        let key = self.keys.entry(req.key_xid).or_insert_with(|| {
            let mut rng = rand::thread_rng();
            let mut keybuf = [0u8; 32];
            (0..8).for_each(|i| {
                keybuf[i] = if rng.gen_bool(0.5) {
                    rng.gen_range(b'a'..=b'z')
                } else {
                    rng.gen_range(b'A'..=b'Z')
                };
            });
            crypto::aesc::Key::from(keybuf)
        });

        let shortkey = &key.as_bytes()[0..9];
        let r = Payload::EncryptKey2Response(crypto_mgr::EncryptKey2Response {
            key_id: req.key_xid,
            shortkey: UnboundVec(shortkey.iter().map(|b| b ^ 0xb3).collect()),
        });
        self.stream.send(&r).await
    }

    pub async fn handle_auth_req(&mut self, mut req: crypto_mgr::KeyAuthRequest) -> Result<()> {
        println!("auth req key_id = {}", req.key_id);

        assert_eq!(req.unk1, 0x0);
        assert_eq!(req.unk2, 0x0);

        let key = self
            .keys
            .get(&req.key_id)
            .with_context(|| format!("Unknown key {}", req.key_id))?;
        let deckey: crypto::aesc::DecryptKey = key.expand(crypto::aesc::NumRounds::R16).into();

        block_arr_xor(core::slice::from_mut(&mut req.ip_origin));
        let ip_origin = deckey.decrypt_one(&req.ip_origin);

        block_arr_xor(core::slice::from_mut(&mut req.ip_local));
        let ip_local = deckey.decrypt_one(&req.ip_local);

        block_arr_xor(&mut req.srchash);
        let srchash = deckey.decrypt(&req.srchash);

        block_arr_xor(&mut req.binbuf);
        let binbuf = deckey.decrypt(&req.binbuf);

        println!("ip_origin={ip_origin:#x?}, ip_local={ip_local:#x?}, srchash={srchash:#x?}, binbuf={binbuf:#x?}");

        let ip_local = BlockUtil::one_from_str("127.0.0.1");
        let mut enc_item: [crypto::aesc::Block; 16] = BlockUtil::from_str("Data/Item.scp");
        block_arr_xor(&mut enc_item);
        let mut enc_mobs: [crypto::aesc::Block; 16] = BlockUtil::from_str("Data/Mobs.scp");
        block_arr_xor(&mut enc_mobs);
        let mut enc_warp: [crypto::aesc::Block; 16] = BlockUtil::from_str("Data/Warp.scp");
        block_arr_xor(&mut enc_warp);

        let r = Payload::KeyAuthResponse(crypto_mgr::KeyAuthResponse {
            unk1: 0x1,
            xor_unk2: 0x03010101 ^ 0x1f398ab3,
            ip_local,
            xor_unk3: 4 ^ 0xb3,
            enc_item,
            xor_unk4: 2 ^ 0xb3,
            enc_mobs,
            xor_unk5: 1 ^ 0xb3,
            enc_warp,
            port: 38180,
        });
        self.stream.send(&r).await
    }

    pub async fn handle_esym(&mut self, esym: crypto_mgr::ESYM) -> Result<()> {
        let (req, len) = bincode::decode_from_slice::<crypto_mgr::ESYMRequest, _>(
            esym.data.0.as_slice(),
            bincode::config::legacy(),
        )?;
        if len != esym.data.0.len() {
            bail!("Trailing data in ESYM packet {:#?}", esym);
        }

        println!(
            "ESYM req nation = {}, srchash = {}",
            req.nation.0, req.srchash.0
        );

        let r = crypto_mgr::ESYMResponse {
            unk1: 0x1,
            filesize: 0x0,
            esym: UnboundVec(vec![]), // TODO!
        };

        let mut data = UnboundVec(vec![]);
        bincode::encode_into_std_write(r, &mut data.0, bincode::config::legacy())?;
        let r = Payload::ESYM(crypto_mgr::ESYM { data });
        self.stream.send(&r).await
    }

    pub async fn handle(mut self) -> Result<()> {
        let p = self.stream.recv().await?;
        let Payload::Connect(hello) = &p else {
            bail!("Expected Connect packet, got {p:?}");
        };

        assert_eq!(hello.unk1, 0xf6);
        assert_eq!(hello.world_id, 0xfd);

        println!("Got hello: {p:?}");
        println!("Sending Ack ...");

        let ack = Payload::ConnectAck(common::ConnectAck {
            unk1: 0x0,
            unk2: [0x00, 0xff, 0x00, 0xff, 0x00, 0x00, 0x00, 0x00, 0xf6],
            world_id: 0xf6,
            channel_id: 0xf6,
            unk3: 0x398ab300,
            unk4: 0x1f,
        });
        self.stream.send(&ack).await?;

        loop {
            let p = self.stream.recv().await?;
            match p {
                Payload::EncryptKey2Request(req) => self.handle_key_req(req).await?,
                Payload::KeyAuthRequest(req) => self.handle_auth_req(req).await?,
                Payload::ESYM(req) => self.handle_esym(req).await?,
                _ => {
                    println!("Got packet: {p:?}");
                }
            }
        }
    }
}
