// SPDX-License-Identifier: MIT
// Copyright(c) 2023 Darek Stojaczyk

use crate::executor;
use crate::locked_vec::LockedVec;
use crate::packet_stream::{IPCPacketStream, Service};
use crate::registry::BorrowRef;
use aria::BlockExt;
use clap::Args;
use log::{debug, error, info, trace};
use packet::*;

use rand::Rng;
use std::cell::OnceCell;
use std::fmt::Display;
use std::net::TcpStream;
use std::os::fd::AsRawFd;
use std::sync::Weak;
use std::{net::TcpListener, sync::Arc};

use anyhow::{bail, Context, Result};
use smol::Async;

/// RockAndRoll replacement
#[derive(Args, Debug)]
#[command(about, long_about, verbatim_doc_comment, disable_help_flag = true)]
pub struct CryptoArgs {}

pub struct Listener {
    me: Weak<Listener>,
    tcp_listener: Async<TcpListener>,
    connections: LockedVec<Arc<BorrowRef<Connection, usize>>>,
    args: Arc<crate::args::Config>,
}

impl Listener {
    pub fn new(tcp_listener: Async<TcpListener>, args: &Arc<crate::args::Config>) -> Arc<Self> {
        Arc::new_cyclic(|me| Self {
            me: me.clone(),
            tcp_listener,
            connections: LockedVec::with_capacity(16),
            args: args.clone(),
        })
    }

    pub async fn listen(self: &mut Arc<Self>) -> Result<()> {
        info!(
            "Listener: started on {}",
            self.tcp_listener.get_ref().local_addr()?
        );

        loop {
            let (stream, _) = self.tcp_listener.accept().await?;
            let conn_ref = BorrowRef::new(stream.as_raw_fd() as usize);
            self.connections.push(conn_ref.clone());

            // Give the connection handler its own background task
            let listener = self.me.upgrade().unwrap();
            executor::spawn_local(async move {
                info!("Listener: new connection ...");

                let stream = IPCPacketStream::from_host(Service::RockNRoll, stream)
                    .await
                    .unwrap();
                let conn = Connection {
                    stream,
                    listener,
                    conn_ref,
                    shortkey: OnceCell::new(),
                };
                let id = conn.stream.other_id;

                info!("Listener: {id} connected");
                if let Err(err) = conn.handle().await {
                    error!("Listener: {id} error: {err}");
                } else {
                    info!("Listener: closing {id}");
                }
            })
            .detach();
            // for now the tasks are just dropped, but we might want to
            // wait for them in the future (or send a special shutdown
            // message in each connection)
        }
    }
}

fn xor_blocks_mut(blocks: &mut [Block]) {
    blocks
        .iter_mut()
        .for_each(|c| c.iter_mut().for_each(|b| *b ^= 0xb3));
}

pub struct Connection {
    pub stream: IPCPacketStream<Async<TcpStream>>,
    pub listener: Arc<Listener>,
    pub conn_ref: Arc<BorrowRef<Connection, usize>>,
    pub shortkey: OnceCell<aria::Key>,
}
crate::impl_borrowable!(
    Connection,
    RefData = usize,
    borrow_ref = .conn_ref
);

impl Display for Connection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.stream.fmt(f)
    }
}

impl Connection {
    pub async fn handle_key_req(&mut self, mut req: pkt_crypto::EncryptKey2Request) -> Result<()> {
        debug!(
            "{self}: key req key_split_point (w/o xor) = {:#x}",
            req.key_split_point
        );
        req.key_split_point ^= 0x1f398ab3;
        debug!(
            "{self}: key req key_split_point = {:#x}",
            req.key_split_point
        );

        // why the extra scope is needed: https://github.com/rust-lang/rust/issues/69663
        // rng is not Send, and rust complains "this value is used across an await"
        {
            let mut rng = rand::thread_rng();
            let mut keybuf = [0u8; 32];
            (0..8).for_each(|i| {
                keybuf[i] = if rng.gen_bool(0.5) {
                    rng.gen_range(b'a'..=b'z')
                } else {
                    rng.gen_range(b'A'..=b'Z')
                };
            });
            let shortkey = aria::Key::from(keybuf);
            debug!("{self}: shortkey={:x?}", &shortkey.as_bytes()[0..8]);
            let _ = self.shortkey.set(shortkey);
        }

        let mut shortkey = self.shortkey.get().unwrap().clone();
        shortkey.as_bytes_mut()[0..8].rotate_left(req.key_split_point as usize);

        debug!("{self}: sent shortkey={:x?}", &shortkey.as_bytes()[0..8]);
        let shortkey = &shortkey.as_bytes()[0..9];
        self.stream
            .send(&pkt_crypto::EncryptKey2Response {
                key_split_point: req.key_split_point,
                shortkey: BoundVec(shortkey.iter().map(|b| b ^ 0xb3).collect()),
            })
            .await
    }

    pub async fn handle_auth_req(&mut self, mut req: pkt_crypto::KeyAuthRequest) -> Result<()> {
        req.xor_port ^= 0x1f398ab3;
        debug!("{self}: auth req xor_port = {}", req.xor_port);

        assert_eq!(req.unk1, 0x0);
        assert_eq!(req.unk2, 0x0);

        let key = self.shortkey.get().context("shortkey not initialized")?;
        let enckey = key.expand();
        let deckey: aria::DecryptKey = enckey.clone().into();

        xor_blocks_mut(core::slice::from_mut(&mut req.netmask));
        deckey.decrypt_mut(&mut req.netmask);
        let netmask = &req.netmask;

        xor_blocks_mut(core::slice::from_mut(&mut req.nation));
        deckey.decrypt_mut(&mut req.nation);
        let nation = &req.nation;

        xor_blocks_mut(&mut req.srchash);
        req.srchash.iter_mut().for_each(|b| deckey.decrypt_mut(b));
        let srchash = req.srchash;

        xor_blocks_mut(&mut req.binbuf);
        req.binbuf.iter_mut().for_each(|b| deckey.decrypt_mut(b));
        let binbuf = req.binbuf;

        let netmask = netmask
            .try_as_str()
            .with_context(|| format!("invalid str in netmask: {netmask:?}"))?;
        let nation = nation
            .try_as_str()
            .with_context(|| format!("invalid str in nation: {nation:?}"))?;
        let srchash = srchash
            .try_as_str()
            .with_context(|| format!("invalid str in srchash: {srchash:?}"))?;
        let binbuf = binbuf
            .try_as_str()
            .with_context(|| format!("invalid str in binbuf: {binbuf:?}"))?;
        debug!("{self}: netmask={netmask}, nation={nation}, srchash={srchash}, binbuf={binbuf}");

        let ip_local = Block::new("127.0.0.1");
        let mut enc_item: [Block; 16] = Block::arr_from_slice("Data/Item.scp");
        enc_item.iter_mut().for_each(|b| enckey.encrypt_mut(b));
        xor_blocks_mut(&mut enc_item);
        let mut enc_mobs: [Block; 16] = Block::arr_from_slice("Data/Mobs.scp");
        enc_mobs.iter_mut().for_each(|b| enckey.encrypt_mut(b));
        xor_blocks_mut(&mut enc_mobs);
        let mut enc_warp: [Block; 16] = Block::arr_from_slice("Data/Warp.scp");
        enc_warp.iter_mut().for_each(|b| enckey.encrypt_mut(b));
        xor_blocks_mut(&mut enc_warp);

        self.stream
            .send(&pkt_crypto::KeyAuthResponse {
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
            })
            .await
    }

    pub async fn handle_esym(&mut self, esym: pkt_crypto::ESYM) -> Result<()> {
        let (req, len) = bincode::decode_from_slice::<pkt_crypto::ESYMRequest, _>(
            esym.bytes.0.as_slice(),
            bincode::config::legacy(),
        )?;
        if len != esym.bytes.0.len() {
            bail!("{self}: Trailing data in ESYM packet {:#?}", esym);
        }

        debug!(
            "{self}: ESYM req nation = {}, srchash = {}",
            req.nation.0, req.srchash.0
        );

        let path = self
            .listener
            .args
            .common
            .resources_dir
            .join("resources/esym")
            .join(req.srchash.0)
            .with_extension("esym");
        let data = std::fs::read(&path).with_context(|| format!("cannot read {path:?}"))?;

        let r = pkt_crypto::ESYMResponse {
            unk1: 0x1,
            filesize: data.len() as u32,
            esym: BoundVec(data),
        };

        let mut bytes = BoundVec(vec![]);
        bincode::encode_into_std_write(r, &mut bytes.0, bincode::config::legacy())?;
        self.stream.send(&pkt_crypto::ESYM { bytes }).await
    }

    pub async fn handle(mut self) -> Result<()> {
        assert_eq!(self.stream.other_id, Service::GlobalMgrSvr { id: 0xfd });

        self.stream
            .send(&packet::pkt_crypto::ConnectAck {
                unk1: 0x0,
                unk2: [0x00, 0xff, 0x00, 0xff, 0x00, 0x00, 0x00, 0x00],
                unk3: 0xf6,
                unk4: 0xf6,
                unk5: 0x398ab300,
                unk6: 0x1f,
            })
            .await?;

        loop {
            let p = self.stream.recv().await?;
            match p {
                Packet::EncryptKey2Request(req) => self.handle_key_req(req).await?,
                Packet::KeyAuthRequest(req) => self.handle_auth_req(req).await?,
                Packet::ESYM(req) => self.handle_esym(req).await?,
                _ => {
                    trace!("{self}: Got packet: {p:?}");
                }
            }
        }
    }
}
