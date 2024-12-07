// SPDX-License-Identifier: MIT
// Copyright(c) 2024 Darek Stojaczyk

use std::sync::atomic::{AtomicUsize, Ordering};

use anyhow::anyhow;
use anyhow::bail;
use anyhow::Result;
use async_proc::select;
use futures::FutureExt;
use log::warn;
use pkt_login::RequestAuthAccount;
use rsa::pkcs1::DecodeRsaPrivateKey;
use rsa::pkcs1::EncodeRsaPublicKey;
use rsa::Oaep;
use rsa::{RsaPrivateKey, RsaPublicKey};

use packet::pkt_global::*;
use packet::*;
use sha1::Sha1;

use crate::login::db::GlobalDbHandler;
use crate::registry::Entry;

use super::Connection;

pub struct UserConnHandler {
    pub conn: Connection,
    rsa_priv: RsaPrivateKey,
    auth_key: Option<u32>,
    username: Option<String>,
}
crate::impl_registry_entry!(
    UserConnHandler,
    RefData = u32,
    data = .conn,
    borrow_ref = .conn.conn_ref
);

impl std::fmt::Display for UserConnHandler {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.conn)
    }
}

impl UserConnHandler {
    pub fn new(conn: Connection) -> Self {
        let priv_key_path = conn
            .listener
            .args
            .common
            .resources_dir
            .join("resources/login_rsa.pem");
        let rsa_priv = RsaPrivateKey::read_pkcs1_pem_file(priv_key_path).unwrap();

        Self {
            conn,
            rsa_priv,
            auth_key: None,
            username: None,
        }
    }

    pub async fn handle(&mut self) -> Result<()> {
        {
            let p = self.conn.stream.recv().await.unwrap();
            let Packet::C2SConnect(c) = p else {
                bail!("{self}: Expected C2SConnect packet, got {p:?}");
            };
            self.auth_key = Some(c.auth_key);
        }

        {
            let decoder = self.conn.stream.decoder.as_ref().unwrap();
            let xor_seed_2 = decoder.xor_table_seed;
            let xor_key_idx = decoder.xor_key_idx;

            self.conn
                .stream
                .send(&pkt_login::S2CConnect {
                    xor_seed_2,
                    auth_key: 0x4663,
                    user_idx: 0,
                    xor_key_idx,
                })
                .await
                .unwrap();
        }

        {
            let p = self.conn.stream.recv().await.unwrap();
            let Packet::C2SCheckVersion(c) = p else {
                bail!("{self}: Expected C2SCheckVersion packet, got {p:?}");
            };
            if c.client_version != 374 {
                bail!("{self}: Invalid client version {}", c.client_version);
            }

            self.conn
                .stream
                .send(&pkt_login::S2CCheckVersion {
                    server_version: c.client_version,
                    server_magic_key: 0x0059077c,
                    unk2: 0,
                    unk3: 0,
                })
                .await
                .unwrap();
        }

        {
            let p = self.conn.stream.recv().await.unwrap();
            let Packet::C2SEnvironment(c) = p else {
                bail!("{self}: Expected C2SEnvironment packet, got {p:?}");
            };
            let name = std::str::from_utf8(&*c.username)
                .map_err(|_| anyhow!("{self}: Non-utf8 username"))?;
            self.username = Some(name.into());
            println!("{self}: username={}", name);

            self.conn
                .stream
                .send(&pkt_login::S2CEnvironment {
                    unk1: Default::default(),
                    unk2: 0x14c8,
                    unk3: 0,
                })
                .await
                .unwrap();
        }

        {
            let p = self.conn.stream.recv().await.unwrap();
            let Packet::C2SRequestRsaPubKey(_) = p else {
                bail!("{self}: Expected C2SRequestRsaPubKey packet, got {p:?}");
            };

            let pub_key = RsaPublicKey::from(&self.rsa_priv);
            let pub_key = pub_key.to_pkcs1_der().unwrap().into_vec();
            //println!("pub key (len={len}) = {:x?}", pub_key);

            self.conn
                .stream
                .send(&pkt_login::S2CRsaPubKey {
                    unk1: 1,
                    pub_key_num_bytes: pub_key.len().try_into().unwrap(),
                    pub_key: pub_key.into(),
                })
                .await
                .unwrap();

            let p = self.conn.stream.recv().await.unwrap();
            let Packet::C2SAuthAccount(a) = p else {
                bail!("{self}: Expected C2SRequestRsaPubKey packet, got {p:?}");
            };

            let decrypted = self
                .rsa_priv
                .decrypt(Oaep::new::<Sha1>(), &*a.encoded_pass)
                .map_err(|e| anyhow!("Can't decode password: {e:?}"))?;
            let username = std::str::from_utf8(&decrypted[0..33])
                .map_err(|_| anyhow!("Non-utf8 username (2)"))?;
            let password = std::str::from_utf8(&decrypted[33..])
                .map_err(|_| anyhow!("Non-utf8 password (2)"))?;
            let saved_username = self.username.as_ref().unwrap();
            if username != saved_username {
                bail!("Received auth packet for another username (expected={saved_username}, got={username}");
            }

            println!("username = {username}; password = {password}");

            let listener = self.conn.listener.clone();
            let auth_resp = self
                .lend_self_until(async {
                    let globaldb = listener.globaldb.get().unwrap();
                    let mut globaldb = globaldb.borrow::<GlobalDbHandler>().await.unwrap();

                    globaldb
                        .stream
                        .send(&RequestAuthAccount {
                            server_id: 0x80,
                            channel_id: 1,
                            user_idx: 0, // fixme
                            ip: [10, 2, 0, 143],
                            username: username.as_bytes().into(),
                            password: password.as_bytes().into(),
                            zero: 0,
                        })
                        .await
                        .unwrap();

                    let p = globaldb.stream.recv().await.unwrap();
                    let Packet::ResponseAuthAccount(a) = p else {
                        bail!(
                            "{}: Expected ResponseAuthAccount packet, got {p:?}",
                            &*globaldb
                        );
                    };

                    Ok(a)
                })
                .await?;

            // send server list (packet 121) to the client
            // and packet 128
            // and packet 103, which contains data from globaldb

            // send 0x15 to gms: unk2: 1, msg_type: 9
            // wait for 0x16
            // (a 0x16 will be also sent to WorldSvr)

            // send 120 (system message) to the user

            // occasionally send 0x34 to gms - server_id: 0x80, channel_id: 1, rest zeroes
            // wait for 0x35 with server list

            // client may send another 122 (check version)

            // wait for packet 102 - verify links
        }

        loop {
            select! {
                p = self.conn.stream.recv().fuse() => {
                    let p = p.map_err(|e| {
                        anyhow!("{self}: Failed to recv a packet: {e}")
                    })?;
                    match p {
                        Packet::ProfilePathRequest(p) => {
                            self.handle_profile_path(p).await.unwrap();
                        }
                        Packet::SetLoginInstance(_) => {
                            // there's nothing to do
                        }
                        _ => {
                            warn!("{self}: Got unexpected packet: {p:?}");
                        }
                    }
                }
                _ = self.conn.conn_ref.borrower.wait_to_lend().fuse() => {
                    self.lend_self().await;
                }
            }
        }
    }

    async fn handle_profile_path(&mut self, p: ProfilePathRequest) -> Result<()> {
        static COUNTER: AtomicUsize = AtomicUsize::new(0);
        assert_eq!(p.unk1, 0);
        self.conn
            .stream
            .send(&ProfilePathResponse {
                unk1: 5 + COUNTER.fetch_add(1, Ordering::Relaxed) as u32, // TODO: test with more than 2 channels
                scp_id1: 4,
                scp_path1: Arr::from("Data/Item.scp".as_bytes()),
                scp_id2: 2,
                scp_path2: Arr::from("Data/Mobs.scp".as_bytes()),
                scp_id3: 1,
                scp_path3: Arr::from("Data/Warp.scp".as_bytes()),
            })
            .await
    }
}
