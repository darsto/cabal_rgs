// SPDX-License-Identifier: MIT
// Copyright(c) 2024 Darek Stojaczyk

use std::ffi::CStr;
use std::net::IpAddr;
use std::net::Ipv4Addr;
use std::sync::atomic::Ordering;
use std::time::Duration;

use anyhow::bail;
use anyhow::Result;
use anyhow::{anyhow, Context};
use async_proc::select;
use futures::FutureExt;
use log::warn;
use pkt_login::C2SVerifyLinks;
use pkt_login::ResponseAuthAccount;
use pkt_login::{RequestAuthAccount, S2CVerifyLinks};
use rsa::pkcs1::EncodeRsaPublicKey;
use rsa::Oaep;
use rsa::{RsaPrivateKey, RsaPublicKey};

use packet::pkt_global::*;
use packet::*;
use sha1::Sha1;
use smol::Timer;

use crate::login::db::GlobalDbHandler;
use crate::login::gms::GmsHandler;
use crate::registry::Entry;

use super::Connection;

pub struct UserConnHandler {
    pub conn: Connection,
    ip: [u8; 4],
    auth_key: u32,
    username: Option<String>,
    db_auth_resp: Option<ResponseAuthAccount>,
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
    pub fn new(conn: Connection, ip: Ipv4Addr, auth_key: u32) -> Self {
        let ip = ip.octets();

        Self {
            conn,
            ip,
            auth_key,
            username: None,
            db_auth_resp: None,
        }
    }

    pub async fn handle(&mut self) -> Result<()> {
        {
            let decoder = self.conn.stream.decoder.as_ref().unwrap();
            let xor_seed_2 = decoder.xor_table_seed;
            let xor_key_idx = decoder.xor_key_idx;

            self.conn
                .stream
                .send(&pkt_login::S2CConnect {
                    xor_seed_2,
                    auth_key: 0x4663, // rand
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
            // todo: also lend self -> we might get VerifyLinks on GMS connection
            let Packet::C2SEnvironment(c) = p else {
                bail!("{self}: Expected C2SEnvironment packet, got {p:?}");
            };
            let name = CStr::from_bytes_until_nul(&*c.username)
                .ok()
                .and_then(|s| s.to_str().ok())
                .ok_or_else(|| anyhow!("{self}: Non-utf8 username"))?;

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

        let auth_resp = {
            let p = self.conn.stream.recv().await.unwrap();
            let Packet::C2SRequestRsaPubKey(_) = p else {
                bail!("{self}: Expected C2SRequestRsaPubKey packet, got {p:?}");
            };

            let priv_key = RsaPrivateKey::new(&mut rand::thread_rng(), 2048).unwrap();
            let pub_key = RsaPublicKey::from(&priv_key);
            let pub_key = pub_key.to_pkcs1_der().unwrap().into_vec();

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

            let decrypted = priv_key
                .decrypt(Oaep::new::<Sha1>(), &*a.encoded_pass)
                .map_err(|e| anyhow!("{self}: Can't decode password: {e:?}"))?;
            let username = CStr::from_bytes_until_nul(&decrypted[0..33])
                .ok()
                .and_then(|s| s.to_str().ok())
                .ok_or_else(|| anyhow!("{self}: Non-utf8 username (2)"))?;
            let password = CStr::from_bytes_until_nul(&decrypted[33..])
                .ok()
                .and_then(|s| s.to_str().ok())
                .ok_or_else(|| anyhow!("{self}: Non-utf8 password (2)"))?;
            let saved_username = self.username.as_ref().unwrap();
            if username != saved_username {
                println!("saved_len={}, len={}", saved_username.len(), username.len());
                println!(
                    "saved={:?}, cur={:?}",
                    saved_username.as_bytes(),
                    username.as_bytes()
                );
                bail!("{self}: Received auth packet for another username (expected={saved_username}, got={username})");
            }

            println!("username = {username}; password = {password}");

            let listener = self.conn.listener.clone();
            self.lend_self_until(async {
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
            .await?
        };

        {
            if auth_resp.result == 0x20 {
                // todo enum
                let listener = self.conn.listener.clone();
                let world_servers = self
                    .lend_self_until(async {
                        let gms = listener.gms.get().unwrap();
                        let gms = gms.borrow::<GmsHandler>().await.unwrap();

                        gms.world_servers.clone()
                    })
                    .await;

                self.conn
                    .stream
                    .send(&pkt_login::S2CServerList {
                        servers: world_servers.into(),
                    })
                    .await
                    .unwrap();

                let mut url_list = pkt_login::S2CUrlList::default();

                url_list.urls.push("http://localhost?v1=".into());
                url_list.urls.push("".into());
                url_list.urls.push("http://localhost?v2=".into());
                url_list.urls.push("http://localhost?v3=".into());
                url_list.urls.push("".into());

                let mut buf = Vec::with_capacity(512);
                let len = url_list.serialize_no_hdr(&mut buf).unwrap();
                url_list.urls_num_bytes2 = len.try_into().unwrap();
                url_list.urls_num_bytes = url_list.urls_num_bytes2.checked_sub(2).unwrap();

                self.conn.stream.send(&url_list).await.unwrap();
            }

            let s2c_auth = if auth_resp.result == 0x20 {
                pkt_login::S2CAuthAccount {
                    status: auth_resp.result,   // ??
                    user_id: auth_resp.user_id, // ??
                    unk2: 1,
                    unk3: 0x2f,
                    char_count: (auth_resp.characters.len() / 2).try_into().unwrap(),
                    unk4: 0,
                    premium_service_type: auth_resp.premium_service_type,
                    premium_expire_time: auth_resp.premium_expire_time,
                    unk7: 0,
                    sub_password_exists: 0,
                    language: 0,
                    unkkey: auth_resp.unkkey.clone(),
                    characters: auth_resp.characters.clone(),
                }
            } else {
                pkt_login::S2CAuthAccount {
                    status: auth_resp.result,   // ??
                    user_id: auth_resp.user_id, // ??
                    characters: auth_resp.characters.clone(),
                    ..Default::default()
                }
            };

            self.conn.stream.send(&s2c_auth).await.unwrap();
        }

        if auth_resp.result != 0x20 && auth_resp.result != 0x22 {
            // todo: figure out what else to do
            return Ok(());
        }
        let auth_resp = self.db_auth_resp.insert(auth_resp);

        let sys_msg = pkt_global::SystemMessage {
            unk2: auth_resp.user_id,
            msg_type: if auth_resp.result == 0x20 { 9 } else { 1 },
            ..Default::default()
        };
        let listener = self.conn.listener.clone();
        self.lend_self_until(async {
            let gms = listener.gms.get().unwrap();
            let mut gms = gms.borrow::<GmsHandler>().await.unwrap();

            gms.stream.send(&sys_msg).await.unwrap();

            let mut timeout = Timer::after(Duration::from_secs(5)).fuse();
            loop {
                select! {
                    _ = timeout => {
                        bail!("{}: Timed out waiting for SystemMessageForwarded", &*gms);
                    },
                    p = gms.stream.recv().fuse() => {
                        let p = p.map_err(|e| {
                            anyhow!("{}: Failed to recv a packet: {e}", &*gms)
                        })?;
                        if let Packet::SystemMessageForwarded(_) = p {
                            return Ok(());
                        } else {
                            gms.handle_packet(p).await?;
                        }
                    }
                }
            }
        })
        .await?;

        let auth_resp = self.db_auth_resp.as_ref().unwrap();
        match auth_resp.result {
            0x20 => {
                self.conn
                    .stream
                    .send(&pkt_login::S2CSystemMessage {
                        msg_type: 9,
                        data1: 0,
                        data2: 0,
                    })
                    .await
                    .unwrap();
            }
            0x22 => {
                let p = self.conn.stream.recv().await.unwrap();
                let Packet::C2SForceLogin(p) = p else {
                    bail!("{self}: Expected C2SForceLogin packet, got {p:?}");
                };

                if p.do_disconnect == 0 {
                    return Ok(());
                }

                let listener = self.conn.listener.clone();
                let gms_pkt = pkt_global::MultipleLoginDisconnectRequest {
                    unk1: auth_resp.user_id,
                    unk2: auth_resp.unk26,
                };
                self.lend_self_until(async {
                    let gms = listener.gms.get().unwrap();
                    let mut gms = gms.borrow::<GmsHandler>().await.unwrap();

                    gms.stream.send(&gms_pkt).await.unwrap();
                })
                .await;

                self.conn
                    .stream
                    .send(&pkt_login::S2CForceLogin { unk1: 1 })
                    .await
                    .unwrap();
            }
            _ => unreachable!(),
        }

        // waiting for channel selection now
        {
            let p = self.conn.stream.recv().await.unwrap();
            let Packet::C2SCheckVersion(p) = p else {
                bail!("{self}: Expected C2SCheckVersion packet, got {p:?}");
            };
            if p.client_version != 374 {
                bail!("{self}: Invalid client version {}", p.client_version);
            }

            self.conn
                .stream
                .send(&pkt_login::S2CCheckVersion {
                    server_version: p.client_version,
                    server_magic_key: 0x0059077c,
                    unk2: 0,
                    unk3: 0,
                })
                .await
                .unwrap();
        }

        {
            let p = self.conn.stream.recv().await.unwrap();
            let Packet::C2SVerifyLinks(p) = p else {
                bail!("{self}: Expected C2SVerifyLinks packet, got {p:?}");
            };

            self.verify_links(p).await?;
        }

        // then we'll get C2SCheckVersion, followed by C2SVerifyLinks.
        // Then we'll get C2SVerifyLinks whenever the user clicks "Change Server"
        loop {
            select! {
                p = self.conn.stream.recv().fuse() => {
                    let p = p.map_err(|e| {
                        anyhow!("{self}: Failed to recv a packet: {e}")
                    })?;
                    match p {
                        _ => {
                            warn!("{self}: Got unexpected packet: {p:?}");
                        }
                    }
                }
                _ = self.conn.conn_ref.borrower.wait_to_lend().fuse() => {
                    self.lend_self().await;
                }
            }
            let p = self.conn.stream.recv().await.unwrap();

            warn!("{self}: Got unexpected packet: {p:?}");
        }
    }

    async fn verify_links(&mut self, p: C2SVerifyLinks) -> Result<()> {
        let listener = self.conn.listener.clone();
        let auth_resp = self.db_auth_resp.as_ref().unwrap();
        let verify_links = VerifyLinks {
            droute_hdr: DuplexRouteHeader {
                route_hdr: RouteHeader {
                    origin_main_cmd: 0x17,
                    server_id: p.server_id,
                    group_id: p.group_id,
                    world_id: 0,
                    process_id: 0,
                },
                unk1: self
                    .conn
                    .listener
                    .verify_links_unique_idx
                    .fetch_add(1, Ordering::Relaxed), // increasing?
                unk2: 0,
                unk3: auth_resp.user_idx,
                resp_server_id: 128,
                resp_group_id: 1,
                resp_world_id: 0,
                resp_process_id: 0,
            },
            auth_key: p.unk1,
            user_id: auth_resp.user_id,
            unk_user_id: auth_resp.unk26,
            user_ip: self.ip,
            resident_num: auth_resp.resident_num,
            unk2: 0,
            unk3: 0,
            premium_service_type: auth_resp.premium_service_type,
            premium_expire_time: auth_resp.premium_expire_time,
            unk4: auth_resp.unk21,
            unk5: auth_resp.unk22,
            unk6: auth_resp.unk23,
            unk7: auth_resp.unk24,
            unk8: [0; 3],
            unk9: 1, // ?? seems to be always 1
            unk10: [0; 4],
            unk11: 0x665, // ?? login svr connecting time?
            unk12: Arr::default(),
            username: self.username.as_ref().unwrap().as_bytes().into(),
        };

        self.lend_self_until(async {
            let gms = listener.gms.get().unwrap();
            let mut gms = gms.borrow::<GmsHandler>().await.unwrap();

            gms.stream
                .send(&CustomIdPacket {
                    id: RoutePacket::ID,
                    data: verify_links,
                })
                .await
                .unwrap();

            let mut timeout = Timer::after(Duration::from_secs(5)).fuse();
            loop {
                select! {
                    _ = timeout => {
                        bail!("{}: Timed out waiting for VerifyLinksResult", &*gms);
                    },
                    p = gms.stream.recv().fuse() => {
                        let p = p.map_err(|e| {
                            anyhow!("{}: Failed to recv a packet: {e}", &*gms)
                        })?;
                        if let Packet::VerifyLinksResult(_) = p {
                            return Ok(());
                        } else {
                            gms.handle_packet(p).await?;
                        }
                    }
                }
            }
        })
        .await?;

        self.conn
            .stream
            .send(&S2CVerifyLinks {
                unk: vec![1, 1, 1].into(),
            })
            .await
            .unwrap();
        Ok(())
    }

    pub async fn send_diconnect(&self) -> Result<()> {
        let Some(auth_resp) = self.db_auth_resp.as_ref() else {
            return Ok(());
        };

        let pkt = pkt_global::SetLoginInstance {
            unk1: auth_resp.user_id,
            unk2: auth_resp.unk26,
            unk3: 0,
            unk4: Arr::default(),
            unk6: Arr::default(),
            unk7: 0x14,
            unk8: Default::default(),
            unk9: Arr::default(),
        };

        let gms = self.conn.listener.gms.get().unwrap();
        let mut gms = gms.borrow::<GmsHandler>().await.unwrap();

        gms.stream.send(&pkt).await
    }
}
