// SPDX-License-Identifier: MIT
// Copyright(c) 2024 Darek Stojaczyk

use std::ffi::CStr;
use std::net::Ipv4Addr;
use std::net::TcpStream;
use std::sync::Arc;
use std::time::Duration;

use anyhow::anyhow;
use anyhow::bail;
use anyhow::Result;
use async_proc::select;
use futures::FutureExt;
use log::error;
use log::warn;
use pkt_login::C2SCheckVersion;
use pkt_login::C2SVerifyLinks;
use pkt_login::{RequestAuthAccount, S2CVerifyLinks};
use rsa::pkcs1::EncodeRsaPublicKey;
use rsa::Oaep;
use rsa::{RsaPrivateKey, RsaPublicKey};

use packet::pkt_global::*;
use packet::*;
use sha1::Sha1;
use smol::Async;
use smol::Timer;

use crate::packet_stream::PacketStream;
use crate::packet_stream::RecvError;
use crate::registry::BorrowRef;
use crate::registry::Borrowable;

use super::Listener;

struct AuthenticatedUserContext {
    user_id: u32,
    login_idx: u32,
    fm_idx: u16,
    resident_num: u32,
    premium_service_type: u32,
    premium_expire_time: u32,
    /// [`VerifyLinks::unk4`]
    unk4: u32,
    unk5: u32,
    unk6: u32,
    unk7: u32,
}

pub struct UserConnHandler {
    pub listener: Arc<Listener>,
    pub stream: PacketStream<Async<TcpStream>>,
    pub conn_ref: Arc<BorrowRef<UserConnHandler, ()>>,
    pub user_idx: u16,
    pub auth_key: u32,
    ip: [u8; 4],
    #[allow(dead_code)]
    client_auth_key: u32,
    username: Option<String>,
    auth_ctx: Option<AuthenticatedUserContext>,
    pub force_terminate: bool,
}
crate::impl_borrowable!(
    UserConnHandler,
    RefData = (),
    borrow_ref = .conn_ref
);

impl std::fmt::Display for UserConnHandler {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "UserConnHandler")
    }
}

impl UserConnHandler {
    pub fn new(
        listener: Arc<Listener>,
        stream: PacketStream<Async<TcpStream>>,
        conn_ref: Arc<BorrowRef<Self, ()>>,
        ip: Ipv4Addr,
        client_auth_key: u32,
    ) -> Self {
        let user_idx = conn_ref.idx;
        let ip = ip.octets();
        let auth_key = rand::random::<u32>();

        Self {
            listener,
            stream,
            conn_ref,
            user_idx,
            auth_key,
            ip,
            client_auth_key,
            username: None,
            auth_ctx: None,
            force_terminate: false,
        }
    }

    pub async fn handle(&mut self) -> Result<()> {
        {
            let decoder = self.stream.decoder.as_ref().unwrap();
            let xor_seed_2 = decoder.xor_table_seed;
            let xor_key_idx = decoder.xor_key_idx;

            self.stream
                .send(&pkt_login::S2CConnect {
                    xor_seed_2,
                    auth_key: self.auth_key,
                    // ^ this will be also sent to WorldSvr
                    // and we might receive it eventually from GMS
                    user_idx: self.user_idx,
                    xor_key_idx,
                })
                .await
                .unwrap();
        }

        {
            let p = self.stream.recv().await.unwrap();
            let Packet::C2SCheckVersion(p) = p else {
                bail!("{self}: Expected C2SCheckVersion packet, got {p:?}");
            };
            self.handle_check_version(p).await?;
        }

        {
            // Either receive an C2SEnvironment and the rest of user auth packets,
            // or get kicked by GMS telling us we're already authenticated.
            // .lend_self() possibly multiple times to allow for spurious borrows
            let p = loop {
                if self.force_terminate {
                    return Ok(());
                }

                select! {
                    p = self.stream.recv().fuse() => {
                        let p = match p {
                            Ok(p) => p,
                            Err(RecvError::Terminated) => {
                                return Ok(());
                            }
                            Err(e) => {
                                bail!("{self}: Failed to recv a packet: {e}")
                            }
                        };
                        break p
                    }
                    _ = self.conn_ref.borrower.wait_to_lend().fuse() => {
                        self.lend_self().await;
                        if self.auth_ctx.is_some() {
                            return self.handle_authenticated().await;
                        }
                    }
                }
            };

            let Packet::C2SEnvironment(c) = p else {
                bail!("{self}: Expected C2SEnvironment packet, got {p:?}");
            };
            let name = CStr::from_bytes_until_nul(&*c.username)
                .ok()
                .and_then(|s| s.to_str().ok())
                .ok_or_else(|| anyhow!("{self}: Non-utf8 username"))?;

            self.username = Some(name.into());
            println!("{self}: username={}", name);

            self.stream
                .send(&pkt_login::S2CEnvironment {
                    unk1: Default::default(),
                    unk2: 0x14c8,
                    unk3: 0,
                })
                .await
                .unwrap();
        }

        let auth_resp = {
            let p = self.stream.recv().await.unwrap();
            let Packet::C2SRequestRsaPubKey(_) = p else {
                bail!("{self}: Expected C2SRequestRsaPubKey packet, got {p:?}");
            };

            let priv_key = RsaPrivateKey::new(&mut rand::thread_rng(), 2048).unwrap();
            let pub_key = RsaPublicKey::from(&priv_key);
            let pub_key = pub_key.to_pkcs1_der().unwrap().into_vec();

            self.stream
                .send(&pkt_login::S2CRsaPubKey {
                    unk1: 1,
                    pub_key_num_bytes: pub_key.len().try_into().unwrap(),
                    pub_key: pub_key.into(),
                })
                .await
                .unwrap();

            let p = self.stream.recv().await.unwrap();
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

            let listener = self.listener.clone();
            let conn_unique_idx = self.user_idx;
            self.lend_self_until(async {
                let mut globaldb = listener.globaldb.borrow().await.unwrap();

                globaldb
                    .stream
                    .send(&RequestAuthAccount {
                        server_id: 0x80,
                        channel_id: 1,
                        user_idx: conn_unique_idx,
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
                let listener = self.listener.clone();
                let world_servers = self
                    .lend_self_until(async {
                        let gms = listener.gms.borrow().await.unwrap();
                        gms.world_servers.clone()
                    })
                    .await;

                self.stream
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

                self.stream.send(&url_list).await.unwrap();
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

            self.stream.send(&s2c_auth).await.unwrap();
        }

        if auth_resp.result != 0x20 && auth_resp.result != 0x22 {
            // todo: figure out what else to do
            return Ok(());
        }
        self.auth_ctx = Some(AuthenticatedUserContext {
            user_id: auth_resp.user_id,
            login_idx: auth_resp.login_idx,
            fm_idx: auth_resp.db_user_idx,
            resident_num: auth_resp.resident_num,
            premium_service_type: auth_resp.premium_service_type,
            premium_expire_time: auth_resp.premium_expire_time,
            unk4: auth_resp.unk21,
            unk5: auth_resp.unk22,
            unk6: auth_resp.unk23,
            unk7: auth_resp.unk24,
        });
        if auth_resp.result == 0x20 {
            self.listener
                .set_authenticated_connection_idx(auth_resp.user_id, self.user_idx)
                .await;
        }
        if self.force_terminate {
            // another connection just pushed us out
            return Ok(());
        }

        let sys_msg = pkt_global::SystemMessage {
            unk2: auth_resp.user_id,
            msg_type: if auth_resp.result == 0x20 { 9 } else { 1 },
            ..Default::default()
        };
        let listener = self.listener.clone();
        self.lend_self_until(async {
            let mut gms = listener.gms.borrow().await.unwrap();
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

        match auth_resp.result {
            0x20 => {
                self.stream
                    .send(&pkt_login::S2CSystemMessage {
                        msg_type: 9,
                        data1: 0,
                        data2: 0,
                    })
                    .await
                    .unwrap();
            }
            0x22 => {
                let p = self.stream.recv().await.unwrap();
                let Packet::C2SForceLogin(p) = p else {
                    bail!("{self}: Expected C2SForceLogin packet, got {p:?}");
                };

                if p.do_disconnect == 0 {
                    return Ok(());
                }

                let listener = self.listener.clone();
                let conn_idx = self.user_idx;
                let gms_pkt = pkt_global::MultipleLoginDisconnectRequest {
                    user_id: auth_resp.user_id,
                    login_idx: auth_resp.login_idx,
                };
                self.lend_self_until(async {
                    listener
                        .set_authenticated_connection_idx(gms_pkt.user_id, conn_idx)
                        .await;

                    let mut gms = listener.gms.borrow().await.unwrap();
                    gms.stream.send(&gms_pkt).await.unwrap();
                })
                .await;

                self.stream
                    .send(&pkt_login::S2CForceLogin { unk1: 1 })
                    .await
                    .unwrap();
            }
            _ => unreachable!(),
        }

        // Waiting for channel selection now,
        // then we expect C2SCheckVersion followed by C2SVerifyLinks
        self.handle_authenticated().await
    }

    async fn handle_check_version(&mut self, p: C2SCheckVersion) -> Result<()> {
        if p.client_version != 374 {
            bail!("{self}: Invalid client version {}", p.client_version);
        }

        self.stream
            .send(&pkt_login::S2CCheckVersion {
                server_version: p.client_version,
                server_magic_key: 0x0059077c,
                unk2: 0,
                unk3: 0,
            })
            .await
    }

    async fn handle_verify_links(&mut self, p: C2SVerifyLinks) -> Result<()> {
        let auth_ctx = self.auth_ctx.as_ref().unwrap();
        let verify_links = VerifyLinks {
            droute_hdr: DuplexRouteHeader {
                route_hdr: RouteHeader {
                    origin_main_cmd: 0x17,
                    server_id: p.server_id,
                    channel_id: p.channel_id,
                    world_id: 0,
                    process_id: 0,
                },
                unique_idx: self.user_idx as u32,
                to_idx: p.unique_idx,
                fm_idx: auth_ctx.fm_idx,
                resp_server_id: 0x80,
                resp_channel_id: 1,
                resp_world_id: 0,
            },
            resp_process_id: 0,
            auth_key: p.unk1,
            user_id: auth_ctx.user_id,
            login_idx: auth_ctx.login_idx,
            user_ip: self.ip,
            resident_num: auth_ctx.resident_num,
            unk2: 0,
            unk3: 0,
            premium_service_type: auth_ctx.premium_service_type,
            premium_expire_time: auth_ctx.premium_expire_time,
            unk4: auth_ctx.unk4,
            unk5: auth_ctx.unk5,
            unk6: auth_ctx.unk6,
            unk7: auth_ctx.unk7,
            unk8: [0; 3],
            unk9: 1, // ?? seems to be always 1
            unk10: [0; 4],
            unk11: 0x665, // ?? login svr connecting time?
            unk12: Arr::default(),
            username: self.username.as_ref().unwrap().as_bytes().into(),
        };

        let listener = self.listener.clone();
        self.lend_self_until(async {
            let mut gms = listener.gms.borrow().await.unwrap();
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

        // We passed the handle to WorldSvr, and we no longer maintain
        // the connection
        self.auth_ctx = None;

        self.stream
            .send(&S2CVerifyLinks {
                unk: vec![1, 1, 1].into(),
            })
            .await
            .unwrap();
        Ok(())
    }

    pub fn set_authenticated(&mut self, p: VerifyLinks) {
        let Some(username) = CStr::from_bytes_until_nul(&*p.username)
            .ok()
            .and_then(|s| s.to_str().ok())
        else {
            error!(
                "{self}: Received malformed username from GMS for user ID {}",
                p.user_id
            );
            return;
        };

        self.username = Some(username.to_string());
        self.auth_ctx = Some(AuthenticatedUserContext {
            user_id: p.user_id,
            login_idx: p.login_idx,
            fm_idx: p.droute_hdr.to_idx,
            resident_num: p.resident_num,
            premium_service_type: p.premium_service_type,
            premium_expire_time: p.premium_expire_time,
            unk4: p.unk4,
            unk5: p.unk5,
            unk6: p.unk6,
            unk7: p.unk7,
        });
    }

    async fn handle_authenticated(&mut self) -> Result<()> {
        let _ = self.auth_ctx.as_ref().unwrap();
        loop {
            if self.force_terminate {
                return Ok(());
            }

            select! {
                p = self.stream.recv().fuse() => {
                    let p = match p {
                        Ok(p) => p,
                        Err(RecvError::Terminated) => {
                            return Ok(());
                        }
                        Err(e) => {
                            bail!("{self}: Failed to recv a packet: {e}")
                        }
                    };
                    match p {
                        Packet::C2SCheckVersion(p) => {
                            self.handle_check_version(p).await?;
                        }
                        Packet::C2SVerifyLinks(p) => {
                            self.handle_verify_links(p).await?;
                        }
                        _ => {
                            warn!("{self}: Got unexpected packet: {p:?}");
                        }
                    }
                }
                _ = self.conn_ref.borrower.wait_to_lend().fuse() => {
                    self.lend_self().await;
                }
            }
        }
    }

    pub async fn handle_disconnect(&self) -> Result<()> {
        let Some(auth_ctx) = self.auth_ctx.as_ref() else {
            return Ok(());
        };

        self.listener
            .unset_authenticated_connection_idx(auth_ctx.user_id, self.user_idx);

        let pkt = pkt_global::SetLoginInstance {
            user_id: auth_ctx.user_id,
            login_idx: auth_ctx.login_idx,
            unk3: 0,
            unk4: Arr::default(),
            unk6: Arr::default(),
            login: 0,
            unk7: 0x14,
            unk8: Default::default(),
            unk9: Arr::default(),
        };

        let mut gms = self.listener.gms.borrow().await.unwrap();
        gms.stream.send(&pkt).await
    }
}
