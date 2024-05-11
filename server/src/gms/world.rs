// SPDX-License-Identifier: MIT
// Copyright(c) 2024 Darek Stojaczyk

use std::cell::OnceCell;
use std::pin::pin;
use std::sync::atomic::{AtomicUsize, Ordering};

use anyhow::anyhow;
use anyhow::{bail, Result};
use futures::{FutureExt, StreamExt};
use log::trace;
use packet::pkt_common::*;
use packet::pkt_global::*;
use packet::*;

use crate::gms::login::GlobalLoginHandler;

use super::Connection;

pub struct GlobalWorldHandler {
    pub conn: Box<Connection>,
    ip_port: OnceCell<([u8; 4], u16)>,
    state: u32,
}

impl std::fmt::Display for GlobalWorldHandler {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.conn)
    }
}

impl GlobalWorldHandler {
    pub fn new(conn: Box<Connection>) -> Self {
        Self {
            conn,
            state: 5, // unknown
            ip_port: Default::default(),
        }
    }

    pub async fn handle(&mut self) -> Result<()> {
        let conn_ref = self.conn.conn_ref.as_ref().unwrap().clone();
        let service = &conn_ref.service;

        #[rustfmt::skip]
        self.conn.stream
            .send(&Payload::ConnectAck(ConnectAck {
                bytes: BoundVec(vec![
                    0x50, 0, 0, 0, 0, 0, 0, 0,
                    ServiceID::GlobalMgrSvr as u8, 0, 0, 0, 0,
                    service.world_id, service.channel_id, 0, 0, 0, 0, 0x1,
                ]),
            }))
            .await.unwrap();

        self.conn
            .stream
            .send(&Payload::ChangeChannelType(ChangeChannelType {
                server_id: service.world_id,
                channel_id: service.channel_id,
                state: self.state,
            }))
            .await.unwrap();

        let cur_timestamp = std::time::UNIX_EPOCH.elapsed().unwrap().as_secs() as u32;
        let next_daily_reset_time = cur_timestamp.next_multiple_of(24 * 3600) - 24 * 3600 + 4 * 3600; /* FIXME: 4h offset is a temporary hack */
        self.conn
            .stream
            .send(&Payload::DailyQuestResetTime(DailyQuestResetTime {
                next_daily_reset_time,
                unk2: 0,
            }))
            .await.unwrap();

        self.conn
            .stream
            .send(&Payload::AdditionalDungeonInstanceCount(
                AdditionalDungeonInstanceCount { unk1: 0, unk2: 0 },
            ))
            .await.unwrap();

        loop {
            futures::select! {
                p = self.conn.stream.recv().fuse() => {
                    let p = p.map_err(|e| {
                        anyhow!("{self}: Failed to recv a packet: {e}")
                    })?;
                    match p {
                        Payload::ProfilePathRequest(p) => {
                            self.handle_profile_path(p).await.unwrap();
                        }
                        Payload::NotifyUserCount(p) => {
                            self.handle_user_count_update(p).await.unwrap();
                        }
                        Payload::ChannelOptionSync(p) => {
                            self.handle_channel_option_sync(p).await.unwrap();
                        }
                        _ => {
                            trace!("{self}: Got packet: {p:?}");
                        }
                    }
                }
                _ = conn_ref.borrower.wait_to_lend().fuse() => {
                    conn_ref.borrower.lend(&mut self.conn).unwrap().await
                }
            }
        }
    }

    async fn handle_profile_path(&mut self, p: ProfilePathRequest) -> Result<()> {
        static COUNTER: AtomicUsize = AtomicUsize::new(0);
        assert_eq!(p.unk1, 0);
        self.conn
            .stream
            .send(&Payload::ProfilePathResponse(ProfilePathResponse {
                unk1: 6 + COUNTER.fetch_add(1, Ordering::Relaxed) as u32, // TODO: test with more than 2 channels
                scp_id1: 4,
                scp_path1: Arr::from("Data/Item.scp".as_bytes()),
                scp_id2: 2,
                scp_path2: Arr::from("Data/Mobs.scp".as_bytes()),
                scp_id3: 1,
                scp_path3: Arr::from("Data/Warp.scp".as_bytes()),
            }))
            .await
    }

    async fn handle_user_count_update(&mut self, p: NotifyUserCount) -> Result<()> {
        self.conn
            .stream
            .send(&Payload::ChangeServerState(ChangeServerState {
                server_id: self.conn.service().world_id,
                channel_id: self.conn.service().channel_id,
                state: ServerStateEnum::Disabled,
            }))
            .await?;

        let ip_port = (p.ip, p.port);
        let prev_ip_port = self.ip_port.get_or_init(|| ip_port);
        if prev_ip_port != &ip_port {
            bail!(format!(
                "Received NotifyUserCount with a different IP/Port. \
                 Previous={prev_ip_port:?}, New={ip_port:?}",
            ));
        }

        // We need to send out updates to all world servers and the login
        // server. We'll let GlobalLoginHandler do that.
        // In the orignal GMS there should be at most one LoginSvr,
        // but here it doesn't hurt to support more (untested though)
        while let Some(mut handler) = //
            pin!(self.conn.iter_handlers::<GlobalLoginHandler>())
                .next()
                .await
        {
            handler.notify_user_counts = true;
        }

        Ok(())
    }

    pub fn group_node(&self) -> Option<GroupNode> {
        self.ip_port.get().map(|ip_port| GroupNode {
            id: self.conn.service().channel_id,
            unk0: 0,
            unk1: 0,
            unk2: 0,
            unk3: 0,
            unk4: 0,
            unk5: 0,
            unk6: 0,
            unk7: 0,
            unk8: 0,
            ip: ip_port.0,
            port: ip_port.1,
            state: self.state,
        })
    }

    pub async fn handle_channel_option_sync(&mut self, p: ChannelOptionSync) -> Result<()> {
        trace!("{self}: {p:?}");
        Ok(())
    }
}
