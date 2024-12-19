// SPDX-License-Identifier: MIT
// Copyright(c) 2023 Darek Stojaczyk

use packet_proc::packet_list;

use crate::pkt_common::*;
use crate::pkt_crypto::*;
use crate::pkt_event::*;
use crate::pkt_global::*;
use crate::pkt_login::*;
use crate::pkt_party::*;

use crate::Header;
use crate::Payload;
use crate::PayloadDeserializeError;

#[packet_list]
pub enum Packet {
    // Common
    Connect,
    #[attr(path = crate::pkt_common::ConnectAck)]
    ConnectAck,

    // Event Manager
    Keepalive,

    // Crypto Manager
    EncryptKey2Request,
    EncryptKey2Response,
    KeyAuthRequest,
    KeyAuthResponse,
    ESYM,

    // Global Manager
    RegisterChatSvr,
    ChangeServerState,
    ChangeChannelType,
    ClientVersionNotify,
    DailyQuestResetTime,
    AdditionalDungeonInstanceCount,
    SystemMessage,
    SystemMessageForwarded,
    NotifyUserCount,
    ServerState,
    ProfilePathRequest,
    ProfilePathResponse,
    RoutePacket,
    ShutdownStatsSet,
    ChannelOptionSync,
    VerifyLinks,
    VerifyLinksResult,
    SubPasswordCheckRequest,
    SubPasswordCheckResponse,
    SetLoginInstance,
    MultipleLoginDisconnectRequest,
    MultipleLoginDisconnectResponse,

    // Login Manager
    C2SConnect,
    C2SCheckVersion,
    C2SEnvironment,
    C2SRequestRsaPubKey,
    C2SAuthAccount,
    C2SVerifyLinks,
    C2SForceLogin,

    // Login Manager
    RequestClientVersion,
    ResponseAuthAccount,

    // Party Manager
    ClientConnect,
    PartyInvite,
    PartyInviteAck,
    PartyInviteResult,
    PartyInviteCancel,
    PartyLeave,
    PartyKickout,
    PartyLeaderChange,
    PartyAuthChange,
    PartyLootingChange,
    ClientDisconnect,
    PartyMemberDungeonCheck,
    PartyMessage,
    PartyMemberStatsChange,
    IPCInstantWarAutoParty,
    PartySearchRegist,
    PartySearchRegistCancel,
    PartySearchList,
    PartySearchChange,
    PartySearchRegistAutoCancel,
    OathInfoRegist,
    AssistantSummon,
    AssistantSummonCancel,
    SavedSingleDungeonSet,
    SavedSingleDungeonClear,
    // Party Manager, sent only
    PartyInviteResultAck,
    PartyStats,
    PartyKickoutAck,
    PartyLeaderChangeAck,
    PartyAuthChangeAck,
    PartyLootingChangeAck,
    PartyClear,
    PartyLeaveAck,
}

impl Packet {
    pub fn serialize(
        &self,
        dst: &mut Vec<u8>,
        serialize_checksum: bool,
    ) -> Result<usize, crate::PayloadSerializeError> {
        let hdr_len = Header::num_bytes(serialize_checksum);
        // reserve size for header
        dst.resize(hdr_len, 0u8);
        // serialize into the rest of vector
        let payload_len = self.serialize_no_hdr(dst)?;
        let len: u16 = payload_len
            .checked_add(hdr_len)
            .unwrap()
            .try_into()
            .map_err(|_| crate::PayloadSerializeError::PayloadTooLong {
                payload_len: payload_len as usize,
            })?;
        let hdr = Header::new(self.id(), len, serialize_checksum);
        hdr.serialize(&mut dst[0..hdr_len]).unwrap();
        Ok(len as usize)
    }

    pub fn deserialize(
        data: &[u8],
        serialize_checksum: bool,
    ) -> Result<Self, crate::PacketDeserializeError> {
        let hdr_len = Header::num_bytes(serialize_checksum);
        let hdr = Header::deserialize(data, serialize_checksum)?;
        if hdr.len as usize > data.len() {
            return Err(PayloadDeserializeError::PacketTooLong {
                len: hdr.len,
                parsed: data.len() as _,
            }
            .into());
        }
        let pktbuf = &data[hdr_len..(hdr.len as usize)];
        Ok(Self::deserialize_no_hdr(hdr.id, pktbuf)?)
    }
}
