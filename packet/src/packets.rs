// SPDX-License-Identifier: MIT
// Copyright(c) 2023 Darek Stojaczyk

use packet_proc::packet_list;

use crate::pkt_common::*;
use crate::pkt_crypto::*;
use crate::pkt_event::*;
use crate::pkt_global::*;

use crate::Header;
use crate::Payload;

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
}

impl Packet {
    pub fn serialize(&self, dst: &mut Vec<u8>) -> Result<usize, crate::PayloadSerializeError> {
        // reserve size for header
        dst.resize(Header::SIZE, 0u8);
        // serialize into the rest of vector
        let payload_len = self.serialize_no_hdr(dst)?;
        let len: u16 = payload_len
            .checked_add(Header::SIZE)
            .unwrap()
            .try_into()
            .map_err(|_| crate::PayloadSerializeError::PayloadTooLong {
                payload_len: payload_len as usize,
            })?;
        let hdr = Header::new(self.id(), len);
        hdr.serialize(&mut dst[0..Header::SIZE]).unwrap();
        Ok(len as usize)
    }

    pub fn deserialize(data: &[u8]) -> Result<Self, crate::PacketDeserializeError> {
        let hdr = Header::deserialize(data)?;
        let pktbuf = &data[Header::SIZE..(Header::SIZE + hdr.len as usize)];
        Ok(Self::deserialize_no_hdr(hdr.id, pktbuf)?)
    }
}
