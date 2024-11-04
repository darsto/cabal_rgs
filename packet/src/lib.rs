// SPDX-License-Identifier: MIT
// Copyright(c) 2023 Darek Stojaczyk

// Rust-analyzer complains at the assert_def_packet_size! definition
#![allow(clippy::items_after_test_module)]

use std::any::TypeId;

use anyhow::Result;
use bincode::{
    config,
    error::{DecodeError, EncodeError},
    Decode, Encode,
};
use genmatch::*;
use pkt_common::{Unknown, UnknownPayload};
use thiserror::Error;

pub mod pkt_common;
pub mod pkt_crypto;
pub mod pkt_event;
pub mod pkt_global;

mod helper_types;
pub use helper_types::*;

#[genmatch]
pub enum Payload {
    #[attr(ID = _)]
    Unknown(pkt_common::Unknown),
    Connect(pkt_common::Connect),
    ConnectAck(pkt_common::ConnectAck),

    /* Event Manager packets */
    Keepalive(pkt_event::Keepalive),

    /* Crypto Manager packets */
    EncryptKey2Request(pkt_crypto::EncryptKey2Request),
    EncryptKey2Response(pkt_crypto::EncryptKey2Response),
    KeyAuthRequest(pkt_crypto::KeyAuthRequest),
    KeyAuthResponse(pkt_crypto::KeyAuthResponse),
    ESYM(pkt_crypto::ESYM),

    /* Global Manager packets */
    RegisterChatSvr(pkt_global::RegisterChatSvr),
    ChangeServerState(pkt_global::ChangeServerState),
    ChangeChannelType(pkt_global::ChangeChannelType),
    ClientVersionNotify(pkt_global::ClientVersionNotify),
    DailyQuestResetTime(pkt_global::DailyQuestResetTime),
    AdditionalDungeonInstanceCount(pkt_global::AdditionalDungeonInstanceCount),
    SystemMessage(pkt_global::SystemMessage),
    SystemMessageForwarded(pkt_global::SystemMessageForwarded),
    NotifyUserCount(pkt_global::NotifyUserCount),
    ServerState(pkt_global::ServerState),
    ProfilePathRequest(pkt_global::ProfilePathRequest),
    ProfilePathResponse(pkt_global::ProfilePathResponse),
    RoutePacket(pkt_global::RoutePacket),
    ShutdownStatsSet(pkt_global::ShutdownStatsSet),
    ChannelOptionSync(pkt_global::ChannelOptionSync),
    VerifyLinks(pkt_global::VerifyLinks),
    VerifyLinksResult(pkt_global::VerifyLinksResult),
    SubPasswordCheckRequest(pkt_global::SubPasswordCheckRequest),
    SubPasswordCheckResponse(pkt_global::SubPasswordCheckResponse),
    SetLoginInstance(pkt_global::SetLoginInstance),
    MultipleLoginDisconnectRequest(pkt_global::MultipleLoginDisconnectRequest),
    MultipleLoginDisconnectResponse(pkt_global::MultipleLoginDisconnectResponse),
}

#[derive(Debug, PartialEq, Encode, Decode)]
pub struct Header {
    pub magic: u16,
    pub len: u16,
    pub unk1: u32,
    pub id: u16,
}

impl Header {
    pub const MAGIC: u16 = 0xb7e2;
    pub const SIZE: usize = 10;

    pub fn new(id: u16, len: u16) -> Header {
        Header {
            magic: Header::MAGIC,
            len,
            unk1: 0x0,
            id,
        }
    }

    pub fn encode(&self, dst: &mut [u8]) -> Result<usize, EncodeError> {
        let hdr_len = bincode::encode_into_slice(self, dst, config::legacy())?;
        debug_assert_eq!(hdr_len, Header::SIZE);
        Ok(hdr_len)
    }

    pub fn decode(dst: &[u8]) -> Result<Self, HeaderDecodeError> {
        let (hdr, len) = bincode::decode_from_slice::<Header, _>(dst, config::legacy())?;
        debug_assert_eq!(len, Header::SIZE);
        if hdr.magic != Header::MAGIC {
            return Err(HeaderDecodeError::InvalidMagic { found: hdr.magic });
        }
        if (hdr.len as usize) < Header::SIZE {
            return Err(HeaderDecodeError::TooSmall { size: hdr.len });
        }
        Ok(hdr)
    }
}

#[derive(Error, Debug)]
pub enum HeaderDecodeError {
    #[error(
        "Invalid header magic (expected {:#04x}, got {found:#04x})",
        Header::MAGIC
    )]
    InvalidMagic { found: u16 },
    #[error(
        "Packet size smaller than header size (Header size {:#04x}, got {size:#04x})",
        Header::SIZE
    )]
    TooSmall { size: u16 },
    #[error("Decoding failed ({0})")]
    DecodeError(#[from] DecodeError),
}

#[derive(Error, Debug)]
pub enum PayloadDecodeError {
    #[error("Packet is too long. Header specifies {len} bytes, but only {parsed} could be parsed")]
    PacketTooLong { len: u16, parsed: u16 },
    #[error("Decoding failed ({0})")]
    DecodeError(#[from] DecodeError),
}

impl Payload {
    #[genmatch_id(Payload)]
    pub fn new_default(id: usize) -> Payload {
        EnumVariantType(EnumStructType::default())
    }

    fn decode_raw_generic<D: bincode::de::Decode>(data: &[u8]) -> Result<D, PayloadDecodeError> {
        let (obj, len) = bincode::decode_from_slice::<D, _>(data, config::legacy())?;
        if len != data.len() {
            return Err(PayloadDecodeError::PacketTooLong {
                len: data.len() as u16,
                parsed: len as u16,
            });
        }
        Ok(obj)
    }

    #[genmatch_id(Payload)]
    pub fn decode_raw(data: &[u8], id: usize) -> Result<Payload, PayloadDecodeError> {
        Ok(EnumVariantType(Self::decode_raw_generic::<EnumStructType>(
            data,
        )?))
    }

    pub fn encode_into_std_write<T: Encode>(
        obj: &T,
        dst: &mut Vec<u8>,
    ) -> Result<usize, EncodeError> {
        bincode::encode_into_std_write(obj, dst, config::legacy())
    }

    #[genmatch_self(Payload)]
    pub fn encode_raw(&self, dst: &mut Vec<u8>) -> Result<usize, EncodeError> {
        Self::encode_into_std_write(inner, dst)
    }

    #[genmatch_self(Payload)]
    fn _id(&self) -> u16 {
        EnumStructType::ID as u16
    }

    pub fn id(&self) -> u16 {
        if let Payload::Unknown(unk) = &self {
            unk.id
        } else {
            self._id()
        }
    }

    #[genmatch_id(Payload)]
    pub fn type_id(id: usize) -> TypeId {
        TypeId::of::<EnumStructType>()
    }

    pub fn encode(&self, dst: &mut Vec<u8>) -> Result<usize, PayloadEncodeError> {
        // reserve size for header
        dst.resize(Header::SIZE, 0u8);
        // encode into the rest of vector
        let len = if let Payload::Unknown(unk) = &self {
            let len = bincode::encode_into_std_write(&unk.data, dst, config::legacy())?;
            Header::SIZE + len
        } else {
            Header::SIZE + self.encode_raw(dst)?
        };
        let len: u16 = len
            .try_into()
            .map_err(|_e| PayloadEncodeError::PayloadTooLong { payload_len: len })?;

        let mut hdr = Header::new(self.id(), len);
        if let Payload::Unknown(inner) = &self {
            hdr.id = inner.id;
        }
        hdr.encode(&mut dst[0..Header::SIZE])?;
        Ok(len as usize)
    }

    pub fn decode(hdr: &Header, data: &[u8]) -> Result<Self, PayloadDecodeError> {
        let payload = if Self::type_id(hdr.id as usize) == TypeId::of::<Unknown>() {
            let (data, _len) =
                bincode::decode_from_slice::<UnknownPayload, _>(data, config::legacy())?;
            Payload::Unknown(Unknown { id: hdr.id, data })
        } else {
            Self::decode_raw(data, hdr.id as usize)?
        };
        Ok(payload)
    }
}

impl Default for Payload {
    fn default() -> Self {
        Payload::Unknown(pkt_common::Unknown::default())
    }
}

impl std::fmt::Debug for Payload {
    #[genmatch_self(Payload)]
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        inner.fmt(f)
    }
}

#[derive(Error, Debug)]
pub enum PayloadEncodeError {
    #[error(
        "Payload is too long ({payload_len:#04x}). \
        Combined with fixed Header size ({:#04x}) overflows u16",
        Header::MAGIC
    )]
    PayloadTooLong { payload_len: usize },
    #[error("Encoding failed ({0})")]
    EncodeError(EncodeError),
}

impl From<EncodeError> for PayloadEncodeError {
    fn from(value: EncodeError) -> Self {
        PayloadEncodeError::EncodeError(value)
    }
}

#[macro_export]
macro_rules! assert_def_packet_size {
    ($pkt:ident, $size:expr) => {
        paste::paste! {
            #[allow(unused_imports)]
            use super::*;
            #[cfg(test)]
            #[allow(non_snake_case, clippy::items_after_test_module)]
            mod [<$pkt _test_def_packet_size>] {
                use super::*;
                #[test]
                fn test() {
                    let mut buf = [0u8; 4096];
                    let len = bincode::encode_into_slice($pkt::default(), &mut buf, bincode::config::legacy()).unwrap();
                    assert_eq!(len, $size);
                }
            }
        }
    };
}

#[macro_export]
macro_rules! packet_alias {
    ($into:ident, $($from:ident)::+) => {
        impl TryFrom<$($from)::+> for $into {
            type Error = anyhow::Error;

            fn try_from(value: $($from)::+) -> std::result::Result<Self, Self::Error> {
                let (req, len) = bincode::decode_from_slice::<$into, _>(
                    value.bytes.0.as_slice(),
                    bincode::config::legacy(),
                )?;
                if len != value.bytes.0.len() {
                    return Err(anyhow::anyhow!("Trailing data in packet {:#?}", value));
                }
                Ok(req)
            }
        }

        impl TryFrom<& $($from)::+> for $into {
            type Error = anyhow::Error;

            fn try_from(value: & $($from)::+) -> std::result::Result<Self, Self::Error> {
                let (req, len) = bincode::decode_from_slice::<$into, _>(
                    value.bytes.0.as_slice(),
                    bincode::config::legacy(),
                )?;
                if len != value.bytes.0.len() {
                    return Err(anyhow::anyhow!("Trailing data in packet {:#?}", value));
                }
                Ok(req)
            }
        }

        impl TryInto<$($from)::+> for $into {
            type Error = anyhow::Error;

            fn try_into(self) -> std::result::Result<$($from)::+, Self::Error> {
                let mut bytes = BoundVec(vec![]);
                bincode::encode_into_std_write(self, &mut bytes.0, bincode::config::legacy())?;
                Ok($($from)::+ { bytes })
            }
        }

        impl TryInto<$($from)::+> for & $into {
            type Error = anyhow::Error;

            fn try_into(self) -> std::result::Result<$($from)::+, Self::Error> {
                let mut bytes = BoundVec(vec![]);
                bincode::encode_into_std_write(self, &mut bytes.0, bincode::config::legacy())?;
                Ok($($from)::+ { bytes })
            }
        }
    };
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encode() {
        let p = Payload::Unknown(Unknown {
            id: 0xc3e,
            data: BoundVec(vec![118, 1, 0, 0, 103, 35, 108, 32]),
        });

        let mut bytes: Vec<u8> = Vec::new();
        p.encode(&mut bytes).unwrap();

        println!("{:#?}", bytes);
    }
}
