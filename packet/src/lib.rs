// SPDX-License-Identifier: MIT
// Copyright(c) 2023 Darek Stojaczyk

// Rust-analyzer complains at the assert_def_packet_size! definition
#![allow(clippy::items_after_test_module)]

use anyhow::Result;
use bincode::{
    config,
    error::{DecodeError, EncodeError},
    Decode, Encode,
};
use genmatch::*;
use thiserror::Error;

pub mod common;
pub mod crypto_mgr;
pub mod event_mgr;
pub mod global_mgr;

mod helper_types;
pub use helper_types::*;

#[genmatch]
#[derive(Debug)]
pub enum Payload {
    #[attr(ID = _)]
    Unknown(common::Unknown),
    Connect(common::Connect),
    ConnectAck(common::ConnectAck),

    /* Event Manager packets */
    Keepalive(event_mgr::Keepalive),

    /* Crypto Manager packets */
    EncryptKey2Request(crypto_mgr::EncryptKey2Request),
    EncryptKey2Response(crypto_mgr::EncryptKey2Response),
    KeyAuthRequest(crypto_mgr::KeyAuthRequest),
    KeyAuthResponse(crypto_mgr::KeyAuthResponse),
    ESYM(crypto_mgr::ESYM),
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
    #[error("Decoding failed ({0})")]
    DecodeError(DecodeError),
}

impl From<DecodeError> for HeaderDecodeError {
    fn from(value: DecodeError) -> Self {
        HeaderDecodeError::DecodeError(value)
    }
}

impl Payload {
    #[genmatch_id(Payload)]
    pub fn new_default(id: usize) -> Payload {
        EnumVariantType(EnumStructType::default())
    }

    #[genmatch_id(Payload)]
    pub fn decode_raw(data: &[u8], id: usize) -> Result<Payload, DecodeError> {
        let (obj, len) = bincode::decode_from_slice::<EnumStructType, _>(data, config::legacy())?;
        Ok(EnumVariantType(obj))
    }

    #[genmatch_self(Payload)]
    pub fn encode_raw(&self, dst: &mut Vec<u8>) -> Result<usize, EncodeError> {
        bincode::encode_into_std_write(inner, dst, config::legacy())
    }

    #[genmatch_self(Payload)]
    pub fn id(&self) -> u16 {
        EnumStructType::ID as u16
    }

    pub fn encode(&self, dst: &mut Vec<u8>) -> Result<usize, PayloadEncodeError> {
        // reserve size for header
        dst.resize(Header::SIZE, 0u8);
        // encode into the rest of vector
        let len = Header::SIZE + self.encode_raw(dst)?;
        let len: u16 = len
            .try_into()
            .map_err(|_e| PayloadEncodeError::PayloadTooLong { payload_len: len })?;

        let hdr = Header::new(self.id(), len);
        hdr.encode(&mut dst[0..Header::SIZE])?;
        Ok(len as usize)
    }

    pub fn decode(hdr: &Header, data: &[u8]) -> Result<Self, DecodeError> {
        let payload = Self::decode_raw(data, hdr.id as usize)?;
        Ok(payload)
    }
}

impl Default for Payload {
    fn default() -> Self {
        Payload::Unknown(common::Unknown::default())
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
