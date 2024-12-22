use std::any::TypeId;

use anyhow::Result;
use bincode::{
    config,
    error::{DecodeError, EncodeError},
};
use thiserror::Error;

use crate::pkt_common::Unknown;

#[derive(Debug, PartialEq)]
pub struct Header {
    pub len: u16,
    /// Only relevant for encoded packets. Otherwise 0
    pub checksum: u32,
    pub id: u16,

    pub serialize_checksum: bool,
}

impl Header {
    pub const MAGIC: u16 = 0xb7e2;
    pub const SIZE: usize = 10;

    pub fn new(id: u16, len: u16, serialize_checksum: bool) -> Self {
        Self {
            len,
            checksum: 0x0,
            id,
            serialize_checksum,
        }
    }

    pub fn num_bytes(serialize_checksum: bool) -> usize {
        6 + (serialize_checksum as usize) * 4
    }

    pub fn serialize(&self, dst: &mut [u8]) -> Result<usize, EncodeError> {
        let expected_num_bytes = Self::num_bytes(self.serialize_checksum);
        if dst.len() < expected_num_bytes {
            return Err(EncodeError::UnexpectedEnd);
        }
        dst[0..2].copy_from_slice(&Self::MAGIC.to_le_bytes());
        dst[2..4].copy_from_slice(&self.len.to_le_bytes());
        if self.serialize_checksum {
            dst[4..8].copy_from_slice(&self.checksum.to_le_bytes());
            dst[8..10].copy_from_slice(&self.id.to_le_bytes());
        } else {
            dst[4..6].copy_from_slice(&self.id.to_le_bytes());
        }
        Ok(expected_num_bytes)
    }

    pub fn deserialize(
        src: &[u8],
        serialize_checksum: bool,
    ) -> Result<Self, HeaderDeserializeError> {
        let expected_num_bytes = Self::num_bytes(serialize_checksum);
        if src.len() < expected_num_bytes {
            return Err(DecodeError::UnexpectedEnd {
                additional: expected_num_bytes - src.len(),
            }
            .into());
        }

        let magic = u16::from_le_bytes(src[0..2].try_into().unwrap());
        if magic != Header::MAGIC {
            return Err(HeaderDeserializeError::InvalidMagic { found: magic });
        }

        let len = u16::from_le_bytes(src[2..4].try_into().unwrap());
        if (len as usize) < expected_num_bytes {
            return Err(HeaderDeserializeError::TooSmall {
                expected: expected_num_bytes as _,
                found: len,
            });
        }

        if serialize_checksum {
            let checksum = u32::from_le_bytes(src[4..8].try_into().unwrap());
            let id = u16::from_le_bytes(src[8..10].try_into().unwrap());
            Ok(Self {
                len,
                checksum,
                id,
                serialize_checksum,
            })
        } else {
            let id = u16::from_le_bytes(src[4..6].try_into().unwrap());
            Ok(Self {
                len,
                checksum: 0x0,
                id,
                serialize_checksum,
            })
        }
    }
}

#[derive(Error, Debug)]
pub enum HeaderDeserializeError {
    #[error(
        "Invalid header magic (expected {:#04x}, got {found:#04x})",
        Header::MAGIC
    )]
    InvalidMagic { found: u16 },
    #[error("Packet size smaller than header size (expected {expected:#04x}, got {found:#04x})")]
    TooSmall { expected: u16, found: u16 },
    #[error("Deserialize failed ({0})")]
    DeserializeError(#[from] DecodeError),
}

#[derive(Error, Debug)]
pub enum PayloadDeserializeError {
    #[error("Packet is too long. Header specifies {len} bytes, but only {parsed} could be parsed")]
    PacketTooLong { len: u16, parsed: u16 },
    #[error("Deserialize failed ({0})")]
    DeserializeError(#[from] DecodeError),
}

#[derive(Error, Debug)]
pub enum PayloadSerializeError {
    #[error(
        "Payload is too long ({payload_len:#04x}). \
        Combined with fixed Header size ({:#04x}) overflows u16",
        Header::MAGIC
    )]
    PayloadTooLong { payload_len: usize },
    #[error("Serialize failed: {0}")]
    SerializeError(#[from] EncodeError),
}

#[derive(Error, Debug)]
pub enum PacketDeserializeError {
    #[error("Header error: {0}")]
    Header(#[from] HeaderDeserializeError),
    #[error("Payload error: {0}")]
    Payload(#[from] PayloadDeserializeError),
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
                    let mut buf = [0u8; 8192];
                    let len = bincode::encode_into_slice($pkt::default(), &mut buf, bincode::config::legacy()).unwrap();
                    assert_eq!(len, $size);
                }
            }
        }
    };
}

pub trait Payload:
    std::fmt::Debug + PartialEq + Clone + Default + bincode::Encode + bincode::Decode + 'static
{
    fn id(&self) -> u16;

    fn serialize(
        &self,
        dst: &mut Vec<u8>,
        serialize_checksum: bool,
    ) -> Result<usize, PayloadSerializeError> {
        let hdr_len = Header::num_bytes(serialize_checksum);
        // reserve size for header
        dst.resize(hdr_len, 0u8);
        // serialize into the rest of vector
        let payload_len = self.serialize_no_hdr(dst)?;
        let len: u16 = payload_len
            .checked_add(hdr_len)
            .unwrap()
            .try_into()
            .map_err(|_| PayloadSerializeError::PayloadTooLong { payload_len })?;
        let hdr = Header::new(self.id(), len, serialize_checksum);
        hdr.serialize(&mut dst[0..hdr_len])?;
        Ok(len as usize)
    }

    fn serialize_no_hdr(&self, dst: &mut Vec<u8>) -> Result<usize, PayloadSerializeError> {
        let len = if TypeId::of::<Self>() == TypeId::of::<Unknown>() {
            // Safety: Self = Unknown
            let unk: &Unknown = unsafe { core::mem::transmute(self) };
            bincode::encode_into_std_write(&unk.data, dst, config::legacy())?
        } else {
            bincode::encode_into_std_write(self, dst, config::legacy())?
        };
        Ok(len)
    }

    fn deserialize_no_hdr(data: &[u8]) -> Result<Self, PayloadDeserializeError> {
        assert!(TypeId::of::<Self>() != TypeId::of::<Unknown>());

        let (obj, len) = bincode::decode_from_slice::<Self, _>(data, config::legacy())?;
        if len != data.len() {
            return Err(PayloadDeserializeError::PacketTooLong {
                len: data.len() as u16,
                parsed: len as u16,
            });
        }
        Ok(obj)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::BoundVec;

    #[test]
    fn encode() {
        let p = Unknown {
            id: 0xc3e,
            data: BoundVec(vec![118, 1, 0, 0, 103, 35, 108, 32]),
        };

        let mut bytes: Vec<u8> = Vec::new();
        p.serialize(&mut bytes, true).unwrap();

        println!("{:#?}", bytes);
    }
}
