use std::any::TypeId;

use anyhow::Result;
use bincode::{
    config,
    error::{DecodeError, EncodeError},
    Decode, Encode,
};
use thiserror::Error;

use crate::pkt_common::Unknown;

pub trait Payload:
    std::fmt::Debug + PartialEq + Clone + Default + bincode::Encode + bincode::Decode + 'static
{
    fn id(&self) -> u16;

    fn serialize(&self, dst: &mut Vec<u8>) -> Result<usize, PayloadSerializeError> {
        // reserve size for header
        dst.resize(Header::SIZE, 0u8);
        // serialize into the rest of vector
        let payload_len = self.serialize_no_hdr(dst)?;
        let len: u16 = payload_len
            .checked_add(Header::SIZE)
            .unwrap()
            .try_into()
            .map_err(|_| PayloadSerializeError::PayloadTooLong {
                payload_len: payload_len as usize,
            })?;
        let hdr = Header::new(self.id(), len);
        hdr.serialize(&mut dst[0..Header::SIZE])?;
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

    pub fn serialize(&self, dst: &mut [u8]) -> Result<usize, EncodeError> {
        let hdr_len = bincode::encode_into_slice(self, dst, config::legacy())?;
        debug_assert_eq!(hdr_len, Header::SIZE);
        Ok(hdr_len)
    }

    pub fn deserialize(dst: &[u8]) -> Result<Self, HeaderDeserializeError> {
        let (hdr, len) = bincode::decode_from_slice::<Header, _>(dst, config::legacy())?;
        debug_assert_eq!(len, Header::SIZE);
        if hdr.magic != Header::MAGIC {
            return Err(HeaderDeserializeError::InvalidMagic { found: hdr.magic });
        }
        if (hdr.len as usize) < Header::SIZE {
            return Err(HeaderDeserializeError::TooSmall { size: hdr.len });
        }
        Ok(hdr)
    }
}

#[derive(Error, Debug)]
pub enum HeaderDeserializeError {
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
                    let mut buf = [0u8; 4096];
                    let len = bincode::encode_into_slice($pkt::default(), &mut buf, bincode::config::legacy()).unwrap();
                    assert_eq!(len, $size);
                }
            }
        }
    };
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
        p.serialize(&mut bytes).unwrap();

        println!("{:#?}", bytes);
    }
}
