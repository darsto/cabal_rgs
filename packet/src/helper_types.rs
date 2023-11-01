// SPDX-License-Identifier: MIT
// Copyright(c) 2023 Darek Stojaczyk

use std::{
    any::TypeId,
    ops::{Deref, DerefMut},
};

use anyhow::Result;
use bincode::{
    de::{read::Reader, BorrowDecoder},
    enc::write::Writer,
    error::{DecodeError, EncodeError},
    BorrowDecode, Decode, Encode,
};

/// Vec that doesn't encode its length.
/// When decoding, all source bytes will be consumed.
#[derive(Debug, Default, PartialEq)]
pub struct UnboundVec<T>(pub Vec<T>)
where
    T: Encode + Decode;

impl<T> Encode for UnboundVec<T>
where
    T: Encode + Decode + 'static,
{
    fn encode<E: bincode::enc::Encoder>(
        &self,
        encoder: &mut E,
    ) -> std::result::Result<(), EncodeError> {
        if TypeId::of::<T>() == TypeId::of::<u8>() {
            // Safety: T = u8
            let t: &[u8] = unsafe { core::mem::transmute(&self.0[..]) };
            encoder.writer().write(t)?;
            return Ok(());
        }

        for item in &self.0 {
            item.encode(encoder)?;
        }
        Ok(())
    }
}

impl<T> Decode for UnboundVec<T>
where
    T: Encode + Decode + 'static,
{
    fn decode<D: bincode::de::Decoder>(decoder: &mut D) -> std::result::Result<Self, DecodeError> {
        const FULL_PACKET_SIZE: usize = 65536 + 1;
        let len = match decoder.claim_bytes_read(FULL_PACKET_SIZE) {
            Err(DecodeError::UnexpectedEnd { additional }) => {
                debug_assert!(additional <= FULL_PACKET_SIZE);
                FULL_PACKET_SIZE - additional
            }
            Err(err) => return Err(err),
            Ok(_) => {
                return Err(DecodeError::Other("Data has no end"));
            }
        };

        if TypeId::of::<T>() == TypeId::of::<u8>() {
            let mut vec = vec![0u8; len];
            decoder.reader().read(&mut vec)?;
            // Safety: Vec<T> is Vec<u8>
            Ok(UnboundVec(unsafe { core::mem::transmute(vec) }))
        } else {
            decoder.claim_container_read::<T>(len)?;

            let mut vec = Vec::with_capacity(len);
            for _ in 0..len {
                decoder.unclaim_bytes_read(core::mem::size_of::<T>());

                vec.push(T::decode(decoder)?);
            }
            Ok(UnboundVec(vec))
        }
    }
}

impl<'a, T> BorrowDecode<'a> for UnboundVec<T>
where
    T: Encode + Decode,
{
    fn borrow_decode<D: BorrowDecoder<'a>>(_decoder: &mut D) -> Result<Self, DecodeError> {
        unimplemented!();
    }
}

impl<T> Deref for UnboundVec<T>
where
    T: Encode + Decode,
{
    type Target = Vec<T>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<T> DerefMut for UnboundVec<T>
where
    T: Encode + Decode,
{
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

/// Null-terminated String. Doesn't encode its length.
#[derive(Debug, Default, PartialEq)]
pub struct NulltermString(pub String);

impl Encode for NulltermString {
    fn encode<E: bincode::enc::Encoder>(
        &self,
        encoder: &mut E,
    ) -> std::result::Result<(), EncodeError> {
        let vec = UnboundVec(Vec::from(self.0.as_bytes()));
        vec.encode(encoder)?;
        0u8.encode(encoder)
    }
}

impl Decode for NulltermString {
    fn decode<D: bincode::de::Decoder>(decoder: &mut D) -> std::result::Result<Self, DecodeError> {
        let mut vec: Vec<u8> = Vec::new();

        loop {
            decoder.unclaim_bytes_read(1);
            let byte = u8::decode(decoder)?;
            if byte == 0x0 {
                break;
            }
            vec.push(byte);
        }

        let str = String::from_utf8(vec).map_err(|e| DecodeError::Utf8 {
            inner: e.utf8_error(),
        })?;

        Ok(NulltermString(str))
    }
}

impl<'a> BorrowDecode<'a> for NulltermString {
    fn borrow_decode<D: BorrowDecoder<'a>>(_decoder: &mut D) -> Result<Self, DecodeError> {
        unimplemented!();
    }
}

impl Deref for NulltermString {
    type Target = String;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl DerefMut for NulltermString {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}
