// SPDX-License-Identifier: MIT
// Copyright(c) 2023 Darek Stojaczyk

use std::{
    any::TypeId,
    fmt::Debug,
    mem::{size_of, MaybeUninit},
    ops::{Deref, DerefMut},
};

use anyhow::Result;
use bincode::{
    de::{read::Reader, BorrowDecoder},
    enc::write::Writer,
    error::{DecodeError, EncodeError},
    BorrowDecode, Decode, Encode,
};

pub use aria::BlockSlice;

/// Encode-able wrapper for Block
#[repr(C, align(16))]
#[derive(Debug, Default, PartialEq, Eq, Clone)]
pub struct Block([u8; 16]);
impl aria::BlockExt for Block {}

impl AsRef<[u8; 16]> for Block {
    fn as_ref(&self) -> &[u8; 16] {
        &self.0
    }
}

impl AsMut<[u8; 16]> for Block {
    fn as_mut(&mut self) -> &mut [u8; 16] {
        &mut self.0
    }
}

impl From<[u8; 16]> for Block {
    fn from(value: [u8; 16]) -> Self {
        Self(value)
    }
}

impl Deref for Block {
    type Target = [u8; 16];

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl DerefMut for Block {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl Encode for Block {
    fn encode<E: bincode::enc::Encoder>(
        &self,
        encoder: &mut E,
    ) -> std::result::Result<(), EncodeError> {
        self.0.encode(encoder)
    }
}

impl Decode for Block {
    fn decode<D: bincode::de::Decoder>(decoder: &mut D) -> std::result::Result<Self, DecodeError> {
        let mut bytes = [0u8; 16];
        decoder.reader().read(&mut bytes)?;
        Ok(Block(bytes))
    }
}

impl<'a> BorrowDecode<'a> for Block {
    fn borrow_decode<D: BorrowDecoder<'a>>(_: &mut D) -> Result<Self, DecodeError> {
        unimplemented!();
    }
}

/// An array that implements Default trait even for sizes > 32.
/// Safety Note: T must be a primitive
#[derive(PartialEq, Clone, bincode::Encode, bincode::Decode)]
pub struct Arr<T: 'static, const S: usize>([T; S]);

impl<T: Debug, const S: usize> Deref for Arr<T, S> {
    type Target = [T; S];

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<T: Debug, const S: usize> DerefMut for Arr<T, S> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl<T: Debug, const S: usize> Debug for Arr<T, S> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.0.fmt(f)
    }
}

impl<T, const S: usize> Default for Arr<T, S> {
    fn default() -> Self {
        Self(unsafe { MaybeUninit::<[T; S]>::zeroed().assume_init() })
    }
}

impl<T: Copy, const S: usize> From<&[T]> for Arr<T, S> {
    fn from(value: &[T]) -> Self {
        let mut ret = Self::default();
        ret.0[..usize::min(value.len(), S)].copy_from_slice(value);
        ret
    }
}

/// Vec that encodes its length using S bytes (1,2,4,8, or 0).
/// When S is 0, the decoding will consume all source bytes.
#[derive(Debug, Default, Clone, PartialEq)]
pub struct BoundVec<const S: usize, T>(pub Vec<T>);

impl<const S: usize, T> Encode for BoundVec<S, T>
where
    T: Encode + Decode + 'static,
{
    fn encode<E: bincode::enc::Encoder>(
        &self,
        encoder: &mut E,
    ) -> std::result::Result<(), EncodeError> {
        match S {
            0 => {}
            1 => encoder
                .writer()
                .write(&(self.0.len() as u8).to_le_bytes())?,
            2 => encoder
                .writer()
                .write(&(self.0.len() as u16).to_le_bytes())?,
            4 => encoder
                .writer()
                .write(&(self.0.len() as u32).to_le_bytes())?,
            8 => encoder
                .writer()
                .write(&(self.0.len() as u64).to_le_bytes())?,
            _ => unreachable!(),
        }

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

impl<const S: usize, T> Decode for BoundVec<S, T>
where
    T: Encode + Decode + 'static,
{
    fn decode<D: bincode::de::Decoder>(decoder: &mut D) -> std::result::Result<Self, DecodeError> {
        let mut lenbuf = [0u8; S];
        decoder.reader().read(&mut lenbuf)?;

        let len = match S {
            0 => {
                const FULL_PACKET_SIZE: usize = 65536 + 1;
                let mut unused_buf = [0u8; FULL_PACKET_SIZE];
                let len = match decoder.reader().read(&mut unused_buf) {
                    Err(DecodeError::UnexpectedEnd { additional }) => {
                        debug_assert!(additional <= FULL_PACKET_SIZE);
                        FULL_PACKET_SIZE - additional
                    }
                    Err(err) => return Err(err),
                    Ok(_) => {
                        return Err(DecodeError::Other("Data has no end"));
                    }
                };

                // round down, ignore the remainder for now
                len / size_of::<T>()
            }
            1 => u8::from_le_bytes(lenbuf[..1].try_into().unwrap()) as usize,
            2 => u16::from_le_bytes(lenbuf[..2].try_into().unwrap()) as usize,
            4 => u32::from_le_bytes(lenbuf[..4].try_into().unwrap()) as usize,
            8 => u64::from_le_bytes(lenbuf[..8].try_into().unwrap()) as usize,
            _ => unreachable!(),
        };

        decoder.claim_container_read::<T>(len)?;
        if TypeId::of::<T>() == TypeId::of::<u8>() {
            decoder.unclaim_bytes_read(len);
            let mut vec = vec![0u8; len];
            decoder.reader().read(&mut vec)?;
            // Safety: Vec<T> is Vec<u8>
            Ok(BoundVec(unsafe {
                core::mem::transmute::<Vec<u8>, Vec<T>>(vec)
            }))
        } else {
            let mut vec = Vec::with_capacity(len);
            for _ in 0..len {
                decoder.unclaim_bytes_read(core::mem::size_of::<T>());
                vec.push(T::decode(decoder)?);
            }
            Ok(BoundVec(vec))
        }
    }
}

impl<'a, const S: usize, T> BorrowDecode<'a> for BoundVec<S, T>
where
    T: Encode + Decode,
{
    fn borrow_decode<D: BorrowDecoder<'a>>(_decoder: &mut D) -> Result<Self, DecodeError> {
        unimplemented!();
    }
}

impl<const S: usize, T> Deref for BoundVec<S, T>
where
    T: Encode + Decode,
{
    type Target = Vec<T>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<const S: usize, T> DerefMut for BoundVec<S, T>
where
    T: Encode + Decode,
{
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl<const S: usize, T> From<Vec<T>> for BoundVec<S, T> {
    fn from(value: Vec<T>) -> Self {
        Self(value)
    }
}

impl<const S: usize, T: Clone> From<&[T]> for BoundVec<S, T> {
    fn from(value: &[T]) -> Self {
        Self(value.to_vec())
    }
}

impl<const S: usize> From<&str> for BoundVec<S, u8> {
    fn from(value: &str) -> Self {
        Self(value.as_bytes().to_vec())
    }
}

/// Null-terminated String. Doesn't encode its length.
#[derive(Debug, Default, Clone, PartialEq)]
pub struct NulltermString(pub String);

impl Encode for NulltermString {
    fn encode<E: bincode::enc::Encoder>(
        &self,
        encoder: &mut E,
    ) -> std::result::Result<(), EncodeError> {
        let vec = BoundVec::<0, u8>(Vec::from(self.0.as_bytes()));
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

        Ok(Self(str))
    }
}

impl<'a> BorrowDecode<'a> for NulltermString {
    fn borrow_decode<D: BorrowDecoder<'a>>(_decoder: &mut D) -> Result<Self, DecodeError> {
        unimplemented!();
    }
}

impl From<String> for NulltermString {
    fn from(value: String) -> Self {
        Self(value)
    }
}

impl From<&str> for NulltermString {
    fn from(value: &str) -> Self {
        Self(value.to_owned())
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn block_size() {
        assert_eq!(std::mem::size_of::<Block>(), 16);
    }
}
