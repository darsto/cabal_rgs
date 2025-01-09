// SPDX-License-Identifier: MIT
// Copyright(c) 2023 Darek Stojaczyk

use futures::{AsyncRead, AsyncWrite};
use log::{debug, error, trace};
use packet::*;

use anyhow::{anyhow, bail, Result};
use pkt_common::{Connect, ServiceID};
use smol::io::{AsyncReadExt, AsyncWriteExt};
use std::{fmt::Display, io::ErrorKind};
use thiserror::Error;

/// A wrapper that reads / writes complete [`Payload`] packets
/// to the underlying reader / writer.
///
/// Note this doesn't implement [`futures::stream::Stream`].
#[derive(Debug)]
pub struct PacketStream<T: Unpin> {
    pub stream: T,
    send_buf: Vec<u8>,
    recv_buf: AsyncBufReader,
    /// packet length that was parsed in a packet header,
    /// but whose payload is still being received
    recv_pkt_len: Option<u16>,
    pub config: StreamConfig,
    pub decoder: Option<Box<PacketDecoder>>,
}

#[derive(Debug)]
pub struct StreamConfig {
    pub self_name: String,
    pub other_name: String,
    pub serialize_checksum: bool,
    pub deserialize_checksum: bool,
    pub encode_tx: bool,
    pub decode_rx: bool,
}

#[derive(Debug, Error)]
pub enum RecvError {
    #[error("Connection terminated")]
    Terminated,
    #[error("Malformed data: {0}")]
    Malformed(#[from] HeaderDeserializeError),
    #[error("Deserialize: {0}")]
    Deserialize(#[from] PayloadDeserializeError),
    #[error("Decode: {0}")]
    Decode(#[from] PacketDecodeError),
}

impl<T: Unpin> PacketStream<T> {
    pub fn new(stream: T, config: StreamConfig) -> Self {
        let decoder = match config.decode_rx {
            true => Some(Box::new(PacketDecoder::new(Some(0x46631ab5), Some(0x1BB8)))),
            false => None,
        };

        Self {
            stream,
            send_buf: Vec::new(),
            recv_buf: AsyncBufReader::new(),
            recv_pkt_len: None,
            config,
            decoder,
        }
    }
}

impl<T: Unpin + AsyncRead> PacketStream<T> {
    /// Try to receive a packet from the stream.
    /// This is cancellation-safe.
    pub async fn recv(&mut self) -> std::result::Result<Packet, RecvError> {
        let pkt_len = if let Some(pkt_len) = &self.recv_pkt_len {
            *pkt_len
        } else {
            // decode only the first 4 bytes (magic + pkt_len), so
            // decoding (if `self.config.decode_rx`) doesn't succeed even
            // if the packet has no payload => nothing in the buffer is
            // then mutated
            let buf_len = 4;
            let hdr_buf = self
                .recv_buf
                .fill_buf_mut(buf_len, &mut self.stream)
                .await
                .map_err(|_| RecvError::Terminated)?;

            let pkt_len = if let Some(decoder) = &mut self.decoder {
                match decoder.decode(&mut hdr_buf[..4])? {
                    PacketDecodeResult::PayloadIncomplete(len) => len,
                    _ => unreachable!(),
                }
            } else {
                u16::from_le_bytes(hdr_buf[2..4].try_into().unwrap())
            };

            *self.recv_pkt_len.insert(pkt_len)
        };

        let pkt_buf = self
            .recv_buf
            .fill_buf_mut(pkt_len as _, &mut self.stream)
            .await
            .map_err(|_| RecvError::Terminated)?;

        if let Some(decoder) = &mut self.decoder {
            match decoder.decode(pkt_buf)? {
                PacketDecodeResult::Done(len) => {
                    debug_assert_eq!(len, pkt_len);
                }
                _ => unreachable!(),
            }
        }

        let hdr_len = Header::num_bytes(self.config.deserialize_checksum);
        let hdr = Header::deserialize(&pkt_buf[..hdr_len], self.config.deserialize_checksum)?;
        let payload_buf = &pkt_buf[hdr_len..];
        let p = Packet::deserialize_no_hdr(hdr.id, payload_buf);
        if let Err(e) = &p {
            error!("{self_name}<-{other_name}: Can't decode packet {hdr:x?}: {e}\nPayload: {payload_buf:x?}",
                self_name = self.config.self_name,
                other_name = self.config.other_name);
        }

        self.recv_pkt_len = None;
        self.recv_buf.consume(pkt_len as _);

        let p = p?;
        debug!(
            "{self_name}<-{other_name}: recv: {p:?}",
            self_name = self.config.self_name,
            other_name = self.config.other_name
        );
        Ok(p)
    }
}

impl<T: Unpin + AsyncWrite> PacketStream<T> {
    /// Send a packet.
    /// This is cancellation-safe, although the packet might
    /// be send incompletely, and further attempts to send more
    /// packets will immediately fail.
    pub async fn send(&mut self, pkt: &impl Payload) -> Result<()> {
        if !self.send_buf.is_empty() {
            bail!("One of the previous send operations was cancelled. Aborting");
        }
        trace!(
            "{self_name}->{other_name}: sent: {pkt:?}",
            self_name = self.config.self_name,
            other_name = self.config.other_name
        );
        let len = pkt.serialize(&mut self.send_buf, self.config.serialize_checksum)?;
        if let Some(decoder) = &mut self.decoder {
            decoder.encode(&mut self.send_buf[..len]);
        }
        self.stream.write_all(&self.send_buf[..len]).await?;
        self.send_buf.clear();
        Ok(())
    }
}

impl<T: Unpin> Display for PacketStream<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.config.other_name.fmt(f)
    }
}

impl StreamConfig {
    pub fn ipc(self_name: String, other_name: String) -> Self {
        Self {
            self_name,
            other_name,
            serialize_checksum: true,
            deserialize_checksum: true,
            decode_rx: false,
            encode_tx: false,
        }
    }
}

pub struct IPCPacketStream<T: Unpin> {
    pub inner: PacketStream<T>,
    pub self_id: Service,
    pub other_id: Service,
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Service {
    WorldSvr { server: u8, channel: u8 },
    LoginSvr,
    DBAgent,
    AgentShop,
    EventMgr,
    GlobalMgrSvr { id: u8 },
    ChatNode,
    RockNRoll,
    Party,
}

impl<T: Unpin + AsyncRead> IPCPacketStream<T> {
    pub async fn from_host(self_id: Service, stream: T) -> Result<Self, anyhow::Error> {
        let config = StreamConfig::ipc(self_id.to_string(), "New".to_string());
        let mut stream = PacketStream::new(stream, config);
        let p = stream
            .recv()
            .await
            .map_err(|e| anyhow!("Failed to receive the first packet: {e:?}"))?;
        let Packet::Connect(other_id) = p else {
            bail!("Expected Connect packet, got {p:?}");
        };
        stream.config.other_name = other_id.to_string();
        Ok(Self {
            inner: stream,
            self_id,
            other_id: other_id.into(),
        })
    }
}

impl<T: Unpin + AsyncWrite> IPCPacketStream<T> {
    pub async fn from_conn(
        self_id: Service,
        other_id: Service,
        stream: T,
    ) -> Result<Self, anyhow::Error> {
        let config = StreamConfig::ipc(self_id.to_string(), other_id.to_string());
        let mut stream = PacketStream::new(stream, config);
        stream.send(&Connect::from(self_id)).await?;

        Ok(Self {
            inner: stream,
            self_id,
            other_id,
        })
    }
}

impl<T: Unpin + AsyncRead> IPCPacketStream<T> {
    pub async fn recv(&mut self) -> std::result::Result<Packet, RecvError> {
        self.inner.recv().await
    }
}

impl<T: Unpin + AsyncWrite> IPCPacketStream<T> {
    pub async fn send(&mut self, pkt: &impl Payload) -> Result<()> {
        self.inner.send(pkt).await
    }
}

impl<T: Unpin> Display for IPCPacketStream<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.inner.fmt(f)
    }
}

impl Service {
    pub fn service_id(&self) -> ServiceID {
        use ServiceID as S;
        match self {
            Self::WorldSvr { .. } => S::WorldSvr,
            Self::LoginSvr => S::LoginSvr,
            Self::DBAgent => S::DBAgent,
            Self::AgentShop => S::AgentShop,
            Self::EventMgr => S::EventMgr,
            Self::GlobalMgrSvr { .. } => S::GlobalMgrSvr,
            Self::ChatNode => S::ChatNode,
            Self::RockNRoll => S::RockNRoll,
            Self::Party => S::Party,
        }
    }
}

impl From<Connect> for Service {
    fn from(c: Connect) -> Self {
        use ServiceID as S;
        match c.service {
            S::WorldSvr => Self::WorldSvr {
                server: c.server_id,
                channel: c.channel_id,
            },
            S::LoginSvr => Self::LoginSvr,
            S::DBAgent => Self::DBAgent,
            S::AgentShop => Self::AgentShop,
            S::EventMgr => Self::EventMgr,
            S::GlobalMgrSvr => Self::GlobalMgrSvr { id: c.server_id },
            S::ChatNode => Self::ChatNode,
            S::RockNRoll => Self::RockNRoll,
            S::Party => Self::Party,
        }
    }
}

impl From<Service> for Connect {
    fn from(e: Service) -> Self {
        let service = e.service_id();
        use Service as E;
        match e {
            E::WorldSvr { server, channel } => Connect {
                service,
                server_id: server,
                channel_id: channel,
                unk2: 0,
            },
            E::GlobalMgrSvr { id } => Connect {
                service,
                server_id: id,
                channel_id: 0,
                unk2: 0,
            },
            E::LoginSvr => Connect {
                service,
                server_id: 0x80,
                channel_id: 0x1,
                unk2: 0,
            },
            _ => Connect {
                service,
                server_id: 0,
                channel_id: 0,
                unk2: 0,
            },
        }
    }
}

impl std::fmt::Display for Service {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let service_id = self.service_id();
        <ServiceID as std::fmt::Debug>::fmt(&service_id, f)
    }
}

/// Effectively a BufReader, but returns `&mut [u8]` instead of `&[u8]`.
#[derive(Debug)]
struct AsyncBufReader {
    buf: Vec<u8>,
    /// Number of bytes with actual data
    len: usize,
    /// Number of bytes with actual data that
    offset: usize,
}

impl AsyncBufReader {
    fn new() -> Self {
        Self {
            buf: Vec::new(),
            len: 0,
            offset: 0,
        }
    }

    /// This is cancel-safe.
    /// The returned buffer is always exactly [`len`] bytes long.
    async fn fill_buf_mut<T>(&mut self, len: usize, reader: &mut T) -> std::io::Result<&mut [u8]>
    where
        T: AsyncRead + Unpin,
    {
        if len > self.buf.len() {
            self.buf.resize(len, 0);
        }

        if len > self.buf.len() - self.offset {
            // can't receive in one contiguous buffer; defragmentation necessary
            self.make_contiguous();
        }

        // receive
        while len > self.len - self.offset {
            let rcv_buf = &mut self.buf[self.len..];
            let rcv_len = reader.read(rcv_buf).await?;
            if rcv_len == 0 {
                return Err(ErrorKind::ConnectionReset.into());
            }
            self.len += rcv_len;
        }

        Ok(&mut self.buf[self.offset..(self.offset + len)])
    }

    fn consume(&mut self, len: usize) {
        if len >= self.len - self.offset {
            // faster equivalent of [`Self::make_contiguous()`]
            self.len = 0;
            self.offset = 0;
        } else {
            self.offset += len;
        }
    }

    fn make_contiguous(&mut self) {
        self.buf.copy_within(self.offset..self.len, 0);
        self.len -= self.offset;
        self.offset = 0;
    }
}

#[derive(Debug)]
pub struct PacketDecoder {
    pub xor_table_seed: u32,

    first_packet_received: bool,
    pub xor_key_idx: u16,
    xor_table: [u32; 0x8000],
    xor_key: Option<u32>,
}

impl PacketDecoder {
    const XOR_KEY_MASK: u32 = 0x3FFF;
    const XOR_ENCODE_KEY: u32 = 0x7ab38cf1;

    fn new(xor_table_seed: Option<u32>, xor_key_idx: Option<u16>) -> Self {
        let xor_table_seed = xor_table_seed.unwrap_or_else(rand::random);
        let xor_key_idx: u16 =
            xor_key_idx.unwrap_or_else(rand::random) & (Self::XOR_KEY_MASK as u16);

        Self {
            xor_table_seed,
            first_packet_received: false,
            xor_key_idx,
            xor_table: Self::gen_xor_table(xor_table_seed),
            xor_key: None,
        }
    }

    fn decode(&mut self, data: &mut [u8]) -> Result<PacketDecodeResult, PacketDecodeError> {
        let data_len = data.len();
        let mut data_u32 = data
            .chunks_exact_mut(4)
            .map(|c| TryInto::<&mut [u8; 4]>::try_into(c).unwrap());
        let Some(dword) = data_u32.next() else {
            return Ok(PacketDecodeResult::HeaderIncomplete);
        };

        let xor_key = *self.xor_key.get_or_insert_with(|| {
            let expected_pkt_len = 14u32;
            let expected_dword: u32 = (Header::MAGIC as u32) | (expected_pkt_len << 16);
            let dword_u32 = u32::from_le_bytes(*dword);
            dword_u32 ^ expected_dword
        });

        let org_dword = u32::from_le_bytes(*dword);
        let hdr_u32 = org_dword ^ xor_key;
        let magic = (hdr_u32 & 0xFFFF) as u16;
        let pkt_len = (hdr_u32 >> 16) as u16;
        if magic != Header::MAGIC {
            return Err(PacketDecodeError::InvalidMagic(magic));
        }
        if pkt_len as usize > data_len {
            return Ok(PacketDecodeResult::PayloadIncomplete(pkt_len));
        }

        // FIXME: for now this assumes the checksum is always present
        let Some(recv_checksum) = data_u32.next() else {
            // can happen if received pkt_len is malformed
            return Ok(PacketDecodeResult::HeaderIncomplete);
        };
        let recv_checksum = u32::from_le_bytes(*recv_checksum);
        *dword = hdr_u32.to_le_bytes();

        let mut xor_key = self.get_dec_xor_key(org_dword);
        for dword in data_u32 {
            let org_dword = u32::from_le_bytes(*dword);
            Self::store_u32(dword, org_dword ^ xor_key);
            xor_key = self.get_dec_xor_key(org_dword);
        }

        // cant use [`ChunkExactMut::into_remainder()`] since we used .map()
        let remainder = &mut data[data_len / 4 * 4..];
        let mut dword = [0u8; 4];
        dword[..remainder.len()].copy_from_slice(remainder);
        let org_dword = u32::from_le_bytes(dword);
        let dword_u32 = org_dword ^ xor_key;
        remainder.copy_from_slice(&dword_u32.to_le_bytes()[..remainder.len()]);

        let checksum = self.get_dec_xor_key(xor_key) ^ org_dword;
        if checksum != recv_checksum {
            return Err(PacketDecodeError::Checksum {
                expected: recv_checksum,
                calculated: checksum,
                pkt_len,
            });
        }

        self.first_packet_received = true;
        self.xor_key = Some(self.get_dec_xor_key(self.xor_key_idx as u32));
        self.xor_key_idx = self.xor_key_idx.wrapping_add(1);

        Ok(PacketDecodeResult::Done(pkt_len))
    }

    fn encode(&mut self, data: &mut [u8]) {
        let data_len = data.len();
        let mut data_u32 = data
            .chunks_exact_mut(4)
            .map(|c| TryInto::<&mut [u8; 4]>::try_into(c).unwrap());

        let dword = data_u32.next().unwrap();
        let xored_dword = u32::from_le_bytes(*dword) ^ Self::XOR_ENCODE_KEY;
        Self::store_u32(dword, xored_dword);

        let mut xor_key = self.get_enc_xor_key(xored_dword);
        for dword in data_u32 {
            let xored_dword = u32::from_le_bytes(*dword) ^ xor_key;
            Self::store_u32(dword, xored_dword);
            xor_key = self.get_enc_xor_key(xored_dword);
        }

        // cant use [`ChunkExactMut::into_remainder()`] since we used .map()
        let remainder = &mut data[data_len / 4 * 4..];
        let mut dword = [0u8; 4];
        dword[..remainder.len()].copy_from_slice(remainder);
        let org_dword = u32::from_le_bytes(dword);
        let dword_u32 = org_dword ^ xor_key;
        remainder.copy_from_slice(&dword_u32.to_le_bytes()[..remainder.len()]);
    }

    #[inline]
    fn store_u32(dst: &mut [u8; 4], val: u32) {
        #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
        {
            // SAFETY: x86 doesn't care about unaligned access
            let dst_u32: &mut u32 = unsafe { &mut *(dst.as_mut_ptr() as *mut _) };
            *dst_u32 = val
        }
        #[cfg(not(any(target_arch = "x86", target_arch = "x86_64")))]
        {
            *dst = val.to_le_bytes();
        }
    }

    #[inline]
    fn get_dec_xor_key(&self, idx: u32) -> u32 {
        let idx_mul = match self.first_packet_received {
            true => 2,
            false => 1,
        };
        unsafe {
            *self
                .xor_table
                .get_unchecked(((idx & Self::XOR_KEY_MASK) * idx_mul) as usize)
        }
    }

    #[inline]
    fn get_enc_xor_key(&self, idx: u32) -> u32 {
        unsafe {
            *self
                .xor_table
                .get_unchecked((idx & Self::XOR_KEY_MASK) as usize)
        }
    }

    /// Hardcoded magic numbers
    fn gen_xor_table(seed: u32) -> [u32; 0x8000] {
        let mut tmp_seed: u32 = 0x8f54c37b;

        std::array::from_fn(|i| {
            if i == 0x4000 {
                tmp_seed = seed;
            }

            let tmp_v = tmp_seed.wrapping_mul(0x2f6b6f5).wrapping_add(0x14698b7);
            tmp_seed = tmp_v.wrapping_mul(0x2f6b6f5).wrapping_add(0x14698b7);
            let p1 = (tmp_v >> 16).wrapping_mul(0x27f41c3).wrapping_add(0xb327bd) >> 16;
            let p2 = (tmp_seed >> 16)
                .wrapping_mul(0x27f41c3)
                .wrapping_add(0xb327bd)
                & 0xffff0000;
            p1 | p2
        })
    }
}

#[derive(Debug)]
pub enum PacketDecodeResult {
    HeaderIncomplete,
    PayloadIncomplete(u16),
    Done(u16),
}

#[derive(Debug, Error)]
pub enum PacketDecodeError {
    #[error("Invalid header magic (expected {:#04x}, got {0:#04x})", Header::MAGIC)]
    InvalidMagic(u16),
    #[error("Checksum mismatch (expected {expected:#08x}, got {calculated:#08x})")]
    Checksum {
        expected: u32,
        calculated: u32,
        pkt_len: u16,
    },
}

impl PacketDecodeError {
    pub fn decoded_len(&self) -> usize {
        match self {
            Self::Checksum { pkt_len, .. } => *pkt_len as _,
            Self::InvalidMagic { .. } => 0,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_decode_basic() {
        let mut decoder = PacketDecoder::new(Some(0x46631ab5), Some(0x1BB8));

        let mut enc: Vec<u8> = b"\x68\xff\x4c\x25\x5c\xee\xd5\x08\x22\xe3\xcc\x11\x5f\x6f".into();
        let len = match decoder.decode(&mut enc).unwrap() {
            PacketDecodeResult::Done(len) => len as usize,
            _ => panic!(),
        };
        println!("{:x?}", enc);
        assert_eq!(len, enc.len());

        let mut dec: Vec<u8> =
            b"\xe2\xb7\x12\x00\x65\x00\xb5\x1a\x63\x46\x9e\x4c\x00\x00\x00\x00\xb9\x1b".into();
        decoder.encode(&mut dec);
        println!("{:x?}", dec);

        enc = b"\x5f\x57\xd4\xee\xba\x58\xf5\x18\x32\x97\xa5\x47\x6e\x12\xf8\x25\
			\x62\x0d\x31\xee\x61\x0d\xe5\x84\x91\xec"
            .into();
        let len = match decoder.decode(&mut enc).unwrap() {
            PacketDecodeResult::Done(len) => len as usize,
            _ => panic!(),
        };
        assert_eq!(len, enc.len());
        println!("{:x?}", enc);
    }
}
