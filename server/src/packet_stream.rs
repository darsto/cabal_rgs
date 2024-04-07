// SPDX-License-Identifier: MIT
// Copyright(c) 2023 Darek Stojaczyk

use futures::{AsyncRead, AsyncWrite};
use log::trace;
use packet::*;

use anyhow::{anyhow, Result};
use smol::io::{AsyncReadExt, AsyncWriteExt};
use std::fmt::Display;

#[derive(Debug)]
pub struct PacketStream<T: Unpin> {
    pub id: i32,
    pub stream: T,
    pub buf: Vec<u8>,
}

impl<T: Unpin> Display for PacketStream<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Conn #{}", self.id)
    }
}

impl<T: Unpin> PacketStream<T> {
    pub fn new(id: i32, stream: T) -> Self {
        Self {
            id,
            stream,
            buf: Vec::with_capacity(4096),
        }
    }
}

impl<T: Unpin + AsyncRead> PacketStream<T> {
    pub async fn recv(&mut self) -> Result<Payload> {
        let mut hdrbuf = [0u8; Header::SIZE];
        self.stream.read_exact(&mut hdrbuf).await?;
        let hdr = Header::decode(&hdrbuf)?;
        trace!("{self}: got hdr: {hdr:x?}");

        let payload_len = hdr.len as u64 - Header::SIZE as u64;
        self.buf.resize(payload_len as usize, 0u8);
        let slice = &mut self.buf[..];
        self.stream.read_exact(slice).await?;

        let slice = &self.buf[..];
        trace!("{self}: got payload: {:x?}", slice);
        Payload::decode(&hdr, slice)
            .map_err(|e| anyhow!("Can't decode packet {hdr:x?}: {e}\nPayload: {slice:x?}"))
    }
}

impl<T: Unpin + AsyncWrite> PacketStream<T> {
    pub async fn send(&mut self, pkt: &Payload) -> Result<()> {
        self.buf.clear();
        let len = pkt.encode(&mut self.buf)?;
        self.stream.write_all(&self.buf[..len]).await?;
        Ok(())
    }
}
