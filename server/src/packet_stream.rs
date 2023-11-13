// SPDX-License-Identifier: MIT
// Copyright(c) 2023 Darek Stojaczyk

use packet::*;

use anyhow::Result;
use smol::io::{AsyncReadExt, AsyncWriteExt};
use smol::Async;
use std::net::TcpStream;

pub struct PacketStream {
    pub stream: Async<TcpStream>,
    pub buf: Vec<u8>,
}

impl PacketStream {
    pub fn new(stream: Async<TcpStream>) -> Self {
        Self {
            stream,
            buf: Vec::with_capacity(4096),
        }
    }

    pub async fn recv(&mut self) -> Result<Payload> {
        let mut hdrbuf = [0u8; Header::SIZE];
        self.stream.read_exact(&mut hdrbuf).await?;
        let hdr = Header::decode(&hdrbuf)?;
        let payload_len = hdr.len as u64 - Header::SIZE as u64;

        self.buf.clear();
        (&self.stream)
            .take(payload_len)
            .read_to_end(&mut self.buf)
            .await?;
        Ok(Payload::decode(&hdr, &self.buf)?)
    }

    pub async fn send(&mut self, pkt: &Payload) -> Result<()> {
        self.buf.clear();
        let len = pkt.encode(&mut self.buf)?;
        self.stream.write_all(&self.buf[..len]).await?;
        Ok(())
    }
}
