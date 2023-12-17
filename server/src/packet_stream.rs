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
        println!("Awaiting header");
        let mut hdrbuf = [0u8; Header::SIZE];
        self.stream.read_exact(&mut hdrbuf).await?;
        println!("Got hdrbuf: {:x?}", hdrbuf);
        let hdr = Header::decode(&hdrbuf)?;
        println!("Got hdr: {hdr:x?}");
        let payload_len = hdr.len as u64 - Header::SIZE as u64;
        println!("Payload len: {payload_len}");

        self.buf.resize(payload_len as usize, 0u8);
        let slice = &mut self.buf[..];
        self.stream.read_exact(slice).await?;

        println!("Got payload: {:x?}", slice);
        Ok(Payload::decode(&hdr, slice)?)
    }

    pub async fn send(&mut self, pkt: &Payload) -> Result<()> {
        self.buf.clear();
        let len = pkt.encode(&mut self.buf)?;
        self.stream.write_all(&self.buf[..len]).await?;
        Ok(())
    }
}
