// SPDX-License-Identifier: MIT
// Copyright(c) 2023 Darek Stojaczyk

use log::trace;
use packet::*;

use anyhow::Result;
use smol::io::{AsyncReadExt, AsyncWriteExt};
use smol::Async;
use std::fmt::Display;
use std::net::TcpStream;
use std::os::fd::AsRawFd;

pub struct PacketStream {
    pub stream: Async<TcpStream>,
    pub buf: Vec<u8>,
}

impl Display for PacketStream {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let fd = self.stream.as_raw_fd();
        write!(f, "Conn #{fd}")
    }
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
        trace!("{self}: got hdr: {hdr:x?}");

        let payload_len = hdr.len as u64 - Header::SIZE as u64;
        self.buf.resize(payload_len as usize, 0u8);
        let slice = &mut self.buf[..];
        self.stream.read_exact(slice).await?;

        let slice = &self.buf[..];
        trace!("{self}: got payload: {:x?}", slice);
        Ok(Payload::decode(&hdr, slice)?)
    }

    pub async fn send(&mut self, pkt: &Payload) -> Result<()> {
        self.buf.clear();
        let len = pkt.encode(&mut self.buf)?;
        self.stream.write_all(&self.buf[..len]).await?;
        Ok(())
    }
}
