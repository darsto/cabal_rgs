// SPDX-License-Identifier: MIT
// Copyright(c) 2023 Darek Stojaczyk

use futures::{io::BufReader, AsyncBufRead, AsyncRead, AsyncWrite};
use log::{debug, trace};
use packet::*;

use anyhow::{anyhow, bail, Result};
use smol::io::{AsyncBufReadExt, AsyncWriteExt};
use std::fmt::Display;

/// A wrapper that reads / writes complete [`Payload`] packets
/// to the underlying reader / writer.
///
/// Note this doesn't implement [`futures::stream::Stream`].
#[derive(Debug)]
pub struct PacketStream<T: Unpin> {
    pub service: pkt_common::Connect,
    pub stream: T,
    /// Received Header
    recv_hdr: Option<Header>,
    send_buf: Vec<u8>,
}

impl<T: Unpin> PacketStream<T> {
    pub fn new(stream: T) -> Self {
        Self {
            service: Default::default(),
            stream,
            recv_hdr: None,
            send_buf: Vec::new(),
        }
    }
}

impl<T: Unpin + AsyncRead> PacketStream<T> {
    pub fn new_buffered(stream: T) -> PacketStream<BufReader<T>> {
        PacketStream::<_>::new(BufReader::with_capacity(65536, stream))
    }
}

impl<T: Unpin + AsyncBufRead> PacketStream<T> {
    pub async fn from_host(stream: T) -> Result<Self, anyhow::Error> {
        let mut stream = Self::new(stream);
        let p = stream.recv().await.map_err(|e| {
            anyhow!(
                "Conn #{:?}: Failed to receive the first packet: {e:?}",
                stream.service.id
            )
        })?;
        let Payload::Connect(service) = p else {
            bail!(
                "Conn #{:?}: Expected Connect packet, got {p:?}",
                stream.service.id
            );
        };
        if service.id == pkt_common::ServiceID::None {
            bail!("Conn #{:?}: Invalid ServiceID", stream.service.id);
        }
        stream.service = service;
        Ok(stream)
    }

    /// Try to receive a packet from the stream.
    /// This is cancellation-safe.
    pub async fn recv(&mut self) -> Result<Payload> {
        let hdr = if let Some(hdr) = &self.recv_hdr {
            hdr
        } else {
            let buf = loop {
                let buf = self.stream.fill_buf().await?;
                if buf == &[] {
                    bail!("Connection terminated");
                }
                if buf.len() >= Header::SIZE {
                    break &buf[..Header::SIZE];
                }
            };
            let hdr = Header::decode(buf);
            self.stream.consume(Header::SIZE);
            self.recv_hdr.insert(hdr?)
        };

        let payload_len = hdr.len as usize - Header::SIZE;
        let buf = if payload_len == 0 {
            &[]
        } else {
            loop {
                let buf = self.stream.fill_buf().await?;
                if buf == &[] {
                    bail!("Connection terminated while receiving a packet");
                }
                if buf.len() >= payload_len {
                    break &buf[..payload_len];
                }
            }
        };

        let p = Payload::decode(&hdr, buf)
            .map_err(|e| anyhow!("Can't decode packet {hdr:x?}: {e}\nPayload: {buf:x?}"));
        self.stream.consume(payload_len);
        self.recv_hdr = None;

        let p = p?;
        debug!("{self}: Decoded packet: {p:?}");
        Ok(p)
    }
}

impl<T: Unpin + AsyncWrite> PacketStream<T> {
    pub async fn from_conn(stream: T, service: pkt_common::Connect) -> Result<Self, anyhow::Error> {
        let mut stream = Self::new(stream);

        stream
            .send(&Payload::Connect(service.clone()))
            .await
            .unwrap();

        assert!(service.id != pkt_common::ServiceID::None);
        stream.service = service;
        Ok(stream)
    }

    /// Send a packet.
    /// This is cancellation-safe, although the packet might
    /// be send incompletely, and further attempts to send more
    /// packets will immediately fail.
    pub async fn send(&mut self, pkt: &Payload) -> Result<()> {
        if !self.send_buf.is_empty() {
            bail!("One of the previous send operations was cancelled. Aborting");
        }
        trace!("{self}: sent pkt: {pkt:?}");
        let len = pkt.encode(&mut self.send_buf)?;
        self.stream.write_all(&self.send_buf[..len]).await?;
        self.send_buf.clear();
        Ok(())
    }
}

impl<T: Unpin> Display for PacketStream<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Conn {:?}", self.service.id)
    }
}
