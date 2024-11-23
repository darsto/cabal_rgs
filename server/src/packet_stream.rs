// SPDX-License-Identifier: MIT
// Copyright(c) 2023 Darek Stojaczyk

use crate::EndpointID;
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
    pub stream: T,
    /// Received Header
    recv_hdr: Option<Header>,
    send_buf: Vec<u8>,
    config: StreamConfig,
}

#[derive(Debug)]
pub struct StreamConfig {
    pub self_name: String,
    pub other_name: String,
    pub serialize_checksum: bool,
    pub deserialize_checksum: bool,
}

impl<T: Unpin> PacketStream<T> {
    pub fn new(stream: T, config: StreamConfig) -> Self {
        Self {
            stream,
            recv_hdr: None,
            send_buf: Vec::new(),
            config,
        }
    }
}

impl<T: Unpin + AsyncRead> PacketStream<T> {
    pub fn new_buffered(stream: T, config: StreamConfig) -> PacketStream<BufReader<T>> {
        PacketStream::<_>::new(BufReader::with_capacity(65536, stream), config)
    }
}

impl<T: Unpin + AsyncBufRead> PacketStream<T> {
    /// Try to receive a packet from the stream.
    /// This is cancellation-safe.
    pub async fn recv(&mut self) -> Result<Packet> {
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
            let hdr = Header::deserialize(buf, self.config.deserialize_checksum);
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

        let p = Packet::deserialize_no_hdr(hdr.id, buf)
            .map_err(|e| anyhow!("Can't decode packet {hdr:x?}: {e}\nPayload: {buf:x?}"));
        self.stream.consume(payload_len);
        self.recv_hdr = None;

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
        }
    }
}

pub struct IPCPacketStream<T: Unpin> {
    pub inner: PacketStream<T>,
    pub self_id: EndpointID,
    pub other_id: EndpointID,
}

impl<T: Unpin + AsyncBufRead> IPCPacketStream<T> {
    pub async fn from_host(self_id: EndpointID, stream: T) -> Result<Self, anyhow::Error> {
        let config = StreamConfig::ipc(self_id.to_string(), "New".to_string());
        let mut stream = PacketStream::new(stream, config);
        let p = stream
            .recv()
            .await
            .map_err(|e| anyhow!("Failed to receive the first packet: {e:?}"))?;
        let Packet::Connect(other_id) = p else {
            bail!("Expected Connect packet, got {p:?}");
        };
        if other_id.service == pkt_common::ServiceID::None {
            bail!("Received invalid ServiceID: {other_id}");
        }
        Ok(Self {
            inner: stream,
            self_id,
            other_id,
        })
    }
}

impl<T: Unpin + AsyncWrite> IPCPacketStream<T> {
    pub async fn from_conn(
        self_id: EndpointID,
        other_id: EndpointID,
        stream: T,
    ) -> Result<Self, anyhow::Error> {
        assert!(other_id.service != pkt_common::ServiceID::None);
        let config = StreamConfig::ipc(self_id.to_string(), other_id.to_string());
        let mut stream = PacketStream::new(stream, config);
        stream.send(&self_id).await.unwrap();

        Ok(Self {
            inner: stream,
            self_id,
            other_id,
        })
    }
}

impl<T: Unpin + AsyncBufRead> IPCPacketStream<T> {
    pub async fn recv(&mut self) -> Result<Packet> {
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
