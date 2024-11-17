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
    pub self_id: EndpointID,
    pub other_id: EndpointID,
    pub stream: T,
    /// Received Header
    recv_hdr: Option<Header>,
    send_buf: Vec<u8>,
}

impl<T: Unpin> PacketStream<T> {
    pub fn new(self_id: EndpointID, other_id: EndpointID, stream: T) -> Self {
        Self {
            self_id,
            other_id,
            stream,
            recv_hdr: None,
            send_buf: Vec::new(),
        }
    }
}

impl<T: Unpin + AsyncRead> PacketStream<T> {
    pub fn new_buffered(
        self_id: EndpointID,
        other_id: EndpointID,
        stream: T,
    ) -> PacketStream<BufReader<T>> {
        PacketStream::<_>::new(self_id, other_id, BufReader::with_capacity(65536, stream))
    }
}

impl<T: Unpin + AsyncBufRead> PacketStream<T> {
    pub async fn from_host(self_id: EndpointID, stream: T) -> Result<Self, anyhow::Error> {
        let mut stream = Self::new(self_id, EndpointID::default(), stream);
        let p = stream
            .recv()
            .await
            .map_err(|e| anyhow!("Failed to receive the first packet: {e:?}"))?;
        let Packet::Connect(connect) = p else {
            bail!("Expected Connect packet, got {p:?}");
        };
        if connect.service == pkt_common::ServiceID::None {
            bail!("Received invalid ServiceID: {connect}");
        }
        stream.other_id = connect;
        Ok(stream)
    }

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
            let hdr = Header::deserialize(buf, true);
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
            "{self_id}<-{other_id}: recv: {p:?}",
            self_id = self.self_id,
            other_id = self.other_id
        );
        Ok(p)
    }
}

impl<T: Unpin + AsyncWrite> PacketStream<T> {
    pub async fn from_conn(
        self_id: EndpointID,
        other_id: EndpointID,
        stream: T,
    ) -> Result<Self, anyhow::Error> {
        assert!(other_id.service != pkt_common::ServiceID::None);
        let mut stream = Self::new(self_id, other_id, stream);
        stream.send(&stream.self_id.clone()).await.unwrap();

        Ok(stream)
    }

    /// Send a packet.
    /// This is cancellation-safe, although the packet might
    /// be send incompletely, and further attempts to send more
    /// packets will immediately fail.
    pub async fn send(&mut self, pkt: &impl Payload) -> Result<()> {
        if !self.send_buf.is_empty() {
            bail!("One of the previous send operations was cancelled. Aborting");
        }
        trace!(
            "{self_id}->{other_id}: sent: {pkt:?}",
            self_id = self.self_id,
            other_id = self.other_id
        );
        let len = pkt.serialize(&mut self.send_buf, true)?;
        self.stream.write_all(&self.send_buf[..len]).await?;
        self.send_buf.clear();
        Ok(())
    }
}

impl<T: Unpin> Display for PacketStream<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.other_id.fmt(f)
    }
}
