// SPDX-License-Identifier: MIT
// Copyright(c) 2023 Darek Stojaczyk

use crate::packet_stream::PacketStream;
use crate::ThreadLocalExecutor;
use clap::Parser;
use futures::{AsyncRead, AsyncReadExt, AsyncWrite};
use log::{error, info, trace};

use std::fmt::Display;
use std::net::TcpStream;
use std::os::fd::AsRawFd;
use std::{net::TcpListener, sync::Arc};

use anyhow::Result;
use smol::Async;

/// Man in the middle for any cabal service serving cabal packets.
/// All packets are dumped to stdout. The ones that are known are pretty
/// printed.
#[derive(Parser, Debug, Default)]
#[command(about, long_about, verbatim_doc_comment)]
pub struct ProxyArgs {
    #[clap(long = "upstream-port", visible_alias = "up")]
    pub upstream_port: u16,
    #[clap(long = "downstream-port", visible_alias = "dp")]
    pub downstream_port: u16,
}

pub struct Listener {
    tcp_listener: Async<TcpListener>,
    args: Arc<crate::args::Config>,
}

impl Listener {
    pub fn new(tcp_listener: Async<TcpListener>, args: &Arc<crate::args::Config>) -> Self {
        Self {
            tcp_listener,
            args: args.clone(),
        }
    }

    pub async fn listen(&mut self) -> Result<()> {
        info!(
            "Listener: started on {}",
            self.tcp_listener.get_ref().local_addr()?
        );
        let proxyargs = self
            .args
            .services
            .iter()
            .find_map(|s| {
                if let crate::args::Service::Proxy(args) = s {
                    Some(args)
                } else {
                    None
                }
            })
            .unwrap();

        loop {
            let (upstream, _) = self.tcp_listener.accept().await?;
            let downstream =
                Async::<TcpStream>::connect(([127, 0, 0, 1], proxyargs.downstream_port)).await?;
            let upstream_id = upstream.as_raw_fd();
            let downstream_id = downstream.as_raw_fd();

            let upstream = upstream.split();
            let downstream = downstream.split();

            let conn = UpConnection {
                id: upstream_id,
                stream: PacketStream::new(upstream_id, upstream.0),
                downstream: PacketStream::new(downstream_id, downstream.1),
                args: self.args.clone(),
            };

            let conn2 = DwConnection {
                id: downstream_id,
                stream: PacketStream::new(upstream_id, upstream.1),
                downstream: PacketStream::new(downstream_id, downstream.0),
                args: self.args.clone(),
            };

            // Give the connection handler its own background task
            ThreadLocalExecutor::get()
                .unwrap()
                .spawn(async move {
                    let id = conn.id;
                    info!("Listener: new upstream connection #{id}");

                    if let Err(err) = conn.recv_upstream().await {
                        error!("Listener: up connection #{id} error: {err}");
                    }
                    info!("Listener: closing upstream connection #{id}");
                })
                .detach();

            ThreadLocalExecutor::get()
                .unwrap()
                .spawn(async move {
                    let id = conn2.id;

                    if let Err(err) = conn2.recv_downstream().await {
                        error!("Listener: dw connection #{id} error: {err}");
                    }
                })
                .detach();
            // for now the tasks are just dropped, but we might want to
            // wait for them in the future (or send a special shutdown
            // message in each connection)
        }
    }
}

#[derive(Debug)]
pub struct UpConnection<U: Unpin + AsyncRead, D: Unpin + AsyncWrite> {
    pub id: i32,
    pub stream: PacketStream<U>,
    pub downstream: PacketStream<D>,
    pub args: Arc<crate::args::Config>,
}

#[derive(Debug)]
pub struct DwConnection<U: Unpin + AsyncWrite, D: Unpin + AsyncRead> {
    pub id: i32,
    pub stream: PacketStream<U>,
    pub downstream: PacketStream<D>,
    pub args: Arc<crate::args::Config>,
}

impl<U: Unpin + AsyncRead, D: Unpin + AsyncWrite> Display for UpConnection<U, D> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Conn #{}", self.id)
    }
}

impl<U: Unpin + AsyncWrite, D: Unpin + AsyncRead> Display for DwConnection<U, D> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Conn #{}", self.id)
    }
}

impl<U: Unpin + AsyncRead, D: Unpin + AsyncWrite> UpConnection<U, D> {
    pub async fn recv_upstream(mut self) -> Result<()> {
        loop {
            let p = self.stream.recv().await?;
            trace!("{self}: Got up packet({:#x}): {p:?}", p.id());
            self.downstream.send(&p).await?;
        }
    }
}

impl<U: Unpin + AsyncWrite, D: Unpin + AsyncRead> DwConnection<U, D> {
    pub async fn recv_downstream(mut self) -> Result<()> {
        loop {
            let p = self.downstream.recv().await?;
            trace!("{self}: Got dw packet({:#x}): {p:?}", p.id());
            self.stream.send(&p).await?;
        }
    }
}
