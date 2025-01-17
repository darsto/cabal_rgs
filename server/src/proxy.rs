// SPDX-License-Identifier: MIT
// Copyright(c) 2023 Darek Stojaczyk

use crate::executor;
use crate::packet_stream::{PacketStream, StreamConfig};
use clap::Args;
use futures::{AsyncRead, AsyncReadExt, AsyncWrite};
use log::{error, info};

use std::fmt::Display;
use std::net::TcpStream;
use std::os::fd::AsRawFd;
use std::{net::TcpListener, sync::Arc};

use anyhow::Result;
use smol::Async;

/// Man in the middle for any cabal service serving cabal packets.
///
/// All packets are dumped to stdout. The ones that are known are pretty
/// printed.
#[derive(Args, Debug, Default)]
#[command(about, long_about, verbatim_doc_comment, disable_help_flag = true)]
pub struct ProxyArgs {
    #[clap(long = "upstream-port", visible_alias = "up")]
    pub upstream_port: u16,
    #[clap(long = "downstream-port", visible_alias = "dp")]
    pub downstream_port: u16,
    #[clap(hide = true, long, short, action = clap::ArgAction::Help)]
    help: Option<bool>,
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
            info!("Connecting to downstream: {}", proxyargs.downstream_port);
            let downstream =
                Async::<TcpStream>::connect(([127, 0, 0, 1], proxyargs.downstream_port)).await?;

            info!("Connected to downstream");
            let upstream_id = upstream.as_raw_fd();
            let downstream_id = downstream.as_raw_fd();

            let upstream = upstream.split();
            let downstream = downstream.split();

            let conn = UpConnection {
                id: upstream_id,
                stream: PacketStream::new(upstream.0, StreamConfig::ipc("?".into(), "?".into())),
                downstream: PacketStream::new(
                    downstream.1,
                    StreamConfig::ipc("?".into(), "?".into()),
                ),
                args: self.args.clone(),
            };

            let conn2 = DwConnection {
                id: downstream_id,
                stream: PacketStream::new(upstream.1, StreamConfig::ipc("?".into(), "?".into())),
                downstream: PacketStream::new(
                    downstream.0,
                    StreamConfig::ipc("?".into(), "?".into()),
                ),
                args: self.args.clone(),
            };

            // Give the connection handler its own background task
            executor::spawn_local(async move {
                let id = conn.id;
                info!("Listener: new upstream connection #{id}");

                if let Err(err) = conn.recv_upstream().await {
                    error!("Listener: up connection #{id} error: {err}");
                }
                info!("Listener: closing upstream connection #{id}");
            })
            .detach();

            executor::spawn_local(async move {
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
            info!("{self}: Got up packet({:#x}): {p:?}", p.id());
            self.downstream.send(&p).await?;
        }
    }
}

impl<U: Unpin + AsyncWrite, D: Unpin + AsyncRead> DwConnection<U, D> {
    pub async fn recv_downstream(mut self) -> Result<()> {
        loop {
            let p = self.downstream.recv().await?;
            info!("{self}: Got dw packet({:#x}): {p:?}", p.id());
            self.stream.send(&p).await?;
        }
    }
}
