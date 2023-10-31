// SPDX-License-Identifier: MIT
// Copyright(c) 2023 Darek Stojaczyk

// Binary part of the application.
// Everything else is in lib.rs so it can be unit tested.

use std::net::TcpListener;

use anyhow::Result;
use clap::Parser;
use event_mgr::*;
use smol::Async;

fn main() -> Result<()> {
    let args = Args::parse();
    let tcp_listener = Async::<TcpListener>::bind(([127, 0, 0, 1], 38171)) //
        .expect("Cannot bind to 38171");

    let mut listener = Listener::new(tcp_listener, args);
    smol::block_on(listener.listen())
}
