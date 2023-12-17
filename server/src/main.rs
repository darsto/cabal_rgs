// SPDX-License-Identifier: MIT
// Copyright(c) 2023 Darek Stojaczyk

// Binary part of the application.
// Everything else is in lib.rs so it can be unit tested.

use clap::Parser;
use futures::try_join;
use smol::Async;
use std::{net::TcpListener, sync::Arc};

fn main() {
    let args = Arc::new(server::args::Config::parse());

    let sock = Async::<TcpListener>::bind(([127, 0, 0, 1], 38171)) //
        .expect("Cannot bind to 38171");
    let mut event_mgr_listener = server::event_mgr::Listener::new(sock, args.clone());

    let sock = Async::<TcpListener>::bind(([127, 0, 0, 1], 32001)) //
        .expect("Cannot bind to 32001");
    let mut crypto_mgr_listener = server::crypto_mgr::Listener::new(sock, args.clone());

    smol::block_on(async move {
        try_join!(event_mgr_listener.listen(), crypto_mgr_listener.listen()).unwrap();
    });
}
