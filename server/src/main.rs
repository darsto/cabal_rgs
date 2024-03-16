// SPDX-License-Identifier: MIT
// Copyright(c) 2023 Darek Stojaczyk

// Binary part of the application.
// Everything else is in lib.rs so it can be unit tested.

use clap::Parser;
use futures::future;
use server::{setup_log, ThreadLocalExecutor};
use smol::Async;
use std::{net::TcpListener, sync::Arc};

fn main() {
    setup_log(false);

    let args = Arc::new(server::args::Config::parse());
    if args.services.is_empty() {
        eprintln!("At least one --service must be specified. See --help");
        return;
    }

    let sock = Async::<TcpListener>::bind(([127, 0, 0, 1], 38171)) //
        .expect("Cannot bind to 38171");
    let mut event_mgr_listener = server::event_mgr::Listener::new(sock, args.clone());

    let sock = Async::<TcpListener>::bind(([127, 0, 0, 1], 32001)) //
        .expect("Cannot bind to 32001");
    let mut crypto_mgr_listener = server::crypto_mgr::Listener::new(sock, args.clone());

    let async_ex = ThreadLocalExecutor::new().unwrap();
    async_ex.spawn(event_mgr_listener.listen()).detach();
    async_ex.spawn(crypto_mgr_listener.listen()).detach();

    futures::executor::block_on(async_ex.run(future::pending::<()>()));
    // this never returns
}
