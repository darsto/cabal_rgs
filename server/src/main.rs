// SPDX-License-Identifier: MIT
// Copyright(c) 2023 Darek Stojaczyk

// Binary part of the application.
// Everything else is in lib.rs so it can be unit tested.

use futures::future;
use server::{args::Service, setup_log, ThreadLocalExecutor};
use smol::Async;
use std::{net::TcpListener, sync::Arc};

fn main() {
    setup_log(false);

    let args = Arc::new(server::args::parse());
    assert!(!args.services.is_empty());

    let async_ex = ThreadLocalExecutor::new().unwrap();
    if args
        .services
        .iter()
        .any(|f| matches!(f, server::args::Service::Event { .. }))
    {
        let sock = Async::<TcpListener>::bind(([127, 0, 0, 1], 38171)) //
            .expect("Cannot bind to 38171");
        let mut event_mgr_listener = server::event::Listener::new(sock, &args);
        async_ex
            .spawn(async move { event_mgr_listener.listen().await })
            .detach();
    }

    if args
        .services
        .iter()
        .any(|f| matches!(f, server::args::Service::Crypto { .. }))
    {
        let sock = Async::<TcpListener>::bind(([127, 0, 0, 1], 32001)) //
            .expect("Cannot bind to 32001");
        let mut crypto_mgr_listener = server::crypto::Listener::new(sock, &args);
        async_ex
            .spawn(async move { crypto_mgr_listener.listen().await })
            .detach();
    }

    if args
        .services
        .iter()
        .any(|f| matches!(f, server::args::Service::Gms { .. }))
    {
        let sock = Async::<TcpListener>::bind(([127, 0, 0, 1], 38170)) //
            .expect("Cannot bind to 38170");
        let gms_listener = server::gms::Listener::new(sock, &args);
        async_ex
            .spawn(async move { gms_listener.listen().await })
            .detach();
    }

    if let Some(Service::Proxy(proxy)) = args
        .services
        .iter()
        .find(|f| matches!(f, server::args::Service::Proxy { .. }))
    {
        let sock =
            Async::<TcpListener>::bind(([127, 0, 0, 1], proxy.upstream_port)) //
                .unwrap_or_else(|e| panic!("Cannot bind to {}: {e}", proxy.upstream_port));
        let mut proxy_listener = server::proxy::Listener::new(sock, &args);
        async_ex
            .spawn(async move { proxy_listener.listen().await })
            .detach();
    }

    futures::executor::block_on(async_ex.run(future::pending::<()>()));
    // this never returns
}
