// SPDX-License-Identifier: MIT
// Copyright(c) 2023 Darek Stojaczyk

// Binary part of the application.
// Everything else is in lib.rs so it can be unit tested.

use futures::future;
use server::{executor, setup_log};
use smol::Async;
use std::{net::TcpListener, sync::Arc};

fn main() {
    setup_log(false);

    let args = Arc::new(server::args::parse());
    assert!(!args.services.is_empty());

    #[cfg(feature = "event")]
    if args
        .services
        .iter()
        .any(|f| matches!(f, server::args::Service::Event { .. }))
    {
        let sock = Async::<TcpListener>::bind(([127, 0, 0, 1], 38171)) //
            .expect("Cannot bind to 38171");
        let mut event_mgr_listener = server::event::Listener::new(sock, &args);
        executor::spawn_local(async move { event_mgr_listener.listen().await }).detach();
    }

    #[cfg(feature = "crypto")]
    if args
        .services
        .iter()
        .any(|f| matches!(f, server::args::Service::Crypto { .. }))
    {
        let sock = Async::<TcpListener>::bind(([127, 0, 0, 1], 32001)) //
            .expect("Cannot bind to 32001");
        let mut crypto_mgr_listener = server::crypto::Listener::new(sock, &args);
        executor::spawn_local(async move { crypto_mgr_listener.listen().await }).detach();
    }

    #[cfg(feature = "gms")]
    if args
        .services
        .iter()
        .any(|f| matches!(f, server::args::Service::Gms { .. }))
    {
        let sock = Async::<TcpListener>::bind(([127, 0, 0, 1], 38170)) //
            .expect("Cannot bind to 38170");
        let gms_listener = server::gms::Listener::new(sock, &args);
        executor::spawn_local(async move { gms_listener.listen().await }).detach();
    }

    #[cfg(feature = "proxy")]
    if let Some(server::args::Service::Proxy(proxy)) = args
        .services
        .iter()
        .find(|f| matches!(f, server::args::Service::Proxy { .. }))
    {
        let sock =
            Async::<TcpListener>::bind(([127, 0, 0, 1], proxy.upstream_port)) //
                .unwrap_or_else(|e| panic!("Cannot bind to {}: {e}", proxy.upstream_port));
        let mut proxy_listener = server::proxy::Listener::new(sock, &args);
        executor::spawn_local(async move { proxy_listener.listen().await }).detach();
    }

    #[cfg(feature = "login")]
    if args
        .services
        .iter()
        .any(|f| matches!(f, server::args::Service::Login { .. }))
    {
        let sock = Async::<TcpListener>::bind(([0, 0, 0, 0], 38101)) //
            .expect("Cannot bind to 38101");
        let listener = server::login::Listener::new(sock, &args);
        executor::spawn_local(async move { listener.listen().await }).detach();
    }

    executor::run_until(future::pending::<()>());
    // this never returns
}
