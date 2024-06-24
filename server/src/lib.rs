// SPDX-License-Identifier: MIT
// Copyright(c) 2023 Darek Stojaczyk

pub mod args;
pub mod atomic_append_vec;
pub mod packet_stream;

pub mod crypto;
pub mod event;
pub mod gms;
pub mod proxy;

use std::borrow::Borrow;
use std::cell::RefCell;
use std::ops::{Deref, DerefMut};
use std::sync::OnceLock;

use futures::Future;
use log::LevelFilter;
use smol::lock::OnceCell;
use smol::{LocalExecutor, Task};

pub fn setup_log(is_test: bool) {
    let timestamp_fmt = match is_test {
        false => Some(env_logger::fmt::TimestampPrecision::Millis),
        true => None,
    };

    env_logger::Builder::new()
        .filter_module("polling", LevelFilter::Info)
        .filter_module("async_io", LevelFilter::Info)
        .parse_default_env()
        .format_timestamp(timestamp_fmt)
        .is_test(is_test)
        .init();
}

/// A per-thread executor. Any thread can create its own, which can be later obtained
/// in that thread with [`ThreadLocalExecutor::get`]. This utilizes thread local storage.
///
/// Currently the executors cannot communicate with each other, although that might
/// change in future
pub struct ThreadLocalExecutor;

impl ThreadLocalExecutor {
    pub fn spawn_local<F: Future<Output = T> + 'static + Send, T: 'static + Send>(
        future: F,
    ) -> Task<T> {
        smol::spawn(future)
    }
}
