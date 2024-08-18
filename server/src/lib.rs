// SPDX-License-Identifier: MIT
// Copyright(c) 2023 Darek Stojaczyk

pub mod args;
pub mod atomic_append_vec;
pub mod packet_stream;

pub mod crypto;
pub mod event;
pub mod gms;
pub mod proxy;

use log::LevelFilter;

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

pub mod executor {
    use futures::Future;
    use smol::{LocalExecutor, Task};

    thread_local! {
        static ASYNC_EX: LocalExecutor<'static> = LocalExecutor::new();
    }

    pub fn spawn_local<F: Future<Output = T> + 'static, T: 'static>(future: F) -> Task<T> {
        ASYNC_EX.with(|ex| ex.spawn(future))
    }

    pub fn run_until<F: Future<Output = T> + 'static, T: 'static + Send>(future: F) -> T {
        ASYNC_EX.with(|ex| futures::executor::block_on(ex.run(future)))
    }
}
