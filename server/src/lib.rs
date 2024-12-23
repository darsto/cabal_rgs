// SPDX-License-Identifier: MIT
// Copyright(c) 2023 Darek Stojaczyk

pub mod arc_slab;
pub mod args;
pub mod locked_vec;
pub mod packet_stream;
pub mod registry;

#[cfg(feature = "crypto")]
pub mod crypto;
#[cfg(feature = "event")]
pub mod event;
#[cfg(feature = "gms")]
pub mod gms;
#[cfg(feature = "login")]
pub mod login;
#[cfg(feature = "party")]
pub mod party;
#[cfg(feature = "proxy")]
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

/// Hopefuly we'll see async for loops in stable rust one day
#[macro_export]
macro_rules! async_for_each {
    ($item:ident in $iter:expr => $b:block) => {
        {
            let mut iter = core::pin::pin!($iter);
            while let Some($item) = iter.next().await $b
        }
    };
    (mut $item:ident in $iter:expr => $b:block) => {
        {
            let mut iter = core::pin::pin!($iter);
            while let Some(mut $item) = iter.next().await $b
        }
    };
}
