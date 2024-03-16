// SPDX-License-Identifier: MIT
// Copyright(c) 2023 Darek Stojaczyk

pub mod args;
pub mod packet_stream;

pub mod crypto_mgr;
pub mod event_mgr;
pub mod proxy;

use std::cell::RefCell;
use std::ops::{Deref, DerefMut};

use log::LevelFilter;
use smol::LocalExecutor;

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

thread_local! {
    static ASYNC_EX: RefCell<Option<&'static LocalExecutor<'static>>> = Default::default();
}

/// A per-thread executor. Any thread can create its own, which can be later obtained
/// in that thread with [`ThreadLocalExecutor::get`]. This utilizes thread local storage.
///
/// Currently the executors cannot communicate with each other, although that might
/// change in future
pub struct ThreadLocalExecutor<'a> {
    inner: Box<LocalExecutor<'a>>,
}

impl<'a> ThreadLocalExecutor<'a> {
    //
    #[allow(clippy::result_unit_err)]
    pub fn new() -> Result<Self, ()> {
        let ex = Box::new(LocalExecutor::new());
        ASYNC_EX.with(|refcell| {
            // Clippy says casting raw pointer to the same type and constness is unnecessary,
            // but its suggestion simply doesn't work. Ignore the warning for now.
            #[allow(clippy::unnecessary_cast)]
            let ptr = &*ex as *const _ as *const LocalExecutor<'static>;
            // SAFETY: we store the reference in global storage, and so we need to change
            // its lifetime to 'static, but the reference can be only accessed through our
            // [`ThreadLocalExecutor::get`] method which casts the lifetime back to 'a
            *refcell.borrow_mut() = Some(unsafe { ptr.as_ref() }.unwrap());
            Ok(())
        })?;

        Ok(Self { inner: ex })
    }

    pub fn get() -> Option<&'a LocalExecutor<'a>> {
        ASYNC_EX.with(|ex| {
            // Clippy says casting raw pointer to the same type and constness is unnecessary,
            // but its suggestion simply doesn't work. Ignore the warning for now.
            #[allow(clippy::unnecessary_cast)]
            let ptr = &*ex.borrow() as *const _ as *const Option<&'a LocalExecutor<'a>>;
            // SAFETY: We're casting the pointer to its original, real lifetime
            *unsafe { ptr.as_ref() }.unwrap()
        })
    }
}

impl<'a> Drop for ThreadLocalExecutor<'a> {
    fn drop(&mut self) {
        ASYNC_EX.with(|refcell| *refcell.borrow_mut() = None);
    }
}

impl<'a> Deref for ThreadLocalExecutor<'a> {
    type Target = LocalExecutor<'a>;
    fn deref(&self) -> &Self::Target {
        self.inner.as_ref()
    }
}

impl<'a> DerefMut for ThreadLocalExecutor<'a> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        self.inner.as_mut()
    }
}
