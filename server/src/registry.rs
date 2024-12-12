// SPDX-License-Identifier: MIT
// Copyright(c) 2024 Darek Stojaczyk

use crate::atomic_append_vec::AtomicAppendVec;
use borrow_mutex::{BorrowGuardArmed, BorrowMutex};
use futures::FutureExt;

use std::sync::Arc;

pub struct BorrowRegistry<T, R> {
    pub refs: AtomicAppendVec<Arc<BorrowRef<T, R>>>,
}

impl<T, R> BorrowRegistry<T, R> {
    pub fn new(max_connections: usize) -> Self {
        Self {
            refs: AtomicAppendVec::with_capacity(max_connections),
        }
    }

    pub fn add_borrower(&self, data: R) -> Option<Arc<BorrowRef<T, R>>> {
        let conn_ref = BorrowRef::new(data);
        self.refs.push(conn_ref.clone()).ok()?;
        Some(conn_ref)
    }
}

const BORROW_MUTEX_SIZE: usize = 16;

#[allow(dead_code)]
pub trait Entry: Send + std::fmt::Display {
    type RefData;

    fn borrow_ref(&self) -> &Arc<BorrowRef<Self, Self::RefData>>
    where
        Self: Sized;

    fn lend_self(&mut self) -> impl std::future::Future<Output = ()>
    where
        Self: Sized,
    {
        async {
            self.borrow_ref().clone().borrower.lend(self).unwrap().await;
        }
    }

    fn lend_self_until<T>(
        &mut self,
        future: impl futures::Future<Output = T>,
    ) -> impl std::future::Future<Output = T>
    where
        Self: Sized,
    {
        async {
            let conn_ref = self.borrow_ref().clone();
            let mut future = core::pin::pin!(future.fuse());
            loop {
                async_proc::select! {
                    ret = future => {
                        return ret;
                    }
                    _ = conn_ref.borrower.wait_to_lend().fuse() => {
                        conn_ref.borrower.lend(self).unwrap().await;
                    }
                }
            }
        }
    }
}

#[macro_export]
macro_rules! impl_registry_entry {
    ($handler:ty, RefData = $borrow_ref_type:ty, borrow_ref = $(. $borrow_ref_name:ident)+) => {
        impl $crate::registry::Entry for $handler {
            type RefData = $borrow_ref_type;
            fn borrow_ref(&self) -> &::std::sync::Arc<crate::registry::BorrowRef<Self, Self::RefData>> {
                &self $(. $borrow_ref_name)+
            }
        }
    };
}

#[derive(Debug)]
pub struct BorrowRef<T, R> {
    /// An opaque unique identifier. This can be used to identify
    /// the connection without borrowing, and serves no other purpose.
    pub data: R,
    pub borrower: BorrowMutex<BORROW_MUTEX_SIZE, T>,
}

impl<T, R> BorrowRef<T, R> {
    pub fn new(data: R) -> Arc<BorrowRef<T, R>> {
        Arc::new(BorrowRef {
            data,
            borrower: BorrowMutex::new(),
        })
    }

    pub async fn borrow(&self) -> Result<BorrowGuardArmed<'_, T>, borrow_mutex::Error> {
        self.borrower.request_borrow().await
    }
}
