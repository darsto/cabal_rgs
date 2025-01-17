// SPDX-License-Identifier: MIT
// Copyright(c) 2024 Darek Stojaczyk

use borrow_mutex::{BorrowGuardArmed, BorrowMutex};
use futures::FutureExt;

use std::sync::Arc;

use crate::{arc_slab::ArcSlab, executor};

pub struct BorrowRegistry<T, R> {
    pub refs: ArcSlab<BorrowRef<T, R>>,
}

impl<T, R> BorrowRegistry<T, R> {
    pub fn new(max_connections: usize) -> Self {
        Self {
            refs: ArcSlab::with_capacity(max_connections),
        }
    }

    pub fn register(&self, data: R) -> Option<Arc<BorrowRef<T, R>>> {
        let idx = self.refs.reserve_index()?;
        let borrow_ref = Arc::new(BorrowRef {
            idx,
            data,
            borrower: BorrowMutex::new(),
        });
        self.refs.insert(idx, borrow_ref.clone());
        Some(borrow_ref)
    }

    pub fn unregister(&self, borrow_ref: &BorrowRef<T, R>) {
        self.refs.remove(borrow_ref.idx);
    }
}

const BORROW_MUTEX_SIZE: usize = 16;

#[allow(dead_code)]
pub trait Borrowable: Send + std::fmt::Display {
    type RefData;

    fn borrow_ref(&self) -> &Arc<BorrowRef<Self, Self::RefData>>
    where
        Self: Sized;

    fn lend_self(&mut self) -> impl std::future::Future<Output = ()> + '_
    where
        Self: Sized,
    {
        async {
            self.borrow_ref().clone().borrower.lend(self).unwrap().await;
        }
    }

    fn lend_self_until<'a, T>(
        &'a mut self,
        future: impl futures::Future<Output = T> + 'a,
    ) -> impl std::future::Future<Output = T> + 'a
    where
        T: 'a,
        Self: Sized,
    {
        // SAFETY: The Future we return has same lifetime as `future`
        let task = unsafe { executor::spawn_local_scoped(future) };

        async move {
            let conn_ref = self.borrow_ref().clone();
            let mut task = core::pin::pin!(task.fuse());
            loop {
                async_proc::select! {
                    ret = task => {
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
macro_rules! impl_borrowable {
    ($handler:ty, RefData = $borrow_ref_type:ty, borrow_ref = $(. $borrow_ref_name:ident)+) => {
        impl $crate::registry::Borrowable for $handler {
            type RefData = $borrow_ref_type;
            fn borrow_ref(&self) -> &::std::sync::Arc<$crate::registry::BorrowRef<Self, Self::RefData>> {
                &self $(. $borrow_ref_name)+
            }
        }
    };
}

#[derive(Debug)]
pub struct BorrowRef<T, R> {
    /// Index inside [`BorrowRegistry`], if used.
    pub idx: u16,
    /// An opaque unique identifier. This can be used to identify
    /// the connection without borrowing, and serves no other purpose.
    pub data: R,
    pub borrower: BorrowMutex<BORROW_MUTEX_SIZE, T>,
}

impl<T, R> BorrowRef<T, R> {
    pub fn new(data: R) -> Arc<BorrowRef<T, R>> {
        Arc::new(BorrowRef {
            idx: 0,
            data,
            borrower: BorrowMutex::new(),
        })
    }

    pub async fn borrow(&self) -> Result<BorrowGuardArmed<'_, T>, borrow_mutex::Error> {
        self.borrower.try_borrow().await
    }
}
