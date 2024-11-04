// SPDX-License-Identifier: MIT
// Copyright(c) 2024 Darek Stojaczyk

use crate::atomic_append_vec::AtomicAppendVec;
use borrow_mutex::{BorrowGuardArmed, BorrowMutex};
use futures::FutureExt;
use futures::Stream;

use core::any::Any;
use std::any::TypeId;
use std::sync::Arc;

pub struct BorrowRegistry<T> {
    pub name: String,
    pub refs: AtomicAppendVec<Arc<BorrowRef<T>>>,
}

impl<T> BorrowRegistry<T> {
    pub fn new(name: impl Into<String>, max_connections: usize) -> Self {
        Self {
            name: name.into(),
            refs: AtomicAppendVec::with_capacity(max_connections),
        }
    }

    pub fn add_borrower(&self, type_id: TypeId, data: T) -> Option<Arc<BorrowRef<T>>> {
        let conn_ref = Arc::new(BorrowRef {
            type_id,
            data,
            borrower: BorrowMutex::new(),
        });
        self.refs.push(conn_ref.clone()).ok()?;
        Some(conn_ref)
    }

    pub fn borrow_multiple<'a, H>(
        refs: impl IntoIterator<Item = &'a (impl AsRef<BorrowRef<T>> + 'a)>,
    ) -> impl Stream<Item = BorrowGuardArmed<'a, H>>
    where
        H: Entry,
        T: 'static,
    {
        futures::stream::unfold(refs.into_iter(), move |mut iter| async {
            while let Some(next) = iter.next() {
                if next.as_ref().type_id != TypeId::of::<H>() {
                    continue;
                }
                if let Ok(handler) = next.as_ref().borrower.request_borrow().await {
                    return Some((
                        BorrowGuardArmed::map(handler, |handler| {
                            handler.as_any_mut().downcast_mut::<H>().unwrap()
                        }),
                        iter,
                    ));
                }
            }
            None
        })
    }
}

impl<T> std::fmt::Display for BorrowRegistry<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.name)
    }
}

const BORROW_MUTEX_SIZE: usize = 16;

#[allow(dead_code)]
pub trait Entry: AsAny + Send + std::fmt::Display {
    type RefData;

    /// The type that can be borrowed
    fn borrower_id() -> TypeId
    where
        Self: Sized;

    fn borrow_ref(&self) -> &Arc<BorrowRef<Self::RefData>>;
    fn data(&self) -> &dyn Any;
    fn data_mut(&mut self) -> &mut dyn Any;

    fn lend_self(&mut self) -> impl std::future::Future<Output = ()>
    where
        Self: Sized,
    {
        async {
            self.borrow_ref()
                .clone()
                .borrower
                .lend(self as &mut dyn Entry<RefData = Self::RefData>)
                .unwrap()
                .await;
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
            let mut wait_to_lend = core::pin::pin!(conn_ref.borrower.wait_to_lend().fuse());
            loop {
                async_proc::select! {
                    ret = future => {
                        return ret;
                    }
                    _ = wait_to_lend => {
                        conn_ref.borrower.lend(self as &mut dyn Entry<RefData = Self::RefData>).unwrap().await;
                    }
                }
            }
        }
    }
}

#[allow(dead_code)]
pub trait AsAny: Any {
    fn as_any(&self) -> &dyn Any;
    fn as_any_mut(&mut self) -> &mut dyn Any;
}

impl<T: Any> AsAny for T {
    fn as_any(&self) -> &dyn Any {
        self
    }
    fn as_any_mut(&mut self) -> &mut dyn Any {
        self
    }
}

#[macro_export]
macro_rules! impl_registry_entry {
    ($handler:ident, $borrow_ref_type:path, $(. $data_name:ident)+, $(. $borrow_ref_name:ident)+) => {
        impl $crate::registry::Entry for $handler {
            type RefData = $borrow_ref_type;
            fn borrower_id() -> ::core::any::TypeId {
                ::core::any::TypeId::of::<Self>()
            }
            fn data(&self) -> &dyn ::core::any::Any {
                &self $(. $data_name)+ as _
            }
            fn data_mut(&mut self) -> &mut dyn ::core::any::Any {
                &mut self $(. $data_name)+ as _
            }
            fn borrow_ref(&self) -> &::std::sync::Arc<crate::registry::BorrowRef<Self::RefData>> {
                &self $(. $borrow_ref_name)+
            }
        }
    };
}

#[derive(Debug)]
pub struct BorrowRef<T> {
    /// The type that can be borrowed
    pub type_id: TypeId,
    /// An opaque unique identifier. This can be used to identify
    /// the connection without borrowing, and serves no other purpose.
    pub data: T,
    pub borrower: BorrowMutex<BORROW_MUTEX_SIZE, dyn Entry<RefData = T>>,
}

impl<T> BorrowRef<T> {
    pub async fn borrow<'a, H: Entry>(&'a self) -> Result<BorrowGuardArmed<'a, H>, ()>
    where
        T: 'static,
    {
        if self.type_id != TypeId::of::<H>() {
            return Err(());
        }
        self.borrower
            .request_borrow()
            .await
            .map(|entry| {
                BorrowGuardArmed::map(entry, |entry| {
                    entry.as_any_mut().downcast_mut::<H>().unwrap()
                })
            })
            .map_err(|_| ())
    }
}
