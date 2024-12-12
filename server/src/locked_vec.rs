// SPDX-License-Identifier: MIT
// Copyright(c) 2024 Darek Stojaczyk

use std::sync::{RwLock, RwLockReadGuard, RwLockWriteGuard};

/// Convenience wrapper over RwLock<Vec<T>>
pub struct LockedVec<T> {
    inner: RwLock<Vec<T>>,
}

impl<T> LockedVec<T> {
    pub fn new() -> Self {
        LockedVec {
            inner: RwLock::new(Vec::new()),
        }
    }

    pub fn with_capacity(capacity: usize) -> Self {
        LockedVec {
            inner: RwLock::new(Vec::with_capacity(capacity)),
        }
    }

    pub fn len(&self) -> usize {
        self.inner.read().unwrap().len()
    }

    pub fn is_empty(&self) -> bool {
        self.inner.read().unwrap().is_empty()
    }

    pub fn push(&self, value: T) {
        self.inner.write().unwrap().push(value);
    }

    pub fn remove(&self, index: usize) -> T {
        self.inner.write().unwrap().remove(index)
    }

    pub fn swap_remove(&self, index: usize) -> T {
        self.inner.write().unwrap().swap_remove(index)
    }

    pub fn lock_read(&self) -> RwLockReadGuard<'_, Vec<T>> {
        self.inner.read().unwrap()
    }

    pub fn lock_write(&self) -> RwLockWriteGuard<'_, Vec<T>> {
        self.inner.write().unwrap()
    }

    pub fn cloned(&self) -> Vec<T>
    where
        T: Clone,
    {
        self.inner.read().unwrap().clone()
    }

    pub fn first(&self) -> Option<T>
    where
        T: Clone,
    {
        self.inner.read().unwrap().first().cloned()
    }
}
