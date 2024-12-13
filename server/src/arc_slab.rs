// SPDX-License-Identifier: MIT
// Copyright(c) 2024 Darek Stojaczyk

use std::sync::atomic::{AtomicPtr, Ordering};
use std::sync::Arc;

use crossbeam_queue::ArrayQueue;

pub struct ArcSlab<T> {
    vec: Vec<AtomicPtr<T>>,
    free_indices: ArrayQueue<u16>,
}

impl<T: std::fmt::Debug> std::fmt::Debug for ArcSlab<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.pad("ArcSlab { .. }")
    }
}

impl<T> ArcSlab<T> {
    pub fn new(capacity: usize) -> Self {
        Self::with_capacity(capacity)
    }

    pub fn with_capacity(capacity: usize) -> Self {
        assert!(capacity <= u16::MAX as usize + 1);
        let mut vec = Vec::with_capacity(capacity);
        vec.resize_with(capacity as usize, AtomicPtr::default);

        let free_indices = ArrayQueue::new(capacity);
        for i in 0..capacity {
            let _ = free_indices.push(i as u16);
        }

        Self { vec, free_indices }
    }

    pub fn capacity(&self) -> u16 {
        self.free_indices.capacity() as u16
    }

    pub fn len(&self) -> u16 {
        (self.free_indices.capacity() - self.free_indices.len()) as u16
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    pub fn reserve_index(&self) -> Option<u16> {
        self.free_indices.pop()
    }

    pub fn insert(&self, index: u16, arc: Arc<T>) {
        let raw = Arc::into_raw(arc);
        let slot = &self.vec[index as usize];
        slot.store(raw as *mut T, Ordering::Release);
    }

    pub fn get(&self, index: u16) -> Option<Arc<T>> {
        let slot = &self.vec[index as usize];
        let raw = slot.load(Ordering::Acquire);
        if raw.is_null() {
            return None;
        }
        // SAFETY: The ptr comes from [`Arc::into_raw`] without any
        // additional modifications
        let arc = unsafe { Arc::from_raw(raw) };
        // We'll be returning its clone
        let ret = arc.clone();
        std::mem::forget(arc);
        Some(ret)
    }

    pub fn remove(&self, index: u16) {
        let slot = &self.vec[index as usize];
        // no need for release ordering since there is nothing to synchronize with
        let raw = slot.swap(std::ptr::null_mut(), Ordering::Acquire);
        if raw.is_null() {
            return;
        }
        // SAFETY: The ptr comes from [`Arc::into_raw`] without any
        // additional modifications
        let _ = unsafe { Arc::from_raw(raw) };
        self.free_indices.push(index).unwrap();
    }
}
