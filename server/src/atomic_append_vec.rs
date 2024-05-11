// SPDX-License-Identifier: MIT
// Copyright(c) 2024 Darek Stojaczyk

use std::ops::{Index, IndexMut};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::OnceLock;

pub struct AtomicAppendVec<T> {
    vec: Vec<OnceLock<T>>,
    len: AtomicUsize,
}

impl<T: std::fmt::Debug> std::fmt::Debug for AtomicAppendVec<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.vec.fmt(f)
    }
}

impl<T> AtomicAppendVec<T> {
    pub fn new() -> Self {
        Self {
            vec: Vec::new(),
            len: AtomicUsize::new(0),
        }
    }

    pub fn with_capacity(capacity: usize) -> Self {
        let mut vec = Vec::with_capacity(capacity);
        vec.resize_with(capacity, Default::default);
        Self {
            vec,
            len: AtomicUsize::new(0),
        }
    }

    pub fn len(&self) -> usize {
        self.len.load(Ordering::Relaxed)
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    pub fn push(&self, value: T) -> Result<&T, T> {
        let idx = self.len.fetch_add(1, Ordering::Relaxed);
        if idx >= self.vec.capacity() {
            self.len.store(self.vec.capacity(), Ordering::Relaxed);
            Err(value)
        } else {
            Ok(self.vec[idx].get_or_init(|| value))
        }
    }

    pub fn iter(&self) -> impl Iterator<Item = &T> {
        self.vec
            .iter()
            .filter_map(|cell| cell.get())
            .take(self.len.load(Ordering::Relaxed))
    }

    pub fn iter_mut(&mut self) -> impl Iterator<Item = &mut T> {
        self.vec
            .iter_mut()
            .filter_map(|cell| cell.get_mut())
            .take(self.len.load(Ordering::Relaxed))
    }

    #[allow(clippy::should_implement_trait)]
    pub fn into_iter(self) -> impl Iterator<Item = T> {
        self.vec
            .into_iter()
            .filter_map(|cell| cell.into_inner())
            .take(self.len.load(Ordering::Relaxed))
    }
}

impl<T> Index<usize> for AtomicAppendVec<T> {
    type Output = T;

    fn index(&self, index: usize) -> &Self::Output {
        if index >= self.len() {
            panic!("Access out of bounds");
        }

        self.vec.index(index).get().unwrap()
    }
}

impl<T> IndexMut<usize> for AtomicAppendVec<T> {
    fn index_mut(&mut self, index: usize) -> &mut Self::Output {
        if index >= self.len() {
            panic!("Access out of bounds");
        }

        self.vec.index_mut(index).get_mut().unwrap()
    }
}

impl<T> Default for AtomicAppendVec<T> {
    fn default() -> Self {
        Self::new()
    }
}
