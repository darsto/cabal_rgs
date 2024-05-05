// SPDX-License-Identifier: MIT
// Copyright(c) 2024 Darek Stojaczyk

use std::cell::UnsafeCell;
use std::mem::MaybeUninit;
use std::ops::{Index, IndexMut};
use std::slice::{Iter, IterMut};
use std::sync::atomic::{AtomicUsize, Ordering};

pub struct AtomicAppendVec<T> {
    vec: Vec<UnsafeCell<MaybeUninit<T>>>,
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
        Self {
            vec: Vec::with_capacity(capacity),
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
            // SAFETY: we are the only ones referencing this memory
            let slot = unsafe { &mut *self.vec[idx].get() };
            Ok(slot.write(value))
        }
    }

    pub fn iter(&self) -> std::iter::Take<Iter<'_, T>> {
        unsafe { std::mem::transmute(self.vec.iter().take(self.len.load(Ordering::Relaxed))) }
    }

    pub fn iter_mut(&mut self) -> std::iter::Take<IterMut<'_, T>> {
        unsafe { std::mem::transmute(self.vec.iter_mut().take(self.len.load(Ordering::Relaxed))) }
    }
}

impl<T> IntoIterator for AtomicAppendVec<T> {
    type Item = T;
    type IntoIter = std::iter::Take<std::vec::IntoIter<T>>;
    fn into_iter(self) -> Self::IntoIter {
        unsafe { std::mem::transmute(self.vec.into_iter().take(self.len.load(Ordering::Relaxed))) }
    }
}

impl<T> Index<usize> for AtomicAppendVec<T> {
    type Output = T;

    fn index(&self, index: usize) -> &Self::Output {
        if index >= self.len() {
            panic!("Access out of bounds");
        }

        unsafe { std::mem::transmute(self.vec.index(index)) }
    }
}

impl<T> IndexMut<usize> for AtomicAppendVec<T> {
    fn index_mut(&mut self, index: usize) -> &mut Self::Output {
        if index >= self.len() {
            panic!("Access out of bounds");
        }

        unsafe { std::mem::transmute(self.vec.index_mut(index)) }
    }
}

impl<T> Default for AtomicAppendVec<T> {
    fn default() -> Self {
        Self::new()
    }
}
