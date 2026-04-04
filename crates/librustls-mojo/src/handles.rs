//! Generic typed handle table.
//!
//! Maps `i32` handles to owned Rust objects. Thread-safe by default
//! (the whole map is wrapped in a `Mutex`). When the `skip-locks` feature
//! is enabled the mutex is removed and the caller is responsible for
//! ensuring single-threaded access.

use std::collections::HashMap;
use std::sync::atomic::{AtomicI32, Ordering};

/// Global counter that generates unique, positive handle IDs across all tables.
static NEXT_HANDLE: AtomicI32 = AtomicI32::new(1);

fn next_handle() -> i32 {
    NEXT_HANDLE.fetch_add(1, Ordering::Relaxed)
}

// ── lock-full build ──────────────────────────────────────────────────────────

#[cfg(not(feature = "skip-locks"))]
pub struct HandleTable<T> {
    map: std::sync::Mutex<HashMap<i32, T>>,
}

#[cfg(not(feature = "skip-locks"))]
impl<T> HandleTable<T> {
    pub fn new() -> Self {
        Self {
            map: std::sync::Mutex::new(HashMap::new()),
        }
    }

    /// Insert `value` and return a positive handle.
    pub fn insert(&self, value: T) -> i32 {
        let h = next_handle();
        self.map.lock().unwrap().insert(h, value);
        h
    }

    /// Call `f` with a shared reference to the object at `handle`.
    /// Returns `None` if the handle is not present.
    pub fn with<R>(&self, handle: i32, f: impl FnOnce(&T) -> R) -> Option<R> {
        let guard = self.map.lock().unwrap();
        guard.get(&handle).map(f)
    }

    /// Call `f` with an exclusive reference to the object at `handle`.
    /// Returns `None` if the handle is not present.
    pub fn with_mut<R>(&self, handle: i32, f: impl FnOnce(&mut T) -> R) -> Option<R> {
        let mut guard = self.map.lock().unwrap();
        guard.get_mut(&handle).map(f)
    }

    /// Remove and return the object at `handle`, or `None` if absent.
    pub fn remove(&self, handle: i32) -> Option<T> {
        self.map.lock().unwrap().remove(&handle)
    }
}

#[cfg(not(feature = "skip-locks"))]
impl<T> Default for HandleTable<T> {
    fn default() -> Self { Self::new() }
}

// ── lock-free build (skip-locks feature) ────────────────────────────────────

#[cfg(feature = "skip-locks")]
pub struct HandleTable<T> {
    // Safety: the caller guarantees single-threaded access when this feature
    // is enabled. We use UnsafeCell to allow interior mutability.
    map: std::cell::UnsafeCell<HashMap<i32, T>>,
}

#[cfg(feature = "skip-locks")]
// SAFETY: the skip-locks feature explicitly opts in to single-threaded use.
unsafe impl<T: Send> Send for HandleTable<T> {}
#[cfg(feature = "skip-locks")]
unsafe impl<T: Send> Sync for HandleTable<T> {}

#[cfg(feature = "skip-locks")]
impl<T> HandleTable<T> {
    pub fn new() -> Self {
        Self {
            map: std::cell::UnsafeCell::new(HashMap::new()),
        }
    }

    pub fn insert(&self, value: T) -> i32 {
        let h = next_handle();
        // SAFETY: caller guarantees exclusive access under skip-locks.
        unsafe { &mut *self.map.get() }.insert(h, value);
        h
    }

    pub fn with<R>(&self, handle: i32, f: impl FnOnce(&T) -> R) -> Option<R> {
        // SAFETY: shared borrow, caller guarantees no concurrent mutation.
        unsafe { &*self.map.get() }.get(&handle).map(f)
    }

    pub fn with_mut<R>(&self, handle: i32, f: impl FnOnce(&mut T) -> R) -> Option<R> {
        // SAFETY: exclusive borrow, caller guarantees single-threaded access.
        unsafe { &mut *self.map.get() }.get_mut(&handle).map(f)
    }

    pub fn remove(&self, handle: i32) -> Option<T> {
        // SAFETY: exclusive access guaranteed by caller.
        unsafe { &mut *self.map.get() }.remove(&handle)
    }
}

#[cfg(feature = "skip-locks")]
impl<T> Default for HandleTable<T> {
    fn default() -> Self { Self::new() }
}
