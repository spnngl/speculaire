//! The disk that blobs in flight take under `blob_cache.directory` (D205): the fetcher's staging files and the blob
//! cache's writes. A staging file claims its bytes before it writes them, within `blob_cache.max_size`; a cache write
//! counts its bytes as it writes them, never refused, and the cache evicts what it keeps to make room.

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

/// The bound and what is claimed of it; a handle, cheap to clone.
#[derive(Clone, Debug)]
pub struct Space(Arc<Inner>);

#[derive(Debug)]
struct Inner {
    max: AtomicU64,
    claimed: AtomicU64,
}

impl Space {
    /// A space of `max` bytes, none claimed.
    #[must_use]
    pub fn new(max: u64) -> Self {
        Self(Arc::new(Inner {
            max: AtomicU64::new(max),
            claimed: AtomicU64::new(0),
        }))
    }

    /// The bound.
    #[must_use]
    pub fn max(&self) -> u64 {
        self.0.max.load(Ordering::Relaxed)
    }

    /// Changes the bound (`blob_cache.max_size` reloads live, D30). Claims made stay; the next ones follow it.
    pub fn set_max(&self, max: u64) {
        self.0.max.store(max, Ordering::Relaxed);
    }

    /// The bytes claimed now.
    #[must_use]
    pub fn claimed(&self) -> u64 {
        self.0.claimed.load(Ordering::Relaxed)
    }

    /// A claim of `bytes`, or `None` when it would bring what is claimed past the bound.
    #[must_use]
    pub fn claim(&self, bytes: u64) -> Option<Claim> {
        let mut claim = self.count();
        claim.grow(bytes).then_some(claim)
    }

    /// A claim of nothing, which [`Claim::add`] grows past the bound if it must.
    #[must_use]
    pub fn count(&self) -> Claim {
        Claim {
            space: self.clone(),
            bytes: 0,
        }
    }
}

/// Bytes claimed of a [`Space`], given back when it drops.
#[derive(Debug)]
pub struct Claim {
    space: Space,
    bytes: u64,
}

impl Claim {
    /// Claims `more` bytes; `false`, claiming nothing, when that would bring what is claimed past the bound.
    pub fn grow(&mut self, more: u64) -> bool {
        let inner = &self.space.0;
        let max = inner.max.load(Ordering::Relaxed);
        let mut claimed = inner.claimed.load(Ordering::Relaxed);
        loop {
            let Some(total) = claimed.checked_add(more).filter(|&total| total <= max) else {
                return false;
            };
            match inner.claimed.compare_exchange_weak(
                claimed,
                total,
                Ordering::Relaxed,
                Ordering::Relaxed,
            ) {
                Ok(_) => break,
                Err(now) => claimed = now,
            }
        }
        self.bytes += more;
        true
    }

    /// Claims `more` bytes, past the bound if it must.
    pub fn add(&mut self, more: u64) {
        self.space.0.claimed.fetch_add(more, Ordering::Relaxed);
        self.bytes += more;
    }

    /// The bytes it holds.
    #[must_use]
    pub const fn bytes(&self) -> u64 {
        self.bytes
    }
}

impl Drop for Claim {
    fn drop(&mut self) {
        self.space
            .0
            .claimed
            .fetch_sub(self.bytes, Ordering::Relaxed);
    }
}

#[cfg(test)]
mod tests;
