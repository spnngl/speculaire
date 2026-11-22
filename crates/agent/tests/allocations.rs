//! The gate's fast path allocates nothing (D189): a `CreateContainer` whose identity is in memory and whose verdict is
//! kept, on each path, from the call's bytes on NRI's socket to the answer's, the runtime's side included. On the
//! `annotation` path, containerd's `/snapshot/prepare` event has named the snapshot's parent. Each test counts what
//! its thread allocates: every task of the gate runs on it.
#![expect(
    unsafe_code,
    reason = "a global allocator is unsafe to implement, and counting is all this one adds to the system's"
)]

#[expect(dead_code, reason = "the decision benchmarks' helpers go unused here")]
mod wire;

use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::Cell;

use speculaire_nri::Answer;
use wire::{Path, Wire};

/// Requests answered before counting: the first fill the buffers that are kept.
const WARM: u64 = 64;

/// Requests counted.
const REQUESTS: u64 = 256;

/// What `speculaire_gate_seconds` allocates over [`REQUESTS`]: its histogram keeps samples until a scrape in blocks of
/// 64 (metrics-util 0.20.4 `storage/bucket.rs:16`), one allocated when the last fills.
const HISTOGRAM_BLOCKS: u64 = REQUESTS / 64;

#[global_allocator]
static COUNTING: Counting = Counting;

thread_local! {
    static ALLOCATIONS: Cell<u64> = const { Cell::new(0) };
}

/// The system's allocator, counting each allocation and reallocation on the thread that asks for it.
struct Counting;

fn count() {
    // A thread that exits drops its count first: what it allocates then goes uncounted.
    let _ = ALLOCATIONS.try_with(|n| n.set(n.get().saturating_add(1)));
}

// SAFETY: every call goes to `System` with the caller's arguments, and so keeps its contract.
unsafe impl GlobalAlloc for Counting {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        count();
        // SAFETY: the caller keeps `alloc`'s contract.
        unsafe { System.alloc(layout) }
    }

    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        count();
        // SAFETY: the caller keeps `alloc_zeroed`'s contract.
        unsafe { System.alloc_zeroed(layout) }
    }

    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        count();
        // SAFETY: the caller keeps `realloc`'s contract, and `ptr` came from `System` through this allocator.
        unsafe { System.realloc(ptr, layout, new_size) }
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        // SAFETY: the caller keeps `dealloc`'s contract, and `ptr` came from `System` through this allocator.
        unsafe { System.dealloc(ptr, layout) }
    }
}

/// What [`REQUESTS`] allowed requests on `path` allocate, once warm.
fn allocations(path: Path) -> u64 {
    let mut wire = Wire::start(path, false);
    for _ in 0..WARM {
        assert_eq!(wire.create(), Answer::Allow);
    }
    let before = ALLOCATIONS.with(Cell::get);
    for _ in 0..REQUESTS {
        assert_eq!(wire.create(), Answer::Allow);
    }
    ALLOCATIONS.with(Cell::get) - before
}

#[test]
fn a_request_on_the_nri_path_allocates_nothing_but_histogram_blocks() {
    assert_eq!(allocations(Path::Nri), HISTOGRAM_BLOCKS);
}

#[test]
fn a_request_on_the_annotation_path_allocates_nothing_but_histogram_blocks() {
    assert_eq!(allocations(Path::Annotation), HISTOGRAM_BLOCKS);
}

#[test]
fn a_request_on_the_image_id_path_allocates_nothing_but_histogram_blocks() {
    assert_eq!(allocations(Path::ImageId), HISTOGRAM_BLOCKS);
}
