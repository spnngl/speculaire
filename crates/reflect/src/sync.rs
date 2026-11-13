//! The index's lock: std's, or Shuttle's in the tests of `--cfg shuttle`, which then explore the schedules (D97).

#[cfg(not(all(test, shuttle)))]
pub(crate) use std::sync::{Mutex, MutexGuard};

#[cfg(all(test, shuttle))]
pub(crate) use shuttle::sync::{Mutex, MutexGuard};
