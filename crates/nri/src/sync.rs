//! The queues' lock: std's, or Shuttle's in the tests of `--cfg shuttle`, which then explore the schedules (D163).

#[cfg(not(all(test, shuttle)))]
pub(crate) use std::sync::Mutex;

#[cfg(all(test, shuttle))]
pub(crate) use shuttle::sync::Mutex;
