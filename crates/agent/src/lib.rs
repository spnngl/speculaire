//! The agent: its config, logs, metrics and status listener; `apps/speculaire` parses arguments and calls [`run`].

pub mod config;
pub mod log;
mod serve;
pub mod status;
pub mod telemetry;

pub use serve::run;
