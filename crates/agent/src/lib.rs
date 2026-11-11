//! The agent: its config, logs, metrics, status listener and systemd notifications; `apps/speculaire` parses arguments and calls [`run`].

pub mod config;
pub mod log;
mod serve;
pub mod status;
mod systemd;
pub mod telemetry;

pub use serve::run;
