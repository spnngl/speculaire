//! The agent: its config, logs, metrics, status listener and systemd notifications; `apps/speculaire` parses arguments and calls [`run`].

mod cache;
#[cfg(test)]
mod capture;
pub mod config;
mod followed;
pub mod gate;
mod identity;
mod listen;
pub mod log;
pub mod node;
mod prewarm;
mod pulls;
mod serve;
pub mod status;
mod systemd;
pub mod telemetry;
pub mod trust;
pub mod verify;

pub use serve::run;
