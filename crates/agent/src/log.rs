//! Diagnostic and audit logs (D37): journald under systemd, JSON on stderr otherwise.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use anyhow::Context as _;
use tracing_subscriber::filter::{FilterExt as _, filter_fn};
use tracing_subscriber::layer::SubscriberExt as _;
use tracing_subscriber::util::SubscriberInitExt as _;
use tracing_subscriber::{EnvFilter, Layer as _, Registry, reload};

use crate::config;

/// The target of audit events; they bypass `log.filter` and follow `audit.enabled` (D37).
pub const AUDIT_TARGET: &str = "speculaire::audit";

/// The syslog identifier of audit events in journald: `journalctl -t speculaire-audit` shows them alone (D37).
const AUDIT_IDENTIFIER: &str = "speculaire-audit";

/// The installed subscriber's live settings.
pub struct Logs {
    filter: reload::Handle<EnvFilter, Registry>,
    audit: Arc<AtomicBool>,
}

impl Logs {
    /// Applies `log.filter` and `audit.enabled` from a reloaded config.
    ///
    /// # Panics
    ///
    /// When the subscriber is gone: [`install`] made it the global default, which lives as long as the process.
    pub fn apply(&self, log: &config::Log, audit: &config::Audit) {
        self.filter
            .reload(log.filter.env_filter())
            .expect("the global subscriber outlives the agent");
        self.audit.store(audit.enabled, Ordering::Relaxed);
    }
}

/// Installs the global subscriber: journald when `JOURNAL_STREAM` is set, JSON on stderr otherwise.
///
/// # Errors
///
/// When the journald socket cannot be opened, or a subscriber is already installed.
pub fn install(log: &config::Log, audit: &config::Audit) -> anyhow::Result<Logs> {
    let (filter, handle) = reload::Layer::new(log.filter.env_filter());
    let diagnostics = filter.and(filter_fn(|meta| meta.target() != AUDIT_TARGET));
    let enabled = Arc::new(AtomicBool::new(audit.enabled));
    let audit_on = Arc::clone(&enabled);
    let audits =
        filter_fn(move |meta| meta.target() == AUDIT_TARGET && audit_on.load(Ordering::Relaxed));

    // Both layers sit directly on the registry, so the filter handle's subscriber type stays `Registry`.
    let layers: Vec<Box<dyn tracing_subscriber::Layer<Registry> + Send + Sync>> =
        if std::env::var_os("JOURNAL_STREAM").is_some() {
            let journald = || tracing_journald::layer().context("opening the journald socket");
            vec![
                journald()?.with_filter(diagnostics).boxed(),
                journald()?
                    .with_syslog_identifier(AUDIT_IDENTIFIER.to_owned())
                    .with_filter(audits)
                    .boxed(),
            ]
        } else {
            let json = || {
                tracing_subscriber::fmt::layer()
                    .json()
                    .with_writer(std::io::stderr)
            };
            vec![
                json().with_filter(diagnostics).boxed(),
                json().with_filter(audits).boxed(),
            ]
        };
    Registry::default()
        .with(layers)
        .try_init()
        .context("installing the log subscriber")?;
    Ok(Logs {
        filter: handle,
        audit: enabled,
    })
}
