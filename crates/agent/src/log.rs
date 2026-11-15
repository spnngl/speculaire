//! Diagnostic and audit logs (D37): journald under systemd, JSON on stderr otherwise.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use anyhow::Context as _;
/// The target of audit events; they bypass `log.filter` and follow `audit.enabled` (D37). The crates that audit name it.
pub use speculaire_mirror::fetch::AUDIT_TARGET;
use tracing_subscriber::filter::{FilterExt as _, filter_fn};
use tracing_subscriber::layer::SubscriberExt as _;
use tracing_subscriber::util::SubscriberInitExt as _;
use tracing_subscriber::{EnvFilter, Layer as _, Registry, reload};

use crate::config;

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
        // The reload asks every callsite again, and a filter's answer sticks: the flag it reads must be new by then.
        self.audit.store(audit.enabled, Ordering::Relaxed);
        self.filter
            .reload(log.filter.env_filter())
            .expect("the global subscriber outlives the agent");
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
    let audits = audit_filter(Arc::clone(&enabled));

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

/// Passes the audit events while `enabled` is set, and nothing else.
fn audit_filter<S>(enabled: Arc<AtomicBool>) -> impl tracing_subscriber::layer::Filter<S> {
    filter_fn(move |meta| meta.target() == AUDIT_TARGET && enabled.load(Ordering::Relaxed))
}

#[cfg(test)]
mod tests {
    use std::io;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::{Arc, Mutex};

    use tracing::info;
    use tracing_subscriber::filter::{FilterExt as _, filter_fn};
    use tracing_subscriber::layer::SubscriberExt as _;
    use tracing_subscriber::{Layer as _, Registry, fmt, reload};

    use super::{AUDIT_TARGET, Logs, audit_filter};
    use crate::config;

    /// A writer that keeps what the subscriber writes.
    struct Sink(Arc<Mutex<Vec<u8>>>);

    impl io::Write for Sink {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(buf);
            Ok(buf.len())
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn the_audit_layer_passes_audit_events_while_enabled() {
        let enabled = Arc::new(AtomicBool::new(false));
        let written = Arc::new(Mutex::new(Vec::new()));
        let subscriber = Registry::default().with(
            fmt::layer()
                .with_writer({
                    let written = Arc::clone(&written);
                    move || Sink(Arc::clone(&written))
                })
                .with_filter(audit_filter(Arc::clone(&enabled))),
        );
        tracing::subscriber::with_default(subscriber, || {
            info!(target: AUDIT_TARGET, "audit while off");
            enabled.store(true, Ordering::Relaxed);
            info!(target: AUDIT_TARGET, "audit while on");
            info!(target: "speculaire::other", "diagnostic while on");
        });
        let written = String::from_utf8(written.lock().unwrap().clone()).unwrap();
        assert!(written.contains("audit while on"), "{written}");
        assert!(!written.contains("audit while off"), "{written}");
        assert!(!written.contains("diagnostic"), "{written}");
    }

    #[test]
    fn audit_turned_on_by_a_reload_reaches_a_callsite_seen_while_off() {
        let (filter, handle) = reload::Layer::new(config::Log::default().filter.env_filter());
        let logs = Logs {
            filter: handle,
            audit: Arc::new(AtomicBool::new(false)),
        };
        let written = Arc::new(Mutex::new(Vec::new()));
        let writer = {
            let written = Arc::clone(&written);
            move || Sink(Arc::clone(&written))
        };
        // As `install` layers them: both filters refuse an audit event while audit is off.
        let subscriber = Registry::default()
            .with(
                fmt::layer()
                    .with_writer(writer.clone())
                    .with_filter(filter.and(filter_fn(|meta| meta.target() != AUDIT_TARGET))),
            )
            .with(
                fmt::layer()
                    .with_writer(writer)
                    .with_filter(audit_filter(Arc::clone(&logs.audit))),
            );
        tracing::subscriber::with_default(subscriber, || {
            for enabled in [false, true] {
                logs.apply(&config::Log::default(), &config::Audit { enabled });
                info!(target: AUDIT_TARGET, enabled, "one callsite");
            }
        });
        let written = String::from_utf8(written.lock().unwrap().clone()).unwrap();
        assert!(written.contains("enabled=true"), "{written}");
        assert!(!written.contains("enabled=false"), "{written}");
    }
}
