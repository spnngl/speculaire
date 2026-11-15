//! Diagnostic and audit logs (D37): journald under systemd, JSON on stderr otherwise; span timings on stderr.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use anyhow::Context as _;
/// The target of audit events; they bypass `log.filter` and follow `audit.enabled` (D37). The crates that audit name it.
pub use speculaire_mirror::fetch::AUDIT_TARGET;
use tracing_subscriber::filter::{FilterExt as _, filter_fn};
use tracing_subscriber::fmt::format::FmtSpan;
use tracing_subscriber::layer::SubscriberExt as _;
use tracing_subscriber::util::SubscriberInitExt as _;
use tracing_subscriber::{EnvFilter, Layer as _, Registry, reload};

use crate::config;

/// The syslog identifier of audit events in journald: `journalctl -t speculaire-audit` shows them alone (D37).
const AUDIT_IDENTIFIER: &str = "speculaire-audit";

/// The installed subscriber's live settings.
pub struct Logs {
    filter: reload::Handle<EnvFilter, Registry>,
    /// `log.filter` again, for the timings: an `EnvFilter` filters one layer.
    spans: reload::Handle<EnvFilter, Registry>,
    audit: Arc<AtomicBool>,
    timings: Arc<AtomicBool>,
}

impl Logs {
    /// Applies `log.filter`, `log.timings` and `audit.enabled` from a reloaded config.
    ///
    /// # Panics
    ///
    /// When the subscriber is gone: [`install`] made it the global default, which lives as long as the process.
    pub fn apply(&self, log: &config::Log, audit: &config::Audit) {
        // The reload asks every callsite again, and a filter's answer sticks: the flags it reads must be new by then.
        self.audit.store(audit.enabled, Ordering::Relaxed);
        self.timings.store(log.timings, Ordering::Relaxed);
        for handle in [&self.filter, &self.spans] {
            handle
                .reload(log.filter.env_filter())
                .expect("the global subscriber outlives the agent");
        }
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
    let (spans, spans_handle) = reload::Layer::new(log.filter.env_filter());
    let timings = Arc::new(AtomicBool::new(log.timings));

    // Every layer sits directly on the registry, so the filter handles' subscriber type stays `Registry`.
    let mut layers: Vec<Box<dyn tracing_subscriber::Layer<Registry> + Send + Sync>> =
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
    // journald has no span closes: the timings go to stderr in both cases, which systemd also sends to the journal.
    layers.push(
        tracing_subscriber::fmt::layer()
            .json()
            .with_writer(std::io::stderr)
            .with_span_events(FmtSpan::CLOSE)
            .with_filter(spans.and(timings_filter(Arc::clone(&timings))))
            .boxed(),
    );
    Registry::default()
        .with(layers)
        .try_init()
        .context("installing the log subscriber")?;
    Ok(Logs {
        filter: handle,
        spans: spans_handle,
        audit: enabled,
        timings,
    })
}

/// Passes spans while `enabled` is set, and no event: the layer writes a span's close itself.
fn timings_filter<S>(enabled: Arc<AtomicBool>) -> impl tracing_subscriber::layer::Filter<S> {
    filter_fn(move |meta| meta.is_span() && enabled.load(Ordering::Relaxed))
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

    use tracing::{debug_span, info};
    use tracing_subscriber::filter::{FilterExt as _, filter_fn};
    use tracing_subscriber::fmt::format::FmtSpan;
    use tracing_subscriber::layer::{Identity, SubscriberExt as _};
    use tracing_subscriber::{EnvFilter, Layer as _, Registry, fmt, reload};

    use super::{AUDIT_TARGET, Logs, audit_filter, timings_filter};
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

    /// Logs as `install` builds them, with the diagnostics' filter and the timings': a test layers both, or `apply`
    /// finds a filter gone.
    fn logs() -> (
        Logs,
        reload::Layer<EnvFilter, Registry>,
        reload::Layer<EnvFilter, Registry>,
    ) {
        let (filter, handle) = reload::Layer::new(config::Log::default().filter.env_filter());
        let (spans, spans_handle) = reload::Layer::new(config::Log::default().filter.env_filter());
        let logs = Logs {
            filter: handle,
            spans: spans_handle,
            audit: Arc::new(AtomicBool::new(false)),
            timings: Arc::new(AtomicBool::new(false)),
        };
        (logs, filter, spans)
    }

    #[test]
    fn audit_turned_on_by_a_reload_reaches_a_callsite_seen_while_off() {
        let (logs, filter, spans) = logs();
        let written = Arc::new(Mutex::new(Vec::new()));
        let writer = {
            let written = Arc::clone(&written);
            move || Sink(Arc::clone(&written))
        };
        // As `install` layers them: both filters refuse an audit event while audit is off.
        let subscriber = Registry::default().with(vec![
            fmt::layer()
                .with_writer(writer.clone())
                .with_filter(filter.and(filter_fn(|meta| meta.target() != AUDIT_TARGET)))
                .boxed(),
            fmt::layer()
                .with_writer(writer)
                .with_filter(audit_filter(Arc::clone(&logs.audit)))
                .boxed(),
            Identity::new().with_filter(spans).boxed(),
        ]);
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

    #[test]
    fn timings_turned_on_by_a_reload_log_the_close_of_each_span_the_filter_passes_and_no_event() {
        let (logs, filter, spans) = logs();
        let written = Arc::new(Mutex::new(Vec::new()));
        let subscriber = Registry::default().with(vec![
            Identity::new().with_filter(filter).boxed(),
            fmt::layer()
                .with_writer({
                    let written = Arc::clone(&written);
                    move || Sink(Arc::clone(&written))
                })
                .with_span_events(FmtSpan::CLOSE)
                .with_filter(spans.and(timings_filter(Arc::clone(&logs.timings))))
                .boxed(),
        ]);
        let debug = config::Log {
            filter: "debug".parse().unwrap(),
            timings: true,
        };
        tracing::subscriber::with_default(subscriber, || {
            let warn = config::Log::default();
            let cases = [
                warn.clone(),
                config::Log {
                    timings: true,
                    ..warn
                },
                debug.clone(),
                config::Log {
                    timings: false,
                    ..debug
                },
            ];
            for log in cases {
                logs.apply(&log, &config::Audit::default());
                let _span = debug_span!(
                    "one span",
                    timings = log.timings,
                    filter = log.filter.as_str()
                )
                .entered();
                info!(target: "speculaire::other", "an event inside");
            }
        });
        let written = String::from_utf8(written.lock().unwrap().clone()).unwrap();
        let closes: Vec<_> = written
            .lines()
            .filter(|line| line.contains("close time.busy="))
            .collect();
        assert_eq!(closes.len(), 1, "{written}");
        assert!(
            closes[0].contains(r#"one span{timings=true filter="debug"}"#),
            "{written}"
        );
        assert!(!written.contains("an event inside"), "{written}");
    }
}
