//! A tracing subscriber that the tests read back: what the agent logs and audits.

use std::sync::{Arc, Mutex};

use tracing::Level;

use crate::log::AUDIT_TARGET;

/// What a test's subscriber writes.
#[derive(Clone, Default)]
pub(crate) struct Capture(Arc<Mutex<Vec<u8>>>);

impl Capture {
    /// Makes a subscriber writing the audit events as JSON here this thread's default, until the guard drops.
    ///
    /// A second dispatcher stays registered beside it: with one alone, a callsite another test's thread hits first
    /// caches `never` (tracing-core 0.1.36 `src/callsite.rs:319`, `:546`, `:565`).
    pub(crate) fn install(&self) -> (tracing::subscriber::DefaultGuard, tracing::Dispatch) {
        let sink = self.clone();
        let subscriber = tracing_subscriber::fmt()
            .json()
            .with_max_level(Level::INFO)
            .with_writer(move || sink.clone())
            .finish();
        (
            tracing::subscriber::set_default(subscriber),
            tracing::Dispatch::new(tracing::subscriber::NoSubscriber::default()),
        )
    }

    /// The fields of each audit event written.
    pub(crate) fn events(&self) -> Vec<serde_json::Map<String, serde_json::Value>> {
        self.written(|event| event["target"] == AUDIT_TARGET)
    }

    /// The fields of each warning written.
    pub(crate) fn warnings(&self) -> Vec<serde_json::Map<String, serde_json::Value>> {
        self.written(|event| event["level"] == "WARN")
    }

    /// The fields of each event written that `kept` keeps.
    fn written(
        &self,
        kept: impl Fn(&serde_json::Value) -> bool,
    ) -> Vec<serde_json::Map<String, serde_json::Value>> {
        let written = self.0.lock().expect("no test panics holding the capture");
        String::from_utf8_lossy(&written)
            .lines()
            .map(|line| serde_json::from_str::<serde_json::Value>(line).expect("a JSON event"))
            .filter(|event| kept(event))
            .map(|mut event| match event["fields"].take() {
                serde_json::Value::Object(fields) => fields,
                other => panic!("the fields are no object: {other}"),
            })
            .collect()
    }
}

impl std::io::Write for Capture {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0
            .lock()
            .expect("no test panics holding the capture")
            .extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}
