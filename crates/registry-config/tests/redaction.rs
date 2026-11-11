//! Tracing a config at `trace` level prints no secret (D37).
//!
//! A test binary of its own: tracing caches whether a callsite is enabled, so a test that installs a subscriber must run
//! in a process where no other test has already hit the callsites without one.

use std::io::Write;
use std::path::Path;
use std::sync::{Arc, Mutex};

use speculaire_registry_config::containerd::config;

fn registry_of(text: &str) -> config::Registry {
    let dir = tempfile::tempdir().expect("a temporary directory");
    let path: &Path = &dir.path().join("config.toml");
    std::fs::write(path, text).expect("a file");
    config::load(path).expect("a config")
}

/// A writer that keeps what the subscriber prints.
#[derive(Clone, Default)]
struct Capture(Arc<Mutex<Vec<u8>>>);

impl Write for Capture {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0.lock().expect("a lock").extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

#[test]
fn trace_logging_a_config_prints_no_secret() {
    let capture = Capture::default();
    let sink = capture.clone();
    let subscriber = tracing_subscriber::fmt()
        .with_max_level(tracing::Level::TRACE)
        .with_writer(move || sink.clone())
        .finish();
    let registry = tracing::subscriber::with_default(subscriber, || {
        registry_of(
            r#"version = 3
[plugins."io.containerd.cri.v1.images".registry.configs."a.io".auth]
username = "someone"
password = "hunter2-password"
auth = "aHVudGVyMi1hdXRo"
identitytoken = "hunter2-token"
[plugins."io.containerd.cri.v1.images".registry.headers]
Authorization = ["Bearer hunter2-header"]
"#,
        )
    });
    let printed = String::from_utf8(capture.0.lock().expect("a lock").clone()).expect("text");
    assert!(
        printed.contains("a.io"),
        "the registry is traced: {printed}"
    );
    for secret in [
        "hunter2-password",
        "aHVudGVyMi1hdXRo",
        "hunter2-token",
        "hunter2-header",
    ] {
        assert!(!printed.contains(secret), "{secret} is printed: {printed}");
        assert!(!format!("{registry:?}").contains(secret));
    }
}
