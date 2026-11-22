//! The metrics recorder (D34); `docs/metrics.md` lists every metric it may hold.

use std::time::Duration;

use metrics::{Gauge, counter, describe_counter, describe_gauge, describe_histogram, gauge};
use metrics_exporter_prometheus::{
    Matcher, NativeHistogramConfig, PrometheusBuilder, PrometheusHandle,
};

/// `speculaire_build_info`: 1, labelled with the versions in use; 0 for those an NRI `Configure` replaced (D168).
pub const BUILD_INFO: &str = "speculaire_build_info";
/// `speculaire_nri_connected`: 1 while registered with the runtime's NRI (D41, D64).
pub const NRI_CONNECTED: &str = "speculaire_nri_connected";
/// `speculaire_identity_path`: 1 for the image identity path the gate reads, set at NRI's `Configure` (D15, D169).
pub const IDENTITY_PATH: &str = "speculaire_identity_path";
/// `speculaire_gate_total`: gate decisions, by `mode`, `result` and `stale` (D18, D21, D23, D172).
pub const GATE_TOTAL: &str = "speculaire_gate_total";
/// `speculaire_gate_seconds`: `CreateContainer` handling time, by identity `path` (D107, D172).
pub const GATE_SECONDS: &str = "speculaire_gate_seconds";
/// `speculaire_config_reload_failures_total`: reloads rejected while the previous config stays in use (D30).
pub const CONFIG_RELOAD_FAILURES: &str = "speculaire_config_reload_failures_total";
/// `speculaire_cache_loads_total`: loads of `cache.bin` at startup, by `result` (D31, D176).
pub const CACHE_LOADS: &str = "speculaire_cache_loads_total";
/// `speculaire_prewarm_pulls_total`: images members pushed, by what became of them (D188).
pub const PREWARM_PULLS: &str = "speculaire_prewarm_pulls_total";

/// `speculaire_p2p_enabled`: 1 while a node identity and the cluster CA are loaded and the identity has not expired (D16).
pub const P2P_ENABLED: &str = "speculaire_p2p_enabled";
/// `speculaire_identity_expiry_timestamp_seconds`: when the node identity in use expires, once one is loaded (D16).
pub const IDENTITY_EXPIRY: &str = "speculaire_identity_expiry_timestamp_seconds";
/// `speculaire_trust_root_expiry_timestamp_seconds`: when the trust root in use stops verifying, `0` while none is held
/// (D143).
pub const TRUST_ROOT_EXPIRY: &str = "speculaire_trust_root_expiry_timestamp_seconds";

/// `speculaire_runtime_alive_tasks`: tasks alive in the agent's async runtime.
pub const RUNTIME_ALIVE_TASKS: &str = "speculaire_runtime_alive_tasks";
/// `speculaire_runtime_global_queue_depth`: tasks waiting in the async runtime's global queue.
pub const RUNTIME_GLOBAL_QUEUE_DEPTH: &str = "speculaire_runtime_global_queue_depth";

/// How often the recorder drains histogram samples; the exporter's own listener uses the same period.
pub const UPKEEP_PERIOD: Duration = Duration::from_secs(5);

/// Installs the global recorder and sets the series that exist from startup.
///
/// The caller runs [`PrometheusHandle::run_upkeep`] every [`UPKEEP_PERIOD`].
///
/// # Errors
///
/// When a recorder is already installed.
pub fn install() -> anyhow::Result<PrometheusHandle> {
    // D34: schema 3 (buckets about 9% wide) and 160 buckets, 154 of them spanning 100 µs to 60 s.
    let native = NativeHistogramConfig::new(1.1, 160, 1e-6).map_err(anyhow::Error::msg)?;
    let recorder = PrometheusBuilder::new()
        .with_recommended_naming(true)
        .set_native_histogram_for_metric(Matcher::Prefix("speculaire_".to_owned()), native)
        .build_recorder();
    let handle = recorder.handle();
    metrics::set_global_recorder(recorder)
        .map_err(|_| anyhow::anyhow!("a metrics recorder is already installed"))?;

    describe();
    // The runtime, its version and NRI's come from NRI's `Configure` (D9, D68); empty until then.
    build_info(&Versions::default()).set(1);
    gauge!(NRI_CONNECTED).set(0);
    counter!(CONFIG_RELOAD_FAILURES).absolute(0);
    for result in ["loaded", "discarded"] {
        counter!(CACHE_LOADS, "result" => result).absolute(0);
    }
    for result in ["ok", "failed", "dropped", "no_space"] {
        counter!(PREWARM_PULLS, "result" => result).absolute(0);
    }
    gauge!(P2P_ENABLED).set(0);
    speculaire_mirror::metrics::describe();
    speculaire_mirror::metrics::describe_peer();
    speculaire_reflect::metrics::describe_client();
    Ok(handle)
}

/// The runtime versions `speculaire_build_info` names, as NRI's `Configure` gives them (D68).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct Versions {
    /// `containerd` or `cri-o`.
    pub(crate) runtime: &'static str,
    /// The runtime's release.
    pub(crate) runtime_version: String,
    /// The NRI version the runtime links; empty when unknown (D64).
    pub(crate) nri_version: String,
}

/// The `speculaire_build_info` series of `versions`.
pub(crate) fn build_info(versions: &Versions) -> Gauge {
    gauge!(
        BUILD_INFO,
        "version" => env!("CARGO_PKG_VERSION"),
        "runtime" => versions.runtime,
        "runtime_version" => versions.runtime_version.clone(),
        "nri_version" => versions.nri_version.clone(),
    )
}

/// Describes the metrics of this crate.
fn describe() {
    describe_gauge!(
        BUILD_INFO,
        "1 for the versions in use, 0 for runtime versions a later NRI Configure replaced"
    );
    describe_gauge!(NRI_CONNECTED, "1 while registered with the runtime's NRI");
    describe_gauge!(
        IDENTITY_PATH,
        "1 for the path the gate reads a container's image identity through"
    );
    describe_counter!(GATE_TOTAL, "Gate decisions");
    describe_histogram!(
        GATE_SECONDS,
        metrics::Unit::Seconds,
        "CreateContainer handling time"
    );
    describe_counter!(
        CONFIG_RELOAD_FAILURES,
        "Reloads rejected; the previous config is still in use"
    );
    describe_counter!(
        CACHE_LOADS,
        "Loads of the saved verdicts at startup: loaded, or discarded as unreadable"
    );
    describe_counter!(
        PREWARM_PULLS,
        "Images members pushed to prewarm: pulled, failed, dropped as listed or in flight, or skipped while the image filesystem is over prewarm.max_disk_percent"
    );
    describe_gauge!(
        P2P_ENABLED,
        "1 while this node can make peer links: its kubelet certificate and the cluster CA are loaded"
    );
    describe_gauge!(
        IDENTITY_EXPIRY,
        "When the kubelet certificate in use expires, in seconds since the epoch"
    );
    describe_gauge!(
        TRUST_ROOT_EXPIRY,
        "When the trust root in use stops verifying, in seconds since the epoch; 0 while none is held"
    );
    describe_gauge!(
        RUNTIME_ALIVE_TASKS,
        "Tasks alive in the agent's async runtime"
    );
    describe_gauge!(
        RUNTIME_GLOBAL_QUEUE_DEPTH,
        "Tasks waiting in the async runtime's global queue"
    );
}

/// The async runtime's gauges, read at each scrape: node-exporter sees the process, not its tasks (D34).
pub(crate) struct Runtime {
    alive: Gauge,
    queued: Gauge,
}

impl Runtime {
    /// Registers both gauges.
    pub(crate) fn new() -> Self {
        Self {
            alive: gauge!(RUNTIME_ALIVE_TASKS),
            queued: gauge!(RUNTIME_GLOBAL_QUEUE_DEPTH),
        }
    }

    /// Reads both gauges from `runtime`.
    pub(crate) fn sample(&self, runtime: &tokio::runtime::RuntimeMetrics) {
        let value = |count: usize| u32::try_from(count).unwrap_or(u32::MAX);
        self.alive.set(value(runtime.num_alive_tasks()));
        self.queued.set(value(runtime.global_queue_depth()));
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;
    use std::sync::Mutex;

    use metrics::{
        Counter, Gauge, Histogram, Key, KeyName, Metadata, Recorder, SharedString, Unit,
    };

    /// Keeps the name of every metric described.
    #[derive(Default)]
    struct Names(Mutex<BTreeSet<String>>);

    impl Names {
        fn add(&self, key: &KeyName) {
            self.0
                .lock()
                .expect("no test panics holding the lock")
                .insert(key.as_str().to_owned());
        }
    }

    impl Recorder for Names {
        fn describe_counter(&self, key: KeyName, _: Option<Unit>, _: SharedString) {
            self.add(&key);
        }
        fn describe_gauge(&self, key: KeyName, _: Option<Unit>, _: SharedString) {
            self.add(&key);
        }
        fn describe_histogram(&self, key: KeyName, _: Option<Unit>, _: SharedString) {
            self.add(&key);
        }
        fn register_counter(&self, _: &Key, _: &Metadata<'_>) -> Counter {
            Counter::noop()
        }
        fn register_gauge(&self, _: &Key, _: &Metadata<'_>) -> Gauge {
            Gauge::noop()
        }
        fn register_histogram(&self, _: &Key, _: &Metadata<'_>) -> Histogram {
            Histogram::noop()
        }
    }

    /// The metrics `docs/metrics.md` lists, less those whose `Planned` cell names a milestone (D109).
    fn built() -> BTreeSet<String> {
        include_str!("../../../docs/metrics.md")
            .lines()
            .filter_map(|row| {
                let (name, rest) = row.strip_prefix("| `")?.split_once("` | ")?;
                let last = rest.strip_suffix(" |")?.rsplit(" | ").next()?;
                let planned = last
                    .strip_prefix('M')
                    .is_some_and(|n| !n.is_empty() && n.bytes().all(|b| b.is_ascii_digit()));
                (!planned).then(|| name.to_owned())
            })
            .collect()
    }

    #[test]
    fn the_catalog_lists_every_metric_described_and_no_other_built_one() {
        let names = Names::default();
        metrics::with_local_recorder(&names, || {
            super::describe();
            speculaire_mirror::metrics::describe();
            speculaire_mirror::metrics::describe_peer();
            speculaire_mirror::metrics::describe_fetch();
            speculaire_mirror::metrics::describe_relay();
            speculaire_reflect::metrics::describe();
            speculaire_reflect::metrics::describe_client();
            speculaire_verify::metrics::describe();
        });
        let described = names
            .0
            .into_inner()
            .expect("no test panics holding the lock");
        assert_eq!(described, built());
    }
}
