//! The metrics recorder (D34); `docs/metrics.md` lists every metric it may hold.

use std::time::Duration;

use metrics::{counter, describe_counter, describe_gauge, gauge};
use metrics_exporter_prometheus::{
    Matcher, NativeHistogramConfig, PrometheusBuilder, PrometheusHandle,
};

/// `speculaire_build_info`: always 1, labelled with the versions in use.
pub const BUILD_INFO: &str = "speculaire_build_info";
/// `speculaire_config_reload_failures_total`: reloads rejected while the previous config stays in use (D30).
pub const CONFIG_RELOAD_FAILURES: &str = "speculaire_config_reload_failures_total";

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

    describe_gauge!(BUILD_INFO, "Always 1");
    describe_counter!(
        CONFIG_RELOAD_FAILURES,
        "Reloads rejected; the previous config is still in use"
    );
    // The runtime, its version and NRI's come from NRI's `Configure` (D9, D68); empty until then.
    gauge!(BUILD_INFO, "version" => env!("CARGO_PKG_VERSION"), "runtime" => "", "runtime_version" => "", "nri_version" => "").set(1);
    counter!(CONFIG_RELOAD_FAILURES).absolute(0);
    Ok(handle)
}
