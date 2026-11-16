//! The artifact metrics as the agent's exporter renders them.

use metrics_exporter_prometheus::PrometheusBuilder;

use super::*;

#[test]
fn both_metrics_are_described_and_a_fetch_carries_its_three_labels() {
    let recorder = PrometheusBuilder::new().build_recorder();
    let handle = recorder.handle();
    ::metrics::with_local_recorder(&recorder, || {
        describe();
        fetched(OTHER, Outcome::RateLimited);
        store_bytes(7);
    });
    let rendered = handle.render();
    for wanted in [
        "# HELP speculaire_artifact_fetches_total Requests for artifacts",
        "# HELP speculaire_artifact_store_bytes The size of the artifact store",
        r#"speculaire_artifact_fetches_total{source="upstream",upstream="other",result="rate_limited"} 1"#,
        "speculaire_artifact_store_bytes 7",
    ] {
        assert!(rendered.contains(wanted), "{wanted} in {rendered}");
    }
}
