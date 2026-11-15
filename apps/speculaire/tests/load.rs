//! D33's load scenario, scaled down, against `speculaire agent` as the reflector: `just load`'s path end to end (D104).
#![cfg(target_os = "linux")]

use std::time::Duration;

use speculaire_load::{Scenario, Settings, Targets};

#[tokio::test(flavor = "multi_thread")]
async fn a_small_load_meets_loose_targets() {
    let settings = Settings {
        scenario: Scenario {
            agents: 20,
            blobs: 50,
            pool: 200,
            lookups: 200,
            deltas: 100,
            join: Duration::from_millis(500),
            warmup: Duration::from_millis(500),
            steady: Duration::from_secs(2),
            seed: 1,
        },
        targets: Targets {
            rss: 1 << 30,
            rss_goal: 1 << 20,
            lookup_p99: Duration::from_millis(50),
            // A restart takes the reflector's startup and the agents' wait of up to 5 s before they reconnect (D98).
            resync: Duration::from_secs(30),
        },
        reflector: vec![env!("CARGO_BIN_EXE_speculaire").into()],
    };
    let report = speculaire_load::run(&settings).await.unwrap();
    let markdown = report.markdown();
    assert!(report.passed(), "{markdown}");
    let measured = &report.measured;
    assert!(measured.peak_rss >= measured.steady_rss, "{markdown}");
    // The targets bound the rates from below; the pacers keep them from going over.
    assert!(measured.lookups_per_second <= Some(210.0), "{markdown}");
    assert!(measured.deltas_per_second <= Some(105.0), "{markdown}");
    assert_eq!(measured.failed_lookups, Some(0), "{markdown}");
    assert!(
        markdown.contains("goal missed (reported only)"),
        "{markdown}"
    );
}
