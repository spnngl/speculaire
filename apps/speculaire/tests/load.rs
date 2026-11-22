//! D33's load scenario, scaled down, against `speculaire agent` as the reflector: `just load`'s path end to end (D104).
//! And the pulls from a peer that `just profile peer` profiles, two of them (D116).
#![cfg(target_os = "linux")]

use std::time::Duration;

use speculaire_load::{Pulls, Scenario, Settings, Targets};

#[tokio::test(flavor = "multi_thread")]
async fn a_blob_comes_whole_from_a_peer_each_time() {
    let pulls = Pulls {
        size: 1 << 20,
        count: 2,
        agent: vec![env!("CARGO_BIN_EXE_speculaire").into()],
    };
    let markdown = speculaire_load::pull(&pulls).await.unwrap().markdown();
    assert!(
        markdown.starts_with("2 pulls of a 1 MiB blob"),
        "{markdown}"
    );
    // A pull through TLS, fetched whole from the peer and hashed, takes milliseconds: no time rounds to zero.
    assert!(!markdown.contains(" 0.0 ms"), "{markdown}");
}

/// A small load, with a prewarm wave or without.
fn small(prewarm: bool) -> Settings {
    Settings {
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
            prewarm,
        },
        targets: Targets {
            rss: 1 << 30,
            rss_goal: 1 << 20,
            lookup_p99: Duration::from_millis(50),
            // A restart takes the reflector's startup and the agents' wait of up to 5 s before they reconnect (D98).
            resync: Duration::from_secs(30),
        },
        reflector: vec![env!("CARGO_BIN_EXE_speculaire").into()],
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn a_small_load_meets_loose_targets() {
    let report = speculaire_load::run(&small(false)).await.unwrap();
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

#[tokio::test(flavor = "multi_thread")]
async fn a_small_wave_over_two_reflectors_keeps_to_its_rounds() {
    let report = speculaire_load::run(&small(true)).await.unwrap();
    let markdown = report.markdown();
    assert!(report.passed(), "{markdown}");
    let wave = report.measured.wave.as_ref().unwrap();
    // 2 seeds, then up to 4 agents for each agent sent the image before: 8, then the last 10.
    assert_eq!(wave.rounds, [vec![2, 8, 10], vec![2, 8, 10]], "{markdown}");
    assert!(
        markdown.starts_with("## Load: two reflectors"),
        "{markdown}"
    );
}
