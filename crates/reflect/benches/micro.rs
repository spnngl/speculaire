//! The reflector's index lookup in D33's fleet, 10k agents × 2k blobs (D104), and its parsing of a message:
//! `just bench-micro`.

use std::sync::LazyLock;

use divan::Bencher;
use speculaire_reflect::SNAPSHOT_CHUNK;
use speculaire_reflect::bench::Filled;
use speculaire_reflect::message::Request;
use speculaire_reflect::proto::{AgentMessage, Snapshot, agent_message};

/// Counts each benchmark''s allocations, which D107 asks a hot path to avoid.
#[global_allocator]
static ALLOC: divan::AllocProfiler = divan::AllocProfiler::system();

/// D33's fleet, from a pool where each digest has about 100 holders, as `speculaire-loadgen` draws it.
static FLEET: LazyLock<Filled> = LazyLock::new(|| {
    Filled::new(10_000, 2_000, 200_000, 33)
        .expect("2k digests a node are within the reflector's limit")
});

fn main() {
    divan::main();
}

#[divan::bench]
fn lookup(bencher: Bencher<'_, '_>) {
    let fleet = &*FLEET;
    let mut n = 0;
    bencher.bench_local(|| {
        n += 1;
        fleet.lookup(n)
    });
}

/// The whole fleet announcing to an empty index, as after the reflector restarts: the index takes it under one lock.
#[divan::bench(sample_count = 3, sample_size = 1)]
fn fill() -> Option<Filled> {
    Filled::new(10_000, 2_000, 200_000, 33)
}

/// One full `Snapshot` chunk of sha256 digests, parsed as the reflector reads it.
#[divan::bench]
fn parse(bencher: Bencher<'_, '_>) {
    let snapshot = Snapshot {
        digests: (0..SNAPSHOT_CHUNK)
            .map(|n| format!("sha256:{n:064x}"))
            .collect(),
        last: true,
        seq: 0,
    };
    let message = AgentMessage {
        message: Some(agent_message::Message::Snapshot(snapshot)),
    };
    bencher
        .with_inputs(|| message.clone())
        .bench_values(Request::try_from);
}
