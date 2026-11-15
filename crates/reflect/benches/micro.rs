//! The reflector's index lookup in D33's fleet, 10k agents × 2k blobs (D104): `just bench-micro`.

use std::sync::LazyLock;

use divan::Bencher;
use speculaire_reflect::bench::Filled;

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
