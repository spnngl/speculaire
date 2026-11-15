//! Digest and reference parsing, which every mirror request and reflector message goes through (D107):
//! `just bench-micro`.

use std::collections::HashSet;
use std::hint::black_box;

use divan::{AllocProfiler, Bencher};
use speculaire_oci::reference::{Digest, Reference};

#[global_allocator]
static ALLOC: AllocProfiler = AllocProfiler::system();

const SHA256: &str = "sha256:6c3c624b58dbbcd3c0dd82b4c53f04194d1247c6eebdaab7c610cf7d66709b3b";

fn main() {
    divan::main();
}

#[divan::bench]
fn digest_parse() -> Digest {
    Digest::parse(black_box(SHA256)).expect("a valid digest")
}

#[divan::bench]
fn digest_clone(bencher: Bencher<'_, '_>) {
    let digest = Digest::parse(SHA256).expect("a valid digest");
    bencher.bench_local(|| black_box(&digest).clone());
}

/// A lookup in a set of 2k digests, a node's holdings in D33's fleet.
#[divan::bench]
fn digest_lookup(bencher: Bencher<'_, '_>) {
    let held: HashSet<Digest> = (0..2_000_u32)
        .map(|i| Digest::parse(&format!("sha256:{i:064x}")).expect("a valid digest"))
        .collect();
    let digest = Digest::parse(&format!("sha256:{:064x}", 1_000)).expect("a valid digest");
    bencher.bench_local(|| held.contains(black_box(&digest)));
}

#[divan::bench(args = ["busybox", "ghcr.io/org/app:1.2", "docker.io/library/busybox@sha256:6c3c624b58dbbcd3c0dd82b4c53f04194d1247c6eebdaab7c610cf7d66709b3b"])]
fn reference_parse(text: &str) -> Reference {
    Reference::parse_normalized_named(black_box(text)).expect("a valid reference")
}
