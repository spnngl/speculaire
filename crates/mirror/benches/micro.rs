//! Blob hashing as content arrives (D7, D104): `just bench-micro`.

use divan::Bencher;
use divan::counter::BytesCount;
use speculaire_mirror::bench::{arrive, digest};

/// A 16 MiB blob, arriving in HTTP/2's default 16 KiB frames.
const BLOB: usize = 16 << 20;
const PIECE: usize = 16 << 10;

fn main() {
    divan::main();
}

#[divan::bench(args = ["sha256", "sha512"])]
fn hash(bencher: Bencher<'_, '_>, algorithm: &str) {
    let content = vec![0x5a; BLOB];
    let expected = digest(algorithm, &content).expect("the mirror hashes sha256 and sha512");
    bencher
        .counter(BytesCount::new(BLOB))
        .bench_local(|| arrive(&expected, &content, PIECE));
}
