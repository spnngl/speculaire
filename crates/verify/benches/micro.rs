//! The gate's lookup of a verdict among those of 1k images (D20, D107): `just bench-micro`.

use std::sync::LazyLock;

use divan::Bencher;
use speculaire_oci::reference::Digest;
use speculaire_verify::cache::{self, Current};
use speculaire_verify::{Key, MatchHash, Policies, Signatures, Verdict, Verdicts};
use tokio::time::Instant;

/// Counts each benchmark's allocations, which D107 asks a hot path to avoid.
#[global_allocator]
static ALLOC: divan::AllocProfiler = divan::AllocProfiler::system();

/// The images of a node, each with a rejection under one policy, whose reason the lookup must not copy.
static KEPT: LazyLock<(Vec<Digest>, MatchHash, Verdicts)> = LazyLock::new(|| {
    let policies = Policies::parse(
        "apiVersion: policy.sigstore.dev/v1beta1\nkind: ClusterImagePolicy\nmetadata:\n  name: p\nspec:\n  \
         images:\n  - glob: \"**\"\n  authorities:\n  - keyless:\n      identities:\n      - issuer: i\n        \
         subject: s\n",
    )
    .expect("the policy parses");
    let policies = MatchHash::of(policies.iter());
    let images: Vec<Digest> = (0..1_000_u32)
        .map(|n| Digest::parse(&format!("sha256:{n:064x}")).expect("a digest parses"))
        .collect();
    let verdicts = Verdicts::default();
    for image in &images {
        let rejected = Verdict::Rejected {
            reason: "no signature".into(),
        };
        verdicts.keep(
            Key {
                image,
                policies,
                root: None,
            },
            rejected,
        );
    }
    (images, policies, verdicts)
});

fn main() {
    divan::main();
}

#[divan::bench]
fn lookup(bencher: Bencher<'_, '_>) {
    let (images, policies, verdicts) = &*KEPT;
    let mut n = 0;
    bencher.bench_local(|| {
        n = (n + 1) % images.len();
        let key = Key {
            image: &images[n],
            policies: *policies,
            root: None,
        };
        verdicts.get(key).verdict
    });
}

/// The verdicts of a node of 10k images, half rejected with a reason, and the bytes they save to.
static SAVED: LazyLock<(Verdicts, Signatures, Vec<u8>)> = LazyLock::new(|| {
    let (_, policies, _) = &*KEPT;
    let verdicts = Verdicts::default();
    for n in 0..10_000_u32 {
        let image = Digest::parse(&format!("sha256:{n:064x}")).expect("a digest parses");
        let verdict = if n % 2 == 0 {
            Verdict::Allow
        } else {
            Verdict::Rejected {
                reason: "no signature".into(),
            }
        };
        let key = Key {
            image: &image,
            policies: *policies,
            root: None,
        };
        verdicts.keep(key, verdict);
    }
    let signatures = Signatures::new(0);
    let mut bytes = Vec::new();
    cache::save(
        &verdicts,
        &signatures,
        *policies,
        Instant::now(),
        &mut bytes,
    );
    (verdicts, signatures, bytes)
});

#[divan::bench]
fn save_10k(bencher: Bencher<'_, '_>) {
    let (_, policies, _) = &*KEPT;
    let (verdicts, signatures, bytes) = &*SAVED;
    let mut out = Vec::with_capacity(bytes.len());
    bencher.bench_local(|| cache::save(verdicts, signatures, *policies, Instant::now(), &mut out));
}

#[divan::bench]
fn load_10k(bencher: Bencher<'_, '_>) {
    let (_, policies, _) = &*KEPT;
    let (_, _, bytes) = &*SAVED;
    let current = Current {
        policies: *policies,
        root: None,
    };
    let (verdicts, signatures) = (Verdicts::default(), Signatures::new(0));
    bencher.bench_local(|| cache::load(bytes, current, Instant::now(), &verdicts, &signatures));
}
