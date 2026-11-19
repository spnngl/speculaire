//! The gate's lookup of a verdict among those of 1k images (D20, D107): `just bench-micro`.

use std::sync::LazyLock;

use divan::Bencher;
use speculaire_oci::reference::Digest;
use speculaire_verify::{Key, MatchHash, Policies, Verdict, Verdicts};

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
        verdicts.get(key)
    });
}
