use std::sync::Arc;
use std::time::Duration;

use speculaire_oci::reference::Digest;
use speculaire_runtime::cri::ListedImage;
use speculaire_runtime::identity::MISSING;
use speculaire_runtime::images::Image;

use super::*;
use crate::Policy;

const ID: &str = "ad4f11f7c85f87c0a6d6c0fe492ad53f9cdcff6e8c88b881360c70eff701c67b";

fn digest(byte: u8) -> Digest {
    Digest::parse(&format!("sha256:{}", format!("{byte:02x}").repeat(32))).expect("a digest")
}

/// A policy named `name` on the images of `glob`.
fn policy(name: &str, glob: &str) -> String {
    format!(
        "apiVersion: policy.sigstore.dev/v1beta1\nkind: ClusterImagePolicy\nmetadata:\n  name: {name}\nspec:\n  images:\n  \
         - glob: \"{glob}\"\n  authorities:\n  - keyless:\n      identities:\n      - issuer: https://issuer.test\n        \
         subject: https://subject.test\n"
    )
}

/// The docker.io and mirror.gcr.io policies.
fn policies() -> Policies {
    let text = [
        policy("docker", "docker.io/**"),
        policy("mirror", "mirror.gcr.io/**"),
    ]
    .join("---\n");
    Policies::parse(&text).expect("the test policies parse")
}

fn hash(policies: &Policies, name: &str) -> MatchHash {
    MatchHash::of(
        policies
            .iter()
            .filter(|policy: &&Policy| policy.name() == name),
    )
}

/// busybox as CRI-O lists it, pulled from both registries by the digests given.
fn image(digests: &[Digest]) -> Identified<'static> {
    let repo_digests = ["docker.io/library/busybox", "mirror.gcr.io/library/busybox"]
        .iter()
        .flat_map(|repository| {
            digests
                .iter()
                .map(move |digest| format!("{repository}@{digest}"))
        })
        .collect();
    let listed = ListedImage {
        id: ID.to_owned(),
        repo_tags: vec!["docker.io/library/busybox:1.37".to_owned()],
        repo_digests,
    };
    Identified::Image(Arc::new(Image::from_listed(&listed).expect("an image")))
}

/// Keeps `verdict` for the manifest of `byte` under `policies`.
fn keep(verdicts: &Verdicts, byte: u8, policies: MatchHash, verdict: Verdict) {
    let key = Key {
        image: &digest(byte),
        policies,
        root: None,
    };
    verdicts.keep(key, verdict);
}

fn rejected(reason: &str) -> Verdict {
    Verdict::Rejected {
        reason: reason.into(),
    }
}

fn verdict(
    verdicts: &Verdicts,
    identified: &Identified<'_>,
    policies: &Policies,
) -> Option<Verdict> {
    let lookup = verdicts.identified(identified, policies, None)?;
    Some(lookup.verdict)
}

/// One name of a CRI-O image matched by a policy its verdict fails is enough: the other name passing, or matching no
/// policy, does not save it (D65).
#[test]
fn an_image_whose_one_name_fails_its_policy_has_that_verdict() {
    let policies = policies();
    let (docker, mirror) = (hash(&policies, "docker"), hash(&policies, "mirror"));
    let image = image(&[digest(0xa), digest(0xb)]);
    let verdicts = Verdicts::default();
    for manifest in [0xa, 0xb] {
        keep(&verdicts, manifest, mirror, rejected("unsigned"));
    }
    assert_eq!(
        verdict(&verdicts, &image, &policies),
        Some(rejected("unsigned"))
    );
    for manifest in [0xa, 0xb] {
        keep(&verdicts, manifest, docker, Verdict::Allow);
    }
    assert_eq!(
        verdict(&verdicts, &image, &policies),
        Some(rejected("unsigned"))
    );
    // Without the mirror policy, the mirror name has no verdict, and the docker one passes.
    let docker_only = Policies::parse(&policy("docker", "docker.io/**")).expect("parses");
    assert_eq!(
        verdict(&verdicts, &image, &docker_only),
        Some(Verdict::Allow)
    );
}

/// The image is allowed when one of its listed manifests is; otherwise it has the most hopeful verdict of theirs.
#[test]
fn an_image_has_the_most_hopeful_verdict_of_its_manifests() {
    let policies = Policies::parse(&policy("docker", "docker.io/**")).expect("parses");
    let docker = hash(&policies, "docker");
    let busybox = image(&[digest(0xa), digest(0xb)]);
    let verdicts = Verdicts::default();
    let unverifiable = Verdict::Unverifiable {
        reason: "down".into(),
        retry_at: Instant::now(),
    };
    keep(&verdicts, 0xa, docker, unverifiable.clone());
    keep(&verdicts, 0xb, docker, unverifiable.clone());
    assert_eq!(verdict(&verdicts, &busybox, &policies), Some(unverifiable));
    keep(&verdicts, 0xb, docker, rejected("unsigned"));
    assert_eq!(
        verdict(&verdicts, &busybox, &policies),
        Some(rejected("unsigned"))
    );
    let partly = image(&[digest(0xa), digest(0xb), digest(0xc)]);
    assert_eq!(
        verdict(&verdicts, &partly, &policies),
        Some(Verdict::Pending)
    );
    keep(&verdicts, 0xa, docker, Verdict::Allow);
    assert_eq!(
        verdict(&verdicts, &busybox, &policies),
        Some(Verdict::Allow)
    );
}

/// No identity, or an image ID no listed manifest has, is unverifiable; names no policy matches have no verdict.
#[test]
fn an_image_without_a_listed_manifest_is_unverifiable_and_one_no_policy_matches_has_no_verdict() {
    let policies = policies();
    let verdicts = Verdicts::default();
    let reason = |verdict: Option<Verdict>| match verdict {
        Some(Verdict::Unverifiable { reason, .. }) => reason.to_string(),
        other => format!("{other:?}"),
    };
    assert_eq!(
        reason(verdict(&verdicts, &image(&[]), &policies)),
        NOT_CONFIG
    );
    let unknown = Identified::Unknown(NOT_CONFIG);
    assert_eq!(reason(verdict(&verdicts, &unknown, &policies)), NOT_CONFIG);
    let missing = Identified::Unknown(MISSING);
    assert_eq!(reason(verdict(&verdicts, &missing, &policies)), MISSING);
    let elsewhere = Policies::parse(&policy("quay", "quay.io/**")).expect("parses");
    assert_eq!(verdict(&verdicts, &image(&[digest(0xa)]), &elsewhere), None);
}

/// A container whose snapshot is not its image's is rejected, under any policy or none (D170).
#[test]
fn a_mismatched_identity_is_rejected_whatever_the_policies() {
    let verdicts = Verdicts::default();
    for policies in [
        policies(),
        Policies::parse(&policy("quay", "quay.io/**")).expect("parses"),
    ] {
        assert_eq!(
            verdict(&verdicts, &Identified::Mismatched, &policies),
            Some(rejected(MISMATCH))
        );
    }
}

/// containerd's identity is the one digest and name it reads.
#[test]
fn a_listed_identity_has_the_verdict_of_its_digest_under_its_name() {
    let policies = policies();
    let verdicts = Verdicts::default();
    let listed = Identified::Listed {
        digest: digest(0xa),
        name: "docker.io/library/busybox:1.37",
    };
    let key = Key {
        image: &digest(0xa),
        policies: hash(&policies, "docker"),
        root: None,
    };
    verdicts.keep(key, Verdict::Allow);
    assert_eq!(verdict(&verdicts, &listed, &policies), Some(Verdict::Allow));
    let other = Identified::Listed {
        digest: digest(0xb),
        name: "docker.io/library/busybox:1.37",
    };
    assert_eq!(
        verdict(&verdicts, &other, &policies),
        Some(Verdict::Pending)
    );
}

/// A manifest's verdict is stale when one group's is, and of two failing groups as far from passing, the first
/// name's tells its reason.
#[test]
fn a_manifest_is_stale_when_one_group_is_and_tells_the_first_names_reason() {
    let policies = policies();
    let (docker, mirror) = (hash(&policies, "docker"), hash(&policies, "mirror"));
    let busybox = image(&[digest(0xa)]);
    let verdicts = Verdicts::default();
    verdicts.set_stale_max(Duration::from_secs(3600));
    keep(&verdicts, 0xa, docker, rejected("docker"));
    keep(&verdicts, 0xa, mirror, rejected("mirror"));
    let lookup = verdicts.identified(&busybox, &policies, None);
    assert_eq!(
        lookup,
        Some(Lookup {
            verdict: rejected("docker"),
            stale: false
        })
    );
    // The mirror group, new, answers the docker group's verdict, stale; the docker group's stays.
    let verdicts = Verdicts::default();
    verdicts.set_stale_max(Duration::from_secs(3600));
    keep(&verdicts, 0xa, docker, Verdict::Allow);
    verdicts.rekey(
        &digest(0xa),
        None,
        &[(docker, Some(docker)), (mirror, Some(docker))],
        Instant::now(),
    );
    let lookup = verdicts.identified(&busybox, &policies, None);
    assert_eq!(
        lookup,
        Some(Lookup {
            verdict: Verdict::Allow,
            stale: true
        })
    );
}

/// On CRI-O only the manifests whose config digest is the image ID stand for it; one not verified since the agent
/// started, as `cache.bin` keeps it, stands until it is (D172).
#[test]
fn only_the_manifests_whose_config_digest_is_the_image_id_stand_for_it() {
    let policies = Policies::parse(&policy("docker", "docker.io/**")).expect("parses");
    let docker = hash(&policies, "docker");
    let busybox = image(&[digest(0xa), digest(0xb)]);
    let Identified::Image(listed) = &busybox else {
        unreachable!("image() lists an image");
    };
    let verdicts = Verdicts::default();
    keep(&verdicts, 0xa, docker, Verdict::Allow);
    keep(&verdicts, 0xb, docker, rejected("unsigned"));
    assert_eq!(
        verdict(&verdicts, &busybox, &policies),
        Some(Verdict::Allow)
    );
    verdicts.configure(&digest(0xa), Some(digest(0xc)));
    verdicts.configure(&digest(0xb), Some(listed.id.clone()));
    assert_eq!(
        verdict(&verdicts, &busybox, &policies),
        Some(rejected("unsigned")),
        "the allowed manifest has another config"
    );
    verdicts.configure(&digest(0xb), None);
    let unverifiable = verdict(&verdicts, &busybox, &policies);
    assert!(
        matches!(&unverifiable, Some(Verdict::Unverifiable { reason, .. }) if **reason == *NOT_CONFIG),
        "{unverifiable:?}"
    );
    let listed_digest = Identified::Listed {
        digest: digest(0xa),
        name: "docker.io/library/busybox:1.37",
    };
    assert_eq!(
        verdict(&verdicts, &listed_digest, &policies),
        Some(Verdict::Allow),
        "containerd's identity is the manifest"
    );
}

/// An image ID no list names yet is pending, whatever the policies: the gate waits for the list (D172).
#[test]
fn an_unlisted_image_id_is_pending() {
    let verdicts = Verdicts::default();
    assert_eq!(
        verdict(&verdicts, &Identified::Unlisted, &policies()),
        Some(Verdict::Pending)
    );
}
