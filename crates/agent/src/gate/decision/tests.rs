use std::collections::HashMap;
use std::time::Duration;

use metrics_exporter_prometheus::PrometheusBuilder;
use speculaire_nri::api::{self, Container, CreateContainerRequest, PodSandbox};
use speculaire_oci::platform::Host;
use speculaire_oci::reference::Digest;
use speculaire_oci::tagged::Tagged;
use speculaire_runtime::containerd::Containerd;
use speculaire_runtime::identity::annotation::{
    Annotation, IMAGE_NAME, NO_CHAIN, NO_SNAPSHOT, NOT_STORED,
};
use speculaire_runtime::identity::{IMAGE_REF, MISMATCH, NOT_CONFIG};
use speculaire_runtime::images::{Image, RepoDigest, Update};
use speculaire_runtime::paths::Paths;
use speculaire_verify::cache::{self, Current};
use speculaire_verify::{Absent, Key, MatchHash, Signatures};

use super::running::Running;
use super::*;
use crate::capture::Capture;

/// The image ID of the test image, and its config digest.
const ID: &str = "ad4f11f7c85f87c0a6d6c0fe492ad53f9cdcff6e8c88b881360c70eff701c67b";
const NAME: &str = "reg.test/app";

/// The first cell of each row of `docs/operations.md` § Rejection reasons.
fn reasons() -> Vec<&'static str> {
    let doc = include_str!("../../../../../docs/operations.md");
    let (_, section) = doc
        .split_once("## Rejection reasons\n")
        .expect("operations.md has the section");
    let section = section.split("\n## ").next().unwrap_or(section);
    section
        .lines()
        .filter_map(|row| row.strip_prefix("| `")?.split_once("` |"))
        .map(|(reason, _)| reason)
        .collect()
}

fn settings(text: &str) -> Settings {
    let config = config::parse(&format!("[gate]\n{text}")).expect("the test settings parse");
    Settings::new(&config.gate)
}

fn enforce() -> Settings {
    settings("mode = \"enforce\"\n")
}

fn verdict(verdict: Verdict) -> Decision {
    Decision::Verdict(Lookup {
        verdict,
        stale: false,
    })
}

/// The decision a row's reason comes from.
fn decision_of(reason: &str) -> Decision {
    if let Some(detail) = reason.strip_prefix("rejected: ") {
        verdict(Verdict::Rejected {
            reason: detail.into(),
        })
    } else if let Some(detail) = reason.strip_prefix("unverifiable: ") {
        verdict(Verdict::Unverifiable {
            reason: detail.into(),
            retry_at: Instant::now(),
        })
    } else if reason == PENDING {
        Decision::Verdict(Lookup::PENDING)
    } else if reason == UNMATCHED {
        Decision::Unmatched
    } else {
        panic!("{reason:?} is no reason the gate gives")
    }
}

#[test]
fn each_rejection_reason_comes_out_with_its_text_under_enforce_and_audit_allows_it() {
    let reasons = reasons();
    assert!(reasons.len() > 10, "{reasons:?}");
    for reason in &reasons {
        let decision = decision_of(reason);
        assert_eq!(
            decision.answer(&enforce()),
            Answer::Reject((*reason).to_owned())
        );
        assert_eq!(
            decision.answer(&Settings::new(&config::Gate::default())),
            Answer::Allow,
            "{reason}"
        );
    }
    assert_eq!(
        Decision::Overloaded.answer(&enforce()),
        Answer::Reject(PENDING.to_owned())
    );
}

/// A verifier with `policies` and no trust root, and the engine's end of its asks.
fn verifier(policies: &str) -> (Verifier, mpsc::UnboundedReceiver<Asked>) {
    let (asker, asks) = mpsc::unbounded_channel();
    let policies = Policies::parse(policies).expect("the test policies parse");
    let verifier = Verifier {
        verdicts: Arc::new(Verdicts::default()),
        policies: watch::channel(Arc::new(policies)).1,
        trust: watch::channel(Err(Absent::new("none in this test"))).1,
        asker,
        synchronized: Arc::default(),
    };
    (verifier, asks)
}

/// A policy named `app` over `NAME`.
fn policy() -> String {
    format!(
        "apiVersion: policy.sigstore.dev/v1beta1\nkind: ClusterImagePolicy\nmetadata:\n  name: app\nspec:\n  images:\n  \
         - glob: \"{NAME}\"\n  authorities:\n  - keyless:\n      identities:\n      - issuer: https://issuer.test\n        \
         subject: someone\n"
    )
}

#[test]
fn the_reasons_of_a_missing_identity_are_rows_of_the_table() {
    let (verifier, _) = verifier(&policy());
    let reasons = reasons();
    let unknown = [MISSING, NOT_CONFIG, NOT_STORED, NO_CHAIN, NO_SNAPSHOT].map(Identified::Unknown);
    for identified in unknown.iter().chain([&Identified::Mismatched]) {
        let Answer::Reject(reason) = verifier.decide(&enforce(), identified).answer(&enforce())
        else {
            panic!("{identified:?} is allowed");
        };
        assert!(
            reasons.contains(&reason.as_str()),
            "{reason:?} is not in operations.md"
        );
    }
    let mismatch = verifier.decide(&enforce(), &Identified::Mismatched);
    assert_eq!(
        mismatch.answer(&enforce()),
        Answer::Reject(format!("rejected: {MISMATCH}"))
    );
}

#[test]
fn unmatched_is_denied_under_deny_and_allowed_under_allow() {
    let deny = settings("mode = \"enforce\"\nunmatched = \"deny\"\n");
    let allow = settings("mode = \"enforce\"\nunmatched = \"allow\"\n");
    assert_eq!(
        Decision::Unmatched.answer(&deny),
        Answer::Reject(UNMATCHED.to_owned())
    );
    assert_eq!(Decision::Unmatched.answer(&allow), Answer::Allow);
    assert_eq!(Decision::Unmatched.result(), "unmatched");
}

#[test]
fn a_stale_allow_allows_and_counts_as_stale() {
    let recorder = PrometheusBuilder::new().build_recorder();
    let handle = recorder.handle();
    let stale = Decision::Verdict(Lookup {
        verdict: Verdict::Allow,
        stale: true,
    });
    let fresh = Decision::Verdict(Lookup {
        verdict: Verdict::Allow,
        stale: false,
    });
    for decision in [&stale, &fresh] {
        let answer =
            metrics::with_local_recorder(&recorder, || crate::gate::answer(decision, &enforce()));
        assert_eq!(answer, Answer::Allow);
    }
    let rendered = handle.render();
    for stale in ["true", "false"] {
        let counted =
            format!(r#"speculaire_gate_total{{mode="enforce",result="allow",stale="{stale}"}} 1"#);
        assert!(rendered.contains(&counted), "{counted} in {rendered}");
    }
}

fn digest(byte: u8) -> Digest {
    Digest::parse(&format!("sha256:{}", format!("{byte:02x}").repeat(32))).expect("a digest")
}

/// A CRI-O decider over `verifier`, under `settings`, whose list names the test image when `listed`.
fn decider(verifier: Verifier, settings: Settings, listed: bool) -> Decider {
    let (_, read) = watch::channel(Arc::new(settings));
    let decider = Decider::new(Arc::new(NodeIdentity::crio()), verifier, read);
    if listed {
        decider.keep(&list());
    }
    decider
}

/// CRI-O's list: the test image, pulled from `NAME` by the manifest of byte 0xa.
fn list() -> List {
    let image = Image {
        id: Digest::parse(&format!("sha256:{ID}")).expect("a digest"),
        repo_digests: vec![RepoDigest {
            repository: NAME.to_owned(),
            digest: digest(0xa),
        }],
        tags: Vec::new(),
    };
    let mut list = List::default();
    list.apply(Update::Listing(vec![image]));
    list
}

/// A `CreateContainer` of the test image, container `c` of pod `p` in `namespace`.
fn request(namespace: &str) -> CreateContainerRequest {
    CreateContainerRequest {
        pod: Some(PodSandbox {
            name: "p".to_owned(),
            namespace: namespace.to_owned(),
            ..PodSandbox::default()
        }),
        container: Some(Container {
            name: "c".to_owned(),
            annotations: HashMap::from([(IMAGE_REF.to_owned(), ID.to_owned())]),
            ..Container::default()
        }),
    }
}

/// The key of the test image's manifest under the test policy.
fn keep(verifier: &Verifier, verdict: Verdict) {
    let policies = verifier.policies.borrow();
    let key = Key {
        image: &digest(0xa),
        policies: MatchHash::of(policies.iter()),
        root: None,
    };
    verifier.verdicts.keep(key, verdict);
}

fn far() -> Instant {
    Instant::now() + Duration::from_secs(60)
}

#[tokio::test]
async fn an_exempt_namespace_allows_under_enforce_and_an_empty_exemption_exempts_nothing() {
    let (verifier, _) = verifier(&policy());
    keep(
        &verifier,
        Verdict::Rejected {
            reason: "no signature".into(),
        },
    );
    let exempt = settings("mode = \"enforce\"\n[gate.exempt]\nnamespaces = [\"kube-system\"]\n");
    let decider = decider(verifier.clone(), exempt.clone(), true);
    let decision = decider
        .decide(&(&request("kube-system")).into(), &exempt, far())
        .await;
    assert_eq!(decision, Decision::Exempt(Exemption::Namespace));
    assert_eq!(decision.answer(&exempt), Answer::Allow);
    assert_eq!(decision.result(), "exempt");
    let other = decider
        .decide(&(&request("default")).into(), &exempt, far())
        .await;
    assert_eq!(
        other.answer(&exempt),
        Answer::Reject("rejected: no signature".to_owned())
    );

    let none = enforce();
    for namespace in ["kube-system", "default", ""] {
        let decision = decider
            .decide(&(&request(namespace)).into(), &none, far())
            .await;
        assert_eq!(decision.result(), "rejected", "{namespace:?}");
    }
    let image = settings(&format!(
        "mode = \"enforce\"\n[gate.exempt]\nimages = [\"{NAME}\"]\n"
    ));
    assert_eq!(
        decider
            .decide(&(&request("default")).into(), &image, far())
            .await,
        Decision::Exempt(Exemption::Image)
    );
    let other = settings("mode = \"enforce\"\n[gate.exempt]\nimages = [\"reg.test/other\"]\n");
    let decision = decider
        .decide(&(&request("default")).into(), &other, far())
        .await;
    assert_eq!(decision.result(), "rejected");
}

/// The fields of `event` in `docs/operations.md` § Audit events.
fn audit_fields(event: &str) -> Vec<&'static str> {
    let doc = include_str!("../../../../../docs/operations.md");
    let (_, section) = doc
        .split_once("## Audit events\n")
        .expect("operations.md has the section");
    let section = section.split("\n## ").next().unwrap_or(section);
    let row = format!("| `{event}` | `");
    section
        .lines()
        .filter_map(|line| line.strip_prefix(row.as_str())?.split_once('`'))
        .map(|(field, _)| field)
        .collect()
}

#[tokio::test]
async fn each_decision_is_one_gate_event_with_every_field_operations_md_names() {
    let (verifier, _) = verifier(&policy());
    keep(
        &verifier,
        Verdict::Rejected {
            reason: "no signature".into(),
        },
    );
    let exempt = settings("mode = \"enforce\"\n[gate.exempt]\nnamespaces = [\"kube-system\"]\n");
    let decider = decider(verifier, exempt.clone(), true);
    let capture = Capture::default();
    {
        let _guard = capture.install();
        decider
            .decide(&(&request("default")).into(), &exempt, far())
            .await;
        decider
            .decide(&(&request("kube-system")).into(), &exempt, far())
            .await;
        decider.overloaded(
            &(&request("default")).into(),
            &Settings::new(&config::Gate::default()),
        );
    }
    let events = capture.events();
    let names = audit_fields("gate");
    assert!(names.len() >= 12, "{names:?}");
    for event in &events {
        let mut fields: Vec<&str> = event.keys().map(String::as_str).collect();
        fields.sort_unstable();
        let mut want = names.clone();
        want.push("event");
        want.sort_unstable();
        assert_eq!(fields, want);
        assert_eq!(event["event"], "gate");
        assert_eq!(event["pod"], "p");
        assert_eq!(event["container"], "c");
        assert_eq!(event["identity_path"], "image_id");
        assert_eq!(event["stale"], false);
    }
    let [rejected, exempted, overloaded] = events.as_slice() else {
        panic!("one event per decision: {events:?}");
    };
    assert_eq!(rejected["namespace"], "default");
    assert_eq!(rejected["image_identity"], format!("sha256:{ID}"));
    assert_eq!(rejected["image_name"], NAME);
    assert_eq!(rejected["matched_policies"], "app");
    assert_eq!(rejected["mode"], "enforce");
    assert_eq!(rejected["result"], "rejected");
    assert_eq!(rejected["reason"], "rejected: no signature");
    assert_eq!(rejected["exemption"], "");
    assert_eq!(exempted["namespace"], "kube-system");
    assert_eq!(exempted["image_identity"], "");
    assert_eq!(exempted["image_name"], "");
    assert_eq!(exempted["result"], "exempt");
    assert_eq!(exempted["reason"], "");
    assert_eq!(exempted["exemption"], "namespace");
    assert_eq!(overloaded["mode"], "audit");
    assert_eq!(overloaded["result"], "overloaded");
    assert_eq!(overloaded["reason"], PENDING);
    assert_eq!(overloaded["matched_policies"], "");
}

#[tokio::test]
async fn the_gate_event_names_an_exempt_image_and_each_matched_policy_once() {
    let two = format!(
        "{}---\n{}",
        policy(),
        policy().replace("name: app", "name: other")
    );
    let (verifier, _) = verifier(&two);
    let image = settings(&format!("[gate.exempt]\nimages = [\"{NAME}\"]\n"));
    let decider = decider(verifier, image.clone(), true);
    let capture = Capture::default();
    {
        let _guard = capture.install();
        decider
            .decide(&(&request("default")).into(), &image, far())
            .await;
    }
    let events = capture.events();
    let [exempted] = events.as_slice() else {
        panic!("one event: {events:?}");
    };
    assert_eq!(exempted["exemption"], "image");
    assert_eq!(exempted["matched_policies"], "app, other");
    assert_eq!(Exemption::Image.name(), "image");
}

#[tokio::test]
async fn a_request_without_a_container_is_unverifiable_and_its_gate_event_names_no_image() {
    let (verifier, _) = verifier(&policy());
    let decider = decider(verifier, enforce(), true);
    let request = CreateContainerRequest {
        container: None,
        ..request("default")
    };
    let capture = Capture::default();
    let decision = {
        let _guard = capture.install();
        decider.decide(&(&request).into(), &enforce(), far()).await
    };
    let reason = format!("unverifiable: {MISSING}");
    assert_eq!(decision.answer(&enforce()), Answer::Reject(reason.clone()));
    let events = capture.events();
    let [event] = events.as_slice() else {
        panic!("one event: {events:?}");
    };
    assert_eq!(event["container"], "");
    assert_eq!(event["image_name"], "");
    assert_eq!(event["matched_policies"], "");
    assert_eq!(event["reason"], reason);
}

#[tokio::test]
async fn an_image_no_policy_matches_is_unmatched() {
    let (verifier, _) = verifier("");
    let settings = enforce();
    let decider = decider(verifier, settings.clone(), true);
    assert_eq!(
        decider
            .decide(&(&request("default")).into(), &settings, far())
            .await,
        Decision::Unmatched
    );
}

/// One image under two repositories, as the e2e fixtures `e2e/signed:1` and `e2e/unsigned:1` are: containerd sorts its
/// references, so `Container.image.name` is always the first, `LAX`'s, whichever the pod asked for (D179).
const LAX: &str = "reg.test/lax";
const STRICT: &str = "reg.test/strict";

/// The policies over `images`, one each, named after the repository's last segment, as `policy()` is over `NAME`.
fn policies_over(images: &[&str]) -> String {
    images
        .iter()
        .map(|image| {
            let name = image.rsplit('/').next().unwrap_or(image);
            policy()
                .replace("name: app", &format!("name: {name}"))
                .replace(NAME, image)
        })
        .collect::<Vec<_>>()
        .join("---\n")
}

/// Keeps `verdict` for the test manifest under the policies over `image`.
fn keep_under(verifier: &Verifier, image: &str, verdict: Verdict) {
    let policies = verifier.policies.borrow();
    let reference = Reference::parse_normalized_named(image).expect("a name");
    let key = Key {
        image: &digest(0xa),
        policies: MatchHash::of(policies.matching(&reference)),
        root: None,
    };
    verifier.verdicts.keep(key, verdict);
}

/// The runtime's list: the test image under `LAX:1` and `STRICT:1`, pulled by the manifest of byte 0xa.
fn both() -> List {
    let image = Image {
        id: Digest::parse(&format!("sha256:{ID}")).expect("a digest"),
        repo_digests: [LAX, STRICT]
            .map(|repository| RepoDigest {
                repository: repository.to_owned(),
                digest: digest(0xa),
            })
            .to_vec(),
        tags: [LAX, STRICT]
            .map(|repository| Tagged::parse(&format!("{repository}:1")).expect("a tag"))
            .to_vec(),
    };
    let mut list = List::default();
    list.apply(Update::Listing(vec![image]));
    list
}

/// A decider over `verifier` and `settings`, on containerd 2.4's path or CRI-O's, whose list is `list`.
fn on(
    crio: bool,
    verifier: Verifier,
    settings: Settings,
    list: &List,
) -> (Decider, tempfile::TempDir) {
    let dir = tempfile::tempdir().expect("a temporary directory");
    let identity = if crio {
        NodeIdentity::crio()
    } else {
        let containerd = Containerd::new(
            Paths::under(dir.path()),
            dir.path().join("containerd.sock"),
            None,
        );
        NodeIdentity::containerd(Annotation::new(containerd, Host::current()))
    };
    let decider = Decider::new(
        Arc::new(identity),
        verifier,
        watch::channel(Arc::new(settings)).1,
    );
    decider.keep(list);
    (decider, dir)
}

/// A `CreateContainer` of the test image by a pod that asked for `asked`, as each runtime sends it: containerd 2.4 names
/// `LAX:1` in `Container.image` and `asked` in its annotation, CRI-O the image ID alone.
fn asking(asked: &str) -> CreateContainerRequest {
    let mut request = request("default");
    let container = request.container.as_mut().expect("a container");
    container
        .annotations
        .insert(IMAGE_NAME.to_owned(), asked.to_owned());
    container.image = Some(api::Image {
        name: format!("{LAX}:1"),
        digest: digest(0xa).to_string(),
        config_digest: format!("sha256:{ID}"),
    });
    request
}

fn no_signature() -> Verdict {
    Verdict::Rejected {
        reason: "no signature".into(),
    }
}

/// Whatever other name the runtime has for the image, a pod that asked for the strict name gets the strict policy:
/// not unmatched (a), not the lax policy (b), not exempt (c); on CRI-O, which gives no requested name, every name must
/// pass and be exempt (D179).
#[tokio::test]
async fn the_name_the_pod_asked_for_chooses_the_policies_and_never_another_name_of_its_image() {
    let mut allowed = Vec::new();
    for crio in [false, true] {
        let path = if crio { "image_id" } else { "nri" };
        let cases = [
            // (a) The other name matches no policy, and unmatched images are allowed.
            (
                "a",
                answer(crio, &both(), STRICT, &[STRICT], ALLOW_UNMATCHED).await,
            ),
            // (b) The other name matches a lax policy, which the image passes.
            ("b", answer(crio, &both(), STRICT, &[STRICT, LAX], "").await),
            // (c) The other name is exempt.
            (
                "c",
                answer(crio, &both(), STRICT, &[STRICT], EXEMPT_LAX).await,
            ),
        ];
        for (case, answer) in cases {
            if answer != rejected() {
                allowed.push(format!("({case}) on {path}: {answer:?}"));
            }
        }
    }
    assert!(allowed.is_empty(), "{allowed:#?}");
}

/// On containerd the lax name the pod asked for is the one matched, once the list names the image by it; until then,
/// and on CRI-O, every name is, so the strictest policy decides and an exemption must hold for each (D179).
#[tokio::test]
async fn a_requested_name_the_list_does_not_name_the_image_by_falls_back_to_every_name() {
    let none = List::default();
    let exempt_both = format!("[gate.exempt]\nimages = [\"{LAX}\", \"{STRICT}\"]\n");
    let both_policies: &[&str] = &[STRICT, LAX];
    let cases = [
        (false, &both(), LAX, both_policies, "", Answer::Allow),
        (
            false,
            &both(),
            LAX,
            &[STRICT][..],
            ALLOW_UNMATCHED,
            Answer::Allow,
        ),
        (
            false,
            &both(),
            LAX,
            &[STRICT][..],
            EXEMPT_LAX,
            Answer::Allow,
        ),
        (
            false,
            &none,
            STRICT,
            &[STRICT][..],
            ALLOW_UNMATCHED,
            rejected(),
        ),
        (false, &none, STRICT, both_policies, "", rejected()),
        (true, &both(), LAX, both_policies, "", rejected()),
        (
            true,
            &both(),
            LAX,
            &[STRICT][..],
            &exempt_both,
            Answer::Allow,
        ),
    ];
    for (crio, list, asked, over, text, want) in cases {
        let got = answer(crio, list, asked, over, text).await;
        assert_eq!(
            got,
            want,
            "crio {crio}, {} listed, {asked} under {over:?}, {text:?}",
            list.images().count()
        );
    }
}

const ALLOW_UNMATCHED: &str = "unmatched = \"allow\"\n";
const EXEMPT_LAX: &str = "[gate.exempt]\nimages = [\"reg.test/lax\"]\n";

fn rejected() -> Answer {
    Answer::Reject("rejected: no signature".to_owned())
}

/// The answer to a pod that asked for `asked`, on CRI-O or containerd 2.4 whose list is `list`, under the policies over
/// `over` and the gate settings `text`: `STRICT`'s policy rejects the image, `LAX`'s allows it.
async fn answer(crio: bool, list: &List, asked: &str, over: &[&str], text: &str) -> Answer {
    let (verifier, _) = verifier(&policies_over(over));
    keep_under(&verifier, STRICT, no_signature());
    keep_under(&verifier, LAX, Verdict::Allow);
    let settings = settings(&format!("mode = \"enforce\"\n{text}"));
    let (decider, _dir) = on(crio, verifier, settings.clone(), list);
    let request = asking(&format!("{asked}:1"));
    decider
        .decide(&(&request).into(), &settings, far())
        .await
        .answer(&settings)
}

#[tokio::test]
async fn a_verdict_landing_within_gate_wait_is_used() {
    let (verifier, mut asks) = verifier(&policy());
    let settings = settings("mode = \"enforce\"\nwait = 5\n");
    let decider = decider(verifier.clone(), settings.clone(), true);
    let lands = async {
        tokio::time::sleep(Duration::from_millis(50)).await;
        keep(&verifier, Verdict::Allow);
    };
    let request = request("default");
    let started = Instant::now();
    let read = (&request).into();
    let (decision, ()) = tokio::join!(decider.decide(&read, &settings, far()), lands);
    assert_eq!(decision, verdict(Verdict::Allow));
    assert!(
        started.elapsed() < Duration::from_secs(4),
        "{:?}",
        started.elapsed()
    );
    let asked = asks.try_recv().expect("the gate asked for the root");
    assert_eq!(
        asked,
        Asked {
            root: digest(0xa),
            names: vec![NAME.to_owned()],
            by: Asking::GateMiss,
        }
    );
}

#[tokio::test]
async fn a_verdict_missing_at_gate_wait_or_at_the_deadline_is_pending() {
    let (verifier, _) = verifier(&policy());
    let short = settings("mode = \"enforce\"\nwait = 0.1\n");
    let decider = decider(verifier, short.clone(), true);
    let request = request("default");
    let started = Instant::now();
    let decision = decider.decide(&(&request).into(), &short, far()).await;
    assert!(started.elapsed() >= Duration::from_millis(100));
    assert_eq!(decision.answer(&short), Answer::Reject(PENDING.to_owned()));

    let long = settings("mode = \"enforce\"\nwait = 5\n");
    let started = Instant::now();
    let soon = Instant::now() + Duration::from_millis(20);
    let decision = decider.decide(&(&request).into(), &long, soon).await;
    assert!(
        started.elapsed() < Duration::from_secs(4),
        "{:?}",
        started.elapsed()
    );
    assert_eq!(decision, Decision::Verdict(Lookup::PENDING));
}

#[tokio::test]
async fn an_image_id_the_list_names_within_gate_wait_gets_its_verdict() {
    let (verifier, _) = verifier(&policy());
    keep(&verifier, Verdict::Allow);
    let settings = settings("mode = \"enforce\"\nwait = 5\n");
    let decider = decider(verifier, settings.clone(), false);
    let lists = async {
        tokio::time::sleep(Duration::from_millis(50)).await;
        decider.keep(&list());
    };
    let request = request("default");
    let read = (&request).into();
    let (decision, ()) = tokio::join!(decider.decide(&read, &settings, far()), lists);
    assert_eq!(decision, verdict(Verdict::Allow));
}

#[tokio::test]
async fn an_image_id_no_list_names_by_gate_wait_is_pending() {
    let (verifier, _) = verifier(&policy());
    keep(&verifier, Verdict::Allow);
    let short = settings("mode = \"enforce\"\nwait = 0.05\n");
    let decider = decider(verifier, short.clone(), false);
    let decision = decider
        .decide(&(&request("default")).into(), &short, far())
        .await;
    assert_eq!(decision.answer(&short), Answer::Reject(PENDING.to_owned()));
}

/// Container `c` of pod `p` in each of `namespaces`, running the test image, as `Synchronize` lists them.
fn running(namespaces: &[&str]) -> Vec<Running> {
    let (pods, containers) = namespaces
        .iter()
        .map(|namespace| {
            let request = request(namespace);
            let pod = PodSandbox {
                id: (*namespace).to_owned(),
                ..request.pod.expect("the request has a pod")
            };
            let container = Container {
                pod_sandbox_id: (*namespace).to_owned(),
                ..request.container.expect("the request has a container")
            };
            (pod, container)
        })
        .unzip();
    Running::listed(pods, containers)
}

#[tokio::test]
async fn a_running_container_is_asked_for_under_synchronize_and_warned_of_once_per_verdict_change()
{
    let (verifier, mut asks) = verifier(&policy());
    let exempt = settings("mode = \"enforce\"\n[gate.exempt]\nnamespaces = [\"kube-system\"]\n");
    let decider = decider(verifier.clone(), exempt, false);
    let (synchronized, listed) = watch::channel(Arc::default());
    let capture = Capture::default();
    let _guard = capture.install();
    let rejected = Verdict::Rejected {
        reason: "no signature".into(),
    };
    let unverifiable = Verdict::Unverifiable {
        reason: "offline".into(),
        retry_at: Instant::now(),
    };
    // A fresh rejection is final: it comes last.
    let verdicts = [
        unverifiable.clone(),
        unverifiable.clone(),
        Verdict::Pending,
        Verdict::Allow,
        unverifiable,
        rejected,
    ];
    let lands = async {
        let untold = async || {
            let told = verifier.synchronized.notified();
            tokio::time::timeout(Duration::from_millis(1), told)
                .await
                .is_err()
        };
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert!(untold().await, "the list started before any `Synchronize`");
        synchronized.send_replace(Arc::new(running(&["default", "kube-system"])));
        // No image list yet: the gate reads the identity again, and the list waits.
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert!(
            asks.try_recv().is_err(),
            "asked before the identity was read"
        );
        assert!(untold().await, "the list started before the gate asked");
        decider.identity().keep(&list());
        let asked = asks.recv().await.expect("the gate asks");
        assert_eq!((&asked.root, asked.by), (&digest(0xa), Asking::Synchronize));
        tokio::time::timeout(Duration::from_secs(1), verifier.synchronized.notified())
            .await
            .expect("the gate tells the image list once it asked");
        // A list kept wakes the watch, which reads again only the containers it has no identity of.
        decider.keep(&list());
        tokio::time::sleep(Duration::from_millis(20)).await;
        for verdict in verdicts {
            keep(&verifier, verdict);
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    };
    tokio::select! {
        () = decider.watch_running(listed) => panic!("the watch ends"),
        () = lands => {}
    }
    assert!(
        asks.try_recv().is_err(),
        "a container asked for twice, or the exempt one"
    );
    let warnings = capture.warnings();
    let reasons: Vec<&serde_json::Value> =
        warnings.iter().map(|fields| &fields["reason"]).collect();
    assert_eq!(
        reasons,
        [
            "unverifiable: offline",
            "unverifiable: offline",
            "rejected: no signature"
        ]
    );
    for fields in &warnings {
        assert_eq!(
            (&fields["namespace"], &fields["pod"], &fields["container"]),
            (&"default".into(), &"p".into(), &"c".into())
        );
        assert!(
            fields["image"]
                .as_str()
                .is_some_and(|image| !image.is_empty()),
            "{fields:?}"
        );
    }
}

/// A verdict loaded from `cache.bin` warns of a running container at start, like any verdict, and not again when
/// re-verification lands the same one (D175, D176).
#[tokio::test]
async fn a_rejection_loaded_from_the_cache_warns_of_a_running_container_once() {
    let (saved, _) = verifier(&policy());
    let (verifier, mut asks) = verifier(&policy());
    let decider = decider(verifier.clone(), enforce(), true);
    let (synchronized, listed) = watch::channel(Arc::default());
    let capture = Capture::default();
    let _guard = capture.install();
    let rejected = Verdict::Rejected {
        reason: "no signature".into(),
    };
    let mut bytes = Vec::new();
    keep(&saved, rejected.clone());
    let policies = MatchHash::of(verifier.policies.borrow().iter());
    let signatures = Signatures::new(0);
    cache::save(
        &saved.verdicts,
        &signatures,
        policies,
        Instant::now(),
        &mut bytes,
    );
    let current = Current {
        policies,
        root: None,
    };
    cache::load(
        &bytes,
        current,
        Instant::now(),
        &verifier.verdicts,
        &signatures,
    )
    .expect("the saved verdicts load");
    let lands = async {
        synchronized.send_replace(Arc::new(running(&["default"])));
        asks.recv().await.expect("the gate asks");
        tokio::time::sleep(Duration::from_millis(20)).await;
        assert_eq!(
            capture.warnings().len(),
            1,
            "no warning before verification"
        );
        keep(&verifier, rejected);
        tokio::time::sleep(Duration::from_millis(20)).await;
    };
    tokio::select! {
        () = decider.watch_running(listed) => panic!("the watch ends"),
        () = lands => {}
    }
    let warnings = capture.warnings();
    let reasons: Vec<&serde_json::Value> =
        warnings.iter().map(|fields| &fields["reason"]).collect();
    assert_eq!(reasons, ["rejected: no signature"]);
}
