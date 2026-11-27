use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use axum::Router;
use axum::routing::get;
use bytes::Bytes;
use secrecy::{ExposeSecret, SecretString};
use serde_json::{Value, json};
use speculaire_runtime::registries::Endpoint;

use super::{Api, DaemonSet, Pods, Progress, endpoint};

const UID: &str = "ds-uid";

fn daemonset(generation: i64, observed: i64, desired: i64, ready: i64) -> Value {
    json!({
        "metadata": {"uid": UID, "generation": generation},
        "status": {
            "observedGeneration": observed,
            "desiredNumberScheduled": desired,
            "numberReady": ready,
        },
    })
}

fn pod(node: &str, owner: &str, ready: bool, init: &Value) -> Value {
    json!({
        "metadata": {"ownerReferences": [{"uid": owner}]},
        "spec": {"nodeName": node},
        "status": {
            "phase": "Pending",
            "conditions": [{"type": "Ready", "status": if ready { "True" } else { "False" }}],
            "initContainerStatuses": [init],
        },
    })
}

fn progress(daemonset: &Value, pods: &[Value]) -> Progress {
    let daemonset = DaemonSet::parse(daemonset.to_string().as_bytes()).unwrap();
    let pods = Pods::parse(json!({"items": pods}).to_string().as_bytes()).unwrap();
    Progress::of(&daemonset, &pods)
}

fn failed(message: &str) -> Value {
    json!({
        "name": "unconfigure",
        "state": {"waiting": {"reason": "CrashLoopBackOff"}},
        "lastState": {"terminated": {"exitCode": 1, "reason": "Error", "message": message}},
    })
}

#[test]
fn every_pod_ready_is_done() {
    let ready = pod("a", UID, true, &json!({"name": "unconfigure"}));
    assert_eq!(progress(&daemonset(1, 1, 1, 1), &[ready]), Progress::Done);
}

#[test]
fn a_spec_the_controller_has_not_seen_is_not_done() {
    // The counts are those of the previous spec.
    assert!(matches!(
        progress(&daemonset(2, 1, 0, 0), &[]),
        Progress::Waiting { .. }
    ));
}

#[test]
fn a_failed_init_container_names_its_node_and_message() {
    let pods = [
        pod("b", UID, false, &failed("error: the key\nnames speculaire")),
        pod("a", UID, true, &json!({"name": "unconfigure"})),
        pod("c", "other", false, &failed("not ours")),
    ];
    let progress = progress(&daemonset(1, 1, 2, 1), &pods);
    assert_eq!(
        progress.to_string(),
        "b: unconfigure failed: error: the key names speculaire"
    );
}

#[test]
fn a_failure_without_message_gives_its_reason_and_exit_code() {
    let init = json!({
        "name": "unconfigure",
        "state": {"terminated": {"exitCode": 2, "reason": "Error"}},
    });
    let progress = progress(&daemonset(1, 1, 1, 0), &[pod("a", UID, false, &init)]);
    assert_eq!(
        progress,
        Progress::Failed(vec![
            "a: unconfigure failed: Error (exit code 2)".to_owned()
        ])
    );
}

#[test]
fn a_waiting_pod_names_what_it_waits_on() {
    let init = json!({"name": "unconfigure", "state": {"waiting": {"reason": "PodInitializing"}}});
    let mut unscheduled = pod("", UID, false, &json!({}));
    unscheduled["spec"] = json!({});
    let pods = [pod("a", UID, false, &init), unscheduled];
    assert_eq!(
        progress(&daemonset(1, 1, 2, 0), &pods).to_string(),
        "0 of 2 pods ready; waiting on (unscheduled): Pending; a: unconfigure PodInitializing"
    );
}

#[test]
fn a_ready_pod_is_not_waited_on_though_a_run_before_failed() {
    let pods = [
        pod("a", UID, true, &failed("refused, then fixed")),
        pod("b", UID, false, &json!({})),
    ];
    assert_eq!(
        progress(&daemonset(1, 1, 2, 1), &pods).to_string(),
        "1 of 2 pods ready; waiting on b: Pending"
    );
}

#[test]
fn what_is_not_an_object_is_refused() {
    assert!(DaemonSet::parse(b"[]").is_err());
    assert!(Pods::parse(b"{}").is_err());
}

/// An API server answering `daemonsets` in turn, the last one again once done, and `pods` to every request, at an
/// endpoint without TLS.
async fn server(daemonsets: &[Value], pods: Value) -> Api {
    let daemonsets: Arc<[String]> = daemonsets.iter().map(Value::to_string).collect();
    let asked = Arc::new(AtomicUsize::new(0));
    let pods = pods.to_string();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let app = Router::new()
        .route(
            "/apis/apps/v1/namespaces/speculaire/daemonsets/hook",
            get(move || async move {
                let n = asked.fetch_add(1, Ordering::Relaxed);
                daemonsets[n.min(daemonsets.len() - 1)].clone()
            }),
        )
        .route(
            "/api/v1/namespaces/speculaire/pods",
            get(move || async move { pods }),
        );
    tokio::spawn(async move { axum::serve(listener, app).await });
    let endpoint = Endpoint {
        root: String::new(),
        ..Endpoint::new(false, address.to_string())
    };
    Api::new(
        endpoint,
        &SecretString::from("token"),
        "speculaire".to_owned(),
    )
}

#[tokio::test]
async fn the_wait_ends_when_every_pod_is_ready() {
    let api = server(&[daemonset(1, 1, 0, 0)], json!({"items": []})).await;
    let mut out = Vec::new();
    api.wait(&["hook".to_owned()], Duration::from_secs(5), &mut out)
        .await
        .unwrap();
    assert_eq!(out, b"hook: every pod is ready\n");
}

#[tokio::test]
async fn the_wait_follows_the_pods_until_every_one_is_ready() {
    let answers = [daemonset(1, 1, 1, 0), daemonset(1, 1, 1, 1)];
    let api = server(&answers, json!({"items": []})).await;
    let mut out = Vec::new();
    api.wait(&["hook".to_owned()], Duration::from_secs(5), &mut out)
        .await
        .unwrap();
    assert_eq!(out, b"hook: 0 of 1 pods ready\nhook: every pod is ready\n");
}

#[tokio::test]
async fn the_wait_fails_at_the_first_failure() {
    let pods = json!({"items": [pod("b", UID, false, &failed("refused"))]});
    let api = server(&[daemonset(1, 1, 1, 0)], pods).await;
    let mut out = Vec::new();
    let error = api
        .wait(&["hook".to_owned()], Duration::from_secs(5), &mut out)
        .await
        .unwrap_err();
    assert_eq!(error.to_string(), "hook: b: unconfigure failed: refused");
    assert_eq!(out, b"", "the failure is the error alone");
}

#[tokio::test]
async fn the_wait_ends_at_the_timeout() {
    let api = server(&[daemonset(1, 1, 1, 0)], json!({"items": []})).await;
    let error = api
        .wait(&["hook".to_owned()], Duration::ZERO, &mut Vec::new())
        .await
        .unwrap_err();
    assert_eq!(
        error.to_string(),
        "not ready within 0 s: hook: 0 of 1 pods ready"
    );
}

#[tokio::test]
async fn an_unknown_daemonset_is_waited_on_with_the_server_s_reason() {
    let api = server(&[daemonset(1, 1, 1, 0)], json!({"items": []})).await;
    let error = api
        .wait(&["missing".to_owned()], Duration::ZERO, &mut Vec::new())
        .await
        .unwrap_err();
    assert!(error.to_string().contains("404 Not Found"), "{error}");
}

#[test]
fn the_api_server_is_asked_at_its_root_over_https_trusting_the_cluster_ca_alone() {
    let ca = Bytes::from_static(b"cluster CA");
    let server = endpoint("10.96.0.1", "443", ca.clone());
    assert!(server.https);
    assert_eq!(server.authority, "10.96.0.1:443");
    assert_eq!(server.root, "");
    assert_eq!(server.tls.roots, [ca]);
    assert_eq!(
        endpoint("fd00::1", "443", Bytes::new()).authority,
        "[fd00::1]:443"
    );
}

#[test]
fn in_a_pod_the_api_is_asked_as_its_service_account_in_its_namespace() {
    let account = tempfile::tempdir().unwrap();
    for (file, content) in [
        ("token", "secret\n"),
        ("namespace", "speculaire\n"),
        ("ca.crt", "cluster CA"),
    ] {
        std::fs::write(account.path().join(file), content).unwrap();
    }
    let env = |name: &str| match name {
        "KUBERNETES_SERVICE_HOST" => Some("10.96.0.1".to_owned()),
        "KUBERNETES_SERVICE_PORT" => Some("443".to_owned()),
        _ => None,
    };
    let api = Api::in_pod(env, account.path()).unwrap();
    assert_eq!(api.namespace, "speculaire");
    assert_eq!(api.endpoint.authority, "10.96.0.1:443");
    assert_eq!(api.endpoint.tls.roots, [Bytes::from_static(b"cluster CA")]);
    let [(name, value)] = &api.endpoint.headers[..] else {
        panic!("one header");
    };
    assert_eq!(
        (name.as_str(), value.expose_secret()),
        ("Authorization", "Bearer secret")
    );
}

#[test]
fn out_of_a_pod_the_api_names_what_is_missing() {
    let account = tempfile::tempdir().unwrap();
    let error = Api::in_pod(|_| None, account.path()).err().unwrap();
    assert_eq!(
        error.to_string(),
        "KUBERNETES_SERVICE_HOST is not set: not in a pod"
    );
    let error = Api::in_pod(|_| Some("1".to_owned()), account.path())
        .err()
        .unwrap();
    assert!(error.to_string().ends_with("/token"), "{error}");
}
