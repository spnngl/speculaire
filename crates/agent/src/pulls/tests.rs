use std::sync::Mutex;
use std::sync::atomic::AtomicBool;

use metrics_exporter_prometheus::{PrometheusBuilder, PrometheusHandle, PrometheusRecorder};
use speculaire_runtime::pull::UsageError;

use super::*;
use crate::capture::Capture;

/// What [`Pull`]'s methods return.
type Boxed<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

fn image(text: &str) -> Reference {
    Reference::parse_docker_ref(text).expect("a reference")
}

fn prewarm(member: &str, text: &str) -> Pushed {
    Pushed {
        member: member.to_owned(),
        push: Push::Prewarm(image(text)),
    }
}

fn list(member: &str, texts: &[&str]) -> Pushed {
    let images = texts.iter().map(|text| image(text)).collect();
    Pushed {
        member: member.to_owned(),
        push: Push::List(PrewarmList::new(images).expect("a short list")),
    }
}

fn failed() -> Outcome {
    Outcome::Failed(cri::Error::Connect {
        path: "/run/containerd.sock".into(),
        message: "refused".to_owned(),
    })
}

/// A state with nothing held, and a recorder to read its counts.
fn state() -> (State, PrometheusRecorder) {
    (
        State::new(Box::new(|_| false)),
        PrometheusBuilder::new().build_recorder(),
    )
}

/// `speculaire_prewarm_pulls_total` for `result`, as `handle` renders it.
fn counted(handle: &PrometheusHandle, result: &str) -> u64 {
    let series = format!(r#"speculaire_prewarm_pulls_total{{result="{result}"}} "#);
    handle
        .render()
        .lines()
        .find_map(|line| line.strip_prefix(&series))
        .map_or(0, |count| count.parse().expect("a count"))
}

/// D51: a push of an image in flight or just pulled is dropped, whoever pushes it; once the runtime's list has had
/// time to show the pull, only the list says whether it is held.
#[test]
fn an_image_is_pulled_once_and_a_push_of_it_while_in_flight_or_held_is_dropped() {
    let (mut state, recorder) = state();
    let handle = recorder.handle();
    let now = Instant::now();
    metrics::with_local_recorder(&recorder, || {
        state.take(prewarm("cp-1", "app:1"), now);
        state.take(prewarm("cp-2", "app:1"), now);
        assert_eq!(state.next(now), Some(image("app:1")));
        state.take(prewarm("cp-2", "app:1"), now);
        assert_eq!(state.next(now), None, "one pull at a time");
        state.done(image("app:1"), Outcome::Pulled, now);
        state.take(prewarm("cp-1", "app:1"), now + RELIST / 2);
        assert_eq!(state.next(now), None);
        state.take(prewarm("cp-1", "app:1"), now + RELIST);
        assert_eq!(state.next(now), Some(image("app:1")));
    });
    assert_eq!(counted(&handle, "dropped"), 3);
    assert_eq!(counted(&handle, "ok"), 1);

    let recorder = PrometheusBuilder::new().build_recorder();
    let mut state = State::new(Box::new(|image| image.tag() == Some("held")));
    metrics::with_local_recorder(&recorder, || state.take(prewarm("cp-1", "app:held"), now));
    assert_eq!(state.next(now), None);
    assert_eq!(counted(&recorder.handle(), "dropped"), 1);
}

#[test]
fn pushed_images_are_pulled_in_the_order_they_came_before_any_retry() {
    let (mut state, _) = state();
    let now = Instant::now();
    state.take(list("cp-1", &["old:1"]), now);
    state.take(prewarm("cp-1", "old:1"), now);
    assert_eq!(state.next(now), Some(image("old:1")));
    state.done(image("old:1"), failed(), now);
    let later = now + FIRST_BACKOFF;
    for text in ["b:1", "a:1", "c:1"] {
        state.take(prewarm("cp-1", text), now);
    }
    for text in ["b:1", "a:1", "c:1", "old:1"] {
        assert_eq!(state.next(later), Some(image(text)));
        state.done(image(text), Outcome::Pulled, later);
    }
}

/// Question 5: a failed pull is retried after 30 s, doubling to 10 minutes, while a member's latest list names it.
#[test]
fn a_failed_pull_is_retried_with_backoff_until_no_list_names_it() {
    let (mut state, recorder) = state();
    let handle = recorder.handle();
    let now = Instant::now();
    let mut at = now;
    metrics::with_local_recorder(&recorder, || {
        state.take(list("cp-1", &["app:1"]), now);
        state.take(list("cp-2", &["app:1"]), now);
        state.take(prewarm("cp-1", "app:1"), now);
        assert_eq!(state.next(now), Some(image("app:1")));
        for backoff in [30, 60, 120, 240, 480, 600, 600] {
            state.done(image("app:1"), failed(), at);
            let due = at + Duration::from_secs(backoff);
            assert_eq!(state.wake(), Some(due));
            assert_eq!(state.next(due - Duration::from_millis(1)), None);
            assert_eq!(state.next(due), Some(image("app:1")));
            at = due;
        }
        state.done(image("app:1"), failed(), at);
        // One member still names it.
        state.take(list("cp-1", &[]), at);
        assert_eq!(state.wake(), Some(at), "a list retries at once");
        assert_eq!(state.next(at), Some(image("app:1")));
        state.done(image("app:1"), failed(), at);
        state.take(list("cp-2", &["other:1"]), at);
    });
    assert_eq!(state.wake(), None);
    assert_eq!(state.next(at + MAX_BACKOFF), None);
    assert_eq!(counted(&handle, "failed"), 9);
    // A pull that no list names is not retried.
    state.take(prewarm("cp-1", "app:2"), at);
    assert_eq!(state.next(at), Some(image("app:2")));
    state.done(image("app:2"), failed(), at);
    assert_eq!(state.wake(), None);
}

/// Question 15: a pull skipped for a full disk counts `no_space` and warns once, until a pull goes through.
#[test]
fn a_full_image_filesystem_skips_pulls_with_one_warning_until_a_pull_goes_through() {
    let (mut state, recorder) = state();
    let handle = recorder.handle();
    let capture = Capture::default();
    let _guard = capture.install();
    let now = Instant::now();
    metrics::with_local_recorder(&recorder, || {
        state.take(list("cp-1", &["a:1", "b:1"]), now);
        for text in ["a:1", "b:1"] {
            state.take(prewarm("cp-1", text), now);
            assert_eq!(state.next(now), Some(image(text)));
            state.done(image(text), Outcome::Full(90), now);
        }
        assert_eq!(capture.warnings().len(), 1);
        state.take(list("cp-1", &["a:1", "b:1"]), now);
        assert_eq!(state.next(now), Some(image("a:1")));
        state.done(image("a:1"), Outcome::Pulled, now);
        assert_eq!(state.next(now), Some(image("b:1")));
        state.done(image("b:1"), Outcome::Full(90), now);
    });
    let warnings = capture.warnings();
    assert_eq!(warnings.len(), 2, "{warnings:?}");
    assert_eq!(warnings[0]["usage"], 90);
    assert_eq!(counted(&handle, "no_space"), 3);
    assert_eq!(counted(&handle, "ok"), 1);
}

/// A [`Pull`] that records each pull and answers as told.
#[derive(Default)]
struct Fake {
    pulls: Mutex<Vec<String>>,
    fails: Mutex<bool>,
    usage: Mutex<u8>,
    /// Whether a pull never ends.
    hangs: bool,
    /// Set once a pull that never ends is dropped.
    cut: Arc<AtomicBool>,
    /// Whether the usage cannot be read.
    unknown: bool,
}

/// Marks its pull cut when dropped.
struct Cut(Arc<AtomicBool>);

impl Drop for Cut {
    fn drop(&mut self) {
        self.0.store(true, Ordering::Relaxed);
    }
}

impl Fake {
    fn pulls(&self) -> Vec<String> {
        self.pulls.lock().unwrap().clone()
    }
}

impl Pull for Fake {
    fn pull<'a>(&'a self, image: &'a Reference) -> Boxed<'a, Result<(), cri::Error>> {
        self.pulls.lock().unwrap().push(image.to_string());
        let result = if *self.fails.lock().unwrap() {
            Err(cri::Error::Call {
                path: "/run/containerd.sock".into(),
                method: "/runtime.v1.ImageService/PullImage",
                message: "not found".to_owned(),
            })
        } else {
            Ok(())
        };
        let hangs = self.hangs.then(|| Cut(Arc::clone(&self.cut)));
        Box::pin(async move {
            if let Some(_cut) = hangs {
                std::future::pending::<()>().await;
            }
            result
        })
    }

    fn usage(&self) -> Boxed<'_, Result<u8, UsageError>> {
        let usage = if self.unknown {
            Err(UsageError::Unnamed {
                socket: "/run/containerd.sock".into(),
            })
        } else {
            Ok(*self.usage.lock().unwrap())
        };
        Box::pin(async move { usage })
    }
}

/// Lets the worker take what was sent and run what is due.
async fn settle() {
    for _ in 0..10 {
        tokio::task::yield_now().await;
    }
}

/// The worker on the test clock: a failed pull is pulled again 30 s later, and no more once no list names it.
#[tokio::test(start_paused = true)]
async fn the_worker_retries_on_the_clock_and_stops_with_the_list() {
    let fake = Arc::new(Fake::default());
    *fake.fails.lock().unwrap() = true;
    let (pushes, taken) = mpsc::channel(8);
    let pull: Arc<dyn Pull> = Arc::<Fake>::clone(&fake);
    let worker = Prewarm::spawn(taken, pull, |_| false, Percent::new(80).unwrap());
    pushes.send(list("cp-1", &["app:1"])).await.unwrap();
    pushes.send(prewarm("cp-1", "app:1")).await.unwrap();
    settle().await;
    assert_eq!(fake.pulls().len(), 1);
    tokio::time::advance(Duration::from_secs(29)).await;
    settle().await;
    assert_eq!(fake.pulls().len(), 1);
    tokio::time::advance(Duration::from_secs(1)).await;
    settle().await;
    assert_eq!(fake.pulls().len(), 2);
    pushes.send(list("cp-1", &[])).await.unwrap();
    tokio::time::advance(MAX_BACKOFF).await;
    settle().await;
    assert_eq!(fake.pulls(), ["docker.io/library/app:1"; 2]);
    // Over the limit, set live, nothing is pulled.
    *fake.usage.lock().unwrap() = 81;
    *fake.fails.lock().unwrap() = false;
    pushes.send(prewarm("cp-1", "app:2")).await.unwrap();
    settle().await;
    assert_eq!(fake.pulls().len(), 2);
    worker.set_limit(Percent::new(81).unwrap());
    pushes.send(prewarm("cp-1", "app:2")).await.unwrap();
    settle().await;
    assert_eq!(fake.pulls().len(), 3);
    worker.stop().await;
}

/// D39: the agent's stop cuts a pull in flight.
#[tokio::test]
async fn a_stop_cuts_the_pull_in_flight() {
    let fake = Arc::new(Fake {
        hangs: true,
        ..Fake::default()
    });
    let (pushes, taken) = mpsc::channel(8);
    let pull: Arc<dyn Pull> = Arc::<Fake>::clone(&fake);
    let worker = Prewarm::spawn(taken, pull, |_| false, Percent::new(80).unwrap());
    pushes.send(prewarm("cp-1", "app:1")).await.unwrap();
    while fake.pulls().is_empty() {
        tokio::task::yield_now().await;
    }
    tokio::time::timeout(Duration::from_secs(5), worker.stop())
        .await
        .expect("the stop does not wait for the pull");
    assert!(fake.cut.load(Ordering::Relaxed), "the pull is dropped");
}

/// The kubelet's garbage collection still guards a disk whose usage is unknown; the worker ends with its pushes.
#[tokio::test]
async fn an_unknown_usage_still_pulls_and_the_worker_ends_with_its_pushes() {
    let fake = Arc::new(Fake {
        unknown: true,
        ..Fake::default()
    });
    let (pushes, taken) = mpsc::channel(8);
    let pull: Arc<dyn Pull> = Arc::<Fake>::clone(&fake);
    let worker = Prewarm::spawn(taken, pull, |_| false, Percent::new(0).unwrap());
    pushes.send(prewarm("cp-1", "app:1")).await.unwrap();
    while fake.pulls().is_empty() {
        tokio::task::yield_now().await;
    }
    drop(pushes);
    tokio::time::timeout(Duration::from_secs(5), worker.task)
        .await
        .expect("the worker ends once its pushes do")
        .expect("the worker does not panic");
}
