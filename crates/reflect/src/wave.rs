//! The waves of `prewarm.images`: a `Prewarm` to the seeds, then rounds of up to [`FANOUT`] agents per agent sent the
//! image before, until every agent streaming has it (D51, D185, D186).
//!
//! A member reads its waves once a [`TICK`], and never as it answers a `Lookup` (D107). Two members with the same
//! stream set and list send the same `Prewarm`s: each pick is [`seeds`] over the agents not sent the image yet.

use std::collections::HashSet;
use std::num::NonZeroU32;
use std::sync::Arc;
use std::time::Duration;

use futures_util::StreamExt as _;
use futures_util::stream::FuturesUnordered;
use speculaire_oci::reference::Reference;
use tokio::sync::watch;
use tokio::time::{Instant, MissedTickBehavior};
use tokio_util::sync::CancellationToken;
use tracing::{debug, warn};

use crate::index::Index;
use crate::metrics::{self, Cause, Release, Stage};
use crate::outbox::Streams;
use crate::prewarm::{Failure, Image, Plan, Resolution, Resolve};
use crate::push::PrewarmList;
use crate::seed::seeds;

/// How many agents a round sends the image to per agent sent it before (D185).
const FANOUT: usize = 4;
/// How long the waves of the list a member starts with wait: its agents connect again and resync within it (D33).
const SETTLE: Duration = Duration::from_secs(60);
/// The wait after a resolution fails; each failure in a row doubles it, up to [`RETRY_MAX`].
const RETRY: Duration = Duration::from_secs(10);
const RETRY_MAX: Duration = Duration::from_secs(300);
/// How often the waves are read.
const TICK: Duration = Duration::from_secs(1);

/// The wave of each entry of `prewarm.images`.
pub(crate) struct Waves {
    plan: Plan,
    entries: Vec<Entry>,
    index: Arc<Index>,
    streams: Arc<Streams>,
}

struct Entry {
    image: Image,
    resolution: Option<Resolution>,
    next: Next,
    /// Resolutions failed in a row.
    failures: u32,
    wave: Wave,
}

/// When an entry is resolved next.
enum Next {
    /// At this time: the start of its wave, or a retry.
    At(Instant),
    /// Now: a resolution is in flight.
    Flight,
    /// Resolved at this time: a tag is resolved again `prewarm.refresh` later, a digest never (D186).
    Resolved(Instant),
}

enum Wave {
    /// Due: the wave starts with the entry's first resolution.
    Due(Cause),
    /// Started: it sends to the seeds once the image is resolved and some agent streams.
    Started,
    /// The image was sent to `sent`; the agents of the round, `waiting`, were sent it at `since` and have not all
    /// announced it.
    Round {
        sent: HashSet<Arc<str>>,
        waiting: Vec<Arc<str>>,
        since: Instant,
    },
    /// Every agent streaming was sent the image; a stream that opens later is sent it after its `Hello`.
    Done,
}

impl Waves {
    /// The waves of `plan`'s images, which start [`SETTLE`] after `now`. Each stream is sent the list now, and each
    /// that opens later after its `Hello`.
    pub(crate) fn new(plan: Plan, now: Instant, index: Arc<Index>, streams: Arc<Streams>) -> Self {
        let at = now + SETTLE;
        let entries = plan
            .images
            .as_slice()
            .iter()
            .map(|image| Entry::new(image.clone(), Cause::Start, at))
            .collect();
        streams.set_list(&Arc::new(PrewarmList::from(&plan.images)));
        Self {
            plan,
            entries,
            index,
            streams,
        }
    }

    /// Takes `plan` in place of the running one. A new entry's wave starts now; an entry gone is no longer sent to
    /// streams that open. A changed list is sent to each stream.
    pub(crate) fn set(&mut self, plan: Plan, now: Instant) {
        let mut old = std::mem::take(&mut self.entries);
        self.entries = plan
            .images
            .as_slice()
            .iter()
            .map(
                |image| match old.iter().position(|entry| entry.image == *image) {
                    Some(at) => old.swap_remove(at),
                    None => Entry::new(image.clone(), Cause::List, now),
                },
            )
            .collect();
        for gone in old {
            self.streams.withdraw(gone.image.reference());
        }
        if plan.images != self.plan.images {
            self.streams
                .set_list(&Arc::new(PrewarmList::from(&plan.images)));
        }
        self.plan = plan;
    }

    /// Moves each wave on at `now`, and returns the images to resolve, each with its last resolution.
    pub(crate) fn step(&mut self, now: Instant) -> Vec<(Image, Option<Resolution>)> {
        let nodes = self.streams.nodes();
        let streaming: HashSet<&str> = nodes.iter().map(|node| &**node).collect();
        let mut asks = Vec::new();
        for entry in &mut self.entries {
            if entry.due(now, self.plan.refresh) {
                if let Wave::Due(cause) = entry.wave {
                    metrics::wave(cause);
                    entry.wave = Wave::Started;
                }
                entry.next = Next::Flight;
                asks.push((entry.image.clone(), entry.resolution.clone()));
            }
            entry.advance(
                now,
                &self.plan,
                (&nodes, &streaming),
                &self.index,
                &self.streams,
            );
        }
        asks
    }

    /// Takes what resolving `image` gave at `now`. A resolution whose platform manifests changed starts a new wave.
    pub(crate) fn resolved(
        &mut self,
        image: &Image,
        resolved: Result<Resolution, Failure>,
        now: Instant,
    ) {
        let Some(entry) = self
            .entries
            .iter_mut()
            .find(|entry| entry.image == *image && matches!(entry.next, Next::Flight))
        else {
            // The entry left the list as it was resolved.
            return;
        };
        match resolved {
            Ok(resolution) => {
                entry.failures = 0;
                entry.next = Next::Resolved(now);
                if entry
                    .resolution
                    .as_ref()
                    .is_some_and(|known| !known.same_platforms(&resolution))
                {
                    metrics::wave(Cause::Refresh);
                    self.streams.withdraw(image.reference());
                    entry.wave = Wave::Started;
                }
                entry.resolution = Some(resolution);
            }
            Err(err) => {
                entry.failures = entry.failures.saturating_add(1);
                let wait = RETRY
                    .saturating_mul(2_u32.saturating_pow(entry.failures - 1))
                    .min(RETRY_MAX);
                metrics::resolve_failed();
                warn!(
                    image = image.as_str(),
                    error = %err,
                    ?wait,
                    "cannot resolve a prewarm.images entry; trying again"
                );
                entry.next = Next::At(now + wait);
            }
        }
    }
}

impl Entry {
    const fn new(image: Image, cause: Cause, at: Instant) -> Self {
        Self {
            image,
            resolution: None,
            next: Next::At(at),
            failures: 0,
            wave: Wave::Due(cause),
        }
    }

    /// Whether the entry is to be resolved at `now`.
    fn due(&self, now: Instant, refresh: Duration) -> bool {
        match self.next {
            Next::At(at) => at <= now,
            Next::Flight => false,
            Next::Resolved(at) => {
                self.image.reference().digest().is_none()
                    && at.checked_add(refresh).is_some_and(|at| at <= now)
            }
        }
    }

    /// Sends to the seeds once the wave started and the image is resolved, then to the next round once the last
    /// announced the image or `prewarm.seed_timeout` passed (D185). `nodes` are the agents streaming, as `streaming`
    /// too.
    fn advance(
        &mut self,
        now: Instant,
        plan: &Plan,
        (nodes, streaming): (&[Arc<str>], &HashSet<&str>),
        index: &Index,
        streams: &Streams,
    ) {
        let Some(resolution) = &self.resolution else {
            return;
        };
        let image = &self.image;
        match &mut self.wave {
            Wave::Due(_) | Wave::Done => {}
            Wave::Started => {
                let seeds = pick(image, nodes, &HashSet::new(), plan.seeds);
                if seeds.is_empty() {
                    return;
                }
                send(streams, &seeds, image.reference(), Stage::Seed);
                self.wave = Wave::Round {
                    sent: seeds.iter().cloned().collect(),
                    waiting: seeds,
                    since: now,
                };
            }
            Wave::Round {
                sent,
                waiting,
                since,
            } => {
                // An agent whose stream closed no longer holds the round.
                waiting
                    .retain(|node| streaming.contains(&**node) && !holds(index, node, resolution));
                let release = if waiting.is_empty() {
                    Release::Announced
                } else if since
                    .checked_add(plan.seed_timeout)
                    .is_some_and(|end| end <= now)
                {
                    Release::Timeout
                } else {
                    return;
                };
                metrics::round(release);
                let count = u32::try_from(sent.len().saturating_mul(FANOUT))
                    .ok()
                    .and_then(NonZeroU32::new)
                    .unwrap_or(NonZeroU32::MAX);
                let round = pick(image, nodes, sent, count);
                if round.is_empty() {
                    // Streams that opened since the last pick: none is sent it twice.
                    let rest: Vec<_> = streams
                        .release(image.reference())
                        .into_iter()
                        .filter(|node| !sent.contains(node))
                        .collect();
                    send(streams, &rest, image.reference(), Stage::Release);
                    self.wave = Wave::Done;
                    return;
                }
                send(streams, &round, image.reference(), Stage::Release);
                sent.extend(round.iter().cloned());
                *waiting = round;
                *since = now;
            }
        }
    }
}

/// The best `count` of `nodes` not in `sent`, by the image's rendezvous hash (D181).
fn pick(
    image: &Image,
    nodes: &[Arc<str>],
    sent: &HashSet<Arc<str>>,
    count: NonZeroU32,
) -> Vec<Arc<str>> {
    let candidates = nodes
        .iter()
        .filter(|node| !sent.contains(*node))
        .map(|node| &**node);
    seeds(image.as_str(), candidates, count)
        .map(Arc::from)
        .collect()
}

/// Whether `node` announced every layer of one of the resolution's platform manifests.
fn holds(index: &Index, node: &str, resolution: &Resolution) -> bool {
    resolution
        .platforms
        .iter()
        .any(|platform| index.holds(node, &platform.layers))
}

fn send(streams: &Streams, nodes: &[Arc<str>], image: &Reference, stage: Stage) {
    let mut queued = 0;
    for node in nodes {
        match streams.prewarm(node, image) {
            Ok(()) => queued += 1,
            Err(err) => debug!(node = &**node, %image, error = %err, "a prewarm is not queued"),
        }
    }
    metrics::sent(stage, queued);
}

/// Runs `waves` until `stop`: they take each plan `plans` holds, and `resolver` resolves their images.
pub(crate) async fn run(
    mut waves: Waves,
    resolver: Arc<dyn Resolve>,
    mut plans: watch::Receiver<Plan>,
    stop: CancellationToken,
) {
    let mut flights = FuturesUnordered::new();
    let mut tick = tokio::time::interval(TICK);
    tick.set_missed_tick_behavior(MissedTickBehavior::Delay);
    let mut following = true;
    loop {
        for (image, known) in waves.step(Instant::now()) {
            let resolver = Arc::clone(&resolver);
            flights.push(async move {
                let answer = resolver.resolve(image.reference(), known.as_ref()).await;
                (image, answer)
            });
        }
        tokio::select! {
            () = stop.cancelled() => return,
            changed = plans.changed(), if following => match changed {
                Ok(()) => {
                    let plan = plans.borrow_and_update().clone();
                    waves.set(plan, Instant::now());
                }
                // The agent's loop ended: the plan stays as it is.
                Err(_) => following = false,
            },
            Some((image, answer)) = flights.next() => waves.resolved(&image, answer, Instant::now()),
            _ = tick.tick() => {}
        }
    }
}

#[cfg(test)]
mod tests {
    use std::collections::{BTreeMap, BTreeSet};
    use std::net::SocketAddr;

    use metrics_exporter_prometheus::PrometheusBuilder;

    use super::*;
    use crate::Key;
    use crate::index::Stream;
    use crate::outbox::Outbox;
    use crate::prewarm::{Images, Platform, Resolving};

    const TIMEOUT: Duration = Duration::from_secs(300);
    const REFRESH: Duration = Duration::from_secs(3600);

    /// The agents streaming to one member: each announces to its index and takes pushes from its streams.
    struct Member {
        index: Arc<Index>,
        streams: Arc<Streams>,
        agents: BTreeMap<String, (Stream, Arc<Outbox>)>,
    }

    impl Member {
        fn new(nodes: impl IntoIterator<Item = String>) -> Self {
            let mut member = Self {
                index: Arc::default(),
                streams: Arc::default(),
                agents: BTreeMap::new(),
            };
            for node in nodes {
                member.connect(&node);
            }
            member
        }

        fn connect(&mut self, node: &str) {
            let stream = self
                .index
                .join(node, SocketAddr::from(([10, 0, 0, 1], 9000)));
            let outbox = self.streams.open(&Arc::from(node));
            self.agents.insert(node.to_owned(), (stream, outbox));
        }

        fn waves(&self, plan: Plan, now: Instant) -> Waves {
            Waves::new(
                plan,
                now,
                Arc::clone(&self.index),
                Arc::clone(&self.streams),
            )
        }

        fn disconnect(&mut self, node: &str) {
            let (stream, outbox) = self.agents.remove(node).unwrap();
            self.index.leave(&stream);
            self.streams.close(node, &outbox);
        }

        fn announce(&self, node: &str, keys: &[Key]) {
            let (stream, _) = &self.agents[node];
            self.index.apply(stream, keys, &[], usize::MAX).unwrap();
        }

        /// The images each node was sent since the last call, by node, leaving out lists.
        fn sent(&self) -> BTreeMap<String, Vec<Reference>> {
            self.agents
                .iter()
                .map(|(node, (_, outbox))| (node.clone(), outbox.take().images))
                .filter(|(_, images)| !images.is_empty())
                .collect()
        }

        /// The length of the list each node was sent since the last call.
        fn lists(&self) -> Vec<usize> {
            self.agents
                .values()
                .filter_map(|(_, outbox)| outbox.take().list)
                .map(|list| list.images().len())
                .collect()
        }
    }

    fn nodes(count: usize) -> impl DoubleEndedIterator<Item = String> {
        (0..count).map(|n| format!("node-{n}"))
    }

    fn plan(images: &[&str], seeds: u32) -> Plan {
        let images = images.iter().map(|text| Image::parse(text).unwrap());
        Plan {
            images: Images::new(images.collect()).unwrap(),
            seeds: NonZeroU32::new(seeds).unwrap(),
            seed_timeout: TIMEOUT,
            refresh: REFRESH,
        }
    }

    /// An image of one platform manifest, `manifest`, with layers `layers`.
    fn resolution(manifest: u8, layers: &[u8]) -> Resolution {
        Resolution {
            root: Key::Sha256([manifest; 32]),
            platforms: vec![Platform {
                manifest: Key::Sha256([manifest; 32]),
                layers: layers.iter().map(|&n| Key::Sha256([n; 32])).collect(),
            }],
        }
    }

    fn layers(resolution: &Resolution) -> &[Key] {
        &resolution.platforms[0].layers
    }

    /// Runs `test` with a recorder of its own, and returns what it recorded.
    fn recorded(test: impl FnOnce()) -> String {
        let recorder = PrometheusBuilder::new().build_recorder();
        let handle = recorder.handle();
        ::metrics::with_local_recorder(&recorder, test);
        handle.render()
    }

    const NONE: [&str; 0] = [];

    /// The images `waves` asks to resolve at `now`.
    fn asked(waves: &mut Waves, now: Instant) -> Vec<String> {
        let asks = waves.step(now);
        asks.into_iter()
            .map(|(image, _)| image.as_str().to_owned())
            .collect()
    }

    /// Steps `waves` at `now`, answers each resolution it asks for with `resolution` and steps again; returns the
    /// images it asked for.
    fn step(waves: &mut Waves, now: Instant, resolution: &Resolution) -> Vec<String> {
        let asks = waves.step(now);
        for (image, _) in &asks {
            waves.resolved(image, Ok(resolution.clone()), now);
        }
        waves.step(now);
        asks.into_iter()
            .map(|(image, _)| image.as_str().to_owned())
            .collect()
    }

    #[test]
    fn the_seeds_are_sent_the_image_first_and_the_rest_once_both_announced_it() {
        let member = Member::new(nodes(10));
        let start = Instant::now();
        let app = resolution(1, &[2, 3]);
        let text = "registry.example/app:1";
        let mut waves = member.waves(plan(&[text], 2), start);
        // The list a member starts with waits for its agents to come back.
        assert_eq!(asked(&mut waves, start + SETTLE - TICK), NONE);
        assert!(member.sent().is_empty());
        let now = start + SETTLE;
        assert_eq!(step(&mut waves, now, &app), [text]);
        let expected: BTreeSet<&str> = seeds(
            text,
            member.agents.keys().map(String::as_str),
            NonZeroU32::new(2).unwrap(),
        )
        .collect();
        let sent = member.sent();
        assert_eq!(
            sent.keys().map(String::as_str).collect::<BTreeSet<_>>(),
            expected
        );
        let mut pair = expected.into_iter();
        let (first, second) = (pair.next().unwrap(), pair.next().unwrap());
        // One seed announcing, and the other a part of the image, releases nothing.
        member.announce(first, layers(&app));
        member.announce(second, &layers(&app)[..1]);
        waves.step(now + TICK);
        assert!(member.sent().is_empty());
        member.announce(second, layers(&app));
        waves.step(now + TICK * 2);
        let released = member.sent();
        assert_eq!(released.len(), 8);
        assert!(!released.contains_key(first) && !released.contains_key(second));
    }

    #[test]
    fn a_silent_seed_holds_the_release_back_until_the_seed_timeout() {
        let member = Member::new(nodes(10));
        let start = Instant::now();
        let app = resolution(1, &[2]);
        let mut waves = member.waves(plan(&["registry.example/app:1"], 2), start);
        let now = start + SETTLE;
        let text = recorded(|| {
            step(&mut waves, now, &app);
            let seeds: Vec<String> = member.sent().into_keys().collect();
            member.announce(&seeds[0], layers(&app));
            waves.step(now + TIMEOUT - Duration::from_millis(1));
            assert!(member.sent().is_empty());
            waves.step(now + TIMEOUT);
            assert_eq!(member.sent().len(), 8);
        });
        assert!(
            text.contains("speculaire_reflector_prewarm_rounds_total{release=\"timeout\"} 1"),
            "{text}"
        );
        assert!(!text.contains("release=\"announced\""), "{text}");
        assert!(
            text.contains("speculaire_reflector_prewarm_sent_total{stage=\"seed\"} 2"),
            "{text}"
        );
    }

    #[test]
    fn a_seed_whose_stream_closed_no_longer_holds_the_release_back() {
        let mut member = Member::new(nodes(10));
        let start = Instant::now();
        let app = resolution(1, &[2]);
        let mut waves = member.waves(plan(&["registry.example/app:1"], 2), start);
        let now = start + SETTLE;
        step(&mut waves, now, &app);
        let seeds: Vec<String> = member.sent().into_keys().collect();
        member.announce(&seeds[0], layers(&app));
        member.disconnect(&seeds[1]);
        waves.step(now + TICK);
        assert_eq!(member.sent().len(), 8);
    }

    /// Runs the wave of `text` over `member`'s agents, each announcing the image once it is sent it, and returns the
    /// rounds, the seeds first. Each checks that a round is sent only once the one before all announced the image.
    fn rounds(member: &Member, text: &str, app: &Resolution) -> Vec<BTreeSet<String>> {
        let start = Instant::now();
        let mut waves = member.waves(plan(&[text], 2), start);
        let mut now = start + SETTLE;
        step(&mut waves, now, app);
        let mut rounds = Vec::new();
        loop {
            let round: BTreeSet<String> = member.sent().into_keys().collect();
            if round.is_empty() {
                return rounds;
            }
            let mut nodes = round.iter();
            let last = nodes.next_back().unwrap();
            for node in nodes {
                member.announce(node, layers(app));
            }
            now += TICK;
            waves.step(now);
            assert!(member.sent().is_empty(), "sent before the round announced");
            member.announce(last, layers(app));
            now += TICK;
            waves.step(now);
            rounds.push(round);
        }
    }

    #[test]
    fn rounds_grow_by_four_agents_per_holder_and_two_members_send_the_same() {
        let app = resolution(1, &[2, 3]);
        let text = "registry.example/app:1";
        let first = rounds(&Member::new(nodes(1000)), text, &app);
        let sizes: Vec<usize> = first.iter().map(BTreeSet::len).collect();
        assert_eq!(sizes, [2, 8, 40, 200, 750]);
        assert_eq!(first.iter().flatten().collect::<BTreeSet<_>>().len(), 1000);
        // The other member's agents connected in the opposite order.
        let second = rounds(&Member::new(nodes(1000).rev()), text, &app);
        assert_eq!(first, second);
    }

    #[test]
    fn two_members_pick_the_same_seeds_and_send_the_same_prewarms() {
        let list = ["registry.example/app:1", "registry.example/db:2"];
        let app = resolution(1, &[2]);
        let sends = |member: &Member| {
            let start = Instant::now();
            let mut waves = member.waves(plan(&list, 3), start);
            step(&mut waves, start + SETTLE, &app);
            member.sent()
        };
        let first = sends(&Member::new(nodes(20)));
        assert_eq!(first.values().map(Vec::len).sum::<usize>(), 6);
        assert_eq!(first, sends(&Member::new(nodes(20).rev())));
    }

    #[test]
    fn a_tag_is_resolved_again_each_refresh_and_new_platform_manifests_start_a_wave() {
        let member = Member::new(nodes(3));
        let start = Instant::now();
        let old = resolution(1, &[2]);
        let new = resolution(4, &[5]);
        let tag = "registry.example/app:1";
        let digest = format!("registry.example/app@sha256:{}", "a".repeat(64));
        let mut waves = member.waves(plan(&[tag, &digest], 1), start);
        let text = recorded(|| {
            let now = start + SETTLE;
            assert_eq!(step(&mut waves, now, &old), [tag, digest.as_str()]);
            for node in member.agents.keys() {
                member.announce(node, layers(&old));
            }
            waves.step(now + TICK);
            waves.step(now + TICK * 2);
            assert_eq!(member.sent().values().map(Vec::len).sum::<usize>(), 6);
            // The same platform manifests: no wave.
            let refresh = now + REFRESH;
            assert_eq!(asked(&mut waves, refresh - TICK), NONE);
            assert_eq!(step(&mut waves, refresh, &old), [tag]);
            assert!(member.sent().is_empty());
            // New ones: a wave, which starts with the seed.
            let refresh = refresh + REFRESH;
            assert_eq!(step(&mut waves, refresh, &new), [tag]);
            assert_eq!(member.sent().len(), 1);
        });
        assert!(
            text.contains("speculaire_reflector_prewarm_waves_total{cause=\"refresh\"} 1"),
            "{text}"
        );
        assert!(
            text.contains("speculaire_reflector_prewarm_waves_total{cause=\"start\"} 2"),
            "{text}"
        );
    }

    #[test]
    fn an_agent_streaming_after_the_wave_is_sent_the_image_at_its_hello_and_before_it_nothing() {
        let mut member = Member::new(nodes(2));
        let start = Instant::now();
        let app = resolution(1, &[2]);
        let mut waves = member.waves(plan(&["registry.example/app:1"], 1), start);
        member.lists();
        member.connect("early");
        assert!(member.sent().is_empty());
        let now = start + SETTLE;
        step(&mut waves, now, &app);
        let mut sent: Vec<String> = member.sent().into_keys().collect();
        let mut at = now;
        while !sent.is_empty() {
            for node in &sent {
                member.announce(node, layers(&app));
            }
            at += TICK;
            waves.step(at);
            sent = member.sent().into_keys().collect();
        }
        member.connect("late");
        let late = member.agents["late"].1.take();
        assert_eq!(late.images.len(), 1);
        assert!(late.list.is_some());
        assert!(member.sent().is_empty());
    }

    #[test]
    fn an_entry_removed_is_not_sent_to_a_stream_that_opens_later() {
        let mut member = Member::new(nodes(1));
        let start = Instant::now();
        let app = resolution(1, &[2]);
        let both = plan(&["registry.example/app:1", "registry.example/db:1"], 1);
        let mut waves = member.waves(both, start);
        let now = start + SETTLE;
        step(&mut waves, now, &app);
        assert_eq!(member.sent()["node-0"].len(), 2);
        // The one agent announces both: each wave is done.
        member.announce("node-0", layers(&app));
        waves.step(now + TICK);
        waves.set(plan(&["registry.example/db:1"], 1), now);
        member.connect("late");
        let late = member.agents["late"].1.take();
        let images: Vec<String> = late.images.iter().map(ToString::to_string).collect();
        assert_eq!(images, ["registry.example/db:1"]);
    }

    #[test]
    fn a_resolution_goes_to_its_own_entry() {
        let member = Member::new(nodes(10));
        let start = Instant::now();
        let both = plan(&["registry.example/app:1", "registry.example/db:1"], 1);
        let mut waves = member.waves(both, start);
        let now = start + SETTLE;
        let asks = waves.step(now);
        assert_eq!(asks.len(), 2);
        waves.resolved(&asks[1].0, Ok(resolution(1, &[2])), now);
        waves.step(now);
        let sent: Vec<Vec<String>> = member
            .sent()
            .into_values()
            .map(|images| images.iter().map(ToString::to_string).collect())
            .collect();
        assert_eq!(sent, [["registry.example/db:1"]]);
    }

    #[test]
    fn a_new_entry_starts_its_wave_at_once_and_every_stream_is_sent_the_list() {
        let member = Member::new(nodes(2));
        let start = Instant::now();
        let mut waves = member.waves(plan(&["registry.example/app:1"], 1), start);
        assert_eq!(member.lists(), [1, 1]);
        let both = ["registry.example/app:1", "registry.example/db:1"];
        let text = recorded(|| {
            waves.set(plan(&both, 1), start);
            assert_eq!(member.lists(), [2, 2]);
            let asks = waves.step(start);
            assert_eq!(asks.len(), 1);
            assert_eq!(asks[0].0.as_str(), "registry.example/db:1");
            // The same list is not sent again.
            waves.set(plan(&both, 2), start);
            assert_eq!(member.lists(), Vec::<usize>::new());
        });
        assert!(
            text.contains("speculaire_reflector_prewarm_waves_total{cause=\"list\"} 1"),
            "{text}"
        );
    }

    #[test]
    fn a_failed_resolution_is_counted_and_tried_again_later_each_time() {
        let member = Member::new(nodes(1));
        let start = Instant::now();
        let mut waves = member.waves(plan(&["registry.example/app:1"], 1), start);
        let mut now = start + SETTLE;
        let text = recorded(|| {
            for wait in [10, 20, 40] {
                let asks = waves.step(now);
                assert_eq!(asks.len(), 1);
                waves.resolved(&asks[0].0, Err("unreachable".into()), now);
                now += Duration::from_secs(wait);
                assert_eq!(asked(&mut waves, now - Duration::from_millis(1)), NONE);
            }
        });
        assert!(
            text.contains("speculaire_reflector_prewarm_resolve_failures_total 3"),
            "{text}"
        );
        assert!(
            text.contains("speculaire_reflector_prewarm_waves_total{cause=\"start\"} 1"),
            "{text}"
        );
    }

    /// A resolver whose every image is the one resolution.
    struct Fixed(Resolution);

    impl Resolve for Fixed {
        fn resolve<'a>(
            &'a self,
            _image: &'a Reference,
            _known: Option<&'a Resolution>,
        ) -> Resolving<'a> {
            Box::pin(std::future::ready(Ok(self.0.clone())))
        }
    }

    #[tokio::test(start_paused = true)]
    async fn the_task_follows_the_plan_until_stopped() {
        let member = Member::new(nodes(1));
        let (plans, followed) = watch::channel(plan(&[], 1));
        let stop = CancellationToken::new();
        let task = tokio::spawn(run(
            member.waves(plan(&[], 1), Instant::now()),
            Arc::new(Fixed(resolution(1, &[2]))),
            followed,
            stop.clone(),
        ));
        plans.send_replace(plan(&["registry.example/app:1"], 1));
        tokio::time::sleep(TICK * 2).await;
        assert_eq!(member.sent().len(), 1);
        drop(plans);
        tokio::time::sleep(TICK * 2).await;
        stop.cancel();
        task.await.unwrap();
    }
}
