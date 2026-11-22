//! A prewarm wave under D33's load (D51, D185, D193): a registry that serves one image manifest, agents that announce
//! its layers [`PULL`] after their first `Prewarm` as if they had pulled it, and what the wave did, read from each
//! `Prewarm` the agents received.

use std::collections::{BTreeMap, BTreeSet};
use std::net::{Ipv4Addr, SocketAddr};
use std::num::NonZeroU32;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::Duration;

use speculaire_oci::reference::Digest;
use speculaire_reflect::client::{Holdings, Pushed, Source};
use speculaire_reflect::push::Push;
use tokio::io::{AsyncBufReadExt as _, AsyncWriteExt as _, BufReader};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::mpsc;
use tokio::time::Instant;

use crate::agents;

/// How long an agent takes to announce the image after its first `Prewarm`, as a pull would.
const PULL: Duration = Duration::from_secs(4);
/// A pause between two `Prewarm`s of a member that ends a round: a round's come at once, the next round's at least
/// [`PULL`] later.
const ROUND_GAP: Duration = Duration::from_secs(2);
/// `prewarm.seeds`, by default.
const SEEDS: NonZeroU32 = NonZeroU32::new(2).expect("2 is not zero");
/// The image's layers.
pub(crate) const LAYERS: usize = 8;
const REPOSITORY: &str = "load/prewarm";
const TAG: &str = "1";
const MEDIA_TYPE: &str = "application/vnd.oci.image.manifest.v1+json";

/// A plain HTTP registry that serves one image manifest, whose blobs no one fetches, until the runtime stops.
pub(crate) struct Registry {
    /// Where it listens.
    pub(crate) address: SocketAddr,
    /// The image's layers, which the agents announce.
    pub(crate) layers: Arc<[Digest]>,
}

/// The manifest the registry serves, and its digest.
struct Served {
    manifest: String,
    digest: Digest,
}

impl Registry {
    /// Serves an image of random layers, the same for the same `seed`.
    pub(crate) async fn start(seed: u64) -> anyhow::Result<Self> {
        let mut rng = fastrand::Rng::with_seed(seed);
        let config = agents::digest(&mut rng)?;
        let layers: Arc<[Digest]> = (0..LAYERS)
            .map(|_| agents::digest(&mut rng))
            .collect::<Result<_, _>>()?;
        let descriptor = |media: &str, digest: &Digest| {
            format!(r#"{{"mediaType":"{media}","digest":"{digest}","size":1}}"#)
        };
        let manifest = format!(
            r#"{{"schemaVersion":2,"mediaType":"{MEDIA_TYPE}","config":{},"layers":[{}]}}"#,
            descriptor("application/vnd.oci.image.config.v1+json", &config),
            layers
                .iter()
                .map(|layer| descriptor("application/vnd.oci.image.layer.v1.tar+gzip", layer))
                .collect::<Vec<_>>()
                .join(",")
        );
        let digest = speculaire_oci::hash::of("sha256", manifest.as_bytes())
            .ok_or_else(|| anyhow::anyhow!("no sha256"))?;
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let address = listener.local_addr()?;
        tokio::spawn(serve(listener, Arc::new(Served { manifest, digest })));
        Ok(Self { address, layers })
    }

    /// The image's reference.
    pub(crate) fn image(&self) -> String {
        format!("{}/{REPOSITORY}:{TAG}", self.address)
    }
}

async fn serve(listener: TcpListener, served: Arc<Served>) {
    loop {
        if let Ok((stream, _)) = listener.accept().await {
            tokio::spawn(answer(stream, Arc::clone(&served)));
        }
    }
}

/// Answers the requests of one connection, until it closes or fails.
async fn answer(stream: TcpStream, served: Arc<Served>) -> std::io::Result<()> {
    let mut stream = BufReader::new(stream);
    loop {
        let mut request = String::new();
        if stream.read_line(&mut request).await? == 0 {
            return Ok(());
        }
        // The resolver's requests have no body: the head ends at the first empty line.
        loop {
            let mut header = String::new();
            if stream.read_line(&mut header).await? == 0 {
                return Ok(());
            }
            if header.trim_end().is_empty() {
                break;
            }
        }
        let mut words = request.split(' ');
        let (method, path) = (words.next().unwrap_or(""), words.next().unwrap_or(""));
        stream
            .get_mut()
            .write_all(&respond(method, path, &served))
            .await?;
    }
}

/// The response to `method` `path`: the manifest by its tag, or 404.
fn respond(method: &str, path: &str, served: &Served) -> Vec<u8> {
    let found = path
        .strip_prefix("/v2/")
        .and_then(|path| path.strip_prefix(REPOSITORY))
        .is_some_and(|path| path == format!("/manifests/{TAG}"));
    if !found || !matches!(method, "GET" | "HEAD") {
        return b"HTTP/1.1 404 Not Found\r\ncontent-length: 0\r\n\r\n".to_vec();
    }
    let mut response = format!(
        "HTTP/1.1 200 OK\r\ncontent-type: {MEDIA_TYPE}\r\ndocker-content-digest: {}\r\ncontent-length: {}\r\n\r\n",
        served.digest,
        served.manifest.len()
    )
    .into_bytes();
    if method == "GET" {
        response.extend_from_slice(served.manifest.as_bytes());
    }
    response
}

/// A `Prewarm` an agent received.
#[derive(Clone, Debug)]
pub(crate) struct Receipt {
    /// The agent's index.
    agent: usize,
    /// The member that sent it.
    member: String,
    at: Instant,
}

/// Every `Prewarm` the agents received so far, and how many agents announced the image.
#[derive(Debug, Default)]
pub(crate) struct Received {
    receipts: Mutex<Vec<Receipt>>,
    announced: AtomicUsize,
}

impl Received {
    /// How many agents announced the image.
    pub(crate) fn announced(&self) -> usize {
        self.announced.load(Ordering::Relaxed)
    }

    fn receipts(&self) -> MutexGuard<'_, Vec<Receipt>> {
        self.receipts.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// What the wave of `image` did across `members` and `agents` agents.
    pub(crate) fn wave(&self, image: &str, members: &[&str], agents: usize) -> Wave {
        Wave::of(&self.receipts(), image, members, agents)
    }
}

/// The channel of agent `agent`'s pushes: each `Prewarm` is noted in `received`, and [`PULL`] after the first the
/// agent announces `layers` in `holdings`.
pub(crate) fn answer_prewarm(
    agent: usize,
    holdings: &Arc<Holdings>,
    layers: &Arc<[Digest]>,
    received: &Arc<Received>,
) -> mpsc::Sender<Pushed> {
    let (send, mut pushes) = mpsc::channel(8);
    let (holdings, layers, received) = (
        Arc::clone(holdings),
        Arc::clone(layers),
        Arc::clone(received),
    );
    tokio::spawn(async move {
        let mut pulling = None;
        while let Some(Pushed { member, push }) = pushes.recv().await {
            let Push::Prewarm(_) = push else {
                continue;
            };
            let at = Instant::now();
            received.receipts().push(Receipt { agent, member, at });
            pulling.get_or_insert_with(|| {
                let (holdings, layers, received) = (
                    Arc::clone(&holdings),
                    Arc::clone(&layers),
                    Arc::clone(&received),
                );
                tokio::spawn(async move {
                    tokio::time::sleep(PULL).await;
                    for layer in layers.iter() {
                        holdings.add(Source::Content, layer);
                    }
                    received.announced.fetch_add(1, Ordering::Relaxed);
                })
            });
        }
    });
    send
}

/// What a wave did, from the `Prewarm`s the agents received.
#[derive(Clone, Debug, PartialEq)]
pub struct Wave {
    /// Whether each member's first round was the same 2 agents, those D181's rank picks among all.
    pub seeds_agree: bool,
    /// The agents that received one `Prewarm` from each member, no more.
    pub once_each: usize,
    /// The agents of the run.
    pub agents: usize,
    /// The size of each member's rounds, the seeds' first, by member: a round ends at a pause of 2 s.
    pub rounds: Vec<Vec<usize>>,
    /// The largest round over the agents sent the image before it, across members: D185 allows 4.
    pub fanout: Option<f64>,
    /// From the first `Prewarm` to the last.
    pub took: Duration,
}

impl Wave {
    fn of(receipts: &[Receipt], image: &str, members: &[&str], agents: usize) -> Self {
        let names: Vec<String> = (0..agents).map(agents::name).collect();
        let seeds: BTreeSet<&str> =
            speculaire_reflect::seeds(image, names.iter().map(String::as_str), SEEDS).collect();
        let mut counts: BTreeMap<(usize, &str), usize> = BTreeMap::new();
        for receipt in receipts {
            *counts.entry((receipt.agent, &receipt.member)).or_default() += 1;
        }
        let once_each = (0..agents)
            .filter(|&agent| {
                members
                    .iter()
                    .all(|member| counts.get(&(agent, member)) == Some(&1))
            })
            .count();
        let mut seeds_agree = true;
        let mut fanout: Option<f64> = None;
        let mut rounds = Vec::with_capacity(members.len());
        for member in members {
            let mut theirs: Vec<&Receipt> =
                receipts.iter().filter(|r| r.member == *member).collect();
            theirs.sort_by_key(|receipt| receipt.at);
            let split = split(&theirs);
            let first: BTreeSet<&str> = split
                .first()
                .map(|round| round.iter().map(|r| names[r.agent].as_str()).collect())
                .unwrap_or_default();
            seeds_agree &= first == seeds;
            let mut sent = 0_usize;
            for round in &split {
                if sent > 0 {
                    #[expect(clippy::cast_precision_loss, reason = "counts stay far below 2^53")]
                    let ratio = round.len() as f64 / sent as f64;
                    fanout = Some(fanout.map_or(ratio, |max| max.max(ratio)));
                }
                sent += round.len();
            }
            rounds.push(split.iter().map(Vec::len).collect());
        }
        let times = receipts.iter().map(|r| r.at);
        let took = times
            .clone()
            .max()
            .zip(times.min())
            .map_or(Duration::ZERO, |(last, first)| last - first);
        Self {
            seeds_agree,
            once_each,
            agents,
            rounds,
            fanout,
            took,
        }
    }
}

/// `sorted` receipts in rounds: a round ends where the next comes [`ROUND_GAP`] or more later.
fn split<'a>(sorted: &[&'a Receipt]) -> Vec<Vec<&'a Receipt>> {
    let mut rounds: Vec<Vec<&Receipt>> = Vec::new();
    for receipt in sorted {
        match rounds.last_mut() {
            Some(round)
                if round
                    .last()
                    .is_some_and(|last| receipt.at - last.at < ROUND_GAP) =>
            {
                round.push(receipt);
            }
            _ => rounds.push(vec![receipt]),
        }
    }
    rounds
}

#[cfg(test)]
mod tests {
    use super::*;

    const IMAGE: &str = "127.0.0.1:5000/load/prewarm:1";

    /// The receipts of a wave each of `members` sends in the rounds of D185, by rank, `PULL` apart.
    fn wave(members: &[&str], agents: usize, start: Instant) -> Vec<Receipt> {
        let names: Vec<String> = (0..agents).map(agents::name).collect();
        let ranked: Vec<usize> = speculaire_reflect::seeds(
            IMAGE,
            names.iter().map(String::as_str),
            NonZeroU32::new(u32::try_from(agents).unwrap()).unwrap(),
        )
        .map(|name| names.iter().position(|n| n == name).unwrap())
        .collect();
        let mut receipts = Vec::new();
        for member in members {
            let (mut sent, mut at) = (0, start);
            let mut size = 2;
            while sent < agents {
                let round = size.min(agents - sent);
                for (i, &agent) in ranked[sent..sent + round].iter().enumerate() {
                    receipts.push(Receipt {
                        agent,
                        member: (*member).to_owned(),
                        at: at + Duration::from_millis(u64::try_from(i).unwrap()),
                    });
                }
                sent += round;
                size = sent * 4;
                at += PULL + Duration::from_secs(1);
            }
        }
        receipts
    }

    #[test]
    fn a_wave_is_read_in_rounds_from_the_receipts() {
        let start = Instant::now();
        let members = ["a", "b"];
        let wave = Wave::of(&wave(&members, 1000, start), IMAGE, &members, 1000);
        assert!(wave.seeds_agree, "{wave:?}");
        assert_eq!(
            wave.rounds,
            [vec![2, 8, 40, 200, 750], vec![2, 8, 40, 200, 750]]
        );
        assert_eq!(wave.fanout, Some(4.0));
        assert_eq!(wave.once_each, 1000);
        assert_eq!(
            wave.took,
            (PULL + Duration::from_secs(1)) * 4 + Duration::from_millis(749)
        );
    }

    #[test]
    fn a_pause_of_round_gap_ends_a_round_and_a_shorter_one_does_not() {
        let start = Instant::now();
        let receipt = |at| Receipt {
            agent: 0,
            member: "a".to_owned(),
            at,
        };
        let late = start + ROUND_GAP - Duration::from_millis(1);
        let receipts = [receipt(start), receipt(late), receipt(late + ROUND_GAP)];
        let sorted: Vec<&Receipt> = receipts.iter().collect();
        let sizes: Vec<usize> = split(&sorted).iter().map(Vec::len).collect();
        assert_eq!(sizes, [2, 1]);
    }

    #[test]
    fn other_seeds_a_second_prewarm_and_a_larger_round_show() {
        let start = Instant::now();
        let members = ["a", "b"];
        let mut receipts = wave(&members, 100, start);
        // Member b's seeds are another agent and its first.
        let seed = receipts.iter().position(|r| r.member == "b").unwrap();
        receipts[seed].agent = (receipts[seed].agent + 1) % 100;
        let wave = Wave::of(&receipts, IMAGE, &members, 100);
        assert!(!wave.seeds_agree && wave.once_each == 98, "{wave:?}");

        let mut receipts = self::wave(&members, 100, start);
        receipts.push(receipts[0].clone());
        let wave = Wave::of(&receipts, IMAGE, &members, 100);
        assert!(wave.seeds_agree && wave.once_each == 99, "{wave:?}");

        // Member a sends its third round with its second: 48 agents for the 2 seeds.
        let mut receipts = self::wave(&members, 100, start);
        let step = PULL + Duration::from_secs(1);
        for receipt in receipts.iter_mut().filter(|r| r.member == "a") {
            if receipt.at >= start + step * 2 {
                receipt.at -= step;
            }
        }
        let wave = Wave::of(&receipts, IMAGE, &members, 100);
        assert_eq!(wave.rounds, [vec![2, 48, 50], vec![2, 8, 40, 50]]);
        assert_eq!(wave.fanout, Some(24.0));
    }

    #[test]
    fn the_manifest_is_served_by_its_tag_alone() {
        let served = Served {
            manifest: "{}".to_owned(),
            digest: speculaire_oci::hash::of("sha256", b"{}").unwrap(),
        };
        let text = |method, path| String::from_utf8(respond(method, path, &served)).unwrap();
        let get = text("GET", "/v2/load/prewarm/manifests/1");
        assert!(get.starts_with("HTTP/1.1 200 OK\r\n"), "{get}");
        assert!(get.contains(&format!("docker-content-digest: {}\r\n", served.digest)));
        assert!(get.ends_with("content-length: 2\r\n\r\n{}"), "{get}");
        let head = text("HEAD", "/v2/load/prewarm/manifests/1");
        assert!(head.ends_with("content-length: 2\r\n\r\n"), "{head}");
        for (method, path) in [
            ("GET", "/v2/load/prewarm/manifests/2"),
            ("GET", "/v2/load/other/manifests/1"),
            ("GET", "/v2/load/prewarm/blobs/1"),
            ("PUT", "/v2/load/prewarm/manifests/1"),
        ] {
            assert!(
                text(method, path).starts_with("HTTP/1.1 404"),
                "{method} {path}"
            );
        }
    }

    #[tokio::test(start_paused = true)]
    async fn an_agent_notes_each_prewarm_and_announces_the_layers_once_after_its_pull() {
        let holdings = Arc::new(Holdings::default());
        let mut rng = fastrand::Rng::with_seed(7);
        let layers: Arc<[Digest]> = (0..2).map(|_| agents::digest(&mut rng).unwrap()).collect();
        let received = Arc::new(Received::default());
        let pushes = answer_prewarm(3, &holdings, &layers, &received);
        let prewarm =
            Push::Prewarm(speculaire_oci::reference::Reference::parse_docker_ref(IMAGE).unwrap());
        for member in ["a", "b"] {
            pushes
                .send(Pushed {
                    member: member.to_owned(),
                    push: prewarm.clone(),
                })
                .await
                .unwrap();
        }
        tokio::time::sleep(PULL / 2).await;
        assert_eq!(received.receipts().len(), 2);
        assert_eq!(received.announced(), 0);
        tokio::time::sleep(PULL).await;
        assert_eq!(received.announced(), 1);
    }
}
