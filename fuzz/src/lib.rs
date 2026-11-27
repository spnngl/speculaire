//! Fuzz entry points: one function per parser of outside data, each fed arbitrary bytes and required never to panic.
//!
//! `cargo-fuzz` (nightly) reaches them through the shims in `fuzz_targets/`; `cargo test --lib` (stable,
//! `just fuzz-smoke`) replays the seeds plus mutated variants through [`TARGETS`].

#![forbid(unsafe_code)]
#![expect(
    clippy::panic,
    reason = "a fuzz target, and the smoke test replaying it, report a bug by panicking"
)]

#[cfg(test)]
mod smoke;
mod values;

use std::path::Path;
use std::sync::OnceLock;
use std::time::{Duration, SystemTime};

use speculaire_agent::config;
use speculaire_oci::platform::{self as oci_platform, Host, Matcher};
use speculaire_oci::reference::{DockerRef, Reference, Repository};
use speculaire_oci::tagged::Tagged;
use speculaire_registry_config::containerd::config::{self as containerd_config_file, Registry};
use speculaire_registry_config::containerd::hosts;
use speculaire_registry_config::crio::{auth, registries};
use speculaire_verify::policy::{MatchHash, Policies, Policy, PublicKey, Signer};
use speculaire_verify::sbom::{Failure, Format};
use speculaire_verify::statement::Statement;
use speculaire_verify::{Signatures, TrustRoot, Verdicts, cache, legacy, signature};
use tokio::time::Instant;

/// A fuzz entry point.
pub type Entry = fn(&[u8]);

/// Every target by name; `fuzz_targets/<name>.rs` and this list stay in step (checked by the smoke test).
pub const TARGETS: &[(&str, Entry)] = &[
    ("config", config),
    ("config_values", config_values),
    ("containerd_config", containerd_config),
    ("hosts_toml", hosts_toml),
    ("hosts_edit", hosts_edit),
    ("registries_conf", registries_conf),
    ("auth_json", auth_json),
    ("crio_inspect", crio_inspect),
    ("runtime_version", runtime_version),
    ("kube_status", kube_status),
    ("www_authenticate", www_authenticate),
    ("token_answer", token_answer),
    ("manifest", manifest),
    ("image_config", image_config),
    ("mirror_request", mirror_request),
    ("peer_response", peer_response),
    ("reference", reference),
    ("platform", platform),
    ("node_subject", node_subject),
    ("reflect", reflect),
    ("reflect_frame", reflect_frame),
    ("nri_mux", nri_mux),
    ("nri_request", nri_request),
    ("nri_create", nri_create),
    ("containerd_event", containerd_event),
    ("referrers", referrers),
    ("link", link),
    ("retry_after", retry_after),
    ("duration", duration),
    ("policy", policy),
    ("trusted_root", trusted_root),
    ("bundle", bundle),
    ("simplesigning", simplesigning),
    ("statement", statement),
    ("sbom", sbom),
    ("cache_bin", cache_bin),
];

/// The agent's config file, as `check-config` and the agent read it (D30, D60).
///
/// Text that parses serializes to TOML that parses back to the same config: every value prints as it parses.
///
/// # Panics
///
/// When parsing panics, or a parsed config does not survive the round trip.
pub fn config(data: &[u8]) {
    if let Ok(text) = std::str::from_utf8(data) {
        round_trip(text);
    }
}

/// The agent's config file, written from its keys: a few of them, each with a literal that its parser accepts or
/// refuses, or a string of raw bytes. `config` reaches the values that raw bytes seldom spell (D75).
///
/// # Panics
///
/// As [`config`].
pub fn config_values(data: &[u8]) {
    if let Ok(text) = values::document(data) {
        round_trip(&text);
    }
}

/// containerd's `config.toml` and the files it imports, as the agent reads them (D17).
///
/// The input is the file; its imports resolve in a temporary directory, or wherever the input points them. Text that
/// loads yields registry settings that validate or are refused, without a panic.
///
/// # Panics
///
/// When loading panics, or the temporary directory cannot be made.
pub fn containerd_config(data: &[u8]) {
    let dir = tempfile::tempdir().expect("a temporary directory");
    let path = dir.path().join("config.toml");
    std::fs::write(&path, data).expect("a writable temporary directory");
    if let Ok(raw) = containerd_config_file::load_raw(&path) {
        let _ = Registry::try_from(raw);
    }
    let _ = containerd_config_file::load_plugins(&path);
    let _ = containerd_config_file::load_snapshotters(&path);
}

/// A CRI-O `registries.conf` or drop-in (D66).
///
/// A file that parses has one registry per prefix, sorted by prefix; every registry that is not a wildcard is the
/// registry of its own prefix, unless a wildcard comes first there, and its pull sources end with its own endpoint.
///
/// # Panics
///
/// When parsing panics, or a parsed file breaks one of those.
pub fn registries_conf(data: &[u8]) {
    let Ok(text) = std::str::from_utf8(data) else {
        return;
    };
    let Ok(file) = registries::parse_file(text) else {
        return;
    };
    assert!(
        file.registries
            .windows(2)
            .all(|pair| pair[0].prefix < pair[1].prefix),
        "registries are sorted and unique by prefix: {text}"
    );
    let config = registries::Config {
        registries: file.registries,
        credential_helpers: Vec::new(),
    };
    for registry in &config.registries {
        if registry.prefix.starts_with("*.") {
            continue;
        }
        // go.podman.io/image v5.40.0 `pkg/sysregistriesv2/system_registries_v2.go:845-856` keeps the first matching
        // registry, in prefix order (`:508`), of the longest prefix; `*.com` matches `.com` and `*.a.io` `x.a.io`
        // (`:775-793`), and either wins there.
        let first = |found: &registries::Registry| {
            let (theirs, ours) = (found.prefix.len(), registry.prefix.len());
            found.prefix.starts_with("*.")
                && (theirs > ours || theirs == ours && found.prefix < registry.prefix)
        };
        let found = config.find_registry(&registry.prefix);
        assert!(
            found == Some(registry) || found.is_some_and(first),
            "{text}"
        );
        if let Ok(sources) = registry.pull_sources(&format!("{}/app:1", registry.prefix)) {
            assert_eq!(
                sources.last().map(|source| source.endpoint),
                Some(&registry.endpoint),
                "{text}"
            );
        }
    }
}

/// A credential file of CRI-O's image library (D66), in either format.
///
/// # Panics
///
/// When parsing panics.
pub fn auth_json(data: &[u8]) {
    let text = String::from_utf8_lossy(data);
    for legacy in [false, true] {
        let _ = auth::parse_auth_file(&text, legacy);
    }
}

/// A containerd `hosts.toml` (D17).
///
/// A file that parses lists its hosts and ends with its own `server`.
///
/// # Panics
///
/// When parsing panics, or a parsed file lists no host.
pub fn hosts_toml(data: &[u8]) {
    let Ok(text) = std::str::from_utf8(data) else {
        return;
    };
    let dir = Path::new("/etc/containerd/certs.d/docker.io");
    if let Ok(parsed) = hosts::parse_hosts_file(dir, text) {
        assert!(
            !parsed.is_empty(),
            "a parsed file ends with its own `server`: {text}"
        );
    }
}

/// Parses `text`, and a config that parses must print to text that parses back to it.
fn round_trip(text: &str) {
    let Ok(parsed) = config::parse(text) else {
        return;
    };
    let printed = toml::to_string(&parsed)
        .unwrap_or_else(|err| panic!("a parsed config serializes: {err}\n{text}"));
    match config::parse(&printed) {
        Ok(again) => assert_eq!(again, parsed, "round trip through\n{printed}"),
        Err(err) => panic!("a serialized config parses: {err}\n{printed}"),
    }
}

/// An image reference as the CRI plugin parses it (D11, D81), and as a tag the agent announces (D123).
///
/// A reference that parses prints as text that parses to the same reference, and never has a tag together with a
/// digest. A tag that parses prints as text that parses to the same tag, with the same key. A repository and a docker
/// reference parse as the reference does, to its name and to its text (D189).
///
/// # Panics
///
/// When parsing panics, a parsed reference is not a fixed point, or a repository or a docker reference differs
/// from its reference's name or text.
pub fn reference(data: &[u8]) {
    let Ok(text) = std::str::from_utf8(data) else {
        return;
    };
    assert_eq!(
        Repository::parse(text).map(|repository| repository.as_str().to_owned()),
        Reference::parse_normalized_named(text).map(|reference| reference.name().to_owned()),
        "{text}"
    );
    assert_eq!(
        DockerRef::parse(text).map(|docker| docker.as_str().to_owned()),
        Reference::parse_docker_ref(text).map(|reference| reference.to_string()),
        "{text}"
    );
    if let Ok(parsed) = Reference::parse_docker_ref(text) {
        assert!(
            parsed.tag().is_none() || parsed.digest().is_none(),
            "a docker reference keeps one of tag and digest: {text}"
        );
        assert_eq!(
            Reference::parse_docker_ref(&parsed.to_string()).as_ref(),
            Ok(&parsed),
            "{text}"
        );
    }
    if let Some(tagged) = Tagged::parse(text) {
        assert_eq!(Tagged::parse(&tagged.to_string()), Some(tagged), "{text}");
    }
}

/// A platform specifier as containerd parses it (D15, D81).
///
/// A platform that parses normalizes to itself, and matches itself.
///
/// # Panics
///
/// When parsing or matching panics, or a parsed platform breaks one of those.
pub fn platform(data: &[u8]) {
    let Ok(text) = std::str::from_utf8(data) else {
        return;
    };
    let host = Host::current();
    let Ok(parsed) = oci_platform::parse(text, &host) else {
        return;
    };
    let normal = oci_platform::normalize(&parsed, &host);
    assert_eq!(oci_platform::normalize(&normal, &host), normal, "{text}");
    if let Ok(strict) = Matcher::only_strict(&parsed, &host) {
        assert!(strict.matches(&parsed), "{text}");
    }
}

/// What CRI-O's inspect API answers to `GET /config`, as the agent reads it (D64).
///
/// Reading the body, then the NRI settings, the credential file and `auto_reload_registries` from it, never panics.
///
/// # Panics
///
/// When reading panics.
pub fn crio_inspect(data: &[u8]) {
    use speculaire_runtime::crio::{Nri, auto_reload_registries, body, global_auth_file};
    if let Ok(body) = body(data) {
        let _ = Nri::parse(body);
        let _ = global_auth_file(body);
        let _ = auto_reload_registries(body);
    }
}

/// A containerd `hosts.toml` as `configure` edits it (D32, D82).
///
/// Editing never panics. A file that gets the mirror's entry gets it once: editing the result changes nothing, taking
/// the entry out leaves a file that still parses, and containerd reads the mirror first.
///
/// # Panics
///
/// When editing panics, or a result breaks one of those.
pub fn hosts_edit(data: &[u8]) {
    use speculaire_runtime::containerd::hosts::{Entry, add, remove};
    let Ok(text) = std::str::from_utf8(data) else {
        return;
    };
    let dir = std::path::Path::new("/var/lib/speculaire/mirror");
    let entry = Entry {
        url: "https://127.0.0.1:7480".to_owned(),
        ca: dir.join("ca.crt"),
        client: dir.join("client.pem"),
    };
    let _ = remove(text, dir);
    let Ok(added) = add(text, &entry, dir) else {
        return;
    };
    assert_eq!(
        add(&added, &entry, dir).ok().as_deref(),
        Some(added.as_str())
    );
    assert!(remove(&added, dir).is_ok());
    let base = std::path::Path::new("/certs.d/x");
    if hosts::parse_hosts_file(base, text).is_ok() {
        let hosts = hosts::parse_hosts_file(base, &added)
            .unwrap_or_else(|e| panic!("an edited hosts.toml parses: {e:?}\n{text:?}\n{added:?}"));
        assert_eq!(hosts[0].host, "127.0.0.1:7480");
    }
}

/// A request of the runtime to the mirror, or of another agent to the peer API, which shares its parser: its path
/// and query, then a line with its `Range` header (D85, D100, D123, D124).
///
/// Routing and reading containerd's `ns` never panic, nor does reading a referrers request's `artifactType`, which is
/// never empty. A range lies inside a body of any size: it starts at or before its end, and its end is the
/// body's last byte at most; the whole of an empty body has no range.
///
/// # Panics
///
/// When routing or reading a range panics, or a range does not lie in the body.
pub fn mirror_request(data: &[u8]) {
    use speculaire_mirror::request::{
        Method, Ranged, Span, artifact_type, namespace, range, route,
    };
    let Ok(text) = std::str::from_utf8(data) else {
        return;
    };
    let (target, header) = text.split_once('\n').unwrap_or((text, ""));
    let (path, query) = target
        .split_once('?')
        .map_or((target, None), |(path, query)| (path, Some(query)));
    for method in [Method::GET, Method::HEAD] {
        let _ = route(&method, path);
    }
    let _ = namespace(query);
    assert_ne!(artifact_type(query).as_deref(), Some(""));
    for size in [0, 1, 2, 1000, u64::MAX] {
        if let Ranged::Part(span) = range(Some(header), size) {
            assert!(
                span.first <= span.last && span.last < size,
                "{header:?} of {size}"
            );
            assert_eq!(span.bytes(), span.last - span.first + 1);
        }
    }
    assert_eq!(Span::whole(0), None);
}

/// The head of a peer's answer to a fetch, as the fetcher reads it: a line with the status and the offset asked from,
/// then a header per line (D102).
///
/// Reading never panics. A size it gives lies past the offset, is the offset plus the `Content-Length`, and comes from a
/// `200` only for a fetch from the start; a `503` is busy.
///
/// # Panics
///
/// When reading panics, or a size breaks one of those.
pub fn peer_response(data: &[u8]) {
    use http::{HeaderMap, HeaderName, HeaderValue, StatusCode};
    use speculaire_mirror::fetch::read_head;
    use speculaire_mirror::metrics::Fetched;
    let Ok(text) = std::str::from_utf8(data) else {
        return;
    };
    let mut lines = text.lines();
    let mut first = lines.next().unwrap_or_default().split(' ');
    let Some(status) = first
        .next()
        .and_then(|code| StatusCode::from_bytes(code.as_bytes()).ok())
    else {
        return;
    };
    let offset = first.next().and_then(|n| n.parse().ok()).unwrap_or(0);
    let mut headers = HeaderMap::new();
    for line in lines {
        if let Some((name, value)) = line.split_once(':')
            && let Ok(name) = HeaderName::from_bytes(name.as_bytes())
            && let Ok(value) = HeaderValue::from_str(value.trim())
        {
            headers.append(name, value);
        }
    }
    match read_head(status, &headers, offset) {
        Ok(size) => {
            let length: Option<u64> = headers
                .get("content-length")
                .and_then(|value| value.to_str().ok()?.parse().ok());
            let length =
                length.unwrap_or_else(|| panic!("a size with no Content-Length: {text:?}"));
            assert_eq!(offset.checked_add(length), Some(size), "{text:?}");
            assert!(status != StatusCode::OK || offset == 0, "{text:?}");
        }
        Err(failed) => {
            assert_eq!(
                failed == Fetched::Busy,
                status == StatusCode::SERVICE_UNAVAILABLE,
                "{text:?}"
            );
        }
    }
}

/// What the Kubernetes API server answers the uninstall hook's wait: a `DaemonSet` and a list of pods (D211).
///
/// Reading either never panics, and neither does weighing the pods read against the `DaemonSet` read, nor printing
/// the result.
///
/// # Panics
///
/// When reading or weighing panics.
pub fn kube_status(data: &[u8]) {
    use speculaire_agent::hook::{DaemonSet, Pods, Progress};
    let daemonset = DaemonSet::parse(data);
    let pods = Pods::parse(data);
    if let (Ok(daemonset), Ok(pods)) = (daemonset, pods) {
        let _ = Progress::of(&daemonset, &pods).to_string();
    }
}

/// The version a runtime reports about itself over the CRI (D86).
///
/// Reading never panics. A text that is a release prints as `major.minor.patch`, which parses back to the same release,
/// and the numbers are those of the text's first three dotted fields.
///
/// # Panics
///
/// When parsing panics, or a release does not survive printing.
pub fn runtime_version(data: &[u8]) {
    use speculaire_runtime::version::Release;
    let Ok(text) = std::str::from_utf8(data) else {
        return;
    };
    if let Some(release) = Release::parse(text) {
        assert_eq!(Release::parse(&release.to_string()), Some(release));
        let numbers = text.strip_prefix('v').unwrap_or(text);
        assert!(
            numbers.starts_with(|c: char| c.is_ascii_digit()),
            "{text:?}"
        );
    }
}

/// The `WWW-Authenticate` header of a registry's 401, as the upstream client reads it (D88).
///
/// Reading never panics. Every challenge has a scheme, and every scheme and parameter name is in lower case and not
/// empty.
///
/// # Panics
///
/// When reading panics, or a challenge breaks one of those.
pub fn www_authenticate(data: &[u8]) {
    let Ok(text) = std::str::from_utf8(data) else {
        return;
    };
    for challenge in speculaire_registry::challenge::parse(text) {
        assert_ne!(challenge.scheme, "");
        assert_eq!(challenge.scheme, challenge.scheme.to_ascii_lowercase());
        for (name, _) in &challenge.params {
            assert_ne!(name, "");
            assert_eq!(*name, name.to_ascii_lowercase());
        }
    }
}

/// The body of a token endpoint's answer, as the upstream client reads it (D88).
///
/// Reading never panics. A token read is not empty and lasts at least the distribution spec's default minute.
///
/// # Panics
///
/// When reading panics, or an answer read breaks one of those.
pub fn token_answer(data: &[u8]) {
    use secrecy::ExposeSecret as _;
    if let Some((token, lifetime)) = speculaire_registry::token::parse_answer(data) {
        assert_ne!(token.expose_secret(), "");
        assert!(lifetime >= Duration::from_secs(60), "{lifetime:?}");
    }
}

/// A manifest as the relay reads it, to know which digests lie below it (D67, D88).
///
/// Reading never panics. Every digest it finds prints as it parses, and an index points to manifests only.
///
/// # Panics
///
/// When reading panics, or a digest does not survive printing.
pub fn manifest(data: &[u8]) {
    use speculaire_oci::manifest::{Children, children};
    use speculaire_oci::reference::Digest;
    let Ok(found) = children(data) else {
        return;
    };
    for digest in found.digests() {
        assert_eq!(Digest::parse(&digest.to_string()).as_ref(), Ok(digest));
    }
    if let Children::Image { layers, .. } = &found {
        assert_eq!(found.digests().len(), layers.len() + 1);
    }
}

/// A peer certificate's subject, as both sides of a peer link read it to know which node it is (D16).
///
/// Reading never panics. A node it names is not empty, and the subject's common name is that node's.
///
/// # Panics
///
/// When reading panics, or a node it names breaks one of those.
pub fn node_subject(data: &[u8]) {
    use speculaire_pki::node::{COMMON_NAME_PREFIX, node_subject};
    use x509_parser::prelude::{AttributeTypeAndValue, FromDer as _, X509Certificate};
    if let Ok(node) = node_subject(data) {
        assert_ne!(node, "");
        let (_, cert) =
            X509Certificate::from_der(data).expect("a certificate whose subject was read parses");
        let names: Vec<_> = cert
            .subject()
            .iter_common_name()
            .map(AttributeTypeAndValue::as_str)
            .collect();
        assert_eq!(names, [Ok(format!("{COMMON_NAME_PREFIX}{node}").as_str())]);
    }
}

/// Every message of the reflector API: the requests the reflector reads from an agent, and the answers and pushes the
/// agent reads (D2, D97, D98, D105, D184).
///
/// Decoding and parsing never panic. A request or a push that parses encodes back to protobuf that parses to it again,
/// a list holds at most `LIST_CAP` images, and every member or peer an answer keeps has a node. Text parses as a digest of a request exactly when it parses as a
/// [`Digest`](speculaire_oci::reference::Digest), to the same digest.
///
/// # Panics
///
/// When decoding or parsing panics, what parses does not survive the round trip, or the two digest parsers disagree.
pub fn reflect(data: &[u8]) {
    use prost::Message as _;
    use speculaire_oci::reference::Digest;
    use speculaire_reflect::Key;
    use speculaire_reflect::client::{members, peers};
    use speculaire_reflect::message::Request;
    use speculaire_reflect::proto::{self, AgentMessage, LookupResponse, MembersResponse};
    use speculaire_reflect::push::{LIST_CAP, PrewarmList, Push};
    if let Ok(text) = std::str::from_utf8(data) {
        let digest = Digest::parse(text).ok();
        assert_eq!(Key::parse(text), digest.as_ref().map(Key::from));
    }
    if let Ok(message) = AgentMessage::decode(data)
        && let Ok(request) = Request::try_from(message)
    {
        let again = Request::try_from(AgentMessage::from(request.clone()));
        assert_eq!(again, Ok(request));
    }
    if let Ok(response) = MembersResponse::decode(data) {
        assert!(
            members(response)
                .iter()
                .all(|member| !member.node.is_empty())
        );
    }
    if let Ok(response) = LookupResponse::decode(data) {
        assert!(peers(response).iter().all(|peer| !peer.node.is_empty()));
    }
    if let Ok(prewarm) = proto::Prewarm::decode(data)
        && let Ok(push) = Push::try_from(prewarm)
    {
        let Push::Prewarm(image) = &push else {
            panic!("{push:?} parsed from a Prewarm");
        };
        assert_eq!(
            Push::try_from(proto::Prewarm::from(image)),
            Ok(push.clone())
        );
    }
    if let Ok(list) = proto::PrewarmList::decode(data)
        && let Ok(list) = PrewarmList::try_from(list)
    {
        assert!(list.images().len() <= LIST_CAP);
        assert_eq!(
            PrewarmList::try_from(proto::PrewarmList::from(&list)),
            Ok(list)
        );
    }
}

/// A connection to the reflector as frames: each side reads a 4-byte big-endian length, then a message of that many
/// bytes (D105). The reflector reads `AgentMessage`s and the agent `ReflectorMessage`s.
///
/// Reading never panics, and refuses a length over the limit before reading its body. A message read writes as a frame
/// that reads back to it.
///
/// # Panics
///
/// When reading panics or waits, refuses another length than the frame's, or the round trip fails.
pub fn reflect_frame(data: &[u8]) {
    use speculaire_reflect::proto::{AgentMessage, ReflectorMessage};
    frames::<AgentMessage>(data);
    frames::<ReflectorMessage>(data);
}

/// The output of `future`, which reading a slice or writing a `Vec` completes at its first poll.
fn ready<T>(future: impl Future<Output = T>) -> T {
    use std::pin::pin;
    use std::task::{Context, Poll, Waker};

    match pin!(future).poll(&mut Context::from_waker(Waker::noop())) {
        Poll::Ready(output) => output,
        Poll::Pending => panic!("reading or writing memory waited"),
    }
}

/// Reads every frame of `data` as `M`, with a 1 KiB limit so that lengths over it come by often.
fn frames<M: prost::Message + Default + PartialEq>(data: &[u8]) {
    use speculaire_reflect::frame::{self, FrameError, Reader};

    const LIMIT: usize = 1024;
    let mut rest = data;
    let mut reader = Reader::<M>::new(LIMIT);
    loop {
        let start = rest;
        match ready(reader.next(&mut rest)) {
            Ok(Some(message)) => {
                let mut written = Vec::new();
                ready(frame::write(&mut written, &message, LIMIT))
                    .unwrap_or_else(|err| panic!("a message read did not write back: {err}"));
                let again = ready(Reader::<M>::new(LIMIT).next(&mut written.as_slice()));
                assert!(matches!(again, Ok(Some(ref again)) if *again == message));
            }
            Err(FrameError::Size { size, limit }) => {
                let head: [u8; 4] = start
                    .get(..4)
                    .and_then(|head| head.try_into().ok())
                    .unwrap_or_else(|| panic!("a size refusal before 4 bytes of length"));
                assert_eq!(u32::from_be_bytes(head).try_into(), Ok(size));
                assert!(size > limit);
                break;
            }
            Ok(None) | Err(_) => break,
        }
    }
}

/// The trunk of an NRI socket as frames: each an 8-byte header, a big-endian ConnID then a big-endian payload length,
/// then the payload (D9, D163). The multiplexer reads them into its two connections.
///
/// Reading never panics or waits, and refuses a length over the maximum before reading its payload. It ends as the
/// frames say, and each connection reads its frames' payloads, in order.
///
/// # Panics
///
/// When reading panics or waits, or how it ends or what a connection reads is not what the frames say.
pub fn nri_mux(data: &[u8]) {
    use speculaire_nri::{MAX_PAYLOAD, Mux, MuxError, Oversize};
    use tokio::io::AsyncReadExt as _;

    /// How reading the frames ends.
    #[derive(Debug, PartialEq, Eq)]
    enum End {
        Clean,
        Short,
        Oversize(Oversize),
        Full { conn: u32 },
    }
    /// A connection's queue, in frames.
    const QUEUE: usize = 256;

    // What the frames say, read with plain slices.
    let mut payloads = [Vec::new(), Vec::new()];
    let mut queued = [0; 2];
    let mut rest = data;
    let end = loop {
        let Some(([c0, c1, c2, c3, l0, l1, l2, l3], body)) = rest.split_first_chunk::<8>() else {
            break if rest.is_empty() {
                End::Clean
            } else {
                End::Short
            };
        };
        let conn = u32::from_be_bytes([*c0, *c1, *c2, *c3]);
        let length = u32::from_be_bytes([*l0, *l1, *l2, *l3]);
        if length > MAX_PAYLOAD {
            break End::Oversize(Oversize { conn, length });
        }
        let Some((payload, after)) = usize::try_from(length)
            .ok()
            .and_then(|length| body.split_at_checked(length))
        else {
            break End::Short;
        };
        let index = match conn {
            1 => Some(0),
            2 => Some(1),
            _ => None,
        };
        if let Some(index) = index {
            if queued[index] == QUEUE {
                break End::Full { conn };
            }
            queued[index] += 1;
            payloads[index].extend_from_slice(payload);
        }
        rest = after;
    };

    let (mux, mut connections) = Mux::new(data, Vec::new());
    let ended = match ready(mux.run()) {
        Ok(()) => End::Clean,
        Err(MuxError::Io(err)) if err.kind() == std::io::ErrorKind::UnexpectedEof => End::Short,
        Err(MuxError::Oversize(oversize)) => End::Oversize(oversize),
        Err(MuxError::QueueFull { conn, .. }) => End::Full { conn: conn.id() },
        Err(err) => panic!("the trunk closed on {err}"),
    };
    assert_eq!(ended, end);
    let connections = [
        &mut connections.plugin_service,
        &mut connections.runtime_service,
    ];
    for (connection, payloads) in connections.into_iter().zip(payloads) {
        let mut read = Vec::new();
        let mut buf = [0; 4096];
        let ended = loop {
            match ready(connection.read(&mut buf)) {
                Ok(0) => break Ok(()),
                Ok(length) => read.extend_from_slice(&buf[..length]),
                Err(err) => break Err(err),
            }
        };
        assert_eq!(read, payloads);
        assert_eq!(ended.is_ok(), end == End::Clean, "{ended:?}");
    }
}

/// The ttrpc messages of NRI's plugin connection: each a 10-byte header, the big-endian length, stream ID, kind and
/// flags, then a protobuf `Request` whose payload is that of the method it names (D166).
///
/// Reading never panics or waits, and refuses a length over the maximum before reading its body. Each request read
/// encodes back to what decodes to it again; each `CreateContainerRequest` is checked as [`nri_create`] checks one.
///
/// # Panics
///
/// When reading panics or waits, refuses a length within the maximum, a request read does not round-trip, or
/// [`nri_create`] panics.
pub fn nri_request(data: &[u8]) {
    use prost::Message;
    use speculaire_nri::ttrpc::{Call, MAX_MESSAGE, Reader, RequestError};

    fn round_trips<M: Message + Default + PartialEq>(message: &M) {
        assert!(M::decode(message.encode_to_vec().as_slice()).as_ref() == Ok(message));
    }

    let mut requests = Reader::new(data);
    loop {
        match ready(requests.next()) {
            Ok(request) => match request.call {
                Call::Configure(request) => round_trips(&request),
                Call::Synchronize(request) => round_trips(&request),
                Call::CreateContainer(payload) => nri_create(payload),
                Call::Shutdown | Call::Other { .. } => {}
            },
            Err(RequestError::Oversize { length }) => {
                assert!(length > MAX_MESSAGE);
                break;
            }
            Err(RequestError::Decode { .. }) => {}
            Err(RequestError::Io(_)) => break,
        }
    }
}

/// A `CreateContainerRequest` read in place, as the gate reads it (D189).
///
/// Reading never panics. It reads what prost decodes, and refuses no request prost decodes but one with a group, which
/// proto3 never writes. Each container read reads as an image identity on both paths without waiting, the image ID's
/// path with an image of that ID listed (D169).
///
/// # Panics
///
/// When reading panics, differs from prost's, or refuses a request prost decodes for another reason than a group; or
/// an identity read waits or differs from the request.
pub fn nri_create(data: &[u8]) {
    use prost::Message as _;
    use speculaire_nri::api::CreateContainerRequest;
    use speculaire_nri::create::{Error, Request};
    use speculaire_nri::testing::agrees;

    let read = Request::read(data);
    match (&read, CreateContainerRequest::decode(data)) {
        (Ok(read), Ok(decoded)) => assert!(agrees(read, &decoded), "{read:?} != {decoded:?}"),
        (Err(err), Ok(_)) => assert!(matches!(err, Error::Unread { wire_type: 3, .. }), "{err}"),
        (Ok(_) | Err(_), Err(_)) => {}
    }
    if let Ok(Request {
        pod,
        container: Some(container),
    }) = read
    {
        identify(&pod.unwrap_or_default(), &container);
    }
}

/// Reads `container`'s image identity on both paths: a digest read is the request's, a name confirmed is the one the
/// pod asked for, which a list naming the image by it confirms, and an image ID listed reads as its image.
fn identify(
    pod: &speculaire_nri::create::Pod<'_>,
    container: &speculaire_nri::create::Container<'_>,
) {
    use speculaire_runtime::cri::ListedImage;
    use speculaire_runtime::identity::annotation::IMAGE_NAME;
    use speculaire_runtime::identity::{IMAGE_REF, Identified, Identity, ImageId, Nri};
    use speculaire_runtime::images::{Image, List, Update};

    let asked = container.annotations.get(IMAGE_NAME);
    let named = container.image.and_then(|image| {
        Image::from_listed(&ListedImage {
            id: image.config_digest.to_owned(),
            repo_tags: asked.into_iter().map(str::to_owned).collect(),
            repo_digests: Vec::new(),
        })
    });
    let mut list = List::default();
    list.apply(Update::Listing(named.into_iter().collect()));
    let nri = Nri::default();
    nri.keep(&list);
    match ready(nri.identify(pod, container)) {
        Identified::Listed { digest, name } => {
            let image = container.image.expect("a listed identity has an image");
            assert_eq!(digest.to_string(), image.digest);
            assert_eq!(Some(name), asked);
        }
        Identified::Unconfirmed { digest, .. } => {
            let image = container.image.expect("a listed identity has an image");
            assert_eq!(digest.to_string(), image.digest);
        }
        identified => assert!(
            matches!(identified, Identified::Unknown(_)),
            "{identified:?}"
        ),
    }
    let listed = container.annotations.get(IMAGE_REF).and_then(|id| {
        Image::from_listed(&ListedImage {
            id: id.to_owned(),
            repo_tags: Vec::new(),
            repo_digests: Vec::new(),
        })
    });
    let mut list = List::default();
    list.apply(Update::Listing(listed.iter().cloned().collect()));
    let image_id = ImageId::default();
    image_id.keep(&list);
    match (ready(image_id.identify(pod, container)), listed) {
        (Identified::Image(image), Some(listed)) => assert_eq!(*image, listed),
        (Identified::Unknown(_), None) => {}
        (identified, listed) => panic!("{identified:?} for {listed:?}"),
    }
}

/// An event of containerd's `Subscribe`, as the inventory (D99) and the image store (D15) read it.
///
/// Decoding never panics, an event is a change only for content of `k8s.io` created or deleted, and an image event
/// only for an image of `k8s.io` created, updated or deleted.
///
/// # Panics
///
/// When decoding panics, or another event is a change or an image event.
pub fn containerd_event(data: &[u8]) {
    use containerd_client::types::Envelope;
    use prost::Message as _;
    use speculaire_runtime::containerd::{inventory, store};
    let Ok(envelope) = Envelope::decode(data) else {
        return;
    };
    let topic = envelope.topic.as_str();
    if inventory::change(&envelope).is_some() {
        assert_eq!(envelope.namespace, "k8s.io");
        assert!(
            ["/content/create", "/content/delete"].contains(&topic),
            "{topic}"
        );
    }
    if store::event(&envelope).is_some() {
        assert_eq!(envelope.namespace, "k8s.io");
        assert!(
            ["/images/create", "/images/update", "/images/delete"].contains(&topic),
            "{topic}"
        );
    }
}

/// An image config, as the gate reads its chain ID (D15).
///
/// Reading never panics, and a chain ID read prints as it parses.
///
/// # Panics
///
/// When reading panics, or the chain ID does not survive printing.
pub fn image_config(data: &[u8]) {
    use speculaire_oci::chain::of_config;
    use speculaire_oci::reference::Digest;
    if let Ok(chain) = of_config(data) {
        assert_eq!(Digest::parse(&chain.to_string()), Ok(chain));
    }
}

/// A referrers index, a referrer's manifest and an image index, as discovery reads them (D43, D49).
///
/// Reading never panics. Every digest read prints as it parses and forms a valid tag, an artifact type read is never
/// empty, a referrer's blobs are its config then its layers, and a referrer is a bundle only by a type that may say so.
///
/// # Panics
///
/// When reading panics, or what it reads breaks one of those.
pub fn referrers(data: &[u8]) {
    use speculaire_oci::index::Index;
    use speculaire_oci::referrers::{self, BUNDLE, Descriptor, EMPTY, Referrer};
    if let Ok(descriptors) = referrers::index(data) {
        descriptors.iter().for_each(descriptor);
    }
    if let Ok(referrer) = Referrer::parse(data) {
        referrer.subject.iter().for_each(digest);
        assert_ne!(referrer.artifact_type.as_deref(), Some(""));
        descriptor(&referrer.config);
        referrer.layers.iter().for_each(descriptor);
        let blobs: Vec<&Descriptor> = referrer.blobs().collect();
        assert_eq!(blobs.len(), referrer.layers.len() + 1);
        assert_eq!(blobs.first(), Some(&&referrer.config));
        let listed = referrer.listed_type();
        assert!(
            referrer.artifact_type.as_deref() == Some(listed)
                || blobs.iter().any(|blob| blob.media_type == listed),
            "{listed}"
        );
        if referrer.is_bundle() {
            assert!(
                matches!(
                    referrer.artifact_type.as_deref(),
                    None | Some(BUNDLE | EMPTY)
                ),
                "{:?}",
                referrer.artifact_type
            );
        }
    }
    if let Ok(index) = Index::parse(data) {
        for arch in ["amd64", "arm64", "arm"] {
            let host = Host {
                os: "linux".to_owned(),
                arch: arch.to_owned(),
                variant: if arch == "arm" { "v7" } else { "" }.to_owned(),
            };
            if let Some(manifest) = index.platform_manifest(&host) {
                digest(manifest);
                index.attestations(manifest).into_iter().for_each(digest);
            }
        }
        index.images().for_each(digest);
    }
}

/// A descriptor discovery read: its digest holds, its artifact type is never empty.
fn descriptor(descriptor: &speculaire_oci::referrers::Descriptor) {
    digest(&descriptor.digest);
    assert_ne!(descriptor.artifact_type.as_deref(), Some(""));
}

/// A digest discovery read: it prints as it parses, and forms valid tags.
fn digest(digest: &speculaire_oci::reference::Digest) {
    use speculaire_oci::reference::Digest;
    assert_eq!(Digest::parse(&digest.to_string()).as_ref(), Ok(digest));
    let fallback = speculaire_oci::referrers::fallback_tag(digest);
    // distribution-spec v1.1.1-57-g9727462 `spec.md:786-788`: `[a-zA-Z0-9_][a-zA-Z0-9._-]{0,127}`.
    assert!(
        fallback.len() <= 128
            && fallback.starts_with(|c: char| c.is_ascii_alphanumeric() || c == '_')
            && fallback
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b)),
        "{fallback}"
    );
    let signature = speculaire_oci::referrers::signature_tag(digest);
    assert!(
        signature
            .strip_suffix(".sig")
            .is_some_and(|stem| stem.starts_with(&fallback)),
        "{signature}"
    );
}

/// The `Link` header of a paginated referrers answer, as discovery reads it to fetch the next page (D43).
///
/// Reading never panics. The next link is a non-empty part of the value, between its `<` and `>`.
///
/// # Panics
///
/// When reading panics, or a next link breaks that.
pub fn link(data: &[u8]) {
    let Ok(value) = std::str::from_utf8(data) else {
        return;
    };
    if let Some(uri) = speculaire_registry::link::next(value) {
        let at = uri
            .as_ptr()
            .addr()
            .checked_sub(value.as_ptr().addr())
            .expect("the next link lies in the value");
        assert!(!uri.is_empty() && !uri.contains('>'), "{uri:?}");
        assert_eq!(value.get(at..at + uri.len()), Some(uri));
        assert_eq!(value.as_bytes().get(at.wrapping_sub(1)), Some(&b'<'));
        assert_eq!(value.as_bytes().get(at + uri.len()), Some(&b'>'));
    }
}

/// A registry's `Retry-After`, as discovery reads it to know when to ask that host again (D38).
///
/// Reading never panics. Whole seconds are the delay they say, saturating; a date is never more than year 9999 away.
///
/// # Panics
///
/// When reading panics, or a delay breaks that.
pub fn retry_after(data: &[u8]) {
    let now = SystemTime::UNIX_EPOCH + Duration::from_secs(1_700_000_000);
    let Some(delay) = speculaire_registry::retry_after::parse(data, now) else {
        return;
    };
    let text = std::str::from_utf8(data)
        .expect("a delay comes from text")
        .trim();
    if text.bytes().all(|byte| byte.is_ascii_digit()) {
        let seconds = text.parse().unwrap_or(u64::MAX);
        assert_eq!(delay.as_secs(), seconds, "{text:?}");
    } else {
        // 9999-12-31T23:59:59Z, the last time an HTTP date names.
        let last = SystemTime::UNIX_EPOCH + Duration::from_secs(253_402_300_799);
        assert!(now + delay <= last, "{text:?}");
    }
}

/// A number of seconds, as the config and `speculaire-loadgen` read it (D138).
///
/// Reading never panics, and a duration read prints as text that reads back to the same duration. A float, which the
/// config reads through its shortest decimal, prints as the decimal of that same float, as the config writes it.
///
/// # Panics
///
/// When reading panics, or the printed text breaks that.
pub fn duration(data: &[u8]) {
    use speculaire_time::duration::{display, parse};
    let Ok(text) = std::str::from_utf8(data) else {
        return;
    };
    if let Ok(read) = parse(text) {
        let printed = display(read).to_string();
        assert_eq!(parse(&printed), Ok(read), "{text:?} printed {printed:?}");
    }
    if let Ok(float) = text.parse::<f64>()
        && let Ok(read) = parse(&float.to_string())
    {
        let printed = display(read).to_string();
        assert_eq!(printed.parse(), Ok(float), "{text:?} printed {printed:?}");
    }
}

/// The policy file (D11, D142).
///
/// A file that parses has, in each policy, a glob and an authority, and a keyless authority has an identity; parsing it
/// again gives the same policies, and a match hash does not depend on the order of the policies.
///
/// # Panics
///
/// When parsing panics, or a parsed file breaks one of those.
pub fn policy(data: &[u8]) {
    let Ok(text) = std::str::from_utf8(data) else {
        return;
    };
    let Ok(policies) = Policies::parse(text) else {
        return;
    };
    for policy in policies.iter() {
        assert!(
            !policy.images().is_empty() && !policy.authorities().is_empty(),
            "{text}"
        );
        for authority in policy.authorities() {
            if let Signer::Keyless { identities } = &authority.signer {
                assert!(!identities.is_empty(), "{text}");
            }
        }
    }
    let again = Policies::parse(text).expect("text that parsed parses again");
    assert_eq!(
        MatchHash::of(policies.iter()),
        MatchHash::of(again.iter()),
        "{text}"
    );
    let all: Vec<&Policy> = policies.iter().collect();
    assert_eq!(
        MatchHash::of(all.iter().copied()),
        MatchHash::of(all.iter().rev().copied()),
        "{text}"
    );
    for image in ["nginx", "ghcr.io/myorg/app:v1", "registry.example:5000/a/b"] {
        let reference = Reference::parse_docker_ref(image).expect("a valid reference");
        assert!(
            policies
                .matching(&reference)
                .all(|policy| policy.images().iter().any(|glob| glob.matches(&reference)))
        );
    }
}

/// A pinned `trusted_root.json` (D26, D143).
///
/// Bytes that parse give the same hash and expiry when parsed again.
///
/// # Panics
///
/// When parsing panics, or parsing again differs.
pub fn trusted_root(data: &[u8]) {
    let Ok(root) = TrustRoot::parse(data) else {
        return;
    };
    let again = TrustRoot::parse(data).expect("bytes that parsed parse again");
    assert_eq!(root.hash(), again.hash());
    assert_eq!(root.expiry(), again.expiry());
}

/// The recorded trusted root the `bundle` target verifies against, parsed once.
fn recorded_root() -> &'static TrustRoot {
    static ROOT: OnceLock<TrustRoot> = OnceLock::new();
    ROOT.get_or_init(|| {
        TrustRoot::parse(include_bytes!("../../fixtures/sigstore/trusted_root.json"))
            .expect("the recorded trusted root parses")
    })
}

/// A Sigstore bundle, as the artifact store holds it (D145), verified as a signature of the recorded keyless image
/// by its certificate and of the recorded key image by `cosign.pub`.
///
/// A bundle that verifies verifies the same again.
///
/// # Panics
///
/// When verification panics, or verifying again differs.
pub fn bundle(data: &[u8]) {
    let key = PublicKey::try_from(include_str!("../../fixtures/sigstore/cosign.pub").to_owned())
        .expect("the recorded key parses");
    for (target, key) in [
        (
            "sha256:32ee66583f82cd56da74ff4f6e85c4fd8f552c73dfa3a5d945cc5b201f8abcf0",
            None,
        ),
        (
            "sha256:e5376e3fef52cf9bad8caca4a04978fd76dc9a564083d6a463d168321e6f7a98",
            Some(&key),
        ),
    ] {
        let target =
            speculaire_oci::reference::Digest::parse(target).expect("the recorded digests parse");
        let signed = signature::verify(recorded_root(), &target, data, key);
        if signed.is_ok() {
            assert_eq!(
                signed,
                signature::verify(recorded_root(), &target, data, key)
            );
        }
    }
}

/// The recorded `legacy-sig` image, its `.sig` manifest and that manifest's one simple signing payload.
const LEGACY_IMAGE: &str =
    "sha256:167b7290fd4fd86b9040b699e97cd3471b960281d4158e3bd655df2f68e0eb73";
const LEGACY_MANIFEST: &[u8] = include_bytes!(
    "../../fixtures/sigstore/layouts/legacy-sig/blobs/sha256/9390ade129eb1c390b04bacebdd1a7edef608b1d3717d7421ee6b89a5a7f0e73"
);
const LEGACY_PAYLOAD: &[u8] = include_bytes!(
    "../../fixtures/sigstore/layouts/legacy-sig/blobs/sha256/1e6dcfc6a19dcd80fe62b428bbf4bb10ad08e7319401e20792d59f88163193bd"
);

/// A legacy `.sig` layer from the artifact store (D147): arbitrary bytes as its simple signing payload under the
/// recorded `.sig` manifest, then as that manifest over the recorded payload, verified as a signature of the recorded
/// image.
///
/// A layer that verifies verifies the same again.
///
/// # Panics
///
/// When verification panics, or verifying again differs.
pub fn simplesigning(data: &[u8]) {
    let target =
        speculaire_oci::reference::Digest::parse(LEGACY_IMAGE).expect("the recorded digest parses");
    for (manifest, payload) in [(LEGACY_MANIFEST, data), (data, LEGACY_PAYLOAD)] {
        let signed = legacy::verify(recorded_root(), &target, manifest, 0, payload, None);
        if signed.is_ok() {
            assert_eq!(
                signed,
                legacy::verify(recorded_root(), &target, manifest, 0, payload, None)
            );
        }
    }
}

/// A DSSE payload from the artifact store as an in-toto statement (D149).
///
/// A statement that parses parses back from its type, predicate type and raw predicate to the same two.
///
/// # Panics
///
/// When parsing panics, or the statement written back from its parts differs.
pub fn statement(data: &[u8]) {
    let Ok(statement) = Statement::parse(data) else {
        return;
    };
    let predicate_type =
        serde_json::to_string(statement.predicate_type()).expect("a string serializes");
    let predicate = statement
        .predicate()
        .map_or(String::new(), |raw| format!(",\"predicate\":{raw}"));
    let text = format!(
        "{{\"_type\":\"https://in-toto.io/Statement/v1\",\"predicateType\":{predicate_type}{predicate}}}"
    );
    let again = Statement::parse(text.as_bytes()).expect("a statement written back parses");
    assert_eq!(
        (again.predicate_type(), again.predicate()),
        (statement.predicate_type(), statement.predicate())
    );
}

/// An SBOM from an attestation or a BuildKit attestation layer, as SPDX and as CycloneDX JSON (D12, D150).
///
/// A document that counts, its unknown values skipped unbuilt, counts the same in compact JSON.
///
/// # Panics
///
/// When counting panics, or the document that counts written back compact counts otherwise.
pub fn sbom(data: &[u8]) {
    let Ok(text) = std::str::from_utf8(data) else {
        return;
    };
    let compact = serde_json::from_str::<serde_json::Value>(text).map(|value| value.to_string());
    for format in [Format::Spdx, Format::CycloneDx] {
        let packages = format.packages(text);
        // An unparsable document may hold a duplicate key that compact JSON drops.
        if let Ok(compact) = &compact
            && !matches!(packages, Err(Failure::Unparsable(_)))
        {
            assert_eq!(packages, format.packages(compact), "{format:?}");
        }
    }
}

/// `cache.bin`, as the agent loads it on start (D31), as read and with its size and checksum set again.
///
/// A file that loads saves bytes that load and save the same.
///
/// # Panics
///
/// When loading panics, or the bytes saved from a load do not load, or save otherwise.
pub fn cache_bin(data: &[u8]) {
    let current = cache::Current {
        policies: MatchHash::of([]),
        root: None,
    };
    let now = Instant::now();
    let load = |bytes: &[u8]| {
        let (verdicts, signatures) = (Verdicts::default(), Signatures::new(0));
        let loaded = cache::load(bytes, current, now, &verdicts, &signatures);
        loaded.ok().map(|_| {
            let mut saved = Vec::new();
            cache::save(&verdicts, &signatures, current.policies, now, &mut saved);
            saved
        })
    };
    for bytes in [Some(data.to_vec()), resealed(data)].into_iter().flatten() {
        if let Some(saved) = load(&bytes) {
            assert_eq!(load(&saved).as_ref(), Some(&saved));
        }
    }
}

/// `data` with the size `cache.bin`'s header holds and its trailing SHA-256 set to match, so that its parts parse.
fn resealed(data: &[u8]) -> Option<Vec<u8>> {
    let mut bytes = data.get(..data.len().checked_sub(32)?)?.to_vec();
    bytes
        .get_mut(4..12)?
        .copy_from_slice(&u64::try_from(data.len()).ok()?.to_le_bytes());
    let checksum = speculaire_oci::hash::of("sha256", &bytes)?;
    let hex = checksum.encoded().as_bytes();
    for pair in hex.as_chunks::<2>().0 {
        let pair = std::str::from_utf8(pair).ok()?;
        bytes.push(u8::from_str_radix(pair, 16).ok()?);
    }
    Some(bytes)
}
