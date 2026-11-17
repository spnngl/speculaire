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
use std::time::{Duration, SystemTime};

use speculaire_agent::config;
use speculaire_oci::platform::{self as oci_platform, Host, Matcher};
use speculaire_oci::reference::Reference;
use speculaire_oci::tagged::Tagged;
use speculaire_registry_config::containerd::config::{self as containerd_config_file, Registry};
use speculaire_registry_config::containerd::hosts;
use speculaire_registry_config::crio::{auth, registries};

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
    ("www_authenticate", www_authenticate),
    ("token_answer", token_answer),
    ("manifest", manifest),
    ("mirror_request", mirror_request),
    ("peer_response", peer_response),
    ("reference", reference),
    ("platform", platform),
    ("node_subject", node_subject),
    ("reflect", reflect),
    ("reflect_frame", reflect_frame),
    ("containerd_event", containerd_event),
    ("referrers", referrers),
    ("link", link),
    ("retry_after", retry_after),
    ("duration", duration),
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
/// digest. A tag that parses prints as text that parses to the same tag, with the same key.
///
/// # Panics
///
/// When parsing panics, or a parsed reference is not a fixed point.
pub fn reference(data: &[u8]) {
    let Ok(text) = std::str::from_utf8(data) else {
        return;
    };
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
/// Reading the body, then the NRI settings and the credential file from it, never panics.
///
/// # Panics
///
/// When reading panics.
pub fn crio_inspect(data: &[u8]) {
    use speculaire_runtime::crio::{Nri, body, global_auth_file};
    if let Ok(body) = body(data) {
        let _ = Nri::parse(body);
        let _ = global_auth_file(body);
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

/// Every message of the reflector API: the requests the reflector reads from an agent, and the answers the agent
/// reads (D2, D97, D98, D105).
///
/// Decoding and parsing never panic. A request that parses encodes back to protobuf that parses to it again, and every
/// member or peer an answer keeps has a node. Text parses as a digest of a request exactly when it parses as a
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
    use speculaire_reflect::proto::{AgentMessage, LookupResponse, MembersResponse};
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

/// Reads every frame of `data` as `M`, with a 1 KiB limit so that lengths over it come by often.
fn frames<M: prost::Message + Default + PartialEq>(data: &[u8]) {
    use std::pin::pin;
    use std::task::{Context, Poll, Waker};

    use speculaire_reflect::frame::{self, FrameError, Reader};

    const LIMIT: usize = 1024;
    /// The output of `future`, which a slice or a `Vec` completes at its first poll.
    fn ready<T>(future: impl Future<Output = T>) -> T {
        match pin!(future).poll(&mut Context::from_waker(Waker::noop())) {
            Poll::Ready(output) => output,
            Poll::Pending => panic!("reading or writing memory waited"),
        }
    }
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

/// An event of containerd's `Subscribe`, as the inventory reads it (D99).
///
/// Decoding never panics, and an event is a change only for content of `k8s.io` created or deleted.
///
/// # Panics
///
/// When decoding panics, or another event is a change.
pub fn containerd_event(data: &[u8]) {
    use containerd_client::types::Envelope;
    use prost::Message as _;
    use speculaire_runtime::containerd::inventory::change;
    if let Ok(envelope) = Envelope::decode(data)
        && change(&envelope).is_some()
    {
        assert_eq!(envelope.namespace, "k8s.io");
        assert!(
            ["/content/create", "/content/delete"].contains(&envelope.topic.as_str()),
            "{}",
            envelope.topic
        );
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
