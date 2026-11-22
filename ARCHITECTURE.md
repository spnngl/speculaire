# Architecture

Spéculaire is one Rust binary for Linux Kubernetes nodes that run containerd or CRI-O, the CRI runtimes. It has five jobs:

1. **Mirror.** Share container image content between nodes, so a layer leaves the upstream registry about once per cluster.
2. **Distribute artifacts.** Share each image's signatures, attestations and SBOMs between nodes in the same way.
3. **Gate.** Allow a container to start only when its image has an `Allow` *verdict*. Enforcement happens in an NRI plugin.
4. **Prewarm.** Pull a configured list of images onto nodes before workloads need them.
5. **Reflect.** Control-plane nodes run as *reflectors*: they hold the complete content→peer index and answer lookups.

**Scope:**
- containerd ≥ 2.3, with 2.4+ as the main target (D15), and CRI-O at the 3 newest Kubernetes minors kind ships, 1.35 to 1.37 today (D63, D40);
- kubeadm clusters (D16);
- Linux x86_64 and aarch64, on nodes that run a kubelet.

Deployment is a systemd service first, then a Kubernetes DaemonSet.

## Vocabulary

These words have one meaning everywhere: in code, docs, metrics and commits.

| Word | Meaning |
|---|---|
| *agent* | The `speculaire agent` process. One runs on every node. |
| *reflector* | An agent on a control-plane node with `role = "reflector"`. It keeps a *soft-state* index of which nodes hold which digests, and answers lookups (D2). |
| *soft state* | State that can be rebuilt entirely from agents. It is never persisted and needs no consensus. |
| *fall through* | The agent answers 404 fast, so containerd moves on to the next `hosts.toml` host or to upstream. This is the failure mode for every distribution error. The mirror never answers 408 or 429, which containerd retries on the same host (v2.3.0 `core/remotes/docker/resolver.go:777-778`). On CRI-O only a 404 on the manifest falls through, and the whole image then comes from upstream (D66); the relay passes upstream's refusal on instead, a 429 with its `Retry-After` or a 502 (D129). |
| *registry config* | containerd's own upstream settings: `config.toml` (with `imports`) and the `hosts.toml` tree under `config_path`. The agent reads it and has no registry settings of its own (D17). On CRI-O: `registries.conf` and its drop-ins, `certs.d` and the auth file (D66). |
| *artifact store* | The agent's own content-addressed store for referrer artifacts (signatures, attestations, SBOMs). The runtime never pulls these. |
| *blob cache* | On CRI-O, the agent's own content-addressed store of the manifests and blobs its mirror served. CRI-O keeps no compressed blobs, so peers read from it (D67). |
| *image identity* | The image target digest (index or manifest) that a container is created from; on CRI-O, the image ID, which is the config digest of its platform manifest. The gate derives it per D15 and D65. |
| *policy match* | The set of policies whose globs match the normalised pod-spec image name (D11); on CRI-O, any name of the image (D65). When it is empty, `gate.unmatched` decides (D23). |
| *verdict* | `Allow`, `Rejected`, `Unverifiable` or `Pending`, for one key `(image identity, matched-policies hash, trust-root hash)` (D20). |
| *stale verdict* | The previous verdict for an image, still served while re-verification runs after a policy or trust-root change (D21). |
| *gate* | The NRI `CreateContainer` handler. It only reads local state and never touches the network. |
| *node identity* | The node name in the kubelet client certificate, `CN=system:node:<name>` (D16). |
| *withhold, never forge* | The trust rule for peers. A peer can fail to provide content, but cannot get bad bytes accepted, because everything is checked against its digest or its signature. |
| *seed* | One of the `prewarm.seeds` agents a member picks for an image of `prewarm.images`, the first to get its `Prewarm` (D51, D181). |
| *wave* | One prewarm of one image across the agents streaming to a member: its seeds, then rounds of other agents, each released once the round before announced the image (D185, D186). |

## Components

```
     control-plane nodes                                   worker node
  ┌──────────────────────────┐                 ┌──────────────────────────────────┐
  │ agent, role = reflector  │◄──Announce──────┤ agent                            │
  │  digest → {node} map     │   (one stream   │  ├ mirror   127.0.0.1:7480 ◄─────┼── runtime (hosts.toml or registries.conf.d, local mTLS)
  │  prewarm list            │    per member)  │  ├ peer API node-ip:7481 ◄───────┼── other agents (mTLS)
  │  reflector API :7483     │                 │  ├ /metrics :7482 ◄──────────────┼── Prometheus (plain HTTP, D42, D45)
  └──────────────────────────┘───Lookup───────►│  ├ artifact store                │
        ▲ reflector.url (L4 LB):               │  ├ verifier → verdict cache      │
        │                                      │  ├ blob cache (CRI-O)            │
        └─ Members discovery only ─────────────┤  └ gate (NRI plugin) ◄──────────┼── runtime NRI socket
  node links: mTLS with kubelet client certs   └──────────────────────────────────┘
```

The trust boundaries and the risks we accept are in [`docs/security.md`](docs/security.md).

## Flows

### Pull
1. containerd asks the local mirror for the tag, `HEAD /v2/<repo>/manifests/<tag>?ns=<registry>`, which the agent resolves from 2 peers that hold the tag, else falls through (D123); then each manifest and blob by digest, as `GET /v2/<repo>/blobs/<digest>?ns=<registry>` (D14).
2. The agent sends `Lookup(digest)` to a reflector, hedged to a second one. The reflector returns a shuffled subset of `(node identity, address)` pairs, never including the requester.
3. The agent races and hedges fetches from the peer API, as Spegel does. It checks that each peer's certificate names the node identity the reflector returned. It streams the bytes to the runtime while hashing them (D7).
   - If the hash doesn't match the digest, the agent aborts and denies that peer locally for `peer.deny_ttl` (D52).
   - If a peer dies mid-copy, or sends nothing for `peer.stall_timeout`, the agent resumes from the next peer with `Range` (D73).
   - A `503` from a busy peer moves the agent to the next peer at once (D24).
4. Any miss, timeout or unreachable reflector makes the agent *fall through*.
5. containerd commits the blob and emits `/content/create` (on CRI-O, the blob cache keeps it). The agent announces the new digest to every reflector (D99).

On CRI-O, the mirror also fetches what peers lack from upstream, and keeps each blob it serves in the *blob cache* once its digest matches; it announces what it keeps (D66, D67).

### Verify
The verifier works asynchronously, so the gate never waits on the network.

1. **Triggers** (D22), earliest first:
   - the mirror asked for a manifest by digest, or serving one by tag, before the runtime lists it (D152); the store keeps what it names for `artifacts.grace` (D153);
   - a change of the runtime's image list, which containerd's `/images/*` events and CRI-O's `images.json` signal (D65, D121);
   - NRI `Synchronize`, which lists the containers already running; the gate warns of each one a verdict does not allow, and stops none (D175);
   - a gate cache miss (D172).
2. **Discover** referrers for the index digest and the platform manifest digest. Try sources in this order (D126):
   1. the artifact store;
   2. peers, through the reflector;
   3. upstream, using the *registry config* for endpoints, TLS and credentials: the referrers API, then the `sha256-<hex>` fallback tag, then the cosign legacy `.sig` tag. `.att` tags are ignored (D43).

   BuildKit attestation manifests come from the image index itself (D49).
3. **Store and announce.** Put every artifact in the artifact store and announce it like any other digest.
4. **Verify offline** with `sigstore-verify` against the trust root, then evaluate every matching policy, including the SBOM rules (D12). Cache the verdict (D20).
5. **Before a final `Rejected`, try upstream once.** A peer's referrers index is a hint, not content-addressed, so the peer set may be incomplete (*withhold, never forge*).
6. **On a policy or trust-root change,** re-verify every image in the runtime's image store in the background, running containers first (D21).

### Gate
1. NRI `CreateContainer` checks the pod namespace against `gate.exempt`, derives the *image identity* (D15, D65, D169), then checks its names against `gate.exempt` (D18, D172). An exempt container is allowed and counted in metrics.
2. The gate computes the *policy match*. If it is empty, `gate.unmatched` decides (D23).
3. The gate looks up the verdict, falling back to a *stale verdict* (D21). `Pending` asks the verifier for the image (`gate_miss`, D22) and waits at most `gate.wait` (default 300 ms, D47, D172). The wait is short because the call holds the node's single NRI lock, which every pod and container event shares, and must end well inside containerd's `plugin_request_timeout` (D41).
4. If the verdict is still `Pending`, the gate denies with "verification pending" and kubelet retries.
5. **Modes** (`gate.mode`, default `audit`; no setting turns the gate off, D54):
   - `audit` allows, and records the verdict in metrics and the audit log (D37).
   - `enforce` rejects `Rejected`, `Unverifiable` and `Pending`, each with its own reason (`docs/operations.md`).
6. **Fail-closed:** the runtime's default validator requires the plugin: containerd's `required_plugins = ["speculaire"]`, CRI-O's `nri_validator_required_plugins` (D64).

### Prewarm
1. The reflector config holds the list and pushes it to agents as `Prewarm` on the `Announce` stream (D26).
2. Every member resolves each image through the *registry config* to its platform manifests and layers, and starts a *wave*. It picks the same few *seeds*, which pull from upstream. Once each seed has announced every layer of one platform manifest, or after `prewarm.seed_timeout`, it releases a round of up to 4 agents per agent already sent to; each round is released once the one before announced, or timed out, and agents that connect after the last round get the `Prewarm` at once (D51, D185, D186).
3. Agents pull with CRI `PullImage`, which goes through the mirror, one image at a time and only while the image filesystem is below `prewarm.max_disk_percent` (D188). They can pin images with the `io.cri-containerd.pinned=pinned` label (containerd v2.3.0 `internal/cri/labels/labels.go:42-45`) so kubelet GC skips them. CRI-O has no such label, and the agent does not pin there (D65).
4. Artifacts and verdicts are prewarmed along with the images.

## Layout

A row marked (planned) has no path yet; drop the mark when it lands.

| Path | Role |
|---|---|
| `apps/speculaire` | The binary: `version`, `check-config`, `configure`, `unconfigure`, `verify` and `agent` (D62, D156) |
| `apps/loadgen` | `speculaire-loadgen`, test only and never packaged: D33's load against one reflector, `just load` (D104), and a pull from a peer, `just profile peer` (D116) |
| `crates/agent` | The agent: config (D60), the node its config names (D87), preflight at startup (D86), the mirror that `Node::fallback` calls for (D90), logs (D37), metrics (D34), status listener (D42, D45), the gate's NRI registration (D168), the discovery `verify` runs on its own (D156), and the prewarm worker that pulls what members push (D188) |
| `crates/registry-config` | The *registry config* parsers, a module per runtime: containerd's `config.toml` and `hosts.toml` (D17, D78); CRI-O's `registries.conf`, `certs.d` and credential files (D66, D80) |
| `crates/oracle-harness` | Test helper: runs `speculaire-oracle` and reads its answers; the differential tests of the parsers use it (D70, D79) |
| `crates/mirror` | The local mirror: the pull half of the distribution API over TLS 1.3 with a client certificate, from the runtime's `Content`, or the relay and the *blob cache* where the runtime keeps none (D5, D66, D67, D85, D88, D90); the peer API, which serves the same, and the artifact store with its referrers, to other nodes (D100, D124) |
| `crates/registry` | The upstream client the relay and discovery fetch with: HTTP/1.1 and TLS 1.2 or 1.3 on hyper, the Bearer challenge, Basic, identity token, redirects (D88); it takes its endpoints and credentials from the runtime's `Registries` (D89) |
| `crates/oci` | Image references and platforms as containerd parses them (D81), the children of a manifest or index (D88), hashing against a digest (D7), referrers, BuildKit attestation manifests and the referrer tags (D43, D49, D121), an image's chain ID (D15) |
| `crates/runtime` | containerd and CRI-O behind four traits a `Node` hands out (D90): `Wiring` (certificates, `hosts.toml`, CRI-O's drop-in; D82, D83), `Settings` (required plugins, preflight; D84, D86), `Registries` (the registry config the relay fetches with, held as a snapshot that a reload swaps, D88, D89, D91), `Content` (containerd's directory + gRPC), a fifth, `Inventory` (what peers can fetch, D99), a sixth, `Images` (the image list, then its changes, D121), and a seventh, `Pull` (`PullImage` and the image filesystem's usage, D188); which one runs on the node (D64), the CRI calls; containerd's image store copy and snapshot base, for the gate on 2.3 (D15, D167) |
| `crates/configure` | `configure`, `unconfigure`, the preflight and the node half of `check-config`, as thin functions over the runtime's `Wiring` and `Settings` traits; it names no runtime (D82, D83, D86, D90) |
| `crates/fake-runtime` | Test support: a fake containerd on a socket, answering the CRI `Version`, `ListImages`, `PullImage` and `ImageFsInfo` (D188) and introspection `Plugins` (D87), images, snapshots and events driven by the test (D167), CRI-O's `GET /config` (D89, D90), and on a socket of its own NRI's runtime side, which registers the gate (D168) |
| `crates/pki` | the mirror's local CA and certificates (D14, D82); later kubelet certificate loading and rotation, rustls verifiers (D16) |
| `crates/time` | Durations as the config writes them, in seconds (D138), and RFC 3339 timestamps (D135) |
| `crates/load` | The load scenario `speculaire-loadgen` runs: simulated agents on `crates/reflect`'s client, the reflector's targets measured from `/proc` and `/metrics` (D33, D104) |
| `crates/reflect` | Protobuf frames over TLS (D105), the reflector's server and index (D97), and the agent's client: `Members`, one `Announce` stream per member carrying its numbered `Lookup`s, hedged (D2, D98) |
| `crates/artifacts` | Discovery of each listed or fetched image's artifacts from the *artifact store*, then peers through the mirror's fetcher, then upstream through the runtime's `Registries`, into the store, which the peer API serves and which keeps only what listed images name, and fetched ones for a grace (D17, D43, D121, D124, D126, D131, D152, D153) |
| `crates/verify` | Sigstore glue, policy, SBOM checks and verdict cache, over `crates/artifacts`; the policy file and its globs, the trust root, the signature, attestation and SBOM checks, the verdict engine with its in-memory verdicts so far, and the report of each check that `verify` prints (D156) |
| `crates/nri` | NRI plugin protocol without a runtime: multiplexer, ttrpc unary calls, `Handler`, NRI version inference (D9, D163, D166); publishable on its own |
| `fuzz/` | cargo-fuzz targets of the parsers of outside data, a workspace of its own, run by `just fuzz <target>` and nightly; `just check` replays their seeds on stable (D27). `config` takes raw bytes and `config_values` a config file written from the keys (D75) |
| `fixtures/` | `sigstore/`: Sigstore fixtures recorded from public-good by `fixtures.yml`, one OCI layout per case with its trusted root, read by the crates' tests through `crates/artifacts`' `testing` feature and pushed to e2e's upstreams (D139, D141) |
| `oracle/` | Go module, test-only: `speculaire-oracle`, upstream's own code for differential tests, `version`, `hosts`, `config`, `registries`, `certs`, `auth`, `reference`, `platform`, `nri-version` and the fake NRI runtime `nri-runtime` today, run by `just oracle` with the Rust differential tests (D29, D70, D79, D162) |
| `packaging/` | `config.toml`, the reference of every setting (D30, D47); `speculaire.service`, the systemd unit (D53, D69); `Containerfile`, the release image, and `policy/release.yaml`, the policy it passes (D157); nfpm config, runtime drop-in examples and the Helm chart (planned) |
| `e2e/` | kind node image per runtime (`node/containerd/`, `node/crio/`), cluster config (`kind.yaml`), the harness (`src/`: the cluster, its upstream registry, its reflectors'' balancer, Docker Hub's mirrors, the node helpers, and `histogram`, the bench's percentile of a native histogram) and the suites (`tests/`, one binary per area): a Rust test crate run by `just e2e <runtime> <version> [<kubernetes minor>]` (D59, D63, D69, D94, D112, D120) |
| `conformance/` | `just conformance`: the distribution-spec suite against the mirror in a container, its seed content, and the list of expected failures (D85) |
| `bench/` | Benchmarks against Spegel, run by `just bench <kubeconfig>`: `bench.sh`, the node-access pod (`node.yaml`) and the scripts it runs on each node (`node/`), the policy of the speculaire run (`policy.yaml`) (D35, D106, D178); the real-cluster results (planned) |
| `justfile` | The only entry point, for humans and CI (D27); `just dev <recipe>` runs a recipe in the build image (D57) |
| `build/Containerfile` | The build image: the musl build and, on macOS, every recipe (D57) |
| `supply-chain/` | cargo-vet's store: imported audit sets, trusted publishers, exemptions; `just vet` (D71) |
| `.config/nextest.toml` | cargo-nextest's settings for `just check`, `just cov` and `just mutants`: hung and leaky tests fail (D72) |
| `.cargo/mutants.toml` | cargo-mutants' settings for `just mutants`, and each mutant no test can observe, with its reason (D74) |

## Documents

- [`docs/decisions/`](docs/decisions/README.md): every design choice and its reason (`Dn`), one file per topic, plus an index.
- [`docs/TODECIDE.md`](docs/TODECIDE.md): open questions, each with a proposed default.
- [`docs/proposals/`](docs/proposals/): designs for unscheduled work, settled with the user but not yet decisions: [federation of swarms](docs/proposals/federation.md).
- [`docs/security.md`](docs/security.md): trust boundaries and accepted risks.
- [`docs/metrics.md`](docs/metrics.md): every exported metric, with its labels (D34).
- [`docs/operations.md`](docs/operations.md): turning on `enforce`, break glass, rejection reasons, alerts, upgrade and removal.
- [`REFERENCES.md`](REFERENCES.md): specs, upstream source and the research notes in `docs/research/`.
- [`README.md`](README.md) and [`SECURITY.md`](SECURITY.md): for humans; vulnerability reporting and supported versions (D40).
