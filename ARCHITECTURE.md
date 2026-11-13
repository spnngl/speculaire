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
| *fall through* | The agent answers 404 fast, so containerd moves on to the next `hosts.toml` host or to upstream. This is the failure mode for every distribution error. The mirror never answers 408 or 429, which containerd retries on the same host (v2.3.0 `core/remotes/docker/resolver.go:777-778`). On CRI-O only a 404 on the manifest falls through, and the whole image then comes from upstream (D66). |
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
1. containerd requests `GET /v2/<repo>/blobs/<digest>?ns=<registry>` from the local mirror (D14).
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
   - the mirror serving or forwarding a manifest by digest;
   - containerd `/images/create|update` events, or a change of CRI-O's `images.json` (D65);
   - NRI `Synchronize`, which lists the containers already running;
   - a gate cache miss.
2. **Discover** referrers for the index digest and the platform manifest digest. Try sources in this order:
   1. the artifact store;
   2. peers, through the reflector;
   3. upstream, using the *registry config* for endpoints, TLS and credentials: the referrers API, then the `sha256-<hex>` fallback tag, then the cosign legacy `.sig` tag. `.att` tags are ignored (D43).

   BuildKit attestation manifests come from the image index itself (D49).
3. **Store and announce.** Put every artifact in the artifact store and announce it like any other digest.
4. **Verify offline** with `sigstore-verify` against the trust root, then evaluate every matching policy, including the SBOM rules (D12). Cache the verdict (D20).
5. **Before a final `Rejected`, try upstream once.** A peer's referrers index is a hint, not content-addressed, so the peer set may be incomplete (*withhold, never forge*).
6. **On a policy or trust-root change,** re-verify every image in the runtime's image store in the background, running containers first (D21).

### Gate
1. NRI `CreateContainer` derives the *image identity* (D15, D65), then checks `gate.exempt` (D18). An exempt container is allowed and counted in metrics.
2. The gate computes the *policy match*. If it is empty, `gate.unmatched` decides (D23).
3. The gate looks up the verdict, falling back to a *stale verdict* (D21). `Pending` waits at most `gate.wait` (default 300 ms, D47). The wait is short because the call holds the node's single NRI lock, which every pod and container event shares, and must end well inside containerd's `plugin_request_timeout` (D41).
4. If the verdict is still `Pending`, the gate denies with "verification pending" and kubelet retries.
5. **Modes** (`gate.mode`, default `audit`; no setting turns the gate off, D54):
   - `audit` allows, and records the verdict in metrics and the audit log (D37).
   - `enforce` rejects `Rejected`, `Unverifiable` and `Pending`, each with its own reason.
6. **Fail-closed:** the runtime's default validator requires the plugin: containerd's `required_plugins = ["speculaire"]`, CRI-O's `nri_validator_required_plugins` (D64).

### Prewarm
1. The reflector config holds the list and pushes it to agents as `Prewarm` on the `Announce` stream (D26).
2. Every member picks the same few seed nodes, which pull from upstream; the rest pull peer-to-peer once the seeds have announced the blobs (D51).
3. Agents pull with CRI `PullImage`, which goes through the mirror. They can pin images with the `io.cri-containerd.pinned=pinned` label (containerd v2.3.0 `internal/cri/labels/labels.go:42-45`) so kubelet GC skips them. CRI-O has no such label, and the agent does not pin there (D65).
4. Artifacts and verdicts are prewarmed along with the images.

## Layout

A row marked (planned) has no path yet; drop the mark when it lands.

| Path | Role |
|---|---|
| `apps/speculaire` | The binary: `version`, `check-config`, `configure`, `unconfigure` and `agent` today; `verify` (planned) (D62) |
| `apps/loadgen` | Test-only reflector load generator, never packaged (D33) (planned) |
| `crates/agent` | The agent: config (D60), the node its config names (D87), preflight at startup (D86), the mirror that `Node::fallback` calls for (D90), logs (D37), metrics (D34) and status listener (D42, D45) |
| `crates/registry-config` | The *registry config* parsers, a module per runtime: containerd's `config.toml` and `hosts.toml` (D17, D78); CRI-O's `registries.conf`, `certs.d` and credential files (D66, D80) |
| `crates/oracle-harness` | Test helper: runs `speculaire-oracle` and reads its answers; the differential tests of the parsers use it (D70, D79) |
| `crates/mirror` | The local mirror: the pull half of the distribution API over TLS 1.3 with a client certificate, from the runtime's `Content`, or the relay and the *blob cache* where the runtime keeps none (D5, D66, D67, D85, D88, D90); later peers |
| `crates/registry` | The upstream client the relay fetches with: HTTP/1.1 and TLS 1.2 or 1.3 on hyper, the Bearer challenge, Basic, identity token, redirects (D88); it takes its endpoints and credentials from the runtime's `Registries` (D89) |
| `crates/oci` | Image references and platforms as containerd parses them (D81), and the children of a manifest or index (D88); later referrers and media types, on `oci-spec` |
| `crates/runtime` | containerd and CRI-O behind four traits a `Node` hands out (D90): `Wiring` (certificates, `hosts.toml`, CRI-O's drop-in; D82, D83), `Settings` (required plugins, preflight; D84, D86), `Registries` (the registry config the relay fetches with, held as a snapshot that a reload swaps, D88, D89, D91), `Content` (containerd's directory + gRPC), and a fifth, `Inventory` (what peers can fetch, D99); which one runs on the node (D64), the CRI calls; later image events, in-memory copy of the image store (planned) |
| `crates/configure` | `configure`, `unconfigure`, the preflight and the node half of `check-config`, as thin functions over the runtime's `Wiring` and `Settings` traits; it names no runtime (D82, D83, D86, D90) |
| `crates/fake-runtime` | Test support: a fake containerd on a socket, answering the CRI `Version`, `ListImages` and introspection `Plugins` (D87), and CRI-O's `GET /config` (D89, D90) |
| `crates/pki` | the mirror's local CA and certificates (D14, D82); later kubelet certificate loading and rotation, rustls verifiers (D16) |
| `crates/reflect` | Protobuf, the reflector's server and index (D97), and the agent's client: `Members`, one `Announce` stream per member, hedged `Lookup` (D2, D98) |
| `crates/verify` | Artifact discovery and *artifact store*, sigstore glue, policy, SBOM checks, verdict cache (planned) |
| `crates/nri` | NRI multiplexer and ttrpc plugin API (D9); publishable on its own (planned) |
| `fuzz/` | cargo-fuzz targets of the parsers of outside data, a workspace of its own, run by `just fuzz <target>` and nightly; `just check` replays their seeds on stable (D27). `config` takes raw bytes and `config_values` a config file written from the keys (D75) |
| `oracle/` | Go module, test-only: `speculaire-oracle`, upstream's own code for differential tests, `version`, `hosts`, `config`, `registries`, `certs`, `auth`, `reference` and `platform` today, run by `just oracle` with the Rust differential tests (D29, D70, D79); a fake NRI runtime later |
| `packaging/` | `config.toml`, the reference of every setting (D30, D47); `speculaire.service`, the systemd unit (D53, D69); nfpm config, runtime drop-in examples and the Helm chart (planned) |
| `e2e/` | kind node image per runtime (`node/containerd/`, `node/crio/`), cluster config (`kind.yaml`), the harness (`src/`: the cluster, its upstream registry, its reflectors'' balancer and the node helpers) and the suites (`tests/`, one binary per area): a Rust test crate run by `just e2e <runtime> <version> [<kubernetes minor>]` (D59, D63, D69, D94) |
| `conformance/` | `just conformance`: the distribution-spec suite against the mirror in a container, its seed content, and the list of expected failures (D85) |
| `bench/` | Benchmarks against Spegel: recipe, node-access pod, policy, results (D35) (planned) |
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
