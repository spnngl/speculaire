# Decisions

Each decision has three parts: the choice (**Decision**), its reasons (**Because**) and the condition for reopening it (**Revisit when**). A new decision goes in its topic's file under the next free number, and gets a line below. Numbers are never reused.

- **Replacing a decision:** mark the old one `superseded by Dn` in its header.
- **Amending a decision:** name the amendment in both headers (`amends Dn` in the new one, `amended by Dn` in the old one).
- **Index line:** each line below gives the topic file, a gist, and the same header note.

Open questions: [`docs/TODECIDE.md`](../TODECIDE.md).

- D1 [reflector](reflector.md): reflectors replace the DHT; no libp2p
- D2 [reflector](reflector.md): reflectors are the control-plane agents; an L4 load balancer is used only for `Members` discovery, and agents stream to every member directly (amended by D33, D51)
- D3 [distribution](distribution.md): every agent announces its own peer address and port (amended by D36)
- D4 [build](build.md): no io_uring in v1, and the unit denies its syscalls
- D5 [distribution](distribution.md): blobs are served from containerd's content directory, with a gRPC fallback
- D6 [distribution](distribution.md): the mirror never gets the `resolve` capability
- D7 [distribution](distribution.md): full-blob responses are hashed in flight; relayed `Range` requests are not (amended by D52)
- D8 [verification](verification.md): crypto comes from sigstore-rust (`sigstore-verify`, `sigstore-trust-root`) (amended by D43)
- D9 [gate](gate.md): enforcement is an external NRI plugin, on our own `nri` crate
- D10 [gate](gate.md): no containerd bindir image-verifier in v1
- D11 [verification](verification.md): the policy is shaped like `ClusterImagePolicy` and matched on the pod-spec image name; every matching policy must pass
- D12 [verification](verification.md): SBOMs are checked for signature, format and package presence in v1; content rules come later; no vulnerability scanning on the node
- D13 [build](build.md): tokio/axum/tonic/rustls stack, `metrics` and `tracing`, static-PIE musl built natively on Alpine (amended by D34, D46)
- D14 [distribution](distribution.md): the mirror is TLS with client auth on `127.0.0.1:7480`, using a local CA from `configure`; the peer API is mTLS on `node-ip:7481` (amended by D32)
- D15 [gate](gate.md): containerd 2.3 minimum, 2.4+ main target; image identity comes from NRI on 2.4, and from the annotation plus a snapshot chain-ID check on 2.3
- D16 [identity](identity.md): node identity is the kubelet client certificate, checked by custom rustls verifiers; P2P stays off until the certificate exists
- D17 [distribution](distribution.md): upstream access reuses containerd's registry config; images pullable only with pull secrets end `Unverifiable`
- D18 [gate](gate.md): `gate.exempt` is explicit and empty by default
- D19 [build](build.md): the dev loop is Docker on macOS plus CI on native runners
- D20 [verification](verification.md): `Verdict` has four states; `Unverifiable` is retried, `Rejected` is final (amended by D31, D38)
- D21 [verification](verification.md): stale verdicts keep serving during re-verification, for up to `verify.stale_max` (amended by D31)
- D22 [verification](verification.md): verification starts at the manifest fetch
- D23 [gate](gate.md): `gate.unmatched` (default `deny`) decides images that no policy matches
- D24 [distribution](distribution.md): the peer API caps concurrent uploads and answers `503` beyond the cap
- D25 [build](build.md): the license is Apache-2.0; ported code names its upstream file, and `NOTICE` keeps upstream copyrights
- D26 [verification](verification.md): the policy and trust root are local files; the reflector pushes only the prewarm list
- D27 [build](build.md): CI and release copy dedens' conventions, plus a kind e2e matrix (amended by D48)
- D28 [build](build.md): release images carry provenance and an SBOM, and e2e checks them with the gate
- D29 [build](build.md): Go is a test oracle, never shipped: a fake NRI runtime, and upstream's own code to check our hosts, config, reference, platform and NRI-version ports (amended by D48)
- D30 [agent](agent.md): one strict config file, reloaded on SIGHUP and when a watched file's modification time is at or after the last check; a bad reload keeps the old config (amended by D37, D47)
- D31 [verification](verification.md): verdicts and signature results are saved in `/run/speculaire` and survive agent restarts (amends D20, D21)
- D32 [agent](agent.md): `configure` and `unconfigure` change only speculaire's own entries; `unconfigure` removes entries before certificates and refuses while `required_plugins` names speculaire (amends D14)
- D33 [reflector](reflector.md): reconnects are jittered, and a nightly 10k-agent load test checks the reflector's memory, lookup latency and resync time (amends D2)
- D34 [build](build.md): metrics are a fixed catalog in `docs/metrics.md` with bounded labels; histograms are native, served over protobuf; no process metrics (amends D13; amended by D50)
- D35 [build](build.md): benchmarks against Spegel with `spegel-org/benchmark`: nightly on kind, and on any kubeadm cluster, through its kubeconfig, before each minor release, which must not be more than 5% slower
- D36 [distribution](distribution.md): the peer address is the local IP of the reflector connection, unless `peer.address` is set (amends D3)
- D37 [agent](agent.md): logs through `tracing` to journald or JSON, default `warn`; an audit log of gate decisions and verdict changes, off by default; secrets never logged (amends D30; amended by D52)
- D38 [verification](verification.md): upstream `429` pauses discovery to that host until `Retry-After`; fallback and `.sig` tags are probed with `HEAD` (amends D20; amended by D43)
- D39 [agent](agent.md): shutdown withdraws from reflectors, drains for 10 s, saves the cache, and leaves NRI last
- D40 [build](build.md): SemVer, `0.x` until `enforce` ships; fixes for the latest minor only; containerd minors from 2.3 while upstream supports them
- D41 [gate](gate.md): `gate.wait` stays under half of containerd's `plugin_request_timeout`; a closed NRI connection re-registers at once
- D42 [agent](agent.md): `/metrics`, `/readyz` and `/livez` listen on `metrics.address`, port 7482, plain HTTP (amended by D45)
- D43 [verification](verification.md): attestations count only as Sigstore bundles found as OCI referrers; `.att` tags and private GitHub attestations are not supported; `.sig` stays (amends D8, D38; amended by D49)
- D44 [gate](gate.md): the DaemonSet installs in `kube-system`, and its own pod carries the NRI tolerate annotation

- D45 [agent](agent.md): the health and metrics listener binds `[::]:7482` from startup; `/readyz` waits for config, mirror and NRI registration (amends D42)
- D46 [build](build.md): musl binaries always use mimalloc in secure mode, built with `SOURCE_DATE_EPOCH=0` (amends D13)
- D47 [agent](agent.md): every setting has a key, a literal default (`"auto"` when computed) and a reload class; names the gate, NRI, policy, trust-root, reflector and prewarm keys (amends D30)
- D48 [build](build.md): the required CI job is `required`; `just check` is "the check" (amends D27, D29)
- D49 [verification](verification.md): a BuildKit SBOM inside a signed index is D43's one exception (amends D43)
- D50 [build](build.md): the `upstream` label names only hosts with a `hosts.toml` directory, else `other` (amends D34)
- D51 [reflector](reflector.md): every member picks the same prewarm seeds by rendezvous hash; agents drop duplicate `Prewarm` (amends D2)
- D52 [distribution](distribution.md): a peer that sends a wrong digest is denied locally for `peer.deny_ttl`, with a `peer` audit event (amends D7, D37)
- D53 [agent](agent.md): the systemd unit's hardening, checked by e2e
- D54 [gate](gate.md): no setting turns the gate off; a disabled NRI stops startup

Next free number: D55.
