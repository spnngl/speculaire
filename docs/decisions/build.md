# Decisions: build, CI and release

Index: `docs/decisions/README.md`. CI and release conventions are researched in `docs/research/ci-dedens.md`.

## D4: No io_uring in v1

- **Decision:** plain tokio, with storage behind a `BlobSource` trait. The systemd unit denies `io_uring_setup`, `io_uring_enter` and `io_uring_register`.
- **Because:**
  - **Measure first.** The workload is a few large sequential streams, mostly served from page cache and bound by the network. io_uring's wins (batched submission, registered buffers, zero-copy send) target many small operations or CPU-bound senders.
  - **Ecosystem.** Every dependency (hyper, tonic, rustls, containerd-client) is epoll/tokio. The io_uring runtimes (tokio-uring, glommio, monoio) are stale or have no hyper support.
  - **Cancellation.** The hedged race drops futures at every `.await`. Dropping an in-flight io_uring operation must not free its buffer while the kernel still owns it, so every buffer would need an owned-buffer hand-off.
  - **Security.**
    - seccomp cannot inspect io_uring operations, so allowing io_uring makes the unit's `SystemCallFilter` bypassable.
    - Container default seccomp profiles block it, which matters in the DaemonSet phase.
    - `kernel.io_uring_disabled` (kernel ≥ 6.6) turns it off on hardened hosts.
  - The peer path is TLS, so even `sendfile` doesn't apply.
  - Details: `~/src/github.com/spnngl/agent-skills/skills/kernel/io-uring/`.
- **Revisit when:** a benchmark shows the agent CPU-bound at serving, at more than 1 core per 10 Gb/s. Then prototype a plaintext-peer `sendfile` path first. Try io_uring only after that, behind a cargo feature with owned buffers, and after reading the io-uring skill.

## D13: Stack and binaries (amended by D34)

- **Decision:**
  - **Stack:** Rust edition 2024, tokio (multi-thread), axum/hyper, tonic/prost, `containerd-client` 0.9, `oci-spec`, rustls with the `aws-lc-rs` provider (+ `rcgen` for D14's local certificates), `sd-notify`, `toml`.
  - **Metrics:** the `metrics` 0.24 facade plus `metrics-exporter-prometheus` 0.18 with `default-features = false`. The agent builds the recorder with `build_recorder`, serves `PrometheusHandle::render` from its own axum `/metrics` route, and calls `run_upkeep` on an interval.
  - **Logs:** `tracing` 0.1, `tracing-subscriber` 0.3 (`env-filter`, `json`), `tracing-journald` 0.3.
  - **Binaries:** static-PIE musl with `mimalloc` (secure mode behind a cargo feature) and `cargo auditable`. They are built natively per architecture inside a digest-pinned `rust:<channel>-alpine`, with no `cross` or `cargo-zigbuild`, and linked with lld through dedens' `.cargo/lld-cc` wrapper (aarch64 static-PIE).
  - Code follows `~/src/github.com/spnngl/agent-skills/skills/rust/rs-coding/SKILL.md`. Lints follow dedens' `[workspace.lints]` (`unsafe_code = "deny"`, clippy `pedantic` plus selected restriction lints).
- **Because:**
  - This is the stack Dragonfly's Rust client proved at scale.
  - `metrics` is a facade, so library crates emit metrics without depending on an exporter. The exporter's default features add its own HTTP listener and a push gateway, which the agent does not use.
  - `aws-lc-rs` is the only crypto provider `sigstore-verify` ships (sigstore-rust 0.16 `crates/sigstore-crypto/Cargo.toml:10-12`), so rustls uses it too and the build image compiles its C code.
  - One artifact works on every distro, and in a scratch image later.
  - Native Alpine builds avoid cross-toolchain drift for C dependencies (rs-coding `musl.md`). dedens rejected QEMU, cross and zigbuild for the same reason (`docs/research/ci-dedens.md` §3).
- **Revisit when:** —

## D34: Metrics are a fixed catalog, with native histograms over protobuf (amends D13)

- **Decision:**
  - **Catalog:** `docs/metrics.md` lists every metric with its type, labels and meaning. A test renders `/metrics` after the e2e suite and fails if a metric is missing from the catalog, or listed there but never emitted.
  - **Labels:** only values from a small fixed set, or bounded by config: `member` (a reflector name) and `upstream` (a registry host from the *registry config*). A label never holds a digest, image, repository, namespace, pod or peer node. The one exception is `speculaire_build_info`, whose version labels have a single value per process.
  - **Naming:** `with_recommended_naming(true)`, base units (`_seconds`, `_bytes`), and no global labels; Prometheus adds `instance`.
  - **Histograms:** every histogram is native. `metrics-exporter-prometheus` gets its `protobuf` feature. All histograms use `set_native_histogram_for_metric(Matcher::Prefix("speculaire_"), NativeHistogramConfig::new(1.1, 160, 1e-6)?)`: schema 3 (buckets about 9% wide, so at most about 4.5% error) and 160 buckets, of which 154 span 100 µs to 60 s.
  - **Exposition:** the axum `/metrics` route negotiates the format the way the exporter's own listener does (`src/exporter/http_listener.rs:167`). For the protobuf `Accept` type it serves `render_protobuf`, and otherwise `render` (text).
  - **Process metrics** (memory, CPU, file descriptors) come from node-exporter and systemd's cgroup accounting; speculaire exports none.
- **Because:**
  - The user chose protobuf and native histograms, and reliance on node-exporter and systemd.
  - Without buckets, the exporter renders histograms as summaries, which cannot be aggregated across nodes (`metrics-exporter-prometheus` 0.18.3 `src/exporter/builder.rs:293-308`).
  - Native histograms need no bucket list per metric, and one config covers both the 500 µs lookup target (D33) and 60 s verifications.
  - A label per peer node or per image would multiply series by up to 10k on every node.
- **Cost:**
  - Text exposition leaves out native histograms entirely (`src/recorder.rs:214-217`). A scraper that does not request protobuf, or a backend without native-histogram support, sees counters and gauges only. Prometheus asks for protobuf only with native-histogram ingestion turned on; the setting depends on its version.
  - The `protobuf` feature runs `prost-build` (`build.rs`), so the build image needs `protoc`. tonic's code generation needs it anyway.
- **Revisit when:** users run a backend without native-histogram support. Then add classic buckets per metric with `set_buckets_for_metric`, which works in both formats.

## D19: Dev loop is Docker plus CI

- **Decision:**
  - Locally (macOS), build and test inside `rust:<channel>-alpine` containers, and run e2e with kind on Docker through `just e2e <containerd-version>`.
  - CI runs the same recipes on native amd64 and arm64 runners, against containerd 2.3 and 2.4.
- **Because:**
  - Docker already gives a native Linux arm64 environment on the Mac.
  - kind nodes run systemd, so the agent runs as a real unit inside them.
- **Revisit when:** —

## D25: License is Apache-2.0

- **Decision:**
  - The project is Apache-2.0 (`LICENSE`).
  - Code ported from another project starts with a comment that names the upstream file and tag. The first port from a project adds that project's copyright line to `NOTICE`.
- **Because:**
  - The user chose Apache-2.0. It matches containerd, NRI and sigstore-rust.
  - We port parts of containerd and NRI (D9, D17, D29), and Apache-2.0 §4 requires keeping their notices.
- **Revisit when:** —

## D27: CI and release copy dedens' conventions

- **Decision:**
  - **Workflow:**
    - `just` is the only entry point, and a change is done when `just check` passes.
    - Every CI step calls a `just` recipe.
    - A single aggregate `gate` job is the only required check.
  - **Workflows** (`docs/research/ci-dedens.md` §1 and §6 "Copy as is"). The repo is `spnngl/speculaire`, so they call the reusable workflows in `spnngl/.github` as dedens does:
    - `ci`: `check`, then `musl` on native amd64/arm64, then `deps` (hack, msrv, minimal-versions, deny), `oracle` (D29) and `e2e`, then `gate`;
    - `lint` (actionlint, zizmor);
    - `commit` (Conventional Commits);
    - `fuzz` (nightly cron);
    - `load` (nightly cron): `just load`, the reflector load test (D33);
    - `bench`: nightly on kind, and by `workflow_dispatch` on a real cluster, `just bench` against Spegel (D35);
    - `mutants` and `deep` (careful), both informational;
    - `advisories`, `codeql`, `betterleaks`, `renovate`;
    - `release`, which reuses `ci`.
  - **Hygiene:**
    - Actions are pinned by SHA and container images by digest.
    - Every workflow starts with `permissions: {}`.
    - Checkout uses `persist-credentials: false`.
    - Every job has a timeout.
  - **Release:**
    - a reproducible double build;
    - nfpm deb and rpm with the systemd unit, checked by lintian and rpmlint, plus install tests;
    - deterministic tarballs and `SHA256SUMS`;
    - a per-arch image and a multi-arch manifest;
    - `actions/attest-build-provenance` on the files and on the image digest.
  - **Differences from dedens:**
    - no macOS leg, because the code is Linux-only;
    - a new `e2e` matrix of {`ubuntu-26.04`, `ubuntu-26.04-arm`} × {containerd 2.3.x, 2.4.x}, which consumes the musl binary built in the same run;
    - one kind node image per containerd version, tracked by Renovate;
    - the image runs as root, because it needs the kubelet key and containerd's content directory;
    - DNS-specific benchmarks, Kani and the turmoil simulation are dropped.
- **Because:** these conventions are proven in a sibling Rust project by the same author, and keeping local runs equal to CI removes "works on my machine".
- **Revisit when:** —

## D28: Dogfood: releases carry what the gate checks

- **Decision:**
  - Each release image gets SLSA build provenance (`attest-build-provenance`) and an SPDX SBOM (`syft`, which reads the `cargo auditable` data) attached with `actions/attest-sbom`.
  - Both are pushed as OCI referrers (`push-to-registry: true`).
  - An e2e test runs speculaire's own image under a policy that requires both, signed by the release workflow's identity.
- **Because:**
  - GitHub attestations are Sigstore bundles stored as referrers, the most common real-world producer of the format D8 verifies.
  - The project should pass its own gate. dedens ships no SBOM (`docs/research/ci-dedens.md` §3).
- **Revisit when:** —

## D29: Go is a test oracle, never shipped

- **Decision:**
  - Production code is pure Rust.
  - `oracle/` is a separate Go module whose `go.mod` pins `containerd/containerd` at the newest supported 2.4.x, and `containerd/nri` at the version that containerd vendors. Renovate tracks both pins. Containerd 2.3's NRI behaviour stays covered by e2e. The module builds one test-only binary, `speculaire-oracle`, with these subcommands:
    - `nri-runtime`: a fake NRI runtime on `pkg/adaptation` (`adaptation.New(name, version, …)`, `adaptation.go:172`). It drives the `nri` crate through registration, `Configure`, a `Synchronize` split into several requests, and `CreateContainer`, with no containerd running.
    - `hosts`, `config`, `reference`, `platform` and `nri-version`: each reads cases as JSON lines on stdin and prints upstream's own result. The sources are, in order: `core/remotes/docker/config`, the config loader, `pkg/reference/docker`, `platforms`, and NRI's `api.InferVersionFromRuntime` (D9).
  - Differential tests feed the same cases to our Rust ports and to the oracle, and require identical output. The cases are containerd's own test cases, the e2e node configs and the fuzz corpus.
  - `just oracle` builds and runs the oracle inside a digest-pinned `golang:<version>-alpine` image, so no Go is needed on the host. In CI it is the `oracle` job of `ci`, required by `gate`.
  - The oracle never appears in release artifacts, packages or images, and no Rust crate depends on it.
- **Because:**
  - The hosts, config, reference, platform and NRI-version ports must behave exactly like upstream, and an error in reference or platform handling is a security bug (D11, D15). Calling containerd's own code is the only exact check, and a Renovate bump that changes upstream behaviour turns the job red.
  - `pkg/adaptation` is the runtime side NRI tests its own plugins against, so it tests the `nri` crate in seconds, without kind.
  - **Rejected:** writing the NRI plugin in Go and forwarding to the Rust agent. That would ship two languages and two binaries, and add a round trip while containerd holds the node-wide NRI lock.
  - **Rejected:** pure Rust without an oracle. Drift from containerd would stay silent until a user hit it.
- **Revisit when:** an upstream Rust NRI crate ships its own runtime harness (D9). Then drop `nri-runtime`. Keep the other subcommands while we maintain the ports.


## D35: Benchmarks against Spegel, with the tool Spegel publishes with

- **Decision:**
  - **Tool:** `spegel-org/benchmark` at a pinned release, tracked by Renovate, run with its `suite` command. It deploys DaemonSets of the static `ghcr.io/spegel-org/benchmark` images (v1 and v2 of 10 MB, 100 MB and 1 GB, each in 1 and 4 layers), reads each pod's pull duration from its events, then rolls v1 to v2, 20% of pods at a time. Like the oracle (D29), it is test tooling and never shipped.
  - **Three runs per suite,** on the same nodes and the same containerd:
    1. baseline: no mirror;
    2. Spegel, at its latest release, installed with its Helm chart at default values;
    3. speculaire, as the systemd unit, with `gate.mode = "audit"` and a policy that matches the benchmark images. Those images are unsigned, so every pull runs discovery and verification, and the gate lets the `rejected` verdict through. This prices the verification work into the run.
  - **Node access:** `just bench <kubeconfig>` needs only a cluster-admin kubeconfig and nodes with `crictl` and `/bin/bash`, which the tool's own image cleanup runs through a `hostPath: /` pod. The tool skips tainted nodes, so control-plane nodes run no benchmark pods. `just bench` installs packages, reads cgroups and resets nodes through a privileged pod per node that enters the host's namespaces (`nsenter -t 1`).
  - **Between runs,** every node is reset: the previous mirror is removed (`helm uninstall`, or `speculaire unconfigure` and package removal), the benchmark images are removed with `crictl rmi`, and the page cache is dropped. The run then checks that no `hosts.toml` holds a mirror entry and that no benchmark blob is left in containerd's content store, and aborts otherwise.
  - **Measured per image set and phase** (first rollout, update):
    - p50, p95 and max pull duration, from the tool;
    - agent CPU time and peak memory per node, read from the agent's cgroup (`cpu.stat`, `memory.peak`): the speculaire unit's, Spegel's pod's;
    - for speculaire, `speculaire_gate_seconds` p99.
  - **Two tiers:**
    - `bench/` holds the recipe, the node-access pod, the speculaire policy and the result files.
    - **kind, nightly:** the `bench` workflow runs the 10 MB and 100 MB sets on a 3-node kind cluster, on amd64 and arm64, and writes the comparison to the job summary. It is informational: one host has no real network, so it catches regressions, not absolute numbers.
    - **Real cluster, before each minor release:** `bench` by `workflow_dispatch`, every image set, on an existing kubeadm cluster, given as a kubeconfig secret of the workflow, with at least 2 control-plane nodes (the reflectors, behind `reflector.url`, D2) and 10 workers, amd64 and arm64. The results go to `bench/results/<speculaire version>.json`.
  - **Release bar:** on the real cluster, for every image set and phase, speculaire's p50 and p95 pull durations are at most 5% above Spegel's, and its CPU time and peak memory per node are at most Spegel's. A miss blocks the minor release until it is fixed, or explained in the release notes.
- **Because:**
  - The user asked for benchmarks against Spegel. Its own tool, images and method make our numbers comparable with its published results (`spegel-org/benchmark-results`: AKS, 10 × `Standard_D8ds_v5` workers), and remove the suspicion of a benchmark tuned for us.
  - Pod events are what users see: they include containerd's whole pull, mirror and *fall through* included.
  - The benchmark depends on Kubernetes and kubeadm only, never on how the cluster was provisioned.
  - Spegel's uninstall and our `unconfigure` each leave different state behind, so the reset checks the node instead of trusting either.
  - The 5% margin absorbs run-to-run noise; a loss larger than that is a regression.
- **Cost:** the real-cluster tier needs a cluster that can be dedicated to it for a few hours each minor release, and the privileged node pods need cluster-admin.
- **Revisit when:** `spegel-org/benchmark` stops being maintained; then fork it into `bench/`.

## D40: SemVer, fixes for the latest minor only

- **Decision:**
  - **Versions:** SemVer. Releases stay `0.x` until the gate ships `enforce`; in `0.x`, a breaking change bumps the minor. A breaking change is one that removes or renames a setting, a CLI command or flag, or a metric, or drops a protocol version or a containerd minor.
  - **Fixes,** security ones included, go to the latest minor release only.
  - **containerd:** every minor from 2.3 on that upstream still supports. A containerd minor is dropped in our first minor release after its upstream end of life. 2.4 and later is the main target (D15).
  - **Kubernetes:** e2e runs the newest Kubernetes that kind ships for each containerd version in the matrix (D27); other versions are expected to work, since speculaire only talks to containerd and the kubelet's certificates.
  - **Upgrade order:** reflectors first, then agents, one minor at a time. A reflector accepts its own protocol version and the previous one (D2).
  - **Vulnerabilities** are reported through GitHub private vulnerability reporting (`SECURITY.md`).
- **Because:**
  - The user chose this policy.
  - One maintained line matches the project's size; backports would double CI.
- **Revisit when:** a user needs a longer-lived line; then add an LTS branch with its own CI.
