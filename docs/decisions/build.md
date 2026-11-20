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

## D13: Stack and binaries (amended by D34, D46, D57, D105, D107, D116)

- **Decision:**
  - **Stack:** Rust edition 2024, tokio (multi-thread), axum/hyper, tonic/prost, `containerd-client` 0.9, `oci-spec`, rustls with the `aws-lc-rs` provider (+ `rcgen` for D14's local certificates), `sd-notify`, `toml`.
  - **Metrics:** the `metrics` 0.24 facade plus `metrics-exporter-prometheus` 0.18 with `default-features = false`. The agent builds the recorder with `build_recorder`, serves `PrometheusHandle::render` from its own axum `/metrics` route, and calls `run_upkeep` on an interval.
  - **Logs:** `tracing` 0.1, `tracing-subscriber` 0.3 (`env-filter`, `json`), `tracing-journald` 0.3.
  - **Binaries:** static-PIE musl with `mimalloc` in secure mode (D46) and `cargo auditable`. They are built natively per architecture inside a digest-pinned `rust:<channel>-alpine`, with no `cross` or `cargo-zigbuild`, and linked with lld through dedens' `.cargo/lld-cc` wrapper (aarch64 static-PIE).
  - Code follows `~/src/github.com/spnngl/agent-skills/skills/rust/rs-coding/SKILL.md`. Lints follow dedens' `[workspace.lints]` (`unsafe_code = "deny"`, clippy `pedantic` plus selected restriction lints).
- **Because:**
  - This is the stack Dragonfly's Rust client proved at scale.
  - `metrics` is a facade, so library crates emit metrics without depending on an exporter. The exporter's default features add its own HTTP listener and a push gateway, which the agent does not use.
  - `aws-lc-rs` is the only crypto provider `sigstore-verify` ships (sigstore-rust 0.16 `crates/sigstore-crypto/Cargo.toml:10-12`), so rustls uses it too and the build image compiles its C code.
  - One artifact works on every distro, and in a scratch image later.
  - **Measured** (M0 spike 06): `sigstore-verify` 0.16.0 with `aws-lc-rs` builds in `rust:1.99.1-alpine` with dedens' `.cargo/` as a `static-pie linked` binary on aarch64 (7.5 MB unstripped, 32 s clean on 10 CPUs) and on x86_64 (8.4 MB, 1 min 29 s clean, built and run under Docker Desktop's amd64 emulation). There was no C or link failure.
  - Native Alpine builds avoid cross-toolchain drift for C dependencies (rs-coding `musl.md`). dedens rejected QEMU, cross and zigbuild for the same reason (`docs/research/ci-dedens.md` §3).
- **Revisit when:** —

## D34: Metrics are a fixed catalog, with native histograms over protobuf (amends D13; amended by D50, D61, D109, D116)

- **Decision:**
  - **Catalog:** `docs/metrics.md` lists every metric with its type, labels and meaning. A test renders `/metrics` after the e2e suite and fails if a metric is missing from the catalog, or listed there but never emitted.
  - **Labels:** only values from a small fixed set, or bounded by config: `member` (a reflector name) and `upstream` (a registry host named by the *registry config*, else `other`, D50). A label never holds a digest, image, repository, namespace, pod or peer node. The one exception is `speculaire_build_info`, whose version labels have a single value per process.
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
  - The `protobuf` feature runs `prost-build` (`build.rs`), so the build image needs `protoc`. The reflector's messages need it anyway (D105).
- **Revisit when:** users run a backend without native-histogram support. Then add classic buckets per metric with `set_buckets_for_metric`, which works in both formats.

## D19: Dev loop is Docker plus CI (amended by D57)

- **Decision:**
  - Locally (macOS), build and test inside `rust:<channel>-alpine` containers, and run e2e with kind on Docker through `just e2e` (D63).
  - CI runs the same recipes on native amd64 and arm64 runners.
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

## D27: CI and release copy dedens' conventions (amended by D48, D58, D59, D63, D71, D72, D74, D75, D76, D77, D97, D104)

- **Decision:**
  - **Workflow:**
    - `just` is the only entry point, and a change is done when `just check` passes.
    - Every CI step calls a `just` recipe.
    - A single aggregate `required` job is the only required check (D48).
  - **Workflows** (`docs/research/ci-dedens.md` §1 and §6 "Copy as is"). The repo is `spnngl/speculaire`, so they call the reusable workflows in `spnngl/.github` as dedens does:
    - `ci`: `check`, then `musl` on native amd64/arm64, then `deps` (hack, msrv, minimal-versions, deny), `oracle` (D29) and `e2e`, then `required`;
    - `lint` (actionlint, zizmor);
    - `commit` (Conventional Commits);
    - `fuzz` (nightly cron);
    - `load` (nightly cron, and dispatch with an `args` input for `speculaire-loadgen`, D104): `just load`, the reflector load test (D33);
    - `bench`: nightly on kind, and by `workflow_dispatch` on a real cluster, `just bench` against Spegel (D35);
    - `mutants` and `deep` (careful, shuttle), both informational;
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
- **Because:**
  - these conventions are proven in a sibling Rust project by the same author, and keeping local runs equal to CI removes "works on my machine".
  - **Measured** (M0 spike 00, kind v0.33.0, Docker Desktop on arm64, containerd 2.3.7 and 2.4.2 on `kindest/node:v1.37.0`): a node image that replaces `/usr/local/bin/containerd`, `containerd-shim-runc-v2` and `ctr` with a release tarball, checked against its `sha256`, starts a 3-node cluster. The node ships containerd 2.3.4, NRI enabled with `/var/run/nri/nri.sock`, no `config_path` and `discard_unpacked_layers = true`, so the node image patches the last two (kind `containerdConfigPatches`). A kind node must match the host architecture. systemd 257 in the node runs a unit with every D53 setting (`systemd-analyze security` lists them all), and a static-PIE binary built in `rust:1.99.1-alpine` with dedens' `.cargo/` runs there. Registry config shows in `containerd config dump`, not in `crictl info`.
  - **Measured in CI** (M0 spike workflow, run 42925541544): the same harness, with spikes 01 and 04, passes on `ubuntu-26.04` and `ubuntu-26.04-arm` against containerd 2.3.7 and 2.4.2, with Docker 29.4.2, 4 CPUs and 15 GiB per runner, in 5 to 7 minutes per leg including the Rust build. Each leg pulls about 8 Docker Hub images anonymously without hitting a rate limit.
- **Revisit when:** —

## D28: Dogfood: releases carry what the gate checks (amended by D157)

- **Decision:**
  - Each release image gets SLSA build provenance (`attest-build-provenance`) and an SPDX SBOM (`syft`, which reads the `cargo auditable` data) attached with `actions/attest-sbom`.
  - Both are pushed as OCI referrers (`push-to-registry: true`).
  - An e2e test runs speculaire's own image under a policy that requires both, signed by the release workflow's identity.
- **Because:**
  - GitHub attestations are Sigstore bundles stored as referrers, the most common real-world producer of the format D8 verifies.
  - The project should pass its own gate. dedens ships no SBOM (`docs/research/ci-dedens.md` §3).
- **Revisit when:** —

## D29: Go is a test oracle, never shipped (amended by D48, D70, D79, D162)

- **Decision:**
  - Production code is pure Rust.
  - `oracle/` is a separate Go module whose `go.mod` pins `containerd/containerd` at the newest supported 2.4.x, and `containerd/nri` at the version that containerd vendors. Renovate tracks both pins. Containerd 2.3's NRI behaviour stays covered by e2e. The module builds one test-only binary, `speculaire-oracle`, with these subcommands:
    - `nri-runtime`: a fake NRI runtime on `pkg/adaptation` (`adaptation.New(name, version, …)`, `adaptation.go:172`). It drives the `nri` crate through registration, `Configure`, a `Synchronize` split into several requests, and `CreateContainer`, with no containerd running.
    - `hosts`, `config`, `reference`, `platform` and `nri-version`: each reads cases as JSON lines on stdin and prints upstream's own result. The sources are, in order: `core/remotes/docker/config`, the config loader, `github.com/distribution/reference`, `platforms`, and NRI's `api.InferVersionFromRuntime` (D9).
  - Differential tests feed the same cases to our Rust ports and to the oracle, and require identical output. The cases are containerd's own test cases, the e2e node configs and the fuzz corpus.
  - `just oracle` builds and runs the oracle inside a digest-pinned `golang:<version>-alpine` image, so no Go is needed on the host. In CI it is the `oracle` job of `ci`, a dependency of `required`.
  - The oracle never appears in release artifacts, packages or images, and no Rust crate depends on it.
- **Because:**
  - The hosts, config, reference, platform and NRI-version ports must behave exactly like upstream, and an error in reference or platform handling is a security bug (D11, D15). Calling containerd's own code is the only exact check, and a Renovate bump that changes upstream behaviour turns the job red.
  - `pkg/adaptation` is the runtime side NRI tests its own plugins against, so it tests the `nri` crate in seconds, without kind.
  - **Rejected:** writing the NRI plugin in Go and forwarding to the Rust agent. That would ship two languages and two binaries, and add a round trip while containerd holds the node-wide NRI lock.
  - **Rejected:** pure Rust without an oracle. Drift from containerd would stay silent until a user hit it.
- **Revisit when:** an upstream Rust NRI crate ships its own runtime harness (D9). Then drop `nri-runtime`. Keep the other subcommands while we maintain the ports.

## D35: Benchmarks against Spegel, with the tool Spegel publishes with (amended by D106, D114)

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

## D40: SemVer, fixes for the latest minor only (amended by D63)

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

## D46: musl binaries use mimalloc in secure mode, always (amends D13)

- **Decision:** the musl build of `speculaire` uses mimalloc with `MI_SECURE=4` (the `mimalloc` crate's `secure` feature) as its `#[global_allocator]`, through a `[target.'cfg(target_env = "musl")'.dependencies]` entry. Tool builds (Miri, fuzz, mutants) and non-musl builds keep the system allocator. The build image sets `SOURCE_DATE_EPOCH=0`.
- **Because:**
  - dedens measured it (dedens D152, D154): no gain for the attacker in any probe case, at 0.89 of the fastest allocator against mallocng's 0.68. A cargo feature would ship two binaries with different safety, and only one of them tested.
  - mimalloc's `options.c` embeds `__DATE__` and `__TIME__`; without `SOURCE_DATE_EPOCH=0` the reproducible double build (D27) differs.
- **Cost:** a higher churn peak (dedens: 184 MiB against mallocng's 94) and about 16k lines of C built by `cc`.
- **Revisit when:** `just bench` (D35) shows the allocator costing more than the 5% release bar.

## D48: The required CI job is `required`; `just check` is the check (amends D27, D29; amended by D72)

- **Decision:** the aggregate CI job that branch protection requires is named `required`. `just check` is called "the check". "Gate" means only the NRI gate (ARCHITECTURE.md § Vocabulary).
- **Because:** dedens calls both "the gate", which in speculaire is the component that admits containers. One word with two meanings breaks the vocabulary rule in `AGENTS.md`.
- **Revisit when:** —

## D50: The `upstream` label names only configured registry hosts (amends D34; amended by D121)

- **Decision:** a registry host with its own directory in the `hosts.toml` tree (D17) keeps its name as the `upstream` label value. Every other host is `upstream="other"`. Peer fetches leave the label empty.
- **Because:** pod authors choose registry hosts, so "a host from the registry config" was not bounded: a pod naming a new host would add series on every node. The `hosts.toml` tree is written by the admin.
- **Revisit when:** admins need per-host numbers for hosts without a `hosts.toml` directory; the audit log (D37) already names them.

## D57: One pinned toolchain, one build image, and `just dev` on macOS (amends D13, D19; amended by D58, D62, D116, D118, D125, D140)

- **Decision:**
  - `rust-toolchain.toml` pins stable `1.99.1` with clippy and rustfmt; the justfile pins one nightly, for rustfmt (`rustfmt.toml` uses unstable options) and `-Z` flags, and RAPx its own (D140). `rust-version` is `1.95`, which `just msrv` checks.
  - `build/Containerfile` is the one build image, from the digest-pinned `rust:<channel>-alpine` whose tag is the pinned stable. Its `build` stage has lld, mimalloc's C toolchain, cargo-auditable and rust-audit-info; its `dev` stage adds the nightly rustfmt, just and the tools of `just check` and the dependency checks.
  - On macOS, `just dev <recipe>` runs any recipe in the `dev` stage; `just musl <target>` builds in the `build` stage. Named volumes keep the cargo registry and each architecture's target directory between runs. `SPECULAIRE_CONTAINER` picks the engine, default `docker`.
- **Because:**
  - A new stable brings new clippy lints, which `-D warnings` turns into errors: an unpinned toolchain breaks the check without a change in the code. Renovate bumps the pin and the image tag together.
  - One image for both local runs and the musl build keeps one list of tool versions. Recipes that re-run themselves in a container when they detect macOS would hide where they run.
  - `1.95` is dedens' `rust-version`: the shipped binary is built with the pin, so the MSRV only bounds the std APIs the code uses (`clippy::incompatible_msrv`).
  - **Measured** (M1 step 00, Docker Desktop on arm64): `just dev check`, `just hack`, `just msrv`, `just minimal-versions` and `just deny` pass; `just musl aarch64-unknown-linux-musl` gives a `static-pie linked` binary that runs in a `scratch` image, lists its 23 crates through `rust-audit-info`, holds no machine path, and has the same SHA-256 from two clean target directories.
- **Revisit when:** a contributor builds on a machine without a container engine.

## D58: CI runs the check on the runner, and the musl build in the build image (amends D27, D57)

- **Decision:**
  - The `check` and `deps` jobs of `ci` run their recipes on the runner, with the pinned toolchains (`just toolchains`), `Swatinem/rust-cache`, and tools from `taiki-e/install-action` at `build/Containerfile`'s versions. The `musl` jobs run `just musl` in the build image.
  - Each tool version carries a `# renovate:` comment with the same `depName` in both files, so one Renovate pull request bumps both.
  - `just musl` fails unless the binary is `static-pie linked` and carries its cargo-auditable list.
  - A `ci` job lands with the M1 step that gives it content, and joins `required.needs` then: `e2e` in step 02, `oracle` in step 06. The `fuzz` workflow lands with the first fuzz target (step 07).
- **Because:**
  - The dev image compiles its tools from source: about four minutes on every run without a layer cache, against seconds for prebuilt binaries. dedens runs its `check` the same way.
  - A job without content passes and so proves nothing in `required`.
  - **Measured** (M1 step 01, PR #3): every job passed in about 5 minutes; the CI aarch64 binary has the SHA-256 of the local `just musl` build (`3058d2cc…3833`), and `required` failed when a throwaway commit failed `check`.
- **Cost:** the tool versions live in two files; a hand edit to one of them makes local and CI runs differ until Renovate's next pull request.
- **Revisit when:** the build image is published to a registry, so CI can pull it instead of building it.

## D59: e2e is a Rust test crate on a kind cluster that `just` recipes manage (amends D27; amended by D63)

- **Decision:**
  - `e2e/` is a workspace crate. Its suites in `e2e/tests/` drive the cluster through `kubectl` and `docker exec`, and every test is `#[ignore]`d: `just check` builds them, and `just e2e-test <minor>` runs them with `--ignored`.
  - The justfile manages the cluster: `just e2e <minor>` runs `e2e-up`, `e2e-test` and `e2e-down` (on exit, pass or fail). `e2e-up` builds `e2e/node/Containerfile`, starts the cluster `speculaire-<minor without dot>` from `e2e/kind.yaml`, copies the binary of `just musl` to each node, and waits until every node is `Ready`.
  - The justfile pins one containerd release per supported minor (D40), kind, and kubectl, each with a `# renovate:` comment. `just e2e-tools` downloads kind and kubectl into `target/e2e/`, checking their published SHA-256. The node image patches `discard_unpacked_layers = false` and `config_path` into containerd's config, and its build fails when the patch no longer applies.
  - The suites' pod image is `e2e::TEST_IMAGE`, pinned by tag and digest.
- **Because:**
  - Rust keeps the suites typed, in the language of the code they test, and needs no other runner. `#[ignore]` keeps a suite that cannot run from looking like a pass.
  - The CI job and a Mac run the same recipe; the musl binary comes from the run's own `musl` job in CI.
  - Pins let Renovate propose each bump as a pull request that e2e tests; the M0 harness resolved the newest release at run time, so a release could break a run with no change in the repository.
  - Renovate's presets skip `tests/` directories, so the image constant lives in `e2e/src/lib.rs`.
  - **Measured** (M1 step 02, Docker Desktop on arm64): `just e2e 2.3` and `just e2e 2.4` each pass in about 45 s from a warm image cache, and exit non-zero when the pod's image digest is wrong; afterwards no `speculaire-*` cluster or container remains. kind's `--wait` covers only the control plane: a worker was not yet `Ready` when the suite started. In CI (PR #4) the four legs pass in 1 to 2 minutes each, with the binary of their run's `musl` job.
- **Cost:** containerd pulls by digest whatever tag precedes it, so a wrong tag in `TEST_IMAGE` goes unnoticed until Renovate rewrites it.
- **Revisit when:** a suite needs more than one cluster at a time.


## D61: `speculaire_build_info` exists from startup, and every build has `protoc` (amends D34; amended by D68, D168)

- **Decision:**
  - `speculaire_build_info` is set when the recorder is installed, with `containerd_version=""` and `nri_version=""`. NRI's `Configure` fills both (D9, M6).
  - `protoc` comes from Alpine's `protobuf-dev` in the build image, and from `taiki-e/install-action` at a Renovate-tracked release in the runner jobs of `ci` (D58).
  - `deny.toml` allows BSD-3-Clause (`matchit`, axum's router) and Zlib (`foldhash`, through `prost-build`).
- **Because:**
  - The version is the first thing to read when the gate never registers, and that is when `Configure` never came.
  - `metrics-exporter-prometheus` 0.18.3 `build.rs` runs `prost_build::compile_protos` when the `protobuf` feature is on, so every job that compiles the agent needs `protoc`.
- **Cost:** once `Configure` fills the versions, the series with empty labels stays exported; the recorder has no call that removes a series.
- **Revisit when:** M6 sets the versions: drop the empty series, or move the runtime versions to a series of their own.

## D62: Binaries live in `apps/`, libraries in `crates/` (amends D57; amended by D156)

- **Decision:**
  - `apps/<name>` holds each binary package: `apps/speculaire` (package `speculaire`, the shipped binary) and, later, `apps/loadgen`. A binary package parses arguments and calls libraries; it holds no other logic.
  - `crates/<name>` holds each library, as package `speculaire-<name>`: `crates/agent` is `speculaire-agent` today.
  - The binary's integration tests live in `apps/speculaire/tests/`, where Cargo builds the binary for them (`CARGO_BIN_EXE_speculaire`).
  - `e2e/` and `oracle/` stay at the top level.
- **Because:** the user asked for libraries and binaries apart. A library holds code a fuzz target, a test or another binary can reuse; a binary-only crate cannot be linked by them.

## D63: e2e covers containerd and CRI-O on the 3 newest Kubernetes minors kind ships (amends D27, D40, D59; amended by D94, D113, D120, D130)

- **Decision:**
  - **Runtimes:** containerd and CRI-O. cri-dockerd has no NRI, so the gate cannot run there.
  - **Support window** (replaces D40's Kubernetes bullet): the 3 newest Kubernetes minors kind ships, 1.35, 1.36 and 1.37 with kind v0.33.0. On each, the containerd minors of D40, and the CRI-O minor equal to the Kubernetes minor. Dropping a Kubernetes or CRI-O minor is a breaking change (D40).
  - **Matrix,** each leg on `ubuntu-26.04` and `ubuntu-26.04-arm`, 14 legs: containerd 2.3 and 2.4 on Kubernetes 1.37; containerd 2.4 on 1.36 and 1.35; CRI-O 1.37, 1.36 and 1.35, each on its own Kubernetes minor. Every supported containerd minor runs on the newest Kubernetes; the newest containerd runs on the older ones.
  - **Node images:** one per runtime release and Kubernetes minor, `FROM` the digest-pinned `kindest/node` of that minor. containerd's image is D59's. CRI-O's installs CRI-O's static bundle (`cri-o.<arch>.v<version>.tar.gz`, checked against its `.sha256sum`) with the bundle's `install` script, which also points `/etc/crictl.yaml` at CRI-O; it disables containerd's unit, keeping containerd installed because kind's entrypoint rewrites containerd's config at every boot; and a drop-in sets `default_runtime = "runc"`.
  - **Cluster config:** CRI-O's kind config sets `criSocket: unix:///var/run/crio/crio.sock` for init and join. Every `kubeadmConfigPatches` entry names its `apiVersion`, with a `v1beta4` and a `v1beta3` variant, because kind v0.33.0 writes `v1beta3` below Kubernetes 1.36 (`pkg/cluster/internal/kubeadm/config.go:677`), where `extraArgs` is a map, and applies a patch naming an `apiVersion` only to that version (`pkg/internal/patch/resource.go:70`).
  - **Recipes:** `just e2e <runtime> <version> [<kubernetes minor>]`, with `<runtime>` `containerd` or `crio`. containerd's Kubernetes minor defaults to the newest; CRI-O's is its own. The justfile pins one release per runtime minor and one `kindest/node` digest per Kubernetes minor, each with a `# renovate:` comment; Renovate moves each pin within its minor only, since a new minor changes the matrix. `e2e/node/<runtime>/Containerfile` takes the `kindest/node` and the release as build arguments. On CRI-O, `e2e-up` appends `e2e/node/crio/kind-patches.yaml` to `e2e/kind.yaml`. The cluster is `speculaire-<runtime><minor>-k<kubernetes minor>`, without dots, and `e2e-down` with the same arguments deletes it. The suites read the runtime, its release and the Kubernetes minor from `SPECULAIRE_E2E_*`, and check each node's `containerRuntimeVersion` and `kubeletVersion` against them.
- **Because:**
  - The user asked for every CRI runtime, tested on the Kubernetes versions speculaire supports.
  - CRI-O's minor follows Kubernetes', so one CRI-O leg per Kubernetes minor covers both. D40's "newest Kubernetes only" leaned on speculaire talking to containerd alone; CRI-O ties the runtime to the Kubernetes minor.
  - crun, the bundle's default runtime, reaches systemd's cgroup manager through D-Bus, which a kind node does not run: with it, kubeadm times out and CRI-O logs `Container creation error: cannot open sd-bus: No such file or directory`. runc uses `/run/systemd/private`, as under kind's containerd.
  - **Measured** (CRI-O spike 00, M0b): on Docker Desktop arm64, a CRI-O cluster is created in 37 to 39 s and every node turns `Ready` with runtime `cri-o://<version>`; kind's `--wait` again covered the control plane only, so the harness waits for every node. `hello` (M0 step 00) runs under every D53 setting and connects to `/var/run/crio/crio.sock` and `/var/run/nri/nri.sock`; a busybox pod runs. `crio status config` shows NRI on by default: `enable_nri = true`, `nri_listen = "/var/run/nri/nri.sock"`, `nri_plugin_registration_timeout = "5s"`, `nri_plugin_request_timeout = "2s"`, `nri_disable_connections = false`, default validator off. containerd 2.4 on Kubernetes 1.35 and 1.36 passes M0's step 00 checks. In CI (run 42999583274 of the throwaway branch `spike/crio`), the 14 legs passed on the first push, in 3.5 to 6.8 minutes each, CRI-O clusters created in 41 to 54 s.
- **Cost:**
  - 14 legs where D59 had 4.
  - `kind load` imports through containerd, so CRI-O nodes pull every image from its registry, kind's control-plane images included: each CRI-O leg depends on `registry.k8s.io` and on the test image's registry.
- **Revisit when:** kind ships a new Kubernetes minor (the oldest leaves the window), kind ships a CRI-O node image, or a containerd minor reaches its upstream end of life.

## D68: `speculaire_build_info` names the runtime (amends D61; amended by D168)

- **Decision:** `speculaire_build_info` has the labels `version`, `runtime`, `runtime_version` and `nri_version`. `runtime` and `runtime_version` are NRI `Configure`'s `runtime_name` and `runtime_version`: `containerd` or `cri-o`, and its release. All three runtime labels are empty until `Configure`, as D61 says.
- **Because:**
  - The agent runs under containerd or CRI-O (D64), and a `containerd_version` label would sit empty on every CRI-O node.
  - `Configure` names the runtime itself: containerd sends `containerd` (CRI-O spike 01), and CRI-O sends `cri-o` (v1.37.2 `internal/nri/nri.go:121`).
- **Revisit when:** D61's revisit, in M6.


## D70: The oracle lands with its pins and `version`; each subcommand lands with the port it checks (amends D29; amended by D79, D80, D81, D162)

- **Decision:**
  - `oracle/` is the Go module `github.com/spnngl/speculaire/oracle`. M1 ships it with one subcommand, `speculaire-oracle version`, which prints the containerd and NRI versions it links, from its build info, as one JSON line: `{"containerd":"v2.4.2","nri":"v0.12.3"}`.
  - D29's subcommands land with the Rust ports they check: `hosts`, `config`, `reference` and `platform` in M2, `nri-runtime` and `nri-version` in M6. The CRI-O ports of M2, `registries.conf` and `certs.d` (D66), get a subcommand on `go.podman.io/image/v5` at the version the newest supported CRI-O requires.
  - Each subcommand reads cases as JSON lines on stdin and prints one JSON line per case on stdout. The Rust side is a test helper crate in `crates/` (D62) that runs the binary.
  - `just oracle` runs `gofmt -l`, `go mod verify`, `go vet`, `go test` and `speculaire-oracle version` in the digest-pinned `golang:<version>-alpine` image of the justfile. The CI job `oracle` runs it, needs no other job, and `required` needs it (D48).
  - The NRI pin moves only with containerd's: Renovate leaves NRI alone and runs `go mod tidy` after a containerd update, which raises NRI to what containerd requires. A test fails when `go mod graph` shows containerd requiring another NRI than the one selected.
- **Because:**
  - A subcommand without its port has nothing to compare against, and a test that only runs upstream code checks nothing of ours.
  - The build info is what the binary links, so `version` cannot disagree with the code the later subcommands call.
  - Renovate cannot read containerd's requirement; Go's version selection can, and the test turns any drift red.
- **Measured (M1 step 07, arm64):** `just oracle` prints `{"containerd":"v2.4.2","nri":"v0.12.3"}`; with `go get github.com/containerd/nri@v0.12.5`, `go test` fails with `github.com/containerd/containerd/v2@v2.4.2 requires NRI "v0.12.3", go.mod selects "v0.12.5"`.
- **Revisit when:** containerd 2.5 is supported (D40): the oracle moves to the newest minor by hand.

## D79: `just oracle` runs the Rust differential tests, and the oracle reaches containerd's unexported code (amends D29, D70)

- **Decision:**
  - `just oracle` builds `speculaire-oracle` into `target/oracle/` and then runs `just oracle-test`, which runs every test target named `oracle` (`cargo test --workspace --test oracle -- --nocapture`) with `SPECULAIRE_ORACLE` set to the binary. The tests run natively on Linux and in the dev image elsewhere (D57), where the static Linux binary of the machine's architecture runs too. The CI job `oracle` installs the pinned Rust toolchain and `protoc` for it.
  - `speculaire-oracle-harness` (`crates/oracle-harness`) reads the variable: unset, a test skips and says so; set to a missing file, it fails. In the job the recipe sets it, so no test passes by being skipped; `--nocapture` keeps each test's "N cases agree with containerd" line in the log.
  - `hosts` calls containerd's unexported `parseHostsFile` and `loadHostDir` through `//go:linkname` (with an empty `linkname.s`, so the declarations may lack a body); `config` runs `LoadConfigWithPlugins` and the CRI image service's decoder. Errors are answered as `{"error": ...}`, a panic of containerd's code too: a daemon would have died, which is an error for a config.
  - The `config` subcommand runs 513 times a case where containerd's version 1 migration renames two plugin sections of a file to one name, which then merge through a Go map, and answers `{"unstable": true}` when the answers differ; it runs any other case once. A test compares only the cases with a stable answer.
  - `just oracle-build` builds the binary alone. The shards of the `mutants` workflow run it and set the variable, so the differential tests judge the mutants of a port: without the oracle they skip, and a mutant that only they see counts as missed.
  - A test mutates every fuzz seed 400 times with a fixed generator (delete, replace or insert a byte of the seed) and sends the results as cases, so the corpus the fuzzers start from gets the differential check on every run.
- **Because:**
  - A parser compared with upstream only on the cases someone thought of agrees with upstream on those cases. The mutations found most of the divergences of D78, and cost about a second.
  - Linking the unexported functions checks the code containerd runs, not a copy of it; the build fails when the symbols move.
- **Measured (M2 step 00, arm64):** `just oracle` runs both tests in under 2 s once built.
- **Revisit when:** containerd exports the host config parsers: drop the linkname.

## D71: cargo-vet gates every crate version of `Cargo.lock` inside `required` (amends D27)

- **Decision:**
  - `supply-chain/` holds cargo-vet's store. It imports the audit sets of mozilla, google, bytecode-alliance, zcash, isrg and embark-studios, trusts the nine crates.io publishers those sets already trust (dtolnay, cuviper, epage, kennykerr, BurntSushi, Amanieu, alexcrichton, seanmonstar, sunfishcode), and exempts the rest. Every crate is held to cargo-vet's default, `safe-to-deploy`.
  - `just vet` runs `cargo vet --locked`, which reads `imports.lock` and needs no network. In CI it is a step of the `deps (deny)` job, so `required` needs it without a job of its own.
  - A pull request that adds a crate, or bumps one that no audit or trust covers, fails `deps (deny)`. Its author, or for a Renovate update its reviewer, runs `just vet-exempt` on the branch and commits `supply-chain/`, or writes an audit or a trust instead.
  - Only the main workspace is vetted. `fuzz/` and `oracle/` run in CI and never ship.
  - `supply-chain/` is left in cargo-vet's format: taplo skips it, because cargo-vet rewrites it on each command.
  - cargo-vet is pinned, with one renovate depName, in `ci.yml` and in the dev stage of `build/Containerfile` (D58).
- **Because:**
  - Each new crate, and each new version nobody vouched for, becomes a decision a person makes in review, not a line Renovate adds.
  - Trusting the publishers the imported sets already trust lets their releases through without an exemption per bump: 63 fewer exemptions to renew.
  - An exemption covers one version, so a Renovate bump of an exempted crate fails until someone renews it. A workflow could renew it, but its pushes start CI only with a write token, which is a secret this repository does not hold.
- **Cost:**
  - A bump of one of the 72 exempted crates needs `just vet-exempt` by hand.
  - Each trust ends one year after it was written (2027-11-11): renew them with `cargo vet trust --all <user>` before then, or `just vet` fails.
- **Measured (2026-11-11, cargo-vet 0.10.3):**
  - `cargo vet init` exempts 164 crates; the six imports leave 135 exempted; the nine trusts then 72 exempted and 92 fully audited.
  - A new dependency (`bytesize 2.7.0`) fails with `bytesize:2.7.0 missing ["safe-to-deploy"]` and passes after `just vet-exempt`; `bytes` moved from an exempted 1.12.1 to 1.12.0 fails the same way; `itoa` (dtolnay) moved from 1.0.19 to 1.0.18 passes unchanged.
  - In CI, PR #20's `deps (deny)` passes; a throwaway PR adding `bytesize` fails it on `just vet`, with the same message.
- **Revisit when:** exemption renewals pass one a week, or the repository gains a write token for automation.

## D72: Coverage gates through `required`, and nextest runs the tests (amends D27, D48)

- **Decision:**
  - `just cov` runs `cargo llvm-cov nextest` on the workspace without `e2e`, whose code runs only against a kind cluster. It prints a summary, and writes the report its arguments ask for. `rust-toolchain.toml` lists `llvm-tools`. `apps/speculaire/tests/agent.rs` counts the binary it starts.
  - The CI job `coverage` writes `just cov --cobertura --output-path target/cobertura.xml` and uploads it with `actions/upload-code-coverage` (label `code-coverage/llvm-cov`). It runs on pull requests, which it checks out at their head commit, and on pushes to `main`, which give the ruleset's `code_coverage` rule its baseline. It is the only job with `code-quality: write`, and `required` needs it.
  - A failed upload only warns (`fail-on-error: false`): the upload API answers 404 to this repository, a personal account's, so the rule gets no report and blocks nothing. The job still runs every test under instrumentation and logs the summary. The action skips pull requests from forks, which would also give the rule no data.
  - cargo-nextest runs the tests of `just check` and `just cov`, configured in `.config/nextest.toml`: a test still running after 2 minutes is killed with its process group, and a test whose child still holds the test's stdout or stderr 500 ms after it ends fails. `cargo test --doc` covers doctests, which nextest skips. `e2e/` keeps `cargo test`, which runs its test binaries one after another.
  - In the build image, `just cov` cancels the path remapping of the musl rustflags (D46), which would hide from llvm-cov which files are the workspace's.
- **Because:**
  - The `code_coverage` rule does not wait for an upload: unless `required` waits for `coverage`, a pull request could merge before its coverage is known.
  - A job of its own keeps `code-quality: write` away from the tools `check` installs.
  - The rule compares the pull request's head with `main`, so the report's lines must be the head's, not those of the merge commit.
  - A hung test otherwise holds the job until its 30-minute timeout, without saying which test hangs.
- **Measured (2026-11-11):**
  - 87.50 % of lines and 85.22 % of regions, on macOS and in the build image alike.
  - A planted test spawning `sleep` with the test's stdout ends `LEAK-FAIL`.
  - In PR #22, the upload failed with `Coverage upload failed (HTTP 404): Not Found` on `PUT /repos/spnngl/speculaire/code-coverage/report`, with Code Quality enabled and no code coverage setting in the repository's settings.
- **Revisit when:** the upload API accepts this repository's reports: make a failed upload fail the job again, and check that a pull request lowering coverage is blocked. Or when the first pull request from a fork arrives.

## D74: cargo-mutants tests the diff of each pull request, in shards, outside `required` (amends D27; amended by D125)

- **Decision:**
  - `just mutants` runs cargo-mutants on a worktree of `HEAD`, with `.cargo/mutants.toml`: nextest as the test tool (D72), every feature, every package's tests for each mutant (`test_workspace`), `e2e/**` excluded. `fuzz/` is a workspace of its own, which cargo-mutants never lists, so it needs no glob (`just mutants-stale` reports one as matching no file). `just mutants-diff` limits the run to the mutants of a diff against `origin/main`; `just mutants-stale` fails on an exclusion that matches no mutant, naming it.
  - `test_workspace` is on because `apps/speculaire/tests/agent.rs` starts the binary and is what sees `serve.rs` and `systemd.rs`: their package's own tests reach neither.
  - `--timeout 240` stays dedens' value. The slowest killed mutant took 11 s in its test phase. A hang is killed by nextest after 2 minutes (D72), before cargo-mutants' 240 s, so it counts as caught: a change that hangs a test is an observed change. No `mutants` nextest profile.
  - One change is excluded, with its reason in the file: `+` to `-` in `serve`'s two `Instant::now() + period`, whose polls start at once and find nothing, because no file has changed since the read before them.
  - `.github/workflows/mutants.yml` runs on pull requests that touch Rust sources, `Cargo.lock`, the cargo-mutants or nextest settings, the workflow or the justfile. `plan` lists the diff's mutants and splits them in up to 4 shards of about 40, `stale` runs `just mutants-stale`, each `shard` runs its part without a baseline, and `summary` writes the missed and timed-out mutants on the run's page. It is not in `required`.
  - cargo-mutants is pinned in `mutants.yml`, with a renovate depName; cargo-nextest's pin is that of `ci.yml`.
- **Because:**
  - A mutant no test notices is a line no test checks. Run on the diff, the cost grows with the change, not with the workspace.
  - 4 shards, not dedens' 8: the account runs 20 jobs at once, and `ci.yml` starts about 31.
  - Outside `required`, a slow or flaky shard cannot block a merge; the summary still shows each missed mutant.
- **Measured (2026-11-11, cargo-mutants 27.1.0, macOS arm64):**
  - The workspace lists 142 mutants; 19 are `e2e/` and 2 are excluded, so 121 are tested (72 of them in the config values).
  - Without `test_workspace`: 44 missed of 123. With it, before new tests: 29 missed, 71 caught, 23 unviable. After the new tests: 98 caught, 23 unviable, 0 missed, 0 timeouts, in 13 minutes (baseline: 4 s build and 2 s test).
  - PR #24 on CI: `plan`, `stale`, one shard (3 mutants: 2 caught, 1 unviable, 40 s of tests in a 66 s job) and `summary` green. A throwaway PR (#25) planted two faults: a pattern matching nothing turned `stale` red, naming it (`exclude_re matches no mutant: 'nowhere\.rs...'`); a removed test of `audit_filter` turned `shard (0)` red with `MISSED log.rs:86:39: replace && with || in audit_filter` and `log.rs:86:23: replace == with != in audit_filter` (run 43104969323), both in the `missed.txt` that `summary` prints. A throwaway docs-only PR (#26) started `ci`, `betterleaks` and `conventional-commits`, and no `mutants` run. The throwaways are closed.
- **Revisit when:** a shard nears its 350 minutes, the missed mutants pile up unread (then put `mutants` in `required`), or a hung test counts as caught too easily.

## D75: A second fuzz target writes config files from the keys (amends D27)

- **Decision:**
  - `config_values` fuzzes `config::parse` with a TOML document that `fuzz/src/values.rs` writes from the fuzzer's bytes. `KEYS` lists every key of `packaging/config.toml`, each with literals its parser accepts, first, and literals it refuses. A draw takes about one key in eight, as a dotted key of the root table, with a literal or a string of raw bytes. The document goes through the round trip of `config`, now `round_trip`, shared by both targets.
  - `config` stays for raw bytes: TOML's syntax errors, and text no list foresaw.
  - `arbitrary` comes from `libfuzzer-sys`, which re-exports it, so `fuzz/` gains no dependency and `speculaire-agent` gains no `arbitrary`, no feature and no `Arbitrary` derive.
  - `just check` holds `KEYS` to the reference file: a smoke test fails when a key of `packaging/config.toml` has no entry or an entry names no key, and another when the first literals of all keys do not parse. The target has two seeds, all zeros (the first literal of every key) and a counting pattern.
- **Because:**
  - Raw bytes rarely spell a value a parser accepts, so the `config` target stopped at the first refusal: in M1 `just fuzz config 60` (about 730 000 runs, with the dictionary) missed every panic planted after the parse, such as `prewarm.seeds >= 10`.
  - A `Config` derived from `arbitrary` would hold only values that parse, and never reach the parsers' errors.
  - A list keeps the generator readable; the unit test keeps it in step with the file.
- **Cost:** a key's literals are written by hand, and a new value type needs its own. A document names a key once, so it never tests a repeated key (the `config` target does).
- **Measured (2026-11-11, cargo-fuzz 0.13.2, macOS arm64, `just fuzz <target> 300`, `cargo fuzz coverage`):**
  - Line coverage of `speculaire-agent` after a 5-minute run, `config` corpus (3 358 817 runs, 3 879 inputs) and `config_values` corpus (1 621 597 runs, 1 540 inputs): `crates/agent/src/config/value.rs` 81.98 % (40 of 222 lines missed) and 89.19 % (24 missed); `crates/agent/src/config.rs` 60.87 % (72 of 184 missed) and 58.15 % (77 missed).
  - What `config_values` adds: a pinned trusted root, a reflector URL, their printing, a zero interval's refusal, a log filter's refusal. What it loses against `config`: the TOML syntax error's position. What neither reaches, being no part of `parse` or its round trip: the accessors (`get`, `as_str`, `env_filter`), `keep_restart_keys`, `load`, and `ParseError`'s `Display`.
  - A panic planted after the parse (`prewarm.seeds >= 10` in `round_trip`): `config_values` finds it in 10 s, 11 s and 12 s of three runs on a fresh corpus without its seeds, and in 2 s with them (the counting seed reaches it); `config` found nothing in 300 s (one run, 2 775 933 runs).
  - The `fuzz` workflow, dispatched on PR #27's branch (run 43106442458): `targets` and one job per target, `fuzz (config)` and `fuzz (config_values)`, green in 6 minutes each.
- **Revisit when:** a target's coverage stops growing before its parsers' last lines, or `KEYS` falls behind its smoke test too often.

## D76: cargo-careful runs the tests under AddressSanitizer on each pull request, in one job (amends D27; amended by D97, D140)

- **Decision:**
  - `just careful [sanitizer] [package]` runs `cargo careful test` on the pinned nightly (`nightly`), with its own target dir `target/careful` and no leak check (`detect_leaks=0`: a leak is no memory error). It names the host target, as `just fuzz` does (dedens D141). Without a package it runs `--workspace --exclude e2e`: every package but `e2e`, which needs a kind cluster. `fuzz/` is not a member; `just check` replays its seeds (D27).
  - `.github/workflows/deep.yml` has the job `careful`, running `just careful address` on `ubuntu-26.04`, on pull requests that change a Rust file, a manifest, `Cargo.lock`, `rust-toolchain.toml`, the justfile or the workflow. It is informational, outside `required`.
  - cargo-careful is pinned in `deep.yml` (`CARGO_CAREFUL_VERSION`, with a renovate depName). `just toolchains` adds `rust-src` to the nightly, for the standard library rebuild.
  - The musl allocator's `secure` feature (D46) is out of scope: careful builds for the host's glibc target, with no mimalloc.
  - It runs on glibc Linux only, and not in `just dev` (D57): the build image is musl, where a sanitized sysroot refuses a static libc (`sanitizer is incompatible with statically linked libc`), and without `crt-static` the ASan runtime (`librustc-nightly_rt.asan.a`) is missing for the musl target. A rebuilt sysroot there lacks the C runtime objects too, with no sanitizer (`cannot open crt1.o`). macOS cannot link the sanitized builds. The image gains no cargo-careful.
- **Because:**
  - AddressSanitizer sees what the tests of safe code cannot: an out-of-bounds read or use after free behind `unsafe` in a dependency, or the unsafe code D27's `deny(unsafe_code)` will one day allow. The standard library's debug assertions check the preconditions of `unsafe` functions that a release build skips.
  - One job, not dedens' one per package: the whole run takes under 2 minutes, and a job per package costs a runner each of the 20. Revisit at 20 minutes.
  - Informational, so that a nightly bump that breaks the sanitizer cannot block a merge.
- **Cost:** C dependencies (aws-lc-rs, mimalloc) are not instrumented. No local run on macOS or in `just dev`: reproduce on a glibc Linux or in a `rust:bookworm` container with `just toolchains` and cargo-careful 0.4.10.
- **Measured (2026-11-11, cargo-careful 0.4.10, `nightly-2026-10-26`):**
  - `just careful address` on a glibc container (aarch64): 26 tests, all pass, no report. PR #28 on CI: `deep` run 43110216779, `careful` green in 91 s (the `just careful address` step 55 s, uncached, the sysroot rebuild included).
  - Planted fault: a `*bytes.as_ptr().add(4)` read one byte past a 4-byte `Vec`, in a test with `#[expect(unsafe_code, reason)]`, on a throwaway PR (#29, closed): `careful` red in run 43110331343 with `ERROR: AddressSanitizer: heap-buffer-overflow`. `get_unchecked(4)` would stop earlier, on the standard library's own precondition check, with no ASan report.
  - A throwaway docs-only PR (#30, closed) started no `deep` run.
  - `just dev careful address` cannot pass: the failures above, seen on aarch64 Alpine. The Done-when item of the plan names it; it is not met, and the decision above is the observed outcome.
- **Revisit when:** the job passes 20 minutes (then one job per package, as dedens does), a nightly bump breaks the sanitized build twice in a row, or the build image gains a glibc stage.

## D77: RAPx analyses the workspace on each pull request and every week, outside `required` (amends D27; amended by D140)

- **Decision:**
  - `just rapx-install` builds RAPx at `rapx_rev` (dedens' commit of RAPx's main, with its fix for async closures, safer-rust/RAPx#319) on its own nightly, `rapx_nightly` (D140), with the nightly's `rustc-dev`, `rust-src` and `llvm-tools-preview`, and Z3 (Homebrew on macOS, `libz3-dev` on Linux). `just rapx [args]` runs `cargo rapx`, by default `check -f -m` (use-after-free, double free, leaks); `just rapx opt` gives optimization hints. Its own target dir, `target/rapx`: RAPx runs `cargo clean --workspace` before each analysis.
  - `.github/workflows/rapx.yml` runs on a Monday cron, on `workflow_dispatch`, and on pull requests that change a Rust file, a manifest, `Cargo.lock`, the justfile or the workflow. One job, `rapx`, puts the `check` and the `opt` output in its summary. A new push cancels the PR's run. It is outside `required`.
  - `rapx_rev` and `rapx_nightly` move together, by hand: RAPx builds on rustc internals.
  - `build/Containerfile`'s dev stage gains no RAPx: it needs Z3 and `rustc-dev` on a pinned nightly, and a local run is `just rapx-install` once.
- **Because:**
  - A run costs a few minutes (dedens: 3 to 5), and `Box::into_raw` and `mem::forget` leak without `unsafe`, which `deny(unsafe_code)` cannot see.
  - The weekly run catches a nightly or dependency change no pull request made.
  - Outside `required`, a nightly bump that breaks RAPx cannot block a merge.
- **Cost:** `rapx` exits 0 on findings (it fails only when it cannot run), so a red job means a pin to bump, never a finding; findings are read in the summary. Here they are false positives so far.
- **Measured (2026-11-11, RAPx 0.7.65 at `8d9d0a2`, `nightly-2026-10-26`, macOS arm64):**
  - `just rapx`: exit 0 in 13 s once built, with each of the three packages (`speculaire-agent`, `e2e`, `speculaire`) checked. 15 warnings, all in safe code that expands macros or async state machines: 8 double frees and 3 use-after-frees reported in "no symbol available" at `crates/agent/src/serve.rs` and `systemd.rs` (`ping.tick().await`), 4 dangling pointers in clap's `update_from_arg_matches_mut` (`apps/speculaire/src/main.rs:23`) and `reload`. The workspace has no `unsafe`, so none is real.
  - `just rapx opt`: exit 0, 3 cloning hints (`crates/agent/src/log.rs:49` and `:58`, `crates/agent/src/telemetry.rs:30`), no other category.
  - Planted fault: `Box::into_raw(Box::new([0_u8; 64]))` in a `pub fn`, never freed: `just rapx` printed `Memory Leak detected in function planted_leak`, with the exit code still 0.
  - PR #31 on CI (`rapx` run 43113130790, `ubuntu-26.04`, Z3 from apt): green in 2 min 51 s, the install 102 s (uncached), `check` 27 s, `opt` 2 s; the same 15 warnings and 3 hints as locally, with both sections in the summary. A throwaway docs-only PR (#32, closed) started no `rapx` run.
  - `workflow_dispatch` on `main` after the merge (run 43115119048): green in 2 min 7 s, the install 76 s, `check` 20 s, `opt` 1 s.
  - Install: building RAPx from source against a Z3 that Homebrew later upgraded left `cargo-rapx` unable to start (`Library not loaded: libz3.5.3.dylib`); `cargo install --force` with the recipe's variables repairs it.
- **Revisit when:** a nightly bump breaks RAPx twice in a row (then drop the PR trigger and keep the weekly run), a PR run passes 15 minutes, or RAPx finds a real leak (then fail the job on a finding).


## D94: The e2e cluster has two reflectors behind an Envoy, an upstream registry, and a dual-stack pass on every leg (amends D63; amended by D112, D113, D130, D159)

- **Decision:**
  - **Reflectors:** the agents of the control plane and of the first worker run `role = "reflector"` (D2 puts reflectors on control-plane nodes; kind's second control plane would add an etcd member and kind's own balancer for nothing the peer suites test). Both are in every agent's `reflector.members`, by node name and kind-network address, port 7483; the second worker is the client no reflector runs on.
  - **Balancer:** `just e2e-up` starts `<cluster>-lb` on kind's network: Envoy at the release kind v0.33.0 runs in front of its API servers (`pkg/cluster/internal/loadbalancer/const.go:20`, a tag there, a digest in the justfile), with a static config that passes TCP through on 7483 to both reflectors' `reflector.listen`, round robin, with a TCP health check every second. Every agent's `reflector.url` is `https://<balancer address>:7483`. To stop a backend, `e2e::balancer::Balancer::stop` rejects the balancer's connections to port 7483 on that node with a TCP reset, until its guard drops; the health check fails and the balancer moves on. The agent stays up, so the same helper serves "a reflector is gone for discovery" and an outage of the agent itself (`Cluster::stop_agent`) stays a separate case.
  - **Upstream:** `just e2e-up` starts `<cluster>-upstream.e2e.test`, D88's registry image on port 80, and points every node's runtime at it over plain HTTP before `speculaire configure`. `e2e::upstream::Upstream::push` creates an image of one random layer, so no node holds its blobs; `requests` parses the access log into (method, path, status), and `blob_gets` counts the `GET`s of each blob of an image.
  - **Node helpers** (`e2e::node`): stop, start, kill and reset (empty journal, restart) an agent; a `tc netem` qdisc on the node's `eth0` until its guard drops; corrupt the file a node serves a blob from (containerd's content store, the agent's blob cache on CRI-O); read a node's metrics.
  - **Dual stack:** `SPECULAIRE_E2E_IP_FAMILY=dual` makes `just e2e-up` write `networking.ipFamily: dual` and name the cluster `<cluster>-dual`; the balancer, `reflector.url` and `reflector.members` then use IPv6 addresses. The Kubernetes argument stays last, and the variable selects the family for `e2e-test` and `e2e-down` too.
  - **Legs:** each of the 14 legs runs the suites twice, IPv4 then dual stack, netem included. `e2e-down` with arguments removes only its cluster's containers, by the label `speculaire-e2e.cluster=<cluster>`.
- **Because:**
  - Step 00 of M3 asks for a cluster where peers are testable: nodes that pull from each other, two reflectors behind an L4 balancer as D2 deploys them, and an upstream whose access log tells which blobs did not come from a peer.
  - Rejecting at the node rather than rewriting Envoy's endpoints keeps one generator of Envoy's config, the recipe.
  - A fresh random image is the only one no node can hold: containerd shares content by digest across images, and CRI-O reuses layers.
  - **Measured:** on Docker Desktop arm64, `just e2e-up` brings up both runtimes in both families, and the suites pass on containerd 2.4 (IPv4 and dual) and CRI-O 1.36 (IPv4) and 1.37 (dual); a pull of a new image through the mirror `GET`s each of its blobs once from the upstream; a 300 ms netem delay raises the TCP connect time from a node to the kubelet of another to 0.3 s. In CI (run 43424016737), the 14 legs passed both passes, netem included on `ubuntu-26.04` and `ubuntu-26.04-arm`; containerd legs took 2.8 to 3.2 minutes and CRI-O legs 5.5 to 6.3, against 1.5 to 2.1 and 3.3 to 3.5 before (run 43408250321).
  - On the runners, `systemd-socket-activate --inetd` closed its connections before the child's output arrived, so the stand-in listener is a Perl one-liner.
- **Cost:**
  - Every leg runs the suites twice: containerd legs take about 1.5 times as long and CRI-O legs 1.8 times, still under a quarter of D63's 30-minute timeout.
  - `tc netem` needs `sch_netem` in the host's kernel: Docker Desktop's and the runners' have it.
  - Until step 02 of M3 the reflectors listen on nothing, so `tests/harness.rs` puts a stand-in listener on port 7483 to check the balancer.
- **Revisit when:** a leg passes 20 minutes (then the dual-stack pass and the slowest peer suites move to a nightly workflow), or kind's balancer image changes.


## D106: The bench's kind tier runs speculaire without gate or policy, with the e2e cluster's reflectors (amends D35; amended by D114)

- **Decision:**
  - **Image sets:** `just bench <kubeconfig> [<set>...]` runs the tool's `measure` once per set, each set being `<size>-<layers>`, 10 MB and 100 MB in 1 and 4 layers by default. `suite` always adds the 1 GB sets.
  - **speculaire's settings,** until the gate (M5) and the policy (M6) exist: `packaging/config.toml`'s defaults, with `role = "reflector"` on every node labelled `node-role.kubernetes.io/control-plane`, those nodes in `reflector.members` by `InternalIP` and port 7483, and `reflector.url` on the first of them. The run has no `gate.mode`, no policy and no `speculaire_gate_seconds`, so it prices the mirror and the peers only. The real-cluster tier puts `reflector.url` on its balancer (D2).
  - **Agent cost:** CPU time per set is the growth of the cgroup's `usage_usec` across the set; peak memory is `memory.peak` at the end of the run, page cache charged to the cgroup included. Both report the node with the most.
  - **Node pod:** Debian slim, pinned by digest: busybox's `nsenter` has no `-a`.
  - **Workflow `bench`:** nightly at 03:00 UTC and on dispatch, `just e2e-up containerd 2.4` on the newest Kubernetes, then `just bench` on it, on `ubuntu-26.04` and `ubuntu-26.04-arm`, 60 minutes each. The tables go to the job summary and `target/bench` to an artifact. The arm64 runner registers QEMU for amd64 first: the bench images are amd64 only. Dispatch runs the kind tier until the real-cluster tier has a cluster.
  - **Pins:** `spegel-org/benchmark`, Spegel's chart, Helm and the node pod's image, in the justfile, tracked by Renovate.
- **Because:**
  - Step 08 of M3 asks for the kind tier now; the gate and the policy arrive in M5 and M6.
  - On kind, the 1 GB sets would take most of the budget for numbers one host cannot make real.
  - The e2e cluster's balancer exists only in kind (D94); the first reflector serves `Members` as well.
  - **Measured:** the first run (43702879308, Kubernetes 1.37.0, containerd 2.4.2, Spegel v0.8.1) took 12 minutes on each runner, `just musl` 5.5 and `just bench` 5. Two workers pull, so p50 is the faster pull and p95 the slower. p50 pull seconds, no mirror / Spegel / speculaire:

    | Set | Phase | amd64 | arm64 |
    |---|---|---|---|
    | 10MB-1 | create | 1.07 / 0.93 / 0.81 | 1.21 / 1.90 / 1.09 |
    | 10MB-1 | update | 0.75 / 0.11 / 0.28 | 0.87 / 0.10 / 0.34 |
    | 10MB-4 | create | 0.99 / 1.06 / 1.05 | 1.10 / 1.17 / 0.97 |
    | 10MB-4 | update | 0.85 / 0.11 / 0.41 | 0.93 / 0.11 / 0.95 |
    | 100MB-1 | create | 3.73 / 3.72 / 1.85 | 3.88 / 3.89 / 2.00 |
    | 100MB-1 | update | 2.56 / 0.80 / 1.16 | 1.52 / 0.67 / 1.10 |
    | 100MB-4 | create | 2.13 / 2.62 / 1.85 | 2.42 / 2.37 / 1.83 |
    | 100MB-4 | update | 1.40 / 0.98 / 1.00 | 1.36 / 0.62 / 1.11 |

    An update rolls one worker at a time, so its p50 is the second worker's pull from the first: speculaire's takes up to 0.8 s more than Spegel's. Per set, speculaire used 0.03 to 0.30 CPU seconds against Spegel's 0.08 to 0.20, and peaked at 233 MiB on amd64 and 215 on arm64 against 31 and 33. On Docker Desktop arm64, `just bench` writes the same tables in 9 minutes.
- **Cost:** 25 runner-minutes a night, and the kind tier's numbers carry no release bar.
- **Revisit when:** the gate and the policy exist (then D35's third run applies in full), or a run passes 45 minutes.


## D107: Hot paths borrow, reuse and keep fixed sizes on the stack; each change shows its saving (amends D13)

- **Decision:** code on a per-request, per-blob, per-frame or per-agent path follows these rules, in this order:
  - **Borrow:** parse into types that borrow the input (`&str`, `&[u8]`) and convert to owned data once, where it must outlive the input. Share a buffer that outlives one owner as `bytes::Bytes`, sliced, never copied.
  - **Reuse:** a loop that fills a buffer allocates it once and `clear()`s it each turn. A reader keeps one read buffer for its connection.
  - **Stack:** a value of fixed size lives on the stack: a digest is `[u8; 32]`, a frame header is an array. A small collection with a known bound uses an array or `arrayvec`; `smallvec` only where a measure shows most values fit inline.
  - **Fixed layouts:** a binary header of fixed layout (the D105 frame length, NRI's ttrpc header) is read and written through `zerocopy` types (`FromBytes`, `IntoBytes`, `big_endian::U32`), not by hand-shifted bytes. `unsafe_code` stays `deny`: `zerocopy`'s derives are the only way to such layouts.
  - Cold paths (startup, config reload, errors) stay plain: owned `String`s and `Vec`s where they read better.
- **Because:** the reflector's memory was its connections' buffers (D104, D105: 49 KB per connection under gRPC, 9 KB with our framing), and pulls through speculaire trail Spegel's by up to 0.8 s (D106). Allocations and copies on hot paths cost both, and the allocator's secure mode (D46) makes each allocation dearer.
- **Proof:** a change made for speed or memory names its measure in the commit body: `just bench-micro`, a DHAT profile from `just valgrind`, `just load`, or `just bench`. A change that only removes an allocation or a copy, keeping the code as clear, needs no measure.
- **Cost:** lifetimes in parsed types, and `zerocopy` (a Google crate with no runtime dependencies) to vet (D71).
- **Revisit when:** a lifetime spreads through more than one crate's public API, which then takes owned or `Bytes` data instead.

## D109: Catalog rows of metrics not built yet name their milestone (amends D34)

- **Decision:**
  - A row of `docs/metrics.md` whose metric no code emits yet gets a `Planned` cell naming the milestone that builds it (`M4`, …). The change that builds the metric removes the cell.
  - `crates/agent/src/telemetry.rs` has a unit test that runs every `describe` function of the agent, the mirror and the reflector under a recording `metrics::Recorder`, and fails unless the names described are the rows without a `Planned` cell.
  - The tests of `/metrics` (`apps/speculaire/tests/agent.rs`, `e2e/tests/unit.rs`) keep failing on a metric missing from the catalog.
- **Because:**
  - D34's test of a listed metric never emitted cannot pass while the catalog holds 11 metrics of M4 to M6, and the catalog is where their labels are agreed before the code.
  - One agent's `/metrics` never holds every metric: the reflector's only on its role, the relay's only on CRI-O, a labelled counter only once counted, and histograms only in protobuf. Every metric is described once in code, so the described names are the complete list, in a test of milliseconds with no runtime.
- **Cost:** a metric described but never set passes. A metric set but not described is caught by the tests of `/metrics` only when they emit it.
- **Revisit when:** a metric is set without its `describe`, or the catalog is generated from the code.

## D112: The e2e cluster has four upstreams and a signed test image; the proxy throttles and a node can lose an upstream (amends D94; amended by D120, D141, D164)

- **Decision:**
  - **Start:** after `kind create cluster`, `just e2e-up` runs `cargo run -p e2e --bin upstreams` (`e2e::upstream::start`). It starts the upstreams, pushes the test images to each, writes each node's runtime config for them and restarts the runtime, before the agents are installed. Each upstream is `<cluster>-<role>.e2e.test` (`e2e::upstream::Kind`), and `e2e-down` removes it by the cluster's label:
    - **`upstream`:** D94's, `registry:3` on plain HTTP, which the runtime config names.
    - **`referrers`:** zot (`zot-minimal` v2.1.23) on plain HTTP, port 80, which the runtime config names: the referrers API.
    - **`private`:** `registry:2.8.3` on TLS behind `docker_auth` 1.14.0 at `<cluster>-token.e2e.test:5001`, M2's private registry (D88). Its CA and the login are only in the runtime config: on containerd, `registry.configs."<host>".auth` in `config.toml` and `ca` in the host's `hosts.toml`; on CRI-O, an entry in `registries.conf.d`, `/etc/containers/certs.d/<host>/ca.crt`, and `/etc/crio/e2e-auth.json`, which a drop-in names as `global_auth_file`.
    - **`public`:** `registry:3` on TLS, its CA in each node's system trust store, with no `hosts.toml` and no `registries.conf` entry.
  - **Test images:** `e2e/signed:1` and `e2e/unsigned:1` are the suites' busybox (`e2e::TEST_IMAGE`) for the node's platform, each with its own annotation, so its own digest. They are built once per cluster in zot: `cosign` v3.1.3, in its container with a key pair made for the run, signs and attests `e2e/signed:1` offline (`--key`, `--tlog-upload=false`, `--use-signing-config=false`). It writes a signature, a SLSA provenance (`e2e/fixtures/slsa.json`) and an SPDX document (`e2e/fixtures/spdx.json`) as Sigstore bundle referrers, then a legacy signature and SLSA attestation (`--new-bundle-format=false`) under the `.sig` and `.att` tags. `regctl image copy --referrers --digest-tags` copies both images to the three others, which list the referrers under the fallback tag `sha256-<hex>`. Each node holds the public key at `/etc/speculaire-e2e/cosign.pub`.
  - **Access logs:** `Request` holds the user agent, from registry's combined format and from zot's JSON entries.
  - **Proxy:** `Proxy::throttle(pattern, retry_after, times)` answers `429` with `Retry-After` to the next `times` requests whose path matches, or to all with `None`, until `unthrottle`. The proxy logs every request in the combined format, which `Proxy::requests` reads.
  - **Reject:** `Cluster::reject(node, host)` resets the node's TCP connections to every address of the host's container, with `iptables` and `ip6tables`, until its guard drops, as `Balancer::stop` does.
  - The relay suite writes its logins to CRI-O's `global_auth_file` and restores it after.
- **Because:**
  - Step 00 of M4 asks for the upstreams the verification suites pull from: one with the referrers API, one without (registry:2 and :3 answer `404` there, so clients fall back to the tag), one with a login and a CA only the runtime knows, and one the runtime config does not name.
  - zot implements the referrers API of distribution spec 1.1, ships as one static binary in a multi-arch image, and logs each request with its user agent.
  - Signing in zot puts the referrers where the API lists them; `regctl` then writes the fallback tag as a client must for a registry without the API.
  - The cluster reaches nothing beyond kind's network, and cosign v3 fetches the public-good signing config through TUF by default (`cmd/cosign/cli/options/sign.go:164`, `attest.go:132` at v3.1.3).
  - Rust rather than bash: the harness's `Certificates` and `TokenServer` already make the private registry, and a failure names the command that failed.
  - **Measured:** on Docker Desktop arm64, `e2e/tests/upstreams.rs` and every other suite pass on containerd 2.4 and CRI-O 1.37. A node pulls both images from each upstream with its own config only. zot lists the three referrers; registry:2 and registry:3 answer `404` there and list the same three under the fallback tag; all four serve the `.sig` and `.att` tags. The proxy answers `429` with `Retry-After` and logs the client's user agent. A rejected upstream fails at once from its node and answers the others. Building and copying the test images took 9.7 to 16.4 s, and 64.8 s while other builds shared the machine. In CI, an e2e leg (both passes) took 9.0 to 10.9 min, from 8.2 to 9.5 min before (runs 43728506365 and 43717787646).
- **Cost:** two more images from ghcr.io, and 10 to 20 s for the test images, in each `just e2e-up`.
- **Revisit when:** registry:3 gains the referrers API, or cosign drops the legacy `.sig` and `.att` formats.

## D113: Pull requests run the newest containerd and CRI-O legs; main runs all 14 (amends D63, D94)

- **Decision:**
  - On a pull request, `ci.yml`'s `e2e` runs 4 of D63's 14 legs: containerd 2.4 and CRI-O 1.37, both on Kubernetes 1.37, on both architectures, each with both of D94's passes. A push to `main` runs all 14.
  - Every other leg carries `main-only: true`, and the matrix's `exclude` drops those legs on pull requests, so their jobs never start. Job names stay D63's, and `required` still needs `e2e` (D48).
  - When D63's matrix changes, the newest containerd and the newest CRI-O stay unmarked.
- **Because:**
  - With about 15 pull requests open at once, 14 legs each left pull requests waiting hours for runners. A leg takes 9 to 11 minutes (D112): about 140 runner-minutes per push at 14 legs, 40 at 4.
  - The newest pair runs every suite on both runtimes and both architectures. The other legs differ only in the runtime or Kubernetes minor, which few changes touch.
  - A job's `if` cannot read matrix values, and a skipped step still starts its job on a runner.
- **Cost:** a regression on an older runtime or Kubernetes minor shows on `main` after the merge. Whoever merges watches `main`'s run and fixes forward.
- **Revisit when:** runners keep up with 14 legs per pull request, or `main` breaks on a `main-only` leg twice in a milestone.

## D114: The bench's peak memory is the cgroup's `anon`, page cache shown apart (amends D35, D106)

- **Decision:**
  - **Sampled:** during each set, `bench/node/usage.sh` reads `anon` and `file` from the agent's cgroup `memory.stat` every second, on every node. `memory.peak` is no longer read.
  - **Reported:** per set and node, the peak of each in `results.json` (`memory.anon`, `memory.file`); the table shows, per agent, the highest peak of each over the sets, on the node with the most.
  - **Release bar:** D35's peak memory is the peak of `anon`. `file` carries no bar.
- **Because:** `memory.peak` counts the page cache charged to the cgroup with the process's own memory, and the kernel reclaims page cache under pressure, `anon` only by swapping. In D106's first run speculaire peaked at 215 to 233 MiB against Spegel's 31 to 33, and nothing told the two apart.
- **Measured:** the first run (amd64, arm64) gave speculaire an `anon` peak of 115.5 and 121.5 MiB against Spegel's 21.3 and 23.3, and a `file` peak of 25.6 and 0.8 MiB. Page cache explains little of D106's 215 to 233 MiB: kernel memory, such as socket buffers, or peaks shorter than a second hold the rest.
- **Cost:** a one-second sample misses a peak shorter than a second, and a sampler per node runs through each set.
- **Revisit when:** the agent pins page cache the kernel cannot reclaim, such as by locking or mapping blobs.

## D116: Metrics and spans say where a pull spends its time; profiles run in a glibc image on frame pointers (amends D13, D34, D37, D57, D104)

- **Decision:**
  - **Metrics** (catalog in `docs/metrics.md`, D34):
    - `speculaire_mirror_first_byte_seconds` gets a `source` label: `local`, `peer` or `upstream` for where the bytes came from, `fall_through` for the `404`.
    - `speculaire_mirror_body_seconds{kind,source}`: from the request to the body's last byte, for a body sent to its end.
    - `speculaire_peer_fetch_seconds{result}`: one observation per attempt at one holder, with the results of `speculaire_peer_fetches_total`.
    - `speculaire_peer_upload_seconds`: one observation per blob body sent to a peer, from its request to its last byte.
    - `speculaire_reflector_resync_seconds`, on the reflector: per agent connection, from its accept to the commit of the agent's opening `Snapshot`: what a restarted reflector waits for each agent (D103, D104).
    - `speculaire_runtime_alive_tasks` and `speculaire_runtime_global_queue_depth`: gauges read from tokio's stable `RuntimeMetrics` at each scrape. They come from inside the process, where node-exporter cannot see; memory, CPU and file descriptors stay with node-exporter (D34).
    - Each handle is registered once, at start or at the first use of its label values, and kept: a hot path never looks a metric up by name (D107).
  - **Spans**, at `DEBUG` under `log.filter` (D37): one per mirror request (`kind`, `digest`, `source`, `result`), one per peer fetch attempt (the peer's address, the holder's rank), one per reflector connection (the node identity). A span records no header, token or credential.
  - **Span timings:** the setting `timings` of `[log]`, default `false`, reloaded live, logs each span's busy and idle time when it closes (`FmtSpan::CLOSE`). A JSON layer on stderr logs these closes, and no event, under either sink: `tracing-journald` has no span events, and systemd sends stderr to the journal too. A second reloadable `EnvFilter` holds `log.filter` for that layer.
  - **Profile image:** `build/Containerfile`'s `profile` stage, from the digest-pinned `rust:<channel>-slim-trixie` (glibc), holds perf, Valgrind, inferno and rustfilt. `just profile` and `just valgrind` build the release binaries with line tables in it and run them in a privileged container.
  - **`just profile <target>`:** perf samples each agent of the run at 999 Hz through its frame pointers, attached by pid so that the agent itself gets the run's `SIGTERM`. Each agent gets a folded stack file and an SVG flamegraph in `target/profile/<target>/`, next to the run's report. Targets: `load`, D33's load for 30 s; `peer`, 30 pulls of a 64 MiB blob.
  - **Peer pull:** `speculaire-loadgen peer` (`crates/load`) starts a reflector, a holder and a puller as `speculaire agent`s on fake containerds. Each node's containerd config puts `root` in its temporary directory, where the holder's blob is (D110); a test pulls twice. The puller's fake answers `Content/Info` with `NotFound`, so its mirror fetches from the holder. A client with the mirror's client certificate pulls the blob without `Range`, as containerd does, and the report gives the time to the first and the last byte.
  - **`just valgrind`** runs in the profile image as well, and adds DHAT on the agents of a peer pull (5 pulls of 16 MiB). The `deep` job runs it on the runner's Docker.
  - **Frame pointers:** every Linux build, release and musl binaries included, has `-C force-frame-pointers=yes` (`.cargo/config.toml`), so that perf and eBPF profilers walk a node's stacks without DWARF.
- **Because:**
  - Pulls through speculaire trail Spegel's by up to 0.8 s (D106), and the metrics could not say where: one first-byte histogram, without the source, the body or the peers' side.
  - A label per digest or peer would break D34's bound; a debug span carries them for one node, for the time of a diagnosis.
  - Tokio's queue and task counts exist only inside the process.
  - perf ships in Debian, attaches to a running pid, runs in Docker Desktop's VM, and its folded stacks need no browser; samply's profiles need the Firefox Profiler. Valgrind needs glibc's allocator (D46), and one image gives the laptop and the `deep` job the same Valgrind and protoc.
  - A frame-pointer walk costs perf no DWARF unwinding and works on the shipped binaries.
  - **Measured** (Docker Desktop, arm64, 10 CPUs, loopback): the peer pull's p50 to first byte / last byte is 3.2 / 4.1 ms for 1 MiB, 17.4 / 27.7 ms for 10 MiB and 100.8 / 188.1 ms for 64 MiB. The first byte waits for the whole blob to be fetched, hashed and staged (D102): about 1.5 ms per MiB, more than half of the pull. Under perf, a 64 MiB pull costs the puller 182 ms of CPU and the holder 64 ms. In the puller: SHA-256 18%, on the task that reads from the peer; TLS decryption 9% and encryption 9%; socket reads 8% and writes 6%; the blocking pool's writes to the staging file 12% and reads back from it 8%; `memcpy` 8%. In the holder: TLS encryption 25%, file reads 22%, socket writes 16%. On loopback the blob path costs milliseconds per 10 MB, so most of D106's gap at 10 MB, 0.17 to 0.24 s, lies outside it; the metrics above, on kind, are to find where.
  - **Measured** on kind with `just bench` (D106): Docker Desktop, arm64, 3 nodes, Kubernetes 1.37.0, containerd 2.4.2, Spegel v0.8.1, each agent's `/metrics` read before and after each set, 2 runs. The update's p50, one worker pulling what the other holds, is 0.55 to 0.59 s at 10 MB and 0.73 to 0.86 s at 100 MB through speculaire, 0.04 to 0.12 s and 0.20 to 0.30 s through Spegel. That pull reaches the mirror only by digest, and all of it from a peer. Its mirror took, per blob, 7 ms to the first byte and 10 ms to the last at 10 MB, 32 to 42 ms and 49 to 80 ms at 100 MB; 3 ms per manifest and 0.2 ms per lookup. The rest is containerd resolving the tag at the registry, as D6 has it: a `crictl pull` by tag of an image the node holds, without a mirror, takes 0.44 to 0.48 s against ghcr.io. Spegel resolves tags from its peers (`--resolve-tags`, on by default). So D6 makes most of D106's gap, about 0.45 s; the mirror's 0.03 to 0.16 s is the rest, and the first byte's wait for the whole blob (D102) half of that.
  - **Measured**, frame pointers, on the same host shared with other builds, without then with the flag, alternated: the arm64 musl binary grows 0.8% (10.57 to 10.66 MB). `just bench-micro`, 4 rounds each: the index lookup's median 1.7 to 4.2 µs without and 1.3 to 2.8 µs with, SHA-256 of 16 MiB at best 5.14 ms both. `just load --agents 2000 --measure-only`, 2 rounds each: peak RSS 181 and 181 MiB without, 182 and 185 MiB with; resync 16.8 and 9.0 s without, 12.0 and 10.8 s with; lookup p99 345 µs and 2.8 ms without, 205 µs and 2.8 ms with (the second round of each ran beside other builds). No difference stands out of the noise.
- **Cost:** profiles need a privileged container. The `deep` job's Valgrind build starts cold each run. Frame pointers cost one register and a push per call, below what the measures above can show; a release still checks its pulls against Spegel with `just bench` (D35).
- **Revisit when:** a diagnosis needs off-CPU time (perf's `--off-cpu`, or eBPF); or frame pointers cost more than 2% in `just load` or `just bench`.

## D118: `just dev` mounts the tree at its own path and builds it in its own directory of the volume (amends D57; amended by D125)

- **Decision:**
  - `just dev <recipe>` mounts the tree at its host path, and the git directory of a linked worktree at its own, and sets `CARGO_TARGET_DIR` to `/target<host path>` in `speculaire-dev-<arch>`. The registry volume stays shared.
  - `just musl`, `just conformance` and `just load` keep `/src` and `speculaire-musl-<arch>`: `.cargo/config.toml` remaps `/src` out of the release binary, which D57's reproducibility measure holds to.
- **Because:** every worktree was mounted at `/src` and built in `/target`. Cargo tracks a source by path and mtime, so a worktree run after another one reused artifacts of the other's sources: `just dev check` tested old code, and doctests failed with "can't find crate for `speculaire_*`".
- **Measured:** worktrees A (this change) and B (A plus a failing test) ran `just dev check` one after the other: B ran 573 tests and failed on its own, then A ran its 572 and passed, recompiling nothing: each built in its own directory of the volume, about 7 GB each.
- **Cost:** each worktree builds from scratch once, and its directory stays in the volume after the worktree is removed, until deleted (`docker run --rm -v speculaire-dev-<arch>:/target alpine rm -rf /target<path>`).
- **Revisit when:** parallel worktrees run `just musl`, which then reuse each other's artifacts the same way.

## D120: e2e pulls Docker Hub's images through mirror.gcr.io and the ECR Public Gallery (amends D63, D112; amended by D122)

- **Decision:**
  - **Order:** an image of Docker Hub comes from mirror.gcr.io, then, for an official image (`library/`), from `public.ecr.aws/docker`, then from Docker Hub, as spnngl/images' builds do (`.github/actions/bake-build/action.yml:80-90`).
  - **Host:** the harness pulls each image through `e2e::hub::pulled`, which tries the sources in that order and uses the first that serves it; `regctl image copy` from Docker Hub tries them the same way (`e2e::hub::from_first`). `just e2e-up` pulls `kindest/node`, the node images' `alpine` and Envoy through the `pull` binary of the same crate.
  - **Nodes:** each node image carries the mirrors in its runtime config: `/etc/containerd/certs.d/docker.io/hosts.toml` (`e2e/node/containerd/docker-hub.toml`) and `/etc/containers/registries.conf.d/10-docker-hub.conf`. `speculaire configure` puts the mirror before them (D66, D82), and the agent takes them as the registry's sources, in order (D78).
  - The references stay `docker.io/…@sha256:…`, which Renovate tracks.
- **Because:**
  - CI runners share Docker Hub's anonymous pull limit: legs failed on `429` from a node's pull of busybox (runs 43754605532, 43761469786).
  - Every image is pinned by digest, so each source serves the same bytes or none. mirror.gcr.io and `public.ecr.aws/docker` served busybox 1.37.0 under the same digest.
  - A login needs a secret that pull requests from forks do not get.
  - `public.ecr.aws/docker` mirrors the official images alone, under the path `docker/library/`: containerd reaches it with `override_path`.
- **Cost:** the e2e nodes' runtimes run with mirrors that a default node lacks, and the `configure` suite edits that file as the admin's. mirror.gcr.io caches popular images only; any other falls through to Docker Hub. The build image (`rust`), `golang`, `debian` and `binfmt` of the other recipes still come from Docker Hub.
- **Revisit when:** a mirror fails a leg, or Docker Hub lifts the limit for CI runners.

## D122: The justfile's recipes pull Docker Hub's images through D120's mirrors (amends D120)

- **Decision:**
  - `just hub-pull <image>` tries D120's sources in order and prints the reference it is there under. It replaces the e2e crate's `pull` binary, so no recipe builds Rust to pull an image.
  - `just image <stage>` builds `build`, `dev` and `profile` of `build/Containerfile`. It pulls the stage's base through `hub-pull` and passes it as the named build context of the `FROM` reference (`--build-context <reference>=docker-image://<pulled>`), as `just e2e-up` does for the node images' `alpine`.
  - `oracle-build` and `conformance` run `golang`, and the bench workflow runs `binfmt`, under the reference `hub-pull` prints. The bench pods' `debian` comes through the nodes' mirrors (D120).
  - The `FROM` lines and the justfile's variables keep `docker.io/…@sha256:…`, so Renovate's extraction is unchanged.
- **Because:**
  - CI's musl, conformance and oracle jobs, the mutants shards and the load, deep and bench workflows pull these images, under the same anonymous limit as e2e.
  - Each source serves the digest's bytes or none: two clean builds of the musl binary on the base pulled from mirror.gcr.io have the same SHA-256 (D57).
- **Cost:** `docker build` of `build/Containerfile` without `just image` still pulls its base from Docker Hub.
- **Revisit when:** D120 is revisited.

## D125: Off Linux, `just mutants` runs in the dev image and builds in the volume (amends D57, D74, D118)

- **Decision:**
  - Off Linux, `just mutants`, and so `just mutants-diff`, runs itself through `just dev`, and says so on stderr.
  - `just mutants` builds in `mutants/target` below `CARGO_TARGET_DIR` when set, else below `target/`: in `just dev`, the worktree's directory of `speculaire-dev-<arch>` (D118); on Linux and CI, `target/mutants/target` as before.
  - The dev image has cargo-mutants, at `mutants.yml`'s version under the same `depName` (D58).
- **Because:**
  - macOS compiles `#[cfg(target_os = "linux")]` code out, so no test there can catch its mutants: #161 merged with 3 of `crio/images.rs`'s inotify watch that CI's shards found missed (#172). Run by itself, a macOS author's pre-push `just mutants-diff` now tests what the shards test.
  - D57 kept recipes from re-running themselves in a container, which hides where they run; `just oracle` already does (D79), and the message names the place. A step that needs remembering is one a pre-push run skips.
  - On the bind mount, cargo misses the rlibs it just built: every mutant fails with `E0463 can't find crate`, and cargo-mutants counts it unviable and exits 0.
- **Measured** (Docker Desktop, arm64, from macOS):
  - `just mutants-diff` of a throwaway commit adding an untested Linux-only `wake()` to `crio/images.rs`: 7 mutants in 5 min 24 s, 4 missed, 2 caught, 1 unviable, exit 2. Built on the bind mount (`CARGO_TARGET_DIR` below the tree): 7 unviable, each `can't find crate for oci_spec`, exit 0.
  - `just mutants --file crates/runtime/src/crio/images.rs` on `main`: 15 mutants in 7 min 43 s, 9 caught, 6 unviable, none missed, exit 0.
- **Cost:** a run off Linux needs a container engine; mutants of code built only off Linux, such as `crio/images.rs`'s stand-in `watch`, go untested, as on CI. Each worktree's mutants build stays in its directory of the volume (D118).
- **Revisit when:** speculaire runs on an OS other than Linux, or a contributor builds without a container engine (D57).

## D130: The rate-limit suite runs in the IPv4 pass only (amends D63, D94; amended by D141, D159)

- **Decision:** `e2e/tests/limits.rs` returns at once in the dual-stack pass (D94): its test runs once per leg, in the IPv4 pass, on both runtimes. Every other suite runs in both passes.
- **Because:** the test waits out a 120 s `Retry-After`, and what it checks, a host paused and taken up again, does not depend on the address family. Twice per leg would add 2 min to each of the 14.
- **Measured (M4 step 02):** locally on Docker Desktop arm64 with kind, the suite's test took 130 s on containerd 2.4 and 138 s on CRI-O 1.37; both images' artifacts were in the store 120.6 s after the `429`. On PR #179's CI the test took 130 s in the IPv4 pass of each leg, and the legs 13.4 min (containerd 2.4, x86_64), 13.1 min (containerd 2.4, arm64) and 16.0 min (CRI-O 1.37, arm64).
- **Revisit when:** a leg nears its 20 min budget, then the suite goes nightly; or the pause depends on the address family.

## D140: The pinned nightly keeps the parallel frontend's default; RAPx gets its own nightly (amends D57, D76, D77)

- **Decision:**
  - `nightly` moves to `nightly-2026-11-17`, past `nightly-2026-11-14`, which turned rustc's parallel frontend on with 2 threads by default. No recipe sets `--jobs-frontend`: rustfmt, `-Z direct-minimal-versions`, cargo-careful and cargo-fuzz run with the default.
  - `rapx_nightly` pins RAPx's own nightly, `nightly-2026-10-26`, which moves with `rapx_rev`, by hand. `just rapx-install` and `just rapx` use it; nothing else does.
  - No nightly recipe for the local check loop: `cargo check` and `cargo clippy` stay on the pinned stable, everywhere.
  - Stable keeps the sequential frontend, and so the musl build and every binary we ship.
- **Because:**
  - More threads than 2 bought nothing measurable on this workspace; 8 slowed the fuzz build. Cargo already runs about as many crates as cores, so the frontend's threads only help the few crates compiled alone.
  - The edit-check loop takes about 1 s on stable already, on macOS and in `just dev`; the nightly saves at most 0.3 s of it, and nothing on clippy, the lint `just check` runs. A second toolchain in the loop adds a second build directory and a second set of lints.
  - RAPx's `rapx_rev` does not build on the new nightly (44 errors on rustc internals). Its release that does, 0.7.75 (RAPx `8ef7f386`), stops on a compiler panic on the workspace, `item_name: no name for DefPath { … Closure … }` from `rapx::def_ids::other_api::is_align_offset` (RAPx `77201d8e`), with 1 frontend thread too: a RAPx bug, not the parallel frontend's.
  - The rustc blog post of 2026-11-16 warns that a parallel frontend's diagnostics may come in a different order and its binaries may not be reproducible: D57's reproducible musl build stays on stable.
- **Measured** (Apple M5, 10 cores, cargo's default jobs, shared with other agents' builds, load average 20 to 85; medians in seconds, cold from an empty target directory, incremental after an edit of `crates/mirror` or `crates/agent`):
  - `cargo check --workspace --all-targets --all-features`: cold 30.8 on stable, 33.4 / 26.6 / 27.1 with 2 / 4 / 8 frontend threads; incremental 1.0 on stable, 1.1 / 0.95 / 1.2.
  - `cargo clippy`, same arguments: cold 27.8 on stable, 37.8 with 8 threads; incremental 1.0 and 1.55.
  - `cargo fuzz build` (24 targets, release): cold 134 on `nightly-2026-10-26`, 117 / 106 / 117 / 236 with 1 / 2 / 4 / 8 threads; incremental 48, then 89 / 52 / 58 / 69.
  - `cargo careful test --no-run`, the standard library rebuild included: cold 67 to 78 on `nightly-2026-10-26`, 62 to 64 / 64 to 67 / 61 to 67 with 2 / 4 / 8 threads; incremental 2.4 to 4.2 for all.
  - In `just dev` (Docker Desktop on the same Mac, 10 CPUs, 7.7 GiB): `cargo check` cold 67 on stable (59 to 76), 31 to 55 on the nightly with no trend from 1 to 8 threads; incremental 1.0 on stable, 0.6 to 0.8 on the nightly. `cargo clippy` incremental 1.1 on stable, 1.1 to 1.5 on the nightly.
  - rustfmt of `nightly-2026-11-17` leaves the workspace and `fuzz/` unchanged.
- **Revisit when:** the parallel frontend reaches stable (then use it for everything, after checking two clean musl builds still match), or a RAPx release builds and runs on the pinned nightly (then one nightly again).

## D141: The recorded Sigstore fixtures live in `fixtures/sigstore/`, for the crates' tests and e2e's upstreams (amends D112, D130; amended by D164)

- **Decision:**
  - **Place:** `fixtures/sigstore/`, at the top of the repository, holds D139's recording as its workflow uploaded it, byte for byte (`.gitattributes`: `-text`): one OCI layout per case under `layouts/`, `expected.json`, `trusted_root.json`, `tuf/` and the `key` case's `cosign.pub`. Its `README.md` names the run and how to record again. It stays under 2 MB. `typos` skips its JSON and its layouts.
  - **Not recorded:** `github-private-attestation.sigstore.json`, a bundle from GitHub's private Sigstore instance, is sigstore-rust's at `sigstore-verify-v0.16.0` (Apache-2.0, `NOTICE`). The negative cases are built by code, from the recordings: `Fixture::signature_of` (a case whose only artifact is another case's `.sig`) and `Fixture::flipped` (one byte of a bundle's DSSE signature changed, with the referrer manifest that names it).
  - **Crates' tests:** `speculaire-artifacts` has a `testing` feature. `testing::Layout` reads a case's layout and computes what discovery records of it (`Layout::artifacts`); `testing::Fixture::load` keeps that in a store of its own, in a temporary directory: the root if an index, each artifact's manifest and blobs, the record. A unit test serves every layout to discovery, with the referrers API and without, and checks it records what `Fixture::load` holds.
  - **e2e:** `just e2e-up` copies each layout with `regctl image copy --referrers --digest-tags` from `ocidir://` to zot and to the plain upstream, as `e2e/fixtures:<case>` (`e2e::upstream::FIXTURES`): zot answers its referrers API, `registry:3` serves the recorded fallback tags and `.sig` tags. Every node has the recorded trusted root at `/etc/speculaire/trusted_root.json` (`Cluster::pin`); `Cluster::policy` writes `/etc/speculaire/policy.yaml`. The e2e job installs protoc: through `speculaire-artifacts` the suites build the runtime client, which compiles its `.proto`.
  - **The verify suite:** `e2e/tests/verify.rs`, M5's suite, runs in the IPv4 pass only, as D130's does. Its first test pulls every case from zot, then from the plain upstream, and checks the worker records what `Layout::artifacts` computes and keeps every blob of it. On arm64 it skips the two BuildKit cases, image indexes of `linux/amd64` alone, which no arm64 node pulls; the unit test covers them.
- **Because:**
  - The crates' tests and e2e read the same recording, so it lives above both. The test harness signs with `--tlog-upload=false`, so its bundles cannot pass verification against a trusted root; the recordings can, offline, with their pinned root.
  - Built negative cases cost no new recording, and each new recording writes to the public Rekor log (D139).
  - The verification suites (M5) assert outcomes, so they run once per leg; the address family changes nothing they check.
- **Measured:** the fixtures are 154 files, 345 kB. Locally on Docker Desktop arm64 with kind, the harness's test images took 6.9 s without the fixtures and 7.9 s with them (containerd 2.4); the verify suite's test, 11 cases each from zot then the plain upstream, took 18.8 s on containerd 2.4 and 7.2 s on CRI-O 1.37. The unit test takes 7.6 s on macOS.
- **Revisit when:** the fixtures near 2 MB; the recording's certificates or TUF metadata expire for a test that cannot pin its time; a multi-platform recording lets arm64 pull the BuildKit cases.


## D157: `release` builds one scratch image index, attests it and runs `speculaire verify` on it (amends D27, D28)

- **Decision:**
  - **Triggers:** a version tag `v*`, and `workflow_dispatch` from main. A dispatch pushes the tag `dispatch-<run id>`, with no GitHub release and no version tag; a version tag pushes `<version>`. Later milestones add the rest of D27's release list to the tag's run.
  - **Binaries:** `release` runs `just musl` on each architecture's runner, as ci's `musl` job does, and does not reuse `ci`.
  - **Image:** `packaging/Containerfile` copies the static binary into `scratch` and runs it as root (D27). One `docker buildx build` of both architectures pushes one OCI index of two images to `ghcr.io/spnngl/speculaire`. It has no `RUN`, so no emulator. BuildKit's own provenance and SBOM are off.
  - **Attestations:** on the index digest, `actions/attest-build-provenance` (`https://slsa.dev/provenance/v1`) and `actions/attest-sbom` with an SPDX SBOM that `syft` reads from both binaries' `cargo auditable` data. Both are pushed as referrers and logged in the public-good Rekor.
  - **Check:** the `verify` job runs `speculaire verify` on the index under `packaging/policy/release.yaml`. That policy requires a signature by `release.yml` at `refs/heads/main` or `refs/tags/v…`, the provenance and an SBOM. The job asks ghcr.io anonymously and fetches the public-good TUF root. The runner has no runtime, so it gives `--runtime containerd` and a containerd config without registry config, which sends ghcr.io's requests to ghcr.io (D17). This job replaces D28's e2e test.
- **Because:**
  - `ci` already gated each commit on main. Reusing it would add its e2e matrix to every dispatch.
  - One binary per architecture and no `RUN` give one index from one job, with no QEMU.
  - The `verify` job checks what a node pulls: the pushed index, anonymously, with the public trust root. An e2e test would check a local build under a pinned root instead.
  - **Measured** (locally, before the first run): `syft` lists 461 packages for the two binaries. `speculaire verify` in a container without a runtime, with this policy pointed at the fixtures' recorded provenance and `attest-sbom` cases, prints `allow`, with the provenance and SBOM checks passing.
- **Revisit when:** the tag's run gains packages, tarballs or the reproducible double build; GitHub's attestations leave the public-good Sigstore instance; a node needs an image that runs without root.

## D159: The e2e suites wait less, CRI-O's relay suite runs in the IPv4 pass only, and the suites build while the cluster comes up (amends D94, D130)

- **Decision:**
  - **Shorter waits:** the rate-limit suite's window is 45 s, not 120 s: still longer than discovery's first backoff step, 30 s (D128), so a pause that ignored `Retry-After` still shows. A test that waits for an agent to read a changed file sets that node's `config.poll_interval` to 1 s while it lives: the relay suite on CRI-O, the reflector's rotated certificate, the outage suite's late certificate. The corrupted-blob test of `fetch.rs` delays C by 300 ms, not 1 s; the relay's kill test throttles its proxy to 5 MB/s, not 2. Each still checks what it did.
  - **Passes:** on CRI-O the relay suite runs in the IPv4 pass alone, as D130's and D141's do. Every other suite runs in both passes.
  - **Bring-up:** `just e2e-up` builds the suites, `cargo test -p e2e --no-run`, in the background while it builds the node image and kind creates the cluster, and waits for that build before the upstreams start.
- **Because:**
  - PR #219's CRI-O legs took 17.7 min (arm64) and 21.3 min (x86_64), past D94's 20 min. Before moving suites to main or nightly (D94's revisit), the time went to fixed waits: the rate-limit window (2.2 min), the default 10 s poll (two per reflector rotation, one per relay login and late certificate), a 1 s netem delay on every packet of a TLS fetch, and the relay suite twice on CRI-O (2.4 min each pass against 15 s on containerd).
  - On CRI-O the relay suite turns peers off (`url = ""`), and the dual-stack pass changes only the balancer's and the reflectors' addresses (D94): its second run checks nothing the first did not.
  - The suites' build, about 50 s on a runner without a cache, needs nothing from the cluster.
- **Measured:**
  - In CI, the four PR legs (PR #219 then PR #227, minutes): CRI-O 1.37 x86_64 21.3 then 12.4, arm64 17.7 then 12.8; containerd 2.4 x86_64 16.6 then 11.2, arm64 15.6 then 12.4. On CRI-O x86_64 the IPv4 pass took 8.5 min and the dual-stack pass 3.6 (job 136183276120): relay 93 s, limits 55 s, fetch 34 s, outage 37 s, reflector 2 s.
  - Locally on Docker Desktop arm64 with kind, CRI-O 1.37, one test at a time, before then after: the corrupted-blob test 60 s then 21 to 24 s; the relay login test 21 s then 9 s; the relay kill test 19 s then 12 s; the rotated-certificate test about 18 s then 3 s; the late-certificate test 20.5 s then 10.4 s; each other relay test about 1 s less, as its end restarts the agent once, not twice.
- **Revisit when:** a PR leg passes 18 min again (then the dual-stack pass and the slowest peer suites move to main, D94), or the dual-stack pass gives the relay an IPv6 path (a node's upstream over IPv6).


## D162: `nri-runtime` is a session on `pkg/adaptation` and NRI's own stub, with a raw mode for the frames NRI never writes (amends D29, D70)

- **Decision:**
  - `nri-version` answers each `{runtime, version}` case with `{"nri_version": ...}` or `{"error": ...}` from `api.InferVersionFromRuntime`.
  - `nri-runtime` is one session per process. Each line on stdin is a command, an object whose only key names it, and gets one answer line: `start`, `state`, `stub`, `wait`, `create`, `close` and `report` drive `pkg/adaptation`; `raw`, `accept` and `oversize` drive the raw mode. `speculaire_oracle_harness::nri::Runtime`, from `Oracle::nri_runtime`, writes them; NRI's logs go to the test's stderr.
  - `start` runs `pkg/adaptation` with no pre-installed plugin, sets its registration and request timeouts, adds NRI's default validator when `required_plugins` names any, and can replace the NRI version `Configure` announces, with `""` as CRI-O 1.35 and 1.36 send (D64). `state` is what every plugin that connects next gets in `Synchronize`, which `pkg/adaptation` splits itself.
  - `report` names each connected plugin, its subscribed events and the `Synchronize` requests it got, counted through `pkg/adaptation`'s metrics hook without the oversized attempts that never left. `close` closes every plugin's connection, as a runtime that exits does: `Stop` leaves external plugins connected (`pkg/adaptation/plugin.go:387-403` at v0.12.3).
  - The oracle reads and writes `pkg/adaptation`'s unexported fields (`nriVersion`, `plugins`, a plugin's `mux`, `events`, `closed`) by reflection.
  - `stub` connects NRI's own `pkg/stub` plugin, run inside the oracle, which allows every container or rejects each with a given text.
  - The raw mode owns the socket and frames the mux itself. It delivers the plugin's frames on ConnID 1 to a ttrpc client of the plugin service, which `create` calls; it reads, counts and drops the frames of every other ConnID, so the plugin's calls to the runtime on ConnID 2 stall while the runtime's calls are answered. `oversize` writes one frame whose header says `maxPayloadSize + 1` and whose payload is that long.
- **Because:**
  - `pkg/adaptation` exports neither its plugins nor a way to set the announced version. Reflection checks the code containerd runs, as D79's linkname does, and a renamed field panics the oracle, which turns `just oracle` red.
  - `pkg/adaptation`'s mux splits every write at `maxPayloadSize` and reads every ConnID, so neither frame can come from it.
  - `pkg/stub` is the library NRI's sample plugins use: it is the reference the `nri` crate is compared with, and it tests the oracle without the crate. The samples are modules of their own, which the oracle cannot import.
- **Measured (M6 step 00, arm64):** the six NRI tests of `crates/oracle-harness/tests/oracle.rs` take 1.1 s in the dev image. 400 containers of 25 KiB each, 10 MiB, reach the stub in 3 `Synchronize` requests.
- **Revisit when:** `pkg/adaptation` exports its plugins or the announced version: drop the reflection.


## D164: The `runnable` fixture is busybox for amd64 and arm64, recordable alone, and the newest recording's root is pinned (amends D112, D139, D141)

- **Decision:**
  - **The case:** `runnable` is `docker.io/library/busybox:1.37.0`, the e2e test image (`e2e::TEST_IMAGE`), with a file of its own for its own digest, for `linux/amd64` and `linux/arm64`. `fixtures.yml` signs its image index keyless, as `buildkit-signed`'s, and its oracle row promises `signature` passes. It is the one fixture a pod runs and the gate allows on every node: `e2e::upstream::RUNNABLE`, allowed by `e2e::upstream::runnable_policy`, which reads the signer from `expected.json`. `e2e::upstream::SIGNED` stays for discovery tests: signed with no transparency log entry, it never verifies (D142).
  - **Recording one case:** `fixtures.yml` takes the input `cases`, `all` (the default) or `runnable`. With `runnable`, the run builds, signs, exports and checks that case alone, and its `expected.json` keeps the committed rows of the other cases. Its `trusted_root.json` and `tuf/` replace the committed ones: the newest recording's root is the one the tests and the nodes pin. `crates/verify`'s oracle test checks every case's every check against the pinned root, and `runnable` on both platforms.
  - **Times and hashes:** the tests read the TUF repository's expiry and its trusted root's target name from `tuf/`, not from constants, so a new snapshot needs no test change.
  - **Size:** `fixtures/sigstore/` stays under 6 MB (was 2 MB): busybox's layers are 2.2 MB on `linux/amd64` and 1.9 MB on `linux/arm64`.
- **Because:**
  - The gate's suites need an image that both verifies and runs. The `FROM scratch` cases have no command, and `SIGNED` has no Rekor entry.
  - Recording one case keeps every other case's digest, so the tests pinning them stay, and the run writes one Rekor entry, not about twenty (D139).
  - A newer root holds the older roots' keys while they verify: Sigstore keeps a retired key in the trusted root with its validity end.
  - busybox is already every node's test image (D112) and ships both platforms the e2e legs run; `COPY` onto it needs no emulator.
- **Measured (M6 step 04, run 44767333052, 2026-11-20):** `fixtures/sigstore/` holds 4.4 MB, `layouts/runnable/` 4.1 MB of it. The run's `trusted_root.json` and `tuf/` targets are byte for byte the committed ones; only `tuf/timestamp.json` changed (version 837 to 839).
- **Revisit when:** a newer trusted root no longer verifies an older case; the fixtures near 6 MB; a gate suite needs a runnable image with attestations.
