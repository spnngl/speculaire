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

## D13: Stack and binaries (amended by D34, D46, D57)

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

## D34: Metrics are a fixed catalog, with native histograms over protobuf (amends D13; amended by D50, D61)

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
  - The `protobuf` feature runs `prost-build` (`build.rs`), so the build image needs `protoc`. tonic's code generation needs it anyway.
- **Revisit when:** users run a backend without native-histogram support. Then add classic buckets per metric with `set_buckets_for_metric`, which works in both formats.

## D19: Dev loop is Docker plus CI (amended by D57)

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

## D27: CI and release copy dedens' conventions (amended by D48, D58, D59, D63, D71)

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
- **Because:**
  - these conventions are proven in a sibling Rust project by the same author, and keeping local runs equal to CI removes "works on my machine".
  - **Measured** (M0 spike 00, kind v0.33.0, Docker Desktop on arm64, containerd 2.3.7 and 2.4.2 on `kindest/node:v1.37.0`): a node image that replaces `/usr/local/bin/containerd`, `containerd-shim-runc-v2` and `ctr` with a release tarball, checked against its `sha256`, starts a 3-node cluster. The node ships containerd 2.3.4, NRI enabled with `/var/run/nri/nri.sock`, no `config_path` and `discard_unpacked_layers = true`, so the node image patches the last two (kind `containerdConfigPatches`). A kind node must match the host architecture. systemd 257 in the node runs a unit with every D53 setting (`systemd-analyze security` lists them all), and a static-PIE binary built in `rust:1.99.1-alpine` with dedens' `.cargo/` runs there. Registry config shows in `containerd config dump`, not in `crictl info`.
  - **Measured in CI** (M0 spike workflow, run 42925541544): the same harness, with spikes 01 and 04, passes on `ubuntu-26.04` and `ubuntu-26.04-arm` against containerd 2.3.7 and 2.4.2, with Docker 29.4.2, 4 CPUs and 15 GiB per runner, in 5 to 7 minutes per leg including the Rust build. Each leg pulls about 8 Docker Hub images anonymously without hitting a rate limit.
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

## D29: Go is a test oracle, never shipped (amended by D48, D70)

- **Decision:**
  - Production code is pure Rust.
  - `oracle/` is a separate Go module whose `go.mod` pins `containerd/containerd` at the newest supported 2.4.x, and `containerd/nri` at the version that containerd vendors. Renovate tracks both pins. Containerd 2.3's NRI behaviour stays covered by e2e. The module builds one test-only binary, `speculaire-oracle`, with these subcommands:
    - `nri-runtime`: a fake NRI runtime on `pkg/adaptation` (`adaptation.New(name, version, …)`, `adaptation.go:172`). It drives the `nri` crate through registration, `Configure`, a `Synchronize` split into several requests, and `CreateContainer`, with no containerd running.
    - `hosts`, `config`, `reference`, `platform` and `nri-version`: each reads cases as JSON lines on stdin and prints upstream's own result. The sources are, in order: `core/remotes/docker/config`, the config loader, `pkg/reference/docker`, `platforms`, and NRI's `api.InferVersionFromRuntime` (D9).
  - Differential tests feed the same cases to our Rust ports and to the oracle, and require identical output. The cases are containerd's own test cases, the e2e node configs and the fuzz corpus.
  - `just oracle` builds and runs the oracle inside a digest-pinned `golang:<version>-alpine` image, so no Go is needed on the host. In CI it is the `oracle` job of `ci`, a dependency of `required`.
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

## D48: The required CI job is `required`; `just check` is the check (amends D27, D29)

- **Decision:** the aggregate CI job that branch protection requires is named `required`. `just check` is called "the check". "Gate" means only the NRI gate (ARCHITECTURE.md § Vocabulary).
- **Because:** dedens calls both "the gate", which in speculaire is the component that admits containers. One word with two meanings breaks the vocabulary rule in `AGENTS.md`.
- **Revisit when:** —

## D50: The `upstream` label names only configured registry hosts (amends D34)

- **Decision:** a registry host with its own directory in the `hosts.toml` tree (D17) keeps its name as the `upstream` label value. Every other host is `upstream="other"`. Peer fetches leave the label empty.
- **Because:** pod authors choose registry hosts, so "a host from the registry config" was not bounded: a pod naming a new host would add series on every node. The `hosts.toml` tree is written by the admin.
- **Revisit when:** admins need per-host numbers for hosts without a `hosts.toml` directory; the audit log (D37) already names them.

## D57: One pinned toolchain, one build image, and `just dev` on macOS (amends D13, D19; amended by D58, D62)

- **Decision:**
  - `rust-toolchain.toml` pins stable `1.99.1` with clippy and rustfmt; the justfile pins one nightly, for rustfmt (`rustfmt.toml` uses unstable options) and `-Z` flags. `rust-version` is `1.95`, which `just msrv` checks.
  - `build/Containerfile` is the one build image, from the digest-pinned `rust:<channel>-alpine` whose tag is the pinned stable. Its `build` stage has lld, mimalloc's C toolchain, just, cargo-auditable and rust-audit-info; its `dev` stage adds the nightly rustfmt and the tools of `just check` and the dependency checks.
  - On macOS, `just dev <recipe>` runs any recipe in the `dev` stage; `just musl <target>` builds in the `build` stage. Named volumes keep the cargo registry and each architecture's target directory between runs. `SPECULAIRE_CONTAINER` picks the engine, default `docker`.
  - `crates/speculaire` is a binary crate only until a module needs a fuzz target or an integration test; then it gains `src/lib.rs`.
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


## D61: `speculaire_build_info` exists from startup, and every build has `protoc` (amends D34; amended by D68)

- **Decision:**
  - `speculaire_build_info` is set when the recorder is installed, with `containerd_version=""` and `nri_version=""`. NRI's `Configure` fills both (D9, M6).
  - `protoc` comes from Alpine's `protobuf-dev` in the build image, and from `taiki-e/install-action` at a Renovate-tracked release in the runner jobs of `ci` (D58).
  - `deny.toml` allows BSD-3-Clause (`matchit`, axum's router) and Zlib (`foldhash`, through `prost-build`).
- **Because:**
  - The version is the first thing to read when the gate never registers, and that is when `Configure` never came.
  - `metrics-exporter-prometheus` 0.18.3 `build.rs` runs `prost_build::compile_protos` when the `protobuf` feature is on, so every job that compiles the agent needs `protoc`.
- **Cost:** once `Configure` fills the versions, the series with empty labels stays exported; the recorder has no call that removes a series.
- **Revisit when:** M6 sets the versions: drop the empty series, or move the runtime versions to a series of their own.

## D62: Binaries live in `apps/`, libraries in `crates/` (amends D57)

- **Decision:**
  - `apps/<name>` holds each binary package: `apps/speculaire` (package `speculaire`, the shipped binary) and, later, `apps/loadgen`. A binary package parses arguments and calls libraries; it holds no other logic.
  - `crates/<name>` holds each library, as package `speculaire-<name>`: `crates/agent` is `speculaire-agent` today.
  - The binary's integration tests live in `apps/speculaire/tests/`, where Cargo builds the binary for them (`CARGO_BIN_EXE_speculaire`).
  - `e2e/` and `oracle/` stay at the top level.
- **Because:** the user asked for libraries and binaries apart. A library holds code a fuzz target, a test or another binary can reuse; a binary-only crate cannot be linked by them.

## D63: e2e covers containerd and CRI-O on the 3 newest Kubernetes minors kind ships (amends D27, D40, D59)

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

## D68: `speculaire_build_info` names the runtime (amends D61)

- **Decision:** `speculaire_build_info` has the labels `version`, `runtime`, `runtime_version` and `nri_version`. `runtime` and `runtime_version` are NRI `Configure`'s `runtime_name` and `runtime_version`: `containerd` or `cri-o`, and its release. All three runtime labels are empty until `Configure`, as D61 says.
- **Because:**
  - The agent runs under containerd or CRI-O (D64), and a `containerd_version` label would sit empty on every CRI-O node.
  - `Configure` names the runtime itself: containerd sends `containerd` (CRI-O spike 01), and CRI-O sends `cri-o` (v1.37.2 `internal/nri/nri.go:121`).
- **Revisit when:** D61's revisit, in M6.


## D70: The oracle lands with its pins and `version`; each subcommand lands with the port it checks (amends D29)

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
