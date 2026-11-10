# CI / release conventions of `spnngl/dedens`, for a new Rust project

Roots: `dedens/` = `/Users/ldelannoy/src/github.com/spnngl/dedens`. `shared/` = `/Users/ldelannoy/src/github.com/spnngl/.github`, the local clone of `spnngl/.github` at e2c9f9d, which holds the reusable workflows dedens calls at `@main`.
`Dnnn` = decision entries in `dedens/docs/decisions/*.md`.

## 1. Workflow inventory

| File | Trigger | Jobs | Runners | Gates | `just` recipes |
|---|---|---|---|---|---|
| `ci.yml` | push main, PR, `workflow_call` (`ci.yml:5-11`) | `check` (`:26`), `musl` (`:72`), `deps` matrix hack/msrv/minimal-versions/deny (`:101-105`), `coverage` (`:136`, `continue-on-error`), `gate` (`:169`) | `macos-26`, `ubuntu-26.04` (`:30`); `ubuntu-26.04` + `ubuntu-26.04-arm` (`:77-80`); `ubuntu-latest` for `gate` (`:172`) | **Only required check: `gate`** (`:167-185`, `.github/AGENTS.md:7-8`). Needs check, musl, deps, not coverage | `toolchains`, `check`, `musl <target>`, `musl <target> test … privileges::`, `hack`/`msrv`/`minimal-versions`/`deny`, `cov` |
| `release.yml` | tag `v[0-9]+.[0-9]+.[0-9]+`, `workflow_dispatch` with a `publish` input (`:7-16`) | `gate` (calls ci.yml, `:31-34`), `binaries`, `release`, `image`, `deb`, `deb-container`, `rpm`, `manifest` | amd64/arm64 pairs `ubuntu-26.04`/`ubuntu-26.04-arm` (`:43-46,127-130,180-185,220-225,254-257`); containers `ubuntu:26.04@sha256` (`:227`), `almalinux:10@sha256` (`:259`) | Publishing | `release`, `packages`, `image` |
| `lint.yml` | push main / PR on `.github/**` (`:5-14`) | `lint` → `shared/.github/workflows/lint-workflows.yml@main` (`:25`) | ubuntu-latest (`shared/.github/workflows/lint-workflows.yml:18`) | informational (not in ruleset) | — |
| `commit.yml` | PR opened/synchronize/reopened/edited (`:5-11`) | `check` → `conventional-commits.yml@main` (`:24`) | ubuntu-latest | informational (ruleset requires only `gate`) | — |
| `fuzz.yml` | cron `0 3 * * *` + dispatch (`:5-8`) | `targets` (lists `fuzz/fuzz_targets/*.rs` as JSON, `:20-32`), `fuzz` matrix per target (`:34-90`) | ubuntu-26.04 | outside the gate | `toolchains`, `fuzz <t> 300 $(nproc)`, `fuzz-cmin <t>` |
| `deep.yml` | every PR (`:9-10`) | `loom`, `scenarios`→`sim` (matrix per family), `sim-time`, `packages`→`careful` (matrix per crate) | ubuntu-26.04 | informational (`:1-7`) | `loom`, `sim 100 <family>`, `sim-time`, `careful address <pkg>` |
| `mutants.yml` | PR with path filter on `**/*.rs`, `Cargo.toml`, `Cargo.lock`, `.cargo/mutants.toml`, the workflow, `justfile` (`:5-14`) | `plan` (`:32`), `stale` (`:77`), `shard` matrix ≤8 (`:101`), `summary` (`:148`) | ubuntu-26.04 | informational (`:3-4`) | `mutants-diff origin/$BASE --list`, `mutants-stale`, `mutants --in-diff … --shard k/n --baseline=skip` |
| `kani.yml` | cron `0 6 * * 1` + dispatch (`:5-8`) | `kani` | ubuntu-26.04 | outside the gate | `kani-install`, `kani` |
| `rapx.yml` | cron `0 4 * * 1`, dispatch, PR on its own file (`:5-12`) | `rapx` | ubuntu-26.04 | outside the gate; findings go to the step summary | `rapx-install`, `rapx`, `rapx opt` |
| `codeql.yml` | cron `0 7 * * 1` + dispatch (`:5-8`) | `analyze`, `build-mode: none` (`:32-35`) | ubuntu-26.04 | outside the gate; Security tab (D146) | — (only `rustup toolchain install`) |
| `advisories.yml` | cron `0 5 * * *` + dispatch (`:5-8`) | `advisories` | ubuntu-26.04 | outside the gate | `deny advisories` (`:39`) |
| `betterleaks.yml` | PR + dispatch (`:4-6`) | → `shared/.github/workflows/betterleaks.yml@main` (`:19`) | ubuntu-latest | SARIF to code scanning | — |
| `renovate.yml` | push main / PR on `renovate.json5` or the workflow (`:4-14`) | → `shared/.github/workflows/renovate.yml@main` (`renovate-config-validator --strict` in a digest-pinned renovate image, `shared/.github/workflows/renovate.yml:26-41`) | ubuntu-latest | — | — |

`actionlint` knows the `ubuntu-26.04` and `ubuntu-26.04-arm` labels only through `dedens/.github/actionlint.yaml:1-5`.

## 2. Conventions

| Topic | Convention | Evidence |
|---|---|---|
| Action pinning | Third-party actions pinned by full SHA with a `# vX` comment. Own `spnngl/*` workflows at `@main` on purpose. | `dedens/.github/AGENTS.md:3`; e.g. `ci.yml:43`; `dedens/.github/zizmor.yml:6-10` (`"spnngl/*": ref-pin`); Renovate turns off digest pinning for `spnngl/.github` (`shared/renovate.default.json5:35-39`) |
| Container images | `tag@sha256:digest` everywhere: Containerfile base, nfpm, test containers, the actionlint image | `dedens/Containerfile:8`, `dedens/justfile:19`, `release.yml:227,259`, `shared/.github/workflows/lint-workflows.yml:27` |
| Tool versions | A `# renovate: datasource=… depName=…` comment above a `KEY: "x.y.z"` job-env line, then `taiki-e/install-action` with `tool@${{ env.X_VERSION }}` | `.github/AGENTS.md:3-5`; `ci.yml:36-41,58-60`; regex manager `shared/renovate.default.json5:7-20`; justfile/Containerfile managers `dedens/renovate.json5:5-30` |
| Renovate policy | `config:best-practices` + `:semanticCommits`; automerge of minor/patch/digest under `.github/**`, and of major Action bumps | `shared/renovate.default.json5:4,21-34` |
| Stable toolchain pin | Bumped by Renovate. `just` pinned to `1.59.0` via `extractions/setup-just` in every job | `dedens/rust-toolchain.toml:2-4`, `dedens/renovate.json5:6-13`, `ci.yml:46-49` |
| Permissions | `permissions: {}` at the top of every workflow; each job grants the minimum (`contents: read`; release adds `contents: write`, `id-token: write`, `attestations: write`, `packages: write`) | `ci.yml:18-19,33-34`; `release.yml:99-102,133-135,284-287` |
| Checkout | Always `persist-credentials: false` | e.g. `ci.yml:43-45` |
| Timeouts | Every job that runs steps has `timeout-minutes` | `.github/AGENTS.md:6`; e.g. `ci.yml:32` |
| Concurrency | `${{ github.workflow }}-${{ PR number \|\| sha }}`. Only PR runs are cancelled. Scheduled and release runs are never cancelled (`cancel-in-progress: false`) | `ci.yml:13-16`, `release.yml:18-21`, `fuzz.yml:10-13`, `.github/AGENTS.md:6-7` |
| Caching | `Swatinem/rust-cache@v2.9.3`, run after `just toolchains` because its key includes the rustc version. `workspaces:` set for fuzz/ and per-tool target dirs. `key:` per matrix leg. Fuzz corpora saved with `actions/cache` save/restore, one key per run. | `ci.yml:53-57`, `ci.yml:126-128`, `deep.yml:41-42,144-147`, `fuzz.yml:64-82`, `kani.yml:29-32` (caches `~/.cargo/bin`, keyed on `hashFiles('justfile')`) |
| Toolchain install | No toolchain action: `just toolchains` = `rustup toolchain install` (reads `rust-toolchain.toml`) plus the pinned nightly with `rustfmt,rust-src` | `dedens/justfile:27-29`; reason: `dedens/docs/decisions/performance-and-safety.md:39-40` (D141) |
| Nightly | One pinned `nightly := "nightly-2026-10-26"`, used for rustfmt's unstable options, `-Z` flags, fuzz, careful, RAPx. Called through `rustup which --toolchain`. | `dedens/justfile:3-6,48-54`, `dedens/rustfmt.toml:1-5`, `dedens/AGENTS.md:28-29` |
| `just` = single entry point | Every CI step that builds or tests calls a recipe. The `bash -euo pipefail` shell is set globally. Local == CI: "A change is done when `just check` passes". | `dedens/justfile:1`, `dedens/AGENTS.md:30`; `ci.yml:61` |
| `just check` contents | nightly `rustfmt --check`, `taplo fmt --check`, `typos`, `cargo shear --deny-warnings` (workspace + fuzz), `clippy --all-targets --all-features -D warnings`, `cargo doc` with `-D warnings`, `cargo test --workspace --all-features`, fuzz clippy, fuzz smoke tests | `dedens/justfile:32-41` |
| zizmor / actionlint | Run by the shared lint workflow (actionlint 1.7.12 by digest, zizmor 1.31.1). zizmor: `self-repository` disabled, `ref-pin` policy for `spnngl/*`. | `shared/.github/workflows/lint-workflows.yml:26-35`, `dedens/.github/zizmor.yml:3-10` |
| Script hygiene | `${{ }}` values passed through `env:`, never interpolated into `run:` (zizmor template injection); `shell: bash` where pipefail matters | `ci.yml:93-95`, `mutants.yml:52-56`, `rapx.yml:46-47` |
| Aggregate gate | A matrix job's name depends on its values, so a single `gate` job (`if: always()`, checks each `needs.*.result`) is the one ruleset check | `ci.yml:167-184` |
| Repo self-tests | `crates/dedens-repo/tests/repo.rs` asserts that the Containerfile's `rust:` tag equals the channel of `rust-toolchain.toml` | `dedens/crates/dedens-repo/tests/repo.rs:725,825`; `dedens/Containerfile:7` |
| Lints | `[workspace.lints]`: rust `missing_docs`, `unreachable_pub`, `unsafe_code = "deny"`; clippy `pedantic` plus a selection of restriction lints (`unwrap_used`, `panic`, `allow_attributes_without_reason` …) | `dedens/Cargo.toml:150-179`; `dedens/clippy.toml:1-5` (allow unwrap/expect/panic in tests) |
| Profiles | `release`: `lto = "fat"`, `codegen-units = 1`, `strip = true`, no `panic = "abort"` | `dedens/Cargo.toml:181-185` |
| Linker | lld on Linux through `.cargo/lld-cc` (`linker =`, not `rustflags`, so `RUSTFLAGS` cannot override it) | `dedens/.cargo/config.toml:1-31`, `dedens/.cargo/lld-cc:1-28`, D150 `dedens/docs/decisions/scope.md:31-48` |
| deny.toml | `unmaintained = "all"`, `yanked = "deny"`, license allow-list, `wildcards = "deny"`, `multiple-versions = "warn"`, unknown registry/git denied with an allow-list | `dedens/deny.toml:6-39` |

## 3. Release pipeline (`release.yml`, D153/D156/D158)

| Step | How | Evidence |
|---|---|---|
| Gate | `uses: ./.github/workflows/ci.yml` (full CI on the tagged commit) | `release.yml:31-34` |
| Tag check | Tag must equal `v` + the `Cargo.toml` version | `release.yml:60-66` |
| musl build | **Native runner per arch** (`ubuntu-26.04` x86_64, `ubuntu-26.04-arm` aarch64). No cross, no QEMU. Built inside `rust:1.99.1-alpine@sha256` (Containerfile `binaries` stage): `cargo auditable build --release --locked --target $(uname -m)-unknown-linux-musl`, then `dedensd validate` on the built binary. | `release.yml:37-47,67`; `dedens/Containerfile:8-29,43-44`; QEMU, cross and zigbuild were rejected: `scope.md:84,142` |
| Static PIE | x86_64 is static-pie by default. On aarch64, `lld-cc` rewrites `crt1.o`→`rcrt1.o` and `-no-pie`→`-static-pie`, with `relocation-model=pic`. Alpine's lld is used, because Rust's lld has no zlib. | `dedens/.cargo/lld-cc:5-28`, `dedens/.cargo/config.toml:17-31`, D151 `scope.md:61-84` |
| Reproducibility | `just release` builds twice with `--no-cache`, runs `diff -r`, and fails if a build path appears in a binary. `--remap-path-prefix` handles `/src` and `/usr/local/cargo`. `SOURCE_DATE_EPOCH=0` (for mimalloc's `__DATE__`). The `.dockerignore` allow-list keeps the build context small. | `dedens/justfile:265-285`, `dedens/.cargo/config.toml:19-31`, `dedens/Containerfile:22`, `dedens/.dockerignore:1-12` |
| License notices | `cargo-about` generates `THIRD-PARTY-<bin>.txt` offline for the musl targets | `dedens/Containerfile:30-36`, `dedens/deploy/about.toml:1-17` |
| Packages | **nfpm** (`goreleaser/nfpm:v2.48.0@sha256` in docker) builds deb and rpm for each binary. `SOURCE_DATE_EPOCH` = commit time. The changelog is generated. Gzipped man pages. | `dedens/justfile:288-312`, `dedens/deploy/packages/dedensd.yaml:1-83` |
| systemd | The unit is shipped, never enabled. Hardening: `User=` from sysusers.d, `AmbientCapabilities=CAP_NET_BIND_SERVICE` only, `ProtectSystem=strict`, `SystemCallFilter=@system-service`, `SystemCallErrorNumber=EPERM`, `LimitNOFILE=524288`. Maintainer scripts use sysusers or fall back to useradd, and tolerate a missing systemd. | `dedens/deploy/packages/dedensd.service:1-50`, `dedensd.sysusers:1-2`, `dedensd.postinst:1-14`, `dedensd.prerm:1-11`, `dedensd.postrm:1-6` |
| Package lint | `lintian --fail-on error`; `rpmlint -c deploy/packages/rpmlint.toml`, with `no-signature` and `statically-linked-binary` filtered | `release.yml:70-75`, `dedens/deploy/packages/rpmlint.toml:1-9` |
| Tarball | `dedens-<tag>-<arch>-unknown-linux-musl.tar.gz`, made with `tar --sort=name --mtime=@0 --owner=0 --group=0 --numeric-owner \| gzip -n` | `release.yml:77-84` |
| Package tests | `deb`: installed on a real runner, `systemctl start`, functional query, checks the process uid and `CapEff`, then removed. `deb-container`: Ubuntu without systemd, `useradd` path, purge. `rpm`: AlmaLinux 10, `rpm --verify`. | `release.yml:174-210,214-245,248-275` |
| Image | Per-arch native `docker build` of the Containerfile's last stage: `FROM scratch`, CA bundle, passwd/group uid 10001, `USER 10001:10001`, OCI `source` and `licenses` labels. The job checks the user, `--version`, file ownership, and that the image's binary and notice are byte-equal to the archive's (`cmp`). It pushes `ghcr.io/<owner>/dedensd:<tag>-<arch>`. | `release.yml:121-170`, `dedens/Containerfile:46-61`, `dedens/justfile:320-321` |
| Manifest | `docker buildx imagetools create -t :<tag> :<tag>-x86_64 :<tag>-aarch64`, reads the digest, then `attest-build-provenance` with `push-to-registry: true` | `release.yml:278-305` |
| Checksums | `sha256sum -- * \| tee SHA256SUMS` over the merged `dist-*` artifacts | `release.yml:104-109` |
| Signing / provenance | **GitHub artifact attestations** (`actions/attest-build-provenance@v4.2.2`, SLSA build provenance signed through Sigstore with OIDC `id-token: write`) on `dist/*` and on the image digest. **No cosign key signing, no GPG** (rpmlint `no-signature` is filtered on purpose). | `release.yml:110-112,301-305`; `dedens/docs/decisions/scope.md:122-123,168-169` |
| SBOM | **None as a separate document.** The dependency list is embedded in each binary by `cargo-auditable` (readable with `cargo audit bin`), plus the license notices. No syft/cyclonedx, no `attest-sbom`, no buildx `--sbom`. | `dedens/Containerfile:1-2,13-15,26`; `scope.md:125-126` |
| Publish | `gh release create "$TAG" dist/* --verify-tag --generate-notes`, only when `PUBLISH` is true (tag push, or dispatch with `publish` on a tag) | `release.yml:27-28,113-117,281` |
| Ordering | Every package test passes before `image` pushes (`needs: [binaries, deb, deb-container, rpm]`). `release` needs `image` too. | `release.yml:96,119-122` |
| Manual first-release steps | Set the ghcr package public by hand; add a tag ruleset on `v*`; verify with `gh attestation verify` | `dedens/.github/AGENTS.md:11-14` |

## 4. Quality gates beyond tests

| Check | Where / when | Evidence |
|---|---|---|
| fmt (nightly rustfmt), taplo, typos, cargo-shear, clippy, rustdoc | **PR gate** (`just check`) | `justfile:32-41`, `ci.yml:57-61` |
| musl test suite on both arches + root-only tests | **PR gate** | `ci.yml:69-98`, `justfile:249-260` |
| cargo-hack `--feature-powerset` | **PR gate** (`deps`) | `justfile:57-58`, `ci.yml:105` |
| MSRV (`cargo hack --rust-version`, `rust-version = "1.95"`) | **PR gate** | `justfile:61-62`, `Cargo.toml:8` |
| minimal-versions (nightly `-Z direct-minimal-versions`, lock restored) | **PR gate** | `justfile:65-72` |
| cargo-deny (workspace + fuzz) | **PR gate**; `advisories` only, also daily | `justfile:75-77`, `advisories.yml:7,39` |
| coverage (cargo-llvm-cov) | PR, informational, `continue-on-error` | `ci.yml:134-165` |
| Fuzz smoke (stable replay of the seeds) | **PR gate** (`cargo test --manifest-path fuzz/Cargo.toml --lib`) | `justfile:41,433-434`; `fuzz/Cargo.toml` header comment |
| cargo-fuzz (libFuzzer, nightly) | **Nightly cron**, one job per target, 300 s with `-fork=$(nproc)`; `cmin` after (even after a crash); corpus in the Actions cache; crashes uploaded as artifacts. Explicit `--target $host` because a musl cargo-fuzz binary breaks ASan. | `fuzz.yml`, `justfile:338-364`, D141 `performance-and-safety.md:29-36` |
| fuzz layout | `fuzz/` is a separate workspace with its own `Cargo.lock`. 25 one-line shims in `fuzz/fuzz_targets/` over functions in `fuzz/src/*.rs`. `fuzz/dicts/<target>.dict`. Seeds come from `testdata/`. Corpus and artifacts are gitignored. | `fuzz/Cargo.toml:1-40`, `justfile:325,350-354`, `.gitignore` (`fuzz/corpus/`, `fuzz/artifacts/`) |
| cargo-mutants (on the PR diff, sharded ≤8 by 40, nextest, `--baseline=skip`) + stale-exclusion check | **PR, informational** | `mutants.yml`, `justfile:154-215`, `.cargo/mutants.toml:1-5`, D142/D168 `performance-and-safety.md:42-57` |
| cargo-careful + ASan, one job per crate | **PR, informational** (`deep.yml`) | `deep.yml:107-149`, `justfile:230-238`, D144 |
| loom | PR, informational | `deep.yml:26-43`, `justfile:219-224` |
| simulation (turmoil) 100 seeds, plus the time budget | PR, informational | `deep.yml:44-105` |
| Kani | **Weekly** | `kani.yml`, `justfile:503-510`, D145 |
| RAPx | **Weekly** (and PRs that touch `rapx.yml`) | `rapx.yml`, `justfile:480-500` |
| CodeQL (Rust, `build-mode: none`) | **Weekly** | `codeql.yml`, D146 |
| Secret scan (betterleaks, full history, SARIF) | PR | `betterleaks.yml`, `shared/.github/workflows/betterleaks.yml:30-66` |
| Miri | **Not present**: it is added only with the first `unsafe`, and the crate roots `forbid(unsafe_code)` | D15/D16 `performance-and-safety.md:11-16`, `performance-and-safety.md:171-173` |
| cargo-semver-checks | **Not present**: deferred to the first crates.io release (`publish = false`) | D16 `performance-and-safety.md:14-15`, `Cargo.toml:11` |
| Image vuln scan (Grype + Trivy) | Available as `shared/.github/workflows/image-scan.yml`, **not called by dedens** | `shared/.github/workflows/image-scan.yml:1-134` |

## 5. Commit conventions (`commit.yml` → `shared/.github/workflows/conventional-commits.yml`)

- The commit subject must match `^(feat|fix|docs|style|refactor|perf|test|build|ci|chore|revert)(\([^)]+\))?!?: [^ ]`. The type list is a `workflow_call` input (`shared/.github/workflows/conventional-commits.yml:13-16,47-52`).
- Commits come from `gh api …/pulls/N/commits` with no checkout. Merge commits (more than one parent) are skipped. The check refuses PRs over 250 commits (`:29-46,54-55`).
- Each offending commit gets an `::error title=Not a Conventional Commit::sha subject` annotation (`:58-70`).
- It runs on PR `edited` too (`dedens/.github/workflows/commit.yml:6-11`). The same rule is in `dedens/AGENTS.md:34-35`. Renovate uses `:semanticCommits` (`shared/renovate.default.json5:4`).

## 6. Recommendations for the containerd P2P mirror + NRI gate

### Copy as is

| Item | Notes |
|---|---|
| Top-level permissions, concurrency, SHA pins, renovate comments, timeouts, `persist-credentials: false` | All mechanical |
| `lint.yml`, `commit.yml`, `betterleaks.yml`, `renovate.yml`, `advisories.yml`, `codeql.yml` | Reusable callers of `spnngl/.github@main`, or copy the reusable bodies if the repo lives under another owner (`spegel-org`). The `ref-pin` policy and the Renovate `enabled: false` rule are owner-specific (`dedens/.github/zizmor.yml:8-11`, `shared/renovate.default.json5:35-39`). |
| `ci.yml` skeleton: `check` → `musl` (native amd64/arm64 in `rust:alpine`) → `deps` matrix → single `gate` job, reused by `release.yml` through `workflow_call` | Swap the root `privileges::` test for the new daemon's own privilege model (containerd socket and NRI socket access, not port 53) |
| `just` as the only entry point; `toolchains`, `check`, `musl`, `hack`, `msrv`, `minimal-versions`, `deny`, `cov`, `release`, `packages`, `image` | Keep `just check` == CI |
| `rust-toolchain.toml` pin + one pinned nightly; `rustfmt.toml`, `clippy.toml`, `taplo.toml`, `_typos.toml` shape, `deny.toml` policy, `[workspace.lints]`, `[profile.release]` | Recheck the license list against the containerd/OCI/gRPC/protobuf crates |
| `.cargo/config.toml` + `.cargo/lld-cc` (aarch64 static-pie hack, path remaps) | Needed for static-pie musl on aarch64 |
| Containerfile pattern: digest-pinned `rust:<channel>-alpine`, `cargo auditable`, `cargo about`, `binaries` stage, scratch image as uid 10001; `repo.rs`-style test that the tag equals the channel | A DaemonSet variant of the image may need host mounts and root (see open questions) |
| Release: double reproducible build, nfpm deb/rpm + systemd unit + sysusers + tolerant maintainer scripts, lintian/rpmlint, deterministic tar, `SHA256SUMS`, `attest-build-provenance` on files and image digest, per-arch push + `imagetools create` manifest, byte-compare of image vs archive, deb/rpm install tests | Near 1:1 copy. The unit needs `After=containerd.service`, the right socket access, and different capabilities. |
| fuzz.yml (per-target matrix, cached corpus, cmin), stable fuzz-smoke in `just check` | Targets: OCI manifest/index parsing, registry HTTP requests/headers/Range, `hosts.toml`/config parsing, P2P wire messages, NRI message decoding |
| mutants.yml (diff-sharded), deep.yml `careful` | Generic |

### Drop (DNS- or dedens-specific)

- `bench`, `bench-unbound`, `bench-dnsperf`, `profile` (DNS codecs, dnsperf) (`justfile:79-139`)
- `capture*`, `providers`, `odoh-*`, `blocklists`, `rfc-archive`, `root-hints`, `root-anchors` (`justfile:436-533`)
- `sim`/`sim-time` with the D133 budgets and turmoil (`deep.yml:44-105`), unless a sim harness is adopted
- Kani on `dedens-proto` decoders (`kani.yml`), unless there is a small, bounded wire decoder to prove
- The io_uring-specific `--security-opt seccomp=unconfined` in `just musl` (`justfile:246,257`), if io_uring is not used
- The macOS `check` leg (`ci.yml:30`), if NRI/containerd code is Linux-only; keep it only for platform-independent crates
- loom, RAPx: add them only when there is hand-written concurrency or `unsafe` (D16)
- mimalloc secure allocator (D154), unless the same allocator evaluation is redone

### Add

| Need | Suggested shape |
|---|---|
| **kind e2e matrix** | New `e2e` job in `ci.yml`, listed in `required.needs` (D48). `matrix: {os: [ubuntu-26.04, ubuntu-26.04-arm], containerd: ["2.3.x", "2.4.x"]}`, `fail-fast: false`. It consumes the musl binary/image built in the same run (as `release.yml:144-161` does), so the shipped artifact is the tested one. Install kind and kubectl by pinned version with a `# renovate:` comment and checksum verification (the pattern of `shared/.github/actions/scan-image/action.yml:63-90`). `just e2e <containerd-version>` is the single entry point, runnable locally with Docker. |
| containerd version control in kind | `kindest/node` images bundle one containerd per k8s release. For 2.3 vs 2.4, build a node image per version (a Dockerfile layer replacing `/usr/local/bin/containerd*` on a digest-pinned `kindest/node`), with Renovate tracking `containerd/containerd` releases. Enable NRI and the mirror `config_path` in the node's containerd config. |
| e2e assertions | Pull through the mirror from node A, then node B fetches from A (P2P hit), with metrics or logs proving it. NRI gate: admitted vs blocked pod. Restart and upgrade of the daemon. |
| systemd e2e | Extend the `deb` job: install the deb on a runner with containerd and check the unit's hardening (`systemd-analyze security`), uid and caps, like `release.yml:196-210` |
| Image scan | Call `shared/.github/workflows/image-scan.yml` on a schedule for the ghcr image |
| SBOM (if required) | Not a dedens convention. Options: `syft` or `cargo cyclonedx` over the musl binary, plus `actions/attest-sbom`; or keep cargo-auditable only, as dedens does |
| Helm/k8s manifests | If a DaemonSet or chart ships: `kubeconform`/`helm lint` recipe in `just check` |

### Open questions

- ~~Is Docker preinstalled and is kind usable on `ubuntu-26.04-arm`?~~ Yes (M0 spike CI, run 42925541544, 2026-11-11): `ubuntu-26.04` and `ubuntu-26.04-arm` both ship Docker 29.4.2 with 4 CPUs and 15 GiB, and kind v0.33.0 runs the 3-node 2.3 and 2.4 clusters on both, for spikes 00, 01 and 04.
- ~~Does containerd 2.3/2.4 in a kind node need `[plugins."io.containerd.nri.v1.nri"]` enabled explicitly?~~ No (M0 spike 00, containerd 2.3.7 and 2.4.2 over `kindest/node:v1.37.0`): NRI is on by default and `/var/run/nri/nri.sock` exists. The node's containerd config does need two patches: `config_path = "/etc/containerd/certs.d"` under the CRI registry table, and `discard_unpacked_layers = false` (the node ships `true`, which D15's preflight rejects). `crictl info` no longer lists the registry config in 2.3.7; use `containerd config dump`.
- The DaemonSet image needs root/host mounts, which conflicts with dedens' `FROM scratch` + uid 10001 image. Ship one image or two?
- ~~Does the repo live under `spnngl` (reusable workflows at `@main`) or `spegel-org` (copy the reusable workflows)?~~ `spnngl`: the repository is `github.com/spnngl/speculaire` (public).
