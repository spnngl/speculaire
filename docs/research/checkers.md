# Checkers and crates: what speculaire adopts, when

Sources, read 2026-11-11: `~/src/github.com/BurtonQin/Awesome-Rust-Checker/README.md` (updated 2026-08-21), blessed.rs (`~/src/github.com/nicoburns/blessed-rs/data/crates.json`, commit of 2026-10-27), and dedens at `v0.1.0-131-gfd00747` (`docs/research/ci-dedens.md` § 4 lists its checks with file:line). Every verdict is one of **adopt** (now), **trigger** (adopted when its named trigger lands; the milestone that lands it adds the check), **covered** (a tool already in place does the job) or **skip**.

The workspace denies `unsafe_code` and has no hand-written concurrent structure yet, so tools that look for memory errors or races find little today. They earn a place by being cheap to run outside `required`, or by arriving with their trigger.

## Testing and analysis tools

| Tool | Verdict | Why |
|---|---|---|
| cargo-mutants | adopt | The one tool that grades the tests themselves. dedens' shape: PR diff in up to 8 shards of 40, nextest, `--baseline=skip`, a stale-exclusion job (D142, D168 in dedens `docs/decisions/performance-and-safety.md`). The workspace lists 142 mutants (cargo-mutants 27.1.0, 2026-11-11), 19 of them in `e2e/src/lib.rs`. |
| cargo-nextest | adopt | cargo-mutants' test tool, as in dedens D103 (half the time of `cargo test` there). It runs no doctests: a mutant only a doctest catches shows as missed, the safe direction. |
| cargo-fuzz | covered | `fuzz/` and the nightly per-target matrix (`fuzz.yml`, dedens D141). |
| cargo-careful | adopt | Tests on a standard library with debug assertions, under AddressSanitizer on Linux, one job per package (dedens D144). D27 already lists the `deep` workflow for it. C dependencies (aws-lc-rs, mimalloc) are not instrumented. |
| RAPx | adopt | On each pull request and weekly, outside `required`: use-after-free, double free and leaks (`check -f -m`) and optimization hints (`opt`). Builds on rustc internals at a pinned commit and nightly (dedens `justfile:3-9`, `rapx.yml`). `Box::into_raw` and `mem::forget` are safe, so leaks are reachable without `unsafe`. dedens' last six runs took 3 to 5 minutes. |
| cargo-llvm-cov | adopt | Line coverage feeds the ruleset's `code_coverage` rule (minimum 80 %, drop at most 2). GitHub Code Quality reads line coverage only, from a Cobertura XML report (`cargo llvm-cov --cobertura`) uploaded by `actions/upload-code-coverage` (v1.4.4, `2b21a77928be8d5168c2b9581a67f2adbebacc52`) with `code-quality: write`, on pushes to `main` (the baseline) and on pull requests. The rule does not wait for the upload, so the uploading job must be a required check. Local run, 2026-11-11, macOS, workspace without `e2e`: 87.5 % of lines, 85.2 % of regions. |
| Miri | trigger: the first `unsafe` | Interprets tests for UB; FFI (aws-lc-rs) and tokio I/O stop it, so only pure modules would run. |
| loom | trigger: the first hand-written concurrent structure on `std::sync` | Exhaustive interleavings; does not model tokio. |
| Shuttle | trigger: the NRI mux per-connection queues (M6) or the reflector streams (M3) | Randomized scheduling that runs async code, where loom does not. |
| lockbud | trigger: the first `std::sync::Mutex` held across calls | Static double-lock and lock-order detection; a pinned nightly like RAPx. |
| Kani | trigger: the NRI mux frame decoder (M6) | A bounded wire decoder (8-byte header, D9) is what Kani proves well (dedens D145). D27 dropped it for lack of such a decoder. |
| clippy `disallowed-methods`, `disallowed-types` | adopt with the first rule | D37's rules (credentials in `SecretString`, headers never logged) fit `clippy.toml`; dylint only for a rule clippy cannot express. |
| cargo-semver-checks | skip | `publish = false`: no crate has a public API to keep. |
| cargo-audit | covered | cargo-deny reads the same RustSec database (dedens D141 rejected it). |
| cargo-udeps | covered | cargo-shear in `just check`. |
| cargo-auditable | covered | `just musl` (D57). |
| cargo-vet | adopt | Each dependency is audited by a trusted party or exempted, and a new crate needs one or the other, inside `required`. cargo-vet 0.10.3 on `main` (2026-11-11): `cargo vet init` exempts 164 crates; importing the mozilla, google, bytecode-alliance, zcash, isrg and embark-studios sets (`registry.toml` in the cargo-vet repository) then `cargo vet prune` leaves 27 fully audited, 2 partially, 135 exempted. `--locked` reads `imports.lock` and needs no network. `fuzz/` has its own `Cargo.lock`. |
| cargo-geiger, cargo-scan | skip | Report `unsafe` in dependencies without a decision to hang on the report. |
| MIRAI, Rudra, MirChecker, Yuga, redpen | skip | Unmaintained since 2024–2025 or pinned to old nightlies. |
| Prusti, Creusot, Verus, flux, Aeneas, hax | skip | Full verification: specifications cost more than the risk they remove here. |

## Crates from blessed.rs not yet in the workspace

Crates already in use (tokio, axum, hyper, http, tonic, prost, serde, toml, clap, anyhow, thiserror, tracing, regex) are left out.

| Crate | Verdict | Where |
|---|---|---|
| tempfile | trigger: M2 `configure` | `NamedTempFile::persist` is D55's temporary file then rename; also test directories. |
| insta | trigger: M2 `configure` | Snapshot tests of rewritten `hosts.toml` and `registries.conf.d` files, where an exact string assert would hide the diff. |
| arc-swap | trigger: the first component reading live keys (M2) | One way to hand reloaded live keys (D47) to the mirror and the gate; weigh it against `tokio::sync::watch`. |
| criterion or divan | trigger: the first measured hot path (M3, D35) | Micro-benchmarks of blob hashing (D7) and rendezvous hashing (D51). |
| dhat | trigger: the same | Heap-allocation counts in tests of a hot path. |
| release-plz, cargo-release | trigger: M5 release | Compare with dedens' release recipes, which D27 ports. |
| rustix | trigger: the first raw socket call | Peer credentials on the NRI socket, if a decision asks for them. |
| jiff | skip | humantime covers durations; no calendar arithmetic. |
| cross, cargo-zigbuild | skip | Native per-arch builds in the build image (D57). |
