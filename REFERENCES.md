# References

Upstream source is the source of truth. A path written `~/src/<host>/<owner>/<repo>/…` in these docs points to a local clone: make it with the `git_clone` tool, which places clones there. When a research note and upstream code disagree, the code wins: fix the note.

## Research notes

Notes with file:line citations into upstream code, taken at the versions below. Read the matching note before working in its area.

- [`docs/research/spegel.md`](docs/research/spegel.md): request flow, 404 *fall through*, `X-Spegel-Mirrored` loop guard, hedged race, `Range` resume, containerd event watch, flags, distro quirks, Spegel's bugs. **Read before** working on the mirror, the peer API or fetching.
- [`docs/research/rust-stack.md`](docs/research/rust-stack.md): io_uring evidence, libp2p vs reflectors, `containerd-client` RPCs, OCI and TLS crates, systemd and packaging, prior art (Kraken, Dragonfly, Nydus). **Read before** choosing a crate, writing the unit, or revisiting D1/D4.
- [`docs/research/sigstore-and-referrers.md`](docs/research/sigstore-and-referrers.md): sigstore-rs vs sigstore-rust matrix, cosign storage formats and media types, referrers API rules, offline cache contents, policy shapes. **Read before** working on artifact discovery, verification or the policy.
- [`docs/research/nri-and-verifiers.md`](docs/research/nri-and-verifiers.md): NRI hooks, reject semantics, image fields, timeouts and failure policy, wire protocol, bindir verifier contract, gate vs verifier comparison. **Read before** working on the `nri` crate or the gate, or revisiting D9/D10/D15.
- [`docs/research/ci-dedens.md`](docs/research/ci-dedens.md): dedens' justfile, workflows, release pipeline, and what to copy or change. **Read before** touching the justfile, `.github/` or packaging.
- [`docs/research/checkers.md`](docs/research/checkers.md): verdicts on testing and analysis tools (Awesome-Rust-Checker, dedens) and blessed.rs crates, each adopted now, at a named trigger, or skipped. **Read before** adding a check, a workflow, or a crate.

## Upstream

| Repo | Version read | Use for |
|---|---|---|
| `containerd/containerd` | v2.3.0, v2.4.x, main | CRI create path, registry config, `hosts.toml`, content store, NRI wiring |
| `containerd/nri` | v0.11.0 (CRI-O 1.35, 1.36), v0.12.0 (containerd 2.3), v0.12.2 (CRI-O 1.37), v0.12.3 (2.4), main | plugin protocol, `Container` fields, `default_validator` |
| `cri-o/cri-o` | v1.37.2, v1.36.7, v1.35.10 | NRI wiring and config (`internal/nri`, `internal/config/nri`), container create and its annotations (D64, D65), image store and pinning, `registries.conf` reload (D66); read the modules below under its `vendor/` |
| `go.podman.io/image/v5` | v5.40.0 (CRI-O v1.37.2) | `registries.conf` mirrors, `certs.d`, auth files, one source per image, `Range` resume (D66, D67) |
| `go.podman.io/storage` | v1.63.0 (CRI-O v1.37.2) | image ID, `images.json`, layers without compressed blobs (D65, D67); `pkg/configfile`, the search paths of `registries.conf` and `certs.d` (D80) |
| `kubernetes-sigs/kind` | v0.33.0 | node image, kubeadm config versions, the CRI-O node of the e2e harness (D63) |
| `opencontainers/distribution-spec` | main | mirror and peer API endpoints, referrers API, conformance tests |
| `opencontainers/image-spec` | main | manifests, indexes, `subject`, `artifactType` |
| `opencontainers/runtime-spec` | main | the OCI spec NRI adjusts |
| `sigstore/sigstore-rust` | crates 0.16 | verification and trust root (D8) |
| `metrics-rs/metrics` | `metrics-exporter-prometheus-v0.18.3` | recorder, native histograms and protobuf exposition (D34) |
| `sigstore/sigstore-rs` | main | comparison only (D8) |
| `sigstore/cosign` | main | signature and attestation storage formats |
| `sigstore/rekor` | main | transparency-log entry formats |
| `sigstore/docs` | main | policy and bundle concepts |
| `spegel-org/spegel` | main | the project we replace: behaviour to keep and bugs to avoid |
| `spegel-org/website` | main | Spegel's documented setup per distro |
| `spegel-org/benchmark` | v0.0.7 | the benchmark tool and images D35 runs; `README.md` for the method, but its CLI flags are stale: read the code |
| `spegel-org/benchmark-results` | main | Spegel's published results and their AKS setup (`tofu/`) |

## Sibling project and skills

- `~/src/github.com/spnngl/dedens`: the Rust project whose CI, release and doc layout D27 copies. When `docs/research/ci-dedens.md` and its files disagree, its files win.
- `~/src/github.com/spnngl/agent-skills/skills/rust/rs-coding/SKILL.md`: coding workflow and release build rules (musl, mimalloc, auditable). **Read before** writing Rust.
- `~/src/github.com/spnngl/agent-skills/skills/kernel/io-uring/SKILL.md`: io_uring hand-off, cancellation and security rules. **Read before** touching D4.
- `~/src/github.com/mattpocock/skills/skills/productivity/writing-for-agents/SKILL.md`: how to write `AGENTS.md`, `ARCHITECTURE.md`, `REFERENCES.md`, `docs/` and `plan/`. **Read before** editing any of them.
