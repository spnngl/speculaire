# The only entry point, for humans and CI (D27). Ported from dedens `justfile` at v0.1.0-131-gfd00747: its recipes, cut to
# speculaire's.

set shell := ["bash", "-euo", "pipefail", "-c"]

# The one pinned nightly: rustfmt (rustfmt.toml uses unstable options) and `-Z` flags. Stable is pinned in
# rust-toolchain.toml.
nightly := "nightly-2026-10-26"
# The container engine of `dev` and `musl`: `SPECULAIRE_CONTAINER=podman just dev check`.
container := env("SPECULAIRE_CONTAINER", "docker")

# List recipes.
default:
    @just --list

# Install the pinned stable (rust-toolchain.toml) and the pinned nightly's rustfmt.
toolchains:
    rustup toolchain install
    rustup toolchain install {{ nightly }} --profile minimal --component rustfmt

# The check of every change (D48): format, spelling, unused dependencies, lint, docs, tests.
check: (rustfmt "--check")
    taplo fmt --check
    typos
    cargo shear --locked --deny-warnings
    cargo clippy --workspace --all-targets --all-features --locked -- -D warnings
    RUSTDOCFLAGS="-D warnings" cargo doc --workspace --no-deps --document-private-items --locked
    cargo test --workspace --all-features --locked

# Format Rust (pinned nightly rustfmt) and TOML.
fmt: rustfmt
    taplo fmt

# `cargo fmt` of the workspace with the pinned nightly's rustfmt.
[private]
rustfmt *args:
    #!/usr/bin/env bash
    set -euo pipefail
    rustfmt="$(rustup which --toolchain {{ nightly }} rustfmt)"
    RUSTFMT="$rustfmt" cargo fmt --all {{ args }}

# Every feature combination of every crate builds (cargo-hack).
hack:
    cargo hack check --workspace --all-targets --feature-powerset --locked

# The workspace builds with its `rust-version` (cargo-hack installs that toolchain).
msrv:
    cargo hack check --workspace --all-targets --rust-version --locked

# The workspace builds with the lowest versions its manifests allow; Cargo.lock is restored afterwards.
minimal-versions:
    #!/usr/bin/env bash
    set -euo pipefail
    backup=$(mktemp)
    cp Cargo.lock "$backup"
    trap 'mv "$backup" Cargo.lock' EXIT
    rustup run {{ nightly }} cargo update -Z direct-minimal-versions
    cargo check --workspace --all-targets --all-features

# Advisories, licenses, duplicate crates and sources (cargo-deny, deny.toml), or the checks named: just deny advisories
deny *checks:
    cargo deny check {{ checks }}

# Run a recipe in the dev image (D57), as on macOS: just dev check. Volumes speculaire-registry and
# speculaire-dev-<arch> keep the registry and the build between runs.
dev *recipe:
    {{ container }} build --quiet --target dev --build-arg NIGHTLY={{ nightly }} -t localhost/speculaire-dev -f build/Containerfile build >/dev/null
    {{ container }} run --rm -v "$(pwd):/src" -v speculaire-registry:/usr/local/cargo/registry \
        -v "speculaire-dev-{{ arch() }}:/target" -e CARGO_TARGET_DIR=/target localhost/speculaire-dev just {{ recipe }}

# The static-PIE musl binary of this machine's architecture, with its dependency list embedded by cargo-auditable
# (D13, D46), in target/musl/<target>/speculaire: just musl aarch64-unknown-linux-musl. Volumes speculaire-registry
# and speculaire-musl-<arch> keep the registry and the build between runs.
musl target:
    #!/usr/bin/env bash
    set -euo pipefail
    if [[ "{{ target }}" != "{{ arch() }}-unknown-linux-musl" ]]; then
        echo "musl: a container runs the host's architecture: use {{ arch() }}-unknown-linux-musl" >&2
        exit 1
    fi
    {{ container }} build --quiet --target build -t localhost/speculaire-build -f build/Containerfile build >/dev/null
    mkdir -p "target/musl/{{ target }}"
    {{ container }} run --rm -v "$(pwd):/src:ro" -v "$(pwd)/target/musl/{{ target }}:/out" \
        -v speculaire-registry:/usr/local/cargo/registry -v "speculaire-musl-{{ arch() }}:/target" \
        -e CARGO_TARGET_DIR=/target localhost/speculaire-build \
        sh -c 'cargo auditable build --release --locked --target "$1" -p speculaire && cp "/target/$1/release/speculaire" /out/' \
        sh "{{ target }}"
