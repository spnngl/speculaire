# The only entry point, for humans and CI (D27). Ported from dedens `justfile` at v0.1.0-131-gfd00747: its recipes, cut to
# speculaire's.

set shell := ["bash", "-euo", "pipefail", "-c"]

# The one pinned nightly: rustfmt (rustfmt.toml uses unstable options) and `-Z` flags. Stable is pinned in
# rust-toolchain.toml.
nightly := "nightly-2026-10-26"
# The container engine of `dev` and `musl`: `SPECULAIRE_CONTAINER=podman just dev check`.
container := env("SPECULAIRE_CONTAINER", "docker")

# The e2e pins (D27, D59, D63): one release per supported runtime minor (D40), one node image per Kubernetes minor
# kind ships, kind, and the kubectl of the newest node image. Renovate moves each pin within its minor.
# renovate: datasource=github-releases depName=containerd/containerd
containerd_2_3 := "2.3.7"
# renovate: datasource=github-releases depName=containerd/containerd
containerd_2_4 := "2.4.2"
# renovate: datasource=github-releases depName=cri-o/cri-o
crio_1_35 := "1.35.10"
# renovate: datasource=github-releases depName=cri-o/cri-o
crio_1_36 := "1.36.7"
# renovate: datasource=github-releases depName=cri-o/cri-o
crio_1_37 := "1.37.2"
# renovate: datasource=docker depName=docker.io/kindest/node
node_1_35 := "v1.35.8@sha256:07b2536e30b803ed61d1677a79df6115f798ce64c80f9e22f6ed45afd09323c0"
# renovate: datasource=docker depName=docker.io/kindest/node
node_1_36 := "v1.36.4@sha256:099e049362a1526b2db71494e1947aae99bd16290d7c895f2b7ea312e3cbfaed"
# renovate: datasource=docker depName=docker.io/kindest/node
node_1_37 := "v1.37.0@sha256:a1ed56cfb0e7b93589bdf97c8cd566405a265939e3620fc4f5de89adff580ae5"
# The Kubernetes minor of a containerd cluster when `just e2e` names none.
kubernetes_newest := "1.37"
# renovate: datasource=github-releases depName=kubernetes-sigs/kind
kind_version := "0.33.0"
# renovate: datasource=github-releases depName=kubernetes/kubernetes
kubectl_version := "1.37.2"
# `just e2e-tools` downloads kind and kubectl here; the e2e recipes put them first in PATH.
e2e_dir := justfile_directory() / "target/e2e"
e2e_path := (e2e_dir / "kind-" + kind_version) + ":" + (e2e_dir / "kubectl-" + kubectl_version)

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

# Volumes speculaire-registry and speculaire-dev-<arch> keep the registry and the build between runs.
# Run a recipe in the dev image (D57), as on macOS: just dev check
dev *recipe:
    {{ container }} build --quiet --target dev --build-arg NIGHTLY={{ nightly }} -t localhost/speculaire-dev -f build/Containerfile build >/dev/null
    {{ container }} run --rm -v "$(pwd):/src" -v speculaire-registry:/usr/local/cargo/registry \
        -v "speculaire-dev-{{ arch() }}:/target" -e CARGO_TARGET_DIR=/target localhost/speculaire-dev just {{ recipe }}

# The binary embeds its dependency list through cargo-auditable (D13, D46); the recipe fails unless it is static-pie
# and carries that list. Volumes speculaire-registry and speculaire-musl-<arch> keep the registry and the build.
# Build the static-PIE musl binary into target/musl/<target>/speculaire: just musl aarch64-unknown-linux-musl
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
        sh -c 'cargo auditable build --release --locked --target "$1" -p speculaire \
            && cp "/target/$1/release/speculaire" /out/ \
            && rust-audit-info /out/speculaire | grep -q "\"name\":\"speculaire\"" \
            && file /out/speculaire | tee /dev/stderr | grep -q "static-pie linked"' \
        sh "{{ target }}"

# Needs Docker, and the binary of `just musl <arch>-unknown-linux-musl`, which it installs on each node.
# Build the node image, start the cluster, run the suites, delete the cluster (D63): just e2e crio 1.37
e2e runtime version kubernetes="": e2e-tools
    #!/usr/bin/env bash
    set -euo pipefail
    trap '{{ just_executable() }} e2e-down {{ runtime }} {{ version }} {{ quote(kubernetes) }}' EXIT
    {{ just_executable() }} e2e-up {{ runtime }} {{ version }} {{ quote(kubernetes) }}
    {{ just_executable() }} e2e-test {{ runtime }} {{ version }} {{ quote(kubernetes) }}

# Build the node image and start the cluster, for debugging: just e2e-up containerd 2.4 1.35
e2e-up runtime version kubernetes="": e2e-tools
    #!/usr/bin/env bash
    set -euo pipefail
    export PATH="{{ e2e_path }}:$PATH"
    eval "$({{ just_executable() }} e2e-cluster {{ runtime }} {{ version }} {{ quote(kubernetes) }})"
    bin='target/musl/{{ arch() }}-unknown-linux-musl/speculaire'
    if [[ ! -x "$bin" ]]; then
        echo "e2e: no $bin: run just musl {{ arch() }}-unknown-linux-musl" >&2
        exit 1
    fi
    image="localhost/speculaire-node:{{ runtime }}-$release-k$kubernetes"
    docker build --quiet --build-arg "NODE=docker.io/kindest/node:$node" --build-arg "RELEASE=$release" -t "$image" \
        -f 'e2e/node/{{ runtime }}/Containerfile' 'e2e/node/{{ runtime }}' >/dev/null
    config=e2e/kind.yaml
    if [[ '{{ runtime }}' == crio ]]; then
        config='{{ e2e_dir }}/kind-crio.yaml'
        cat e2e/kind.yaml e2e/node/crio/kind-patches.yaml >"$config"
    fi
    kind create cluster --name "$cluster" --image "$image" --config "$config" --wait 180s
    # The reference config, at log.filter "info" so that a healthy start leaves entries in the journal.
    agent_config='{{ e2e_dir }}/config.toml'
    sed 's/^#filter = "warn"$/filter = "info"/' packaging/config.toml >"$agent_config"
    grep -q '^filter = "info"$' "$agent_config"
    # The packages' paths: the binary, the unit and the config (D69).
    for node in $(kind get nodes --name "$cluster"); do
        docker cp "$bin" "$node:/usr/bin/speculaire"
        docker cp packaging/speculaire.service "$node:/usr/lib/systemd/system/speculaire.service"
        docker exec "$node" mkdir -p /etc/speculaire
        docker cp "$agent_config" "$node:/etc/speculaire/config.toml"
        docker exec "$node" sh -c 'systemctl daemon-reload && systemctl enable --now speculaire'
    done
    # kind's --wait covers the control plane only.
    kubectl --context "kind-$cluster" wait --for=condition=Ready nodes --all --timeout=180s

# Run the suites against the cluster of `just e2e-up`; arguments go to the test binary: just e2e-test crio 1.37 '' a_pod_runs
e2e-test runtime version kubernetes="" *args:
    #!/usr/bin/env bash
    set -euo pipefail
    eval "$({{ just_executable() }} e2e-cluster {{ runtime }} {{ version }} {{ quote(kubernetes) }})"
    PATH="{{ e2e_path }}:$PATH" SPECULAIRE_E2E_CLUSTER="$cluster" SPECULAIRE_E2E_RUNTIME='{{ runtime }}' \
        SPECULAIRE_E2E_RELEASE="$release" SPECULAIRE_E2E_KUBERNETES="$kubernetes" \
        cargo test -p e2e --locked -- --ignored {{ args }}

# Delete the e2e cluster `just e2e-up` made with the same arguments, or every e2e cluster: just e2e-down
e2e-down runtime="" version="" kubernetes="":
    #!/usr/bin/env bash
    set -euo pipefail
    export PATH="{{ e2e_path }}:$PATH"
    prefix=speculaire-
    if [[ -n '{{ runtime }}' ]]; then
        eval "$({{ just_executable() }} e2e-cluster {{ runtime }} {{ version }} {{ quote(kubernetes) }})"
        prefix="$cluster"
    fi
    for c in $(kind get clusters 2>/dev/null); do
        if [[ "$c" == "$prefix"* ]]; then
            kind delete cluster --name "$c"
        fi
    done

# Print the shell variables of an e2e cluster: `release`, `kubernetes`, `node` (the kindest/node tag and digest) and
# `cluster`. CRI-O runs on its own Kubernetes minor; containerd on the one named, by default the newest (D63).
[private]
e2e-cluster runtime version kubernetes="":
    #!/usr/bin/env bash
    set -euo pipefail
    case '{{ runtime }} {{ version }}' in
        'containerd 2.3') release='{{ containerd_2_3 }}' ;;
        'containerd 2.4') release='{{ containerd_2_4 }}' ;;
        'crio 1.35') release='{{ crio_1_35 }}' ;;
        'crio 1.36') release='{{ crio_1_36 }}' ;;
        'crio 1.37') release='{{ crio_1_37 }}' ;;
        *) echo 'e2e: no {{ runtime }} {{ version }}: containerd 2.3 or 2.4, or crio 1.35, 1.36 or 1.37' >&2; exit 1 ;;
    esac
    kubernetes='{{ kubernetes }}'
    if [[ '{{ runtime }}' == crio ]]; then
        if [[ -n "$kubernetes" && "$kubernetes" != '{{ version }}' ]]; then
            echo 'e2e: CRI-O {{ version }} runs on Kubernetes {{ version }} only' >&2
            exit 1
        fi
        kubernetes='{{ version }}'
    fi
    kubernetes="${kubernetes:-{{ kubernetes_newest }}}"
    case "$kubernetes" in
        1.35) node='{{ node_1_35 }}' ;;
        1.36) node='{{ node_1_36 }}' ;;
        1.37) node='{{ node_1_37 }}' ;;
        *) echo "e2e: no Kubernetes $kubernetes: 1.35, 1.36 or 1.37" >&2; exit 1 ;;
    esac
    printf 'release=%s\nkubernetes=%s\nnode=%s\ncluster=%s\n' "$release" "$kubernetes" "$node" \
        "speculaire-{{ runtime }}{{ replace(version, ".", "") }}-k${kubernetes//./}"

# Download the pinned kind and kubectl into target/e2e, checking their published SHA-256.
e2e-tools:
    #!/usr/bin/env bash
    set -euo pipefail
    os="$(uname -s | tr '[:upper:]' '[:lower:]')"
    case "$(uname -m)" in
        x86_64 | amd64) arch=amd64 ;;
        aarch64 | arm64) arch=arm64 ;;
        *) echo "e2e-tools: no kind for $(uname -m)" >&2; exit 1 ;;
    esac
    fetch() { # <dir> <name> <url> <sha256 url>
        [[ -x "$1/$2" ]] && return
        mkdir -p "$1"
        curl -fsSLo "$1/$2.part" "$3"
        want="$(curl -fsSL "$4" | cut -d' ' -f1)"
        got="$(shasum -a 256 "$1/$2.part" | cut -d' ' -f1)"
        [[ "$want" == "$got" ]] || { echo "e2e-tools: $3: sha256 $got, want $want" >&2; exit 1; }
        chmod +x "$1/$2.part"
        mv "$1/$2.part" "$1/$2"
    }
    kind='https://github.com/kubernetes-sigs/kind/releases/download/v{{ kind_version }}'
    fetch '{{ e2e_dir }}/kind-{{ kind_version }}' kind "$kind/kind-$os-$arch" "$kind/kind-$os-$arch.sha256sum"
    kubectl="https://dl.k8s.io/release/v{{ kubectl_version }}/bin/$os/$arch/kubectl"
    fetch '{{ e2e_dir }}/kubectl-{{ kubectl_version }}' kubectl "$kubectl" "$kubectl.sha256"
