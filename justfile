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
# The image that builds and runs the Go oracle (D29).
# renovate: datasource=docker depName=docker.io/library/golang
golang := "1.27.4-alpine@sha256:0a5f7fe796599ff487605987432e7619ae45beeb2fba4c2ce0b907879932aebf"
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

# The check of every change (D48): format, spelling, unused dependencies, lint, docs, tests, the fuzz smoke tests.
check: (rustfmt "--check")
    taplo fmt --check
    typos
    cargo shear --locked --deny-warnings
    cargo shear --locked --deny-warnings fuzz
    cargo clippy --workspace --all-targets --all-features --locked -- -D warnings
    cargo clippy --manifest-path fuzz/Cargo.toml --all-targets --locked -- -D warnings
    RUSTDOCFLAGS="-D warnings" cargo doc --workspace --no-deps --document-private-items --locked
    cargo nextest run --workspace --all-features --locked
    cargo test --doc --workspace --all-features --locked
    just fuzz-smoke

# Format Rust (pinned nightly rustfmt) and TOML.
fmt: rustfmt
    taplo fmt

# `cargo fmt` of the workspace and fuzz/ with the pinned nightly's rustfmt.
[private]
rustfmt *args:
    #!/usr/bin/env bash
    set -euo pipefail
    rustfmt="$(rustup which --toolchain {{ nightly }} rustfmt)"
    RUSTFMT="$rustfmt" cargo fmt --all {{ args }}
    RUSTFMT="$rustfmt" cargo fmt --manifest-path fuzz/Cargo.toml {{ args }}

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

# `e2e` runs only against a kind cluster, so it is left out; CI uploads the report of
# `just cov --cobertura --output-path target/cobertura.xml` (D72).
# Line coverage of the workspace's tests: a summary, and the report arguments ask for
cov *report:
    #!/usr/bin/env bash
    set -euo pipefail
    # The pinned stable's own cargo and rustc first: llvm-tools belongs to that toolchain.
    rustc="$(rustup which rustc)"
    export PATH="$(dirname "$rustc"):$PATH"
    # In the build image the host is musl, whose rustflags remap /src and /usr/local/cargo for release binaries
    # (.cargo/config.toml). Cargo appends these after them, and rustc applies the last match: the report keeps the
    # real paths, which it needs to tell the workspace from its dependencies.
    host="$(rustc -vV | sed -n 's/^host: //p')"
    if [[ $host == *-musl ]]; then
        export "CARGO_TARGET_$(tr 'a-z-' 'A-Z_' <<< "$host")_RUSTFLAGS=--remap-path-prefix=/src=/src --remap-path-prefix=/usr/local/cargo=/usr/local/cargo"
    fi
    cargo llvm-cov nextest --no-report --workspace --exclude e2e --all-features --locked
    cargo llvm-cov report --summary-only
    if [[ -n "{{ report }}" ]]; then
        cargo llvm-cov report {{ report }}
    fi

# `--locked` reads supply-chain/imports.lock, so it needs no network (D71).
# Each crate of Cargo.lock is audited by an imported set, published by a trusted publisher, or exempted (cargo-vet)
vet:
    cargo vet --locked

# Run on a branch that fails `just vet` after a bump, then commit supply-chain/ (D71).
# Exempts the crate versions no audit or trust covers, then drops what is no longer needed
vet-exempt:
    cargo vet regenerate exemptions
    cargo vet prune

# Formatting, `go mod verify`, `go vet` and `go test`, then `speculaire-oracle version`. Volumes speculaire-go-mod and
# speculaire-go-build-<arch> keep the module and build caches. `just musl` never builds it, so no artifact holds it.
# Build, check and run the Go test oracle (D29) in the pinned Go image
oracle:
    {{ container }} run --rm -v "$(pwd)/oracle:/src" -w /src -v speculaire-go-mod:/go/pkg/mod \
        -v "speculaire-go-build-{{ arch() }}:/root/.cache/go-build" docker.io/library/golang:{{ golang }} sh -euc ' \
            unformatted=$(gofmt -l .); [ -z "$unformatted" ] || { echo "gofmt: $unformatted" >&2; exit 1; }; \
            go mod verify; go vet ./...; go test ./...; \
            go build -trimpath -o /tmp/speculaire-oracle .; /tmp/speculaire-oracle version'

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


# Derived from packaging/config.toml: the file with its keys uncommented, in fuzz/target/seeds/config, and a token
# dictionary of its tables, keys and quoted strings, so that libFuzzer can write `mode = "enforce"`.
[private]
fuzz-seeds:
    mkdir -p fuzz/target/seeds/config
    sed 's/^#\([a-z]\)/\1/' packaging/config.toml >fuzz/target/seeds/config/reference.toml
    grep -ohE '^\[[a-z_.]+\]|^#?[a-z_]+ =|"[^"]*"' packaging/config.toml | sed 's/^#//' | sort -u | \
        sed 's/\\/\\\\/g; s/"/\\"/g; s/.*/"&"/' >fuzz/target/config.dict

# The pinned nightly's cargo and rustc go first in PATH: cargo-fuzz needs `-Z` flags, and rustup's proxies would pick
# the stable of rust-toolchain.toml. The host's target is named: cargo-fuzz defaults to the one it was built for.
# libFuzzer writes to fuzz/corpus/<target>; fuzz/seeds/<target> and the derived seeds only seed it.
# Fuzz one target with libFuzzer (pinned nightly, cargo-fuzz), in `fork` processes when given: just fuzz config 60
fuzz target="config" seconds="300" fork="0": fuzz-seeds
    #!/usr/bin/env bash
    set -euo pipefail
    rustc="$(rustup which --toolchain {{ nightly }} rustc)"
    export PATH="$(dirname "$rustc"):$PATH"
    host="$(rustc -vV | sed -n 's/^host: //p')"
    cd fuzz
    mkdir -p "corpus/{{ target }}" "seeds/{{ target }}" "target/seeds/{{ target }}"
    cargo fuzz run --target "$host" {{ target }} "corpus/{{ target }}" "seeds/{{ target }}" "target/seeds/{{ target }}" \
        -- -max_total_time={{ seconds }} -fork={{ fork }} $(test -f target/{{ target }}.dict && echo -dict=target/{{ target }}.dict)

# Shrink a target's corpus to the inputs that add coverage (libFuzzer's `-merge=1`).
fuzz-cmin target:
    #!/usr/bin/env bash
    set -euo pipefail
    rustc="$(rustup which --toolchain {{ nightly }} rustc)"
    export PATH="$(dirname "$rustc"):$PATH"
    host="$(rustc -vV | sed -n 's/^host: //p')"
    cd fuzz
    cargo fuzz cmin --target "$host" {{ target }} "corpus/{{ target }}"

# Every fuzz target for `seconds` each, in turn (the nightly `fuzz` workflow runs them in parallel).
fuzz-all seconds="60":
    #!/usr/bin/env bash
    set -euo pipefail
    for target in $(basename -s .rs fuzz/fuzz_targets/*.rs); do
        just fuzz "$target" {{ seconds }}
    done

# Replay every target's seeds, their truncations and bit flips on stable (part of `just check`).
fuzz-smoke:
    cargo test --manifest-path fuzz/Cargo.toml --lib --locked
