# The only entry point, for humans and CI (D27). Ported from dedens `justfile` at v0.1.0-131-gfd00747: its recipes, cut to
# speculaire's.

set shell := ["bash", "-euo", "pipefail", "-c"]

# The one pinned nightly: rustfmt (rustfmt.toml uses unstable options), `-Z` flags, cargo-careful and RAPx. RAPx builds
# on rustc internals, so its version and this nightly move together: bump both by hand. Stable is pinned in
# rust-toolchain.toml.
nightly := "nightly-2026-10-26"
# A commit of RAPx's main: its fix for async closures (safer-rust/RAPx#319) is in no release yet (0.7.65 predates it).
# Back to a crates.io version once one has it.
rapx_rev := "8d9d0a2f0389f48891b9e8bd3321a70a932e2e90"
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

# Install the pinned stable (rust-toolchain.toml) and the pinned nightly's rustfmt and standard library sources
# (`just careful`).
toolchains:
    rustup toolchain install
    rustup toolchain install {{ nightly }} --profile minimal --component rustfmt,rust-src

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

# Ported from dedens `justfile` at v0.1.0-131-gfd00747 (D103, D142, D168 there; D74 here).
# Mutation testing (cargo-mutants, settings in .cargo/mutants.toml, needs cargo-nextest), outside `required`. `args`
# go to cargo-mutants: `just mutants -p speculaire-agent`; add `--iterate` to test only what the last run did not
# catch. Tests the committed HEAD in its own worktree, target/mutants/tree, one run at a time: `--in-place` edits
# files, and a killed run can leave a mutant applied, so the tree is reset first. Builds in target/mutants/target,
# results in target/mutants/mutants.out.
[positional-arguments]
mutants *args:
    #!/usr/bin/env bash
    set -euo pipefail
    out="$(pwd)/target/mutants"
    tree="$out/tree"
    mkdir -p "$out"
    if ! mkdir "$out/lock" 2>/dev/null; then
        echo "another run holds $out/lock: wait for it, or remove the lock if none runs" >&2
        exit 1
    fi
    trap 'rmdir "$out/lock"' EXIT
    head="$(git rev-parse HEAD)"
    git worktree prune
    if [[ -e "$tree/.git" ]]; then
        git -C "$tree" checkout --quiet --force --detach "$head"
    else
        git worktree add --quiet --detach "$tree" "$head"
    fi
    cd "$tree"
    CARGO_TARGET_DIR="$out/target" cargo mutants --in-place --timeout 240 --output "$out" "$@"

# Mutation testing of the code changed since the branch left `base` (`--in-diff`): minutes, where `just mutants`
# takes longer. `args` as for `just mutants`: just mutants-diff origin/main --iterate
[positional-arguments]
mutants-diff base="origin/main" *args:
    #!/usr/bin/env bash
    set -euo pipefail
    shift
    mkdir -p target/mutants
    git diff "{{ base }}...HEAD" > target/mutants/branch.diff
    {{ just_executable() }} mutants --in-diff "$(pwd)/target/mutants/branch.diff" "$@"

# The exclusions of .cargo/mutants.toml that match no mutant or file (D74), each listed, failing if any. Mutants are
# listed without the configuration, with no build, and without colours, which CI's `CARGO_TERM_COLOR=always` would
# put in the names. Perl matches the names: `--re` keeps every field deletion. The list is taken first, so a failing
# cargo-mutants stops the recipe rather than leaving every pattern unmatched.
mutants-stale:
    #!/usr/bin/env bash
    set -euo pipefail
    patterns="$(taplo get -f .cargo/mutants.toml exclude_re)"
    globs="$(taplo get -f .cargo/mutants.toml exclude_globs)"
    names="$(cargo mutants --list --no-config --colors=never)"
    stale=0
    printf '%s\n' "$names" | perl -e '
        chomp(my @names = <STDIN>);
        my $stale = 0;
        for my $re (split /\n/, shift) {
            next if grep { /$re/ } @names;
            print "exclude_re matches no mutant: \x27$re\x27\n";
            $stale = 1;
        }
        exit $stale;
    ' "$patterns" || stale=1
    while IFS= read -r glob; do
        found="$(cargo mutants --list-files --no-config --colors=never --file="$glob")"
        if [[ -z "$found" ]]; then
            echo "exclude_globs matches no file: '$glob'"
            stale=1
        fi
    done <<< "$globs"
    exit "$stale"

# Ported from dedens `justfile` at v0.1.0-131-gfd00747 (D144 there; D76 here).
# The workspace's tests on a standard library built with its debug assertions and UB checks (cargo-careful, pinned
# nightly, D76), under a sanitizer when given: just careful address; one package's alone when named: just careful
# address speculaire-agent. On glibc Linux only: macOS cannot link the sanitized builds, and the musl build image (D57)
# has neither the ASan runtime nor the C runtime objects of a rebuilt standard library. Own target dir. Outside
# `just check`.
careful sanitizer="" package="":
    #!/usr/bin/env bash
    set -euo pipefail
    # The pinned nightly's own cargo and rustc first: cargo-careful builds the standard library with them. The host's
    # target is named: cargo-careful defaults to the one it was built for, which on musl breaks AddressSanitizer.
    rustc="$(rustup which --toolchain {{ nightly }} rustc)"
    export PATH="$(dirname "$rustc"):$PATH" CARGO_TARGET_DIR=target/careful
    host="$(rustc -vV | sed -n 's/^host: //p')"
    # No leak check: a leak is no memory error, and the threads still alive at exit would report.
    export ASAN_OPTIONS="${ASAN_OPTIONS:-detect_leaks=0}"
    cargo careful test --target "$host" {{ if sanitizer == "" { "" } else { "-Zcareful-sanitizer=" + sanitizer } }} {{ if package == "" { "--workspace --exclude e2e" } else { "-p " + package } }} --all-features --locked

# Ported from dedens `justfile` at v0.1.0-131-gfd00747 (D16 there; D77 here).
# Install RAPx at `rapx_rev` and what it builds on: the nightly's rustc-dev, rust-src and llvm-tools, and Z3 (on macOS
# from Homebrew, `brew install z3`; on Linux, libz3-dev).
rapx-install:
    #!/usr/bin/env bash
    set -euo pipefail
    if command -v brew >/dev/null; then
        z3="$(brew --prefix z3)"
        export Z3_SYS_Z3_HEADER="$z3/include/z3.h" LIBRARY_PATH="$z3/lib${LIBRARY_PATH:+:$LIBRARY_PATH}"
    fi
    rustup toolchain install {{ nightly }} --profile minimal --component rustc-dev,rust-src,llvm-tools-preview
    rustc="$(rustup which --toolchain {{ nightly }} rustc)"
    RUSTC="$rustc" rustup run {{ nightly }} cargo install --git https://github.com/safer-rust/RAPx --rev {{ rapx_rev }} rapx --locked

# Ported from dedens `justfile` at v0.1.0-131-gfd00747 (D16 there; D77 here).
# RAPx static analysis, outside the gate: use-after-free, double free and leaks by default; `just rapx opt` for
# optimization hints. Own target dir: RAPx runs `cargo clean --workspace` before each analysis.
rapx *args="check -f -m":
    #!/usr/bin/env bash
    set -euo pipefail
    # The nightly's own cargo first in PATH: RAPx calls `cargo`, which `rustup run` leaves to a Homebrew cargo
    # ahead in PATH, and the dependencies it builds don't load in RAPx's rustc.
    rustc="$(rustup which --toolchain {{ nightly }} rustc)"
    export PATH="$(dirname "$rustc"):$PATH"
    CARGO_TARGET_DIR=target/rapx RUSTC="$rustc" rustup run {{ nightly }} cargo rapx {{ args }}

# `--locked` reads supply-chain/imports.lock, so it needs no network (D71).
# Each crate of Cargo.lock is audited by an imported set, published by a trusted publisher, or exempted (cargo-vet)
vet:
    cargo vet --locked

# Run on a branch that fails `just vet` after a bump, then commit supply-chain/ (D71).
# Exempts the crate versions no audit or trust covers, then drops what is no longer needed
vet-exempt:
    cargo vet regenerate exemptions
    cargo vet prune

# Formatting, `go mod verify`, `go vet` and `go test`, then the binary in target/oracle and `speculaire-oracle version`;
# then the differential tests (`oracle-test`), natively on Linux and in the build image elsewhere, where the Go binary
# (a static Linux binary of this machine's architecture) also runs. Volumes speculaire-go-mod and
# speculaire-go-build-<arch> keep the module and build caches. `just musl` never builds it, so no artifact holds it.
# Build, check and run the Go test oracle (D29), then the Rust tests that compare with it (D70)
oracle:
    mkdir -p target/oracle
    {{ container }} run --rm -v "$(pwd)/oracle:/src" -w /src -v "$(pwd)/target/oracle:/out" -v speculaire-go-mod:/go/pkg/mod \
        -v "speculaire-go-build-{{ arch() }}:/root/.cache/go-build" docker.io/library/golang:{{ golang }} sh -euc ' \
            unformatted=$(gofmt -l .); [ -z "$unformatted" ] || { echo "gofmt: $unformatted" >&2; exit 1; }; \
            go mod verify; go vet ./...; go test ./...; \
            go build -trimpath -o /out/speculaire-oracle .; /out/speculaire-oracle version'
    if [[ "$(uname -s)" == Linux ]]; then {{ just_executable() }} oracle-test; else {{ just_executable() }} dev oracle-test; fi

# The tests that ask target/oracle/speculaire-oracle the cases they run (SPECULAIRE_ORACLE, crates/oracle-harness); the
# output stays on, so that the log shows each comparison ran and was not skipped.
[private]
oracle-test:
    SPECULAIRE_ORACLE="$(pwd)/target/oracle/speculaire-oracle" cargo test --workspace --test oracle --locked -- --nocapture

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
