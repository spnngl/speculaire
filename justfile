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
# The reflectors' load balancer of an e2e cluster (D94): the Envoy release kind v0.33.0 runs in front of its API servers.
# renovate: datasource=docker depName=docker.io/envoyproxy/envoy
envoy := "v1.36.2@sha256:4972515dd9a069b44beb43cebba7851596e72a8c61cd7a7c33d8f48efc5280ba"
# The image that builds and runs the Go oracle (D29).
# renovate: datasource=docker depName=docker.io/library/golang
golang := "1.27.4-alpine@sha256:0a5f7fe796599ff487605987432e7619ae45beeb2fba4c2ce0b907879932aebf"
# The commit of the distribution-spec conformance suite that `just conformance` runs (D85); the mirror serves its pull half.
# renovate: datasource=git-refs depName=https://github.com/opencontainers/distribution-spec
conformance_rev := "97274622c11112caa21efb8c52acca3c6b8fa7f1"
# The build tags of go.podman.io/image: OpenPGP in Go instead of gpgme (cgo), and no storage drivers.
go_tags := "containers_image_openpgp,exclude_graphdriver_btrfs,exclude_graphdriver_devicemapper"
# `just e2e-tools` downloads kind and kubectl here; the e2e recipes put them first in PATH.
e2e_dir := justfile_directory() / "target/e2e"
e2e_path := (e2e_dir / "kind-" + kind_version) + ":" + (e2e_dir / "kubectl-" + kubectl_version)

# The bench (D35, D106): the measuring tool, the mirror compared, the tool installing it, and the node-access pod.
# renovate: datasource=github-releases depName=spegel-org/benchmark
benchmark_version := "0.0.7"
# renovate: datasource=github-releases depName=spegel-org/spegel
spegel_version := "0.8.1"
# renovate: datasource=github-releases depName=helm/helm
helm_version := "4.3.2"
# renovate: datasource=docker depName=docker.io/library/debian
bench_node := "trixie-slim@sha256:a72b4433de1cf7d6bae0c4cee74d0547f58601a643b3375f070c51600d63b6b2"
bench_dir := justfile_directory() / "target/bench-tools"
bench_path := (bench_dir / "benchmark-" + benchmark_version) + ":" + (bench_dir / "helm-" + helm_version)

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
    # In the build image the host is musl, whose rustflags remap /usr/local/cargo for release binaries
    # (.cargo/config.toml). Cargo appends this after them, and rustc applies the last match: the report keeps the
    # real paths, which it needs to tell the workspace from its dependencies. `just dev` mounts the tree at its own
    # path, which no rustflag remaps.
    host="$(rustc -vV | sed -n 's/^host: //p')"
    if [[ $host == *-musl ]]; then
        export "CARGO_TARGET_$(tr 'a-z-' 'A-Z_' <<< "$host")_RUSTFLAGS=--remap-path-prefix=/usr/local/cargo=/usr/local/cargo"
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
# files, and a killed run can leave a mutant applied, so the tree is reset first. A tree deleted by `cargo clean` stays
# registered: `add --force` replaces that one registration, where `git worktree prune` would also drop every worktree
# this filesystem cannot see, as in the dev container. Builds in <target dir>/mutants/target, results in
# target/mutants/mutants.out. Off Linux, runs in the dev image (`just dev`), where Linux-only code compiles (D125).
[positional-arguments]
mutants *args:
    #!/usr/bin/env bash
    set -euo pipefail
    if [[ "$(uname -s)" != Linux ]]; then
        echo 'mutants: in the dev image, where Linux-only code compiles (D125)' >&2
        exec {{ just_executable() }} dev mutants "$@"
    fi
    out="$(pwd)/target/mutants"
    # `just dev` points CARGO_TARGET_DIR at its volume: on the bind mount, every mutant misses crates just built (D125).
    build="${CARGO_TARGET_DIR:-$(pwd)/target}/mutants/target"
    tree="$out/tree"
    mkdir -p "$out"
    if ! mkdir "$out/lock" 2>/dev/null; then
        echo "another run holds $out/lock: wait for it, or remove the lock if none runs" >&2
        exit 1
    fi
    trap 'rmdir "$out/lock"' EXIT
    head="$(git rev-parse HEAD)"
    if [[ -e "$tree/.git" ]]; then
        git -C "$tree" checkout --quiet --force --detach "$head"
    else
        git worktree add --quiet --force --detach "$tree" "$head"
    fi
    cd "$tree"
    CARGO_TARGET_DIR="$build" cargo mutants --in-place --timeout 240 --output "$out" "$@"

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

# Divan's micro-benchmarks (D104): the reflector's index lookup in D33's fleet, and blob hashing as content arrives (D7).
# On this machine, outside CI: the numbers compare changes on one machine only. Arguments go to divan, such as a filter.
# Measure the hot paths: just bench-micro
bench-micro *args:
    cargo bench --locked -p speculaire-reflect -p speculaire-mirror -p speculaire-runtime -p speculaire-oci --bench micro \
        --features speculaire-reflect/bench,speculaire-mirror/bench -- {{ args }}

# `just profile` and `just valgrind` run in the glibc profile image (D116), privileged for perf, on the release
# build with symbols, in a volume of their own.
in_profile := container + ' run --rm -i --privileged -v "$(pwd):/src" -v speculaire-registry:/usr/local/cargo/registry -v speculaire-profile-' + arch() + ':/target -e CARGO_TARGET_DIR=/target -e CARGO_PROFILE_RELEASE_DEBUG=line-tables-only -e CARGO_PROFILE_RELEASE_STRIP=none -e RUST_LOG --ulimit nofile=1048576:1048576 --sysctl "net.ipv4.ip_local_port_range=1024 65535" localhost/speculaire-profile'

# Docker Hub's `image` (`docker.io/…`) from mirror.gcr.io, then from `public.ecr.aws/docker` for an official image
# (`library/`), then from Docker Hub, as e2e's harness (`e2e::hub`, D120, D122): prints the reference it is here
# under, pulling it unless one is.
[private]
hub-pull image:
    #!/usr/bin/env bash
    set -euo pipefail
    path='{{ image }}'
    path="${path#docker.io/}"
    sources=("mirror.gcr.io/$path")
    [[ "$path" == library/* ]] && sources+=("public.ecr.aws/docker/$path")
    sources+=('{{ image }}')
    for source in "${sources[@]}"; do
        if {{ container }} image inspect "$source" >/dev/null 2>&1; then echo "$source"; exit 0; fi
    done
    for source in "${sources[@]}"; do
        if {{ container }} pull --quiet "$source" >/dev/null; then echo "$source"; exit 0; fi
    done
    echo "hub-pull: no source serves {{ image }}" >&2
    exit 1

# The `stage` of build/Containerfile as localhost/speculaire-<stage> (D57, D116). The Docker Hub image its `FROM` lines
# lead to, which Renovate moves, is a named context of the one `hub-pull` pulled (D122).
[private]
image stage:
    #!/usr/bin/env bash
    set -euo pipefail
    from='{{ stage }}'
    until [[ "$from" == docker.io/* ]]; do
        from="$(sed -n "s/^FROM \([^ ]*\) AS $from\$/\1/p" build/Containerfile)"
        [[ -n "$from" ]] || { echo 'image: no stage {{ stage }} on a Docker Hub image' >&2; exit 1; }
    done
    pulled="$({{ just_executable() }} hub-pull "$from")"
    {{ container }} build --quiet --target '{{ stage }}' --build-arg NIGHTLY={{ nightly }} \
        --build-context "$from=docker-image://$pulled" -t 'localhost/speculaire-{{ stage }}' -f build/Containerfile build \
        >/dev/null

# The reflector under a short load (D104), twice: Valgrind's memcheck, failing on a definite leak or a memory error, then
# DHAT; then DHAT on the agents of a short peer pull (D116). The profiles go to target/valgrind/dhat, named after the
# run, the node and the pid. Needs Docker; outside `just check`.
valgrind: (image "profile")
    #!/usr/bin/env bash
    set -euo pipefail
    mkdir -p target/valgrind
    {{ in_profile }} bash -euo pipefail -s <<'EOF'
    cargo build --release --locked -p speculaire -p speculaire-loadgen
    bin=/target/release dhat=/src/target/valgrind/dhat
    rm -rf "$dhat" && mkdir -p "$dhat"
    # Small enough for Valgrind's pace; the measures mean nothing under it, so no target fails the run.
    load=("$bin/speculaire-loadgen" --agents 100 --blobs 500 --pool 10000 --lookups 100 --deltas 50 --join 10s
        --warmup 5s --steady 20s --measure-only --)
    # No undefined-value check: it flags a branch in hyper's HTTP/1 head parsing (hyper 1.12.0 src/proto/h1/io.rs:205)
    # that the optimiser reads early, and leaks are what this run is for.
    "${load[@]}" valgrind --leak-check=full --show-leak-kinds=definite --errors-for-leak-kinds=definite \
        --undef-value-errors=no --error-exitcode=1 "$bin/speculaire"
    "${load[@]}" valgrind --tool=dhat --dhat-out-file="$dhat/load.%q{SPECULAIRE_LOAD_NODE}.%p.json" "$bin/speculaire"
    "$bin/speculaire-loadgen" peer --size-mib 16 --pulls 5 -- \
        valgrind --tool=dhat --dhat-out-file="$dhat/peer.%q{SPECULAIRE_LOAD_NODE}.%p.json" "$bin/speculaire"
    # The container runs as root: the profiles go to the checkout's owner.
    chown -R "$(stat -c %u:%g /src)" "$dhat"
    EOF

# A CPU flamegraph of each agent of a run (D116): `load`, the reflector under D33's load for 30 s, or `peer`, a 64 MiB
# blob pulled 30 times from a peer through a second agent's mirror. perf samples each process by its frame pointers;
# target/profile/<target>/ gets the run's report, and per process a folded stack file and an SVG, named after its node
# and pid. Needs Docker; outside `just check`.
# Profile the peer pull: just profile peer
profile target: (image "profile")
    #!/usr/bin/env bash
    set -euo pipefail
    case '{{ target }}' in
        load) run=(--steady 30s --measure-only --) ;;
        peer) run=(peer --size-mib 64 --pulls 30 --) ;;
        *) echo "profile: no target '{{ target }}': load or peer" >&2; exit 1 ;;
    esac
    mkdir -p target/profile
    {{ in_profile }} bash -euo pipefail -s '{{ target }}' "${run[@]}" <<'EOF'
    cargo build --release --locked -p speculaire -p speculaire-loadgen
    bin=/target/release out="/src/target/profile/$1"
    shift
    rm -rf "$out" && mkdir -p "$out"
    # perf follows the agent's pid through `exec`, so SIGTERM reaches the agent itself, which then exits with success as
    # the run requires, and perf ends with it.
    "$bin/speculaire-loadgen" "$@" sh -c 'perf record --quiet -F 999 --call-graph fp \
        -o "$0/$SPECULAIRE_LOAD_NODE.$$.data" -p $$ 2>/dev/null & exec "$@"' "$out" "$bin/speculaire" | tee "$out/report.md"
    while grep -qx perf /proc/[0-9]*/comm 2>/dev/null; do sleep 0.2; done
    for data in "$out"/*.data; do
        name="${data%.data}"
        perf script -i "$data" --no-inline 2>/dev/null | rustfilt | inferno-collapse-perf >"$name.folded"
        inferno-flamegraph --title "${name##*/}" <"$name.folded" >"$name.svg"
    done
    chown -R "$(stat -c %u:%g /src)" "$out"
    EOF

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
oracle: oracle-build
    if [[ "$(uname -s)" == Linux ]]; then {{ just_executable() }} oracle-test; else {{ just_executable() }} dev oracle-test; fi

# The shards of the mutants workflow ask the binary too (D79).
# Build and check the Go test oracle into target/oracle/speculaire-oracle
oracle-build:
    mkdir -p target/oracle
    golang="$({{ just_executable() }} hub-pull 'docker.io/library/golang:{{ golang }}')"; \
    {{ container }} run --rm -v "$(pwd)/oracle:/src" -w /src -v "$(pwd)/target/oracle:/out" -v speculaire-go-mod:/go/pkg/mod \
        -v "speculaire-go-build-{{ arch() }}:/root/.cache/go-build" -e CGO_ENABLED=0 -e GOFLAGS=-tags={{ go_tags }} "$golang" sh -euc ' \
            unformatted=$(gofmt -l .); [ -z "$unformatted" ] || { echo "gofmt: $unformatted" >&2; exit 1; }; \
            go mod verify; go vet ./...; go test ./...; \
            go build -trimpath -o /out/speculaire-oracle .; /out/speculaire-oracle version'

# The tests that ask target/oracle/speculaire-oracle the cases they run (SPECULAIRE_ORACLE, crates/oracle-harness); the
# output stays on, so that the log shows each comparison ran and was not skipped.
[private]
oracle-test:
    SPECULAIRE_ORACLE="$(pwd)/target/oracle/speculaire-oracle" cargo test --workspace --test oracle --locked -- --nocapture

# The tree is mounted at its own path, with the git directory a worktree points to, and builds in /target<its path>:
# worktrees share volume speculaire-dev-<arch>, each with its own build (D118). Volume speculaire-registry keeps the
# registry.
# Run a recipe in the dev image (D57), as on macOS: just dev check
dev *recipe:
    #!/usr/bin/env bash
    set -euo pipefail
    {{ just_executable() }} image dev
    tree="$(pwd)"
    mounts=(-v "$tree:$tree")
    git="$(git rev-parse --path-format=absolute --git-common-dir 2>/dev/null || true)"
    if [[ -n "$git" && "$git" != "$tree"/* ]]; then
        mounts+=(-v "$git:$git")
    fi
    {{ container }} run --rm "${mounts[@]}" -w "$tree" -v speculaire-registry:/usr/local/cargo/registry \
        -v "speculaire-dev-{{ arch() }}:/target" -e CARGO_TARGET_DIR="/target$tree" localhost/speculaire-dev just {{ recipe }}

# The distribution-spec conformance suite against the mirror of the musl binary, in the Go image (D85): the agent runs in
# a container seeded with content, and the suite pulls from it. Needs Docker and `just musl <arch>-unknown-linux-musl`.
conformance:
    #!/usr/bin/env bash
    set -euo pipefail
    bin='target/musl/{{ arch() }}-unknown-linux-musl/speculaire'
    if [[ ! -x "$bin" ]]; then
        echo "conformance: no $bin: run just musl {{ arch() }}-unknown-linux-musl" >&2
        exit 1
    fi
    mkdir -p target/conformance target/musl-fake
    # The fake containerd of the agent's tests (D87): the node of this run has no runtime.
    {{ just_executable() }} image build
    {{ container }} run --rm -v "$(pwd):/src:ro" -v "$(pwd)/target/musl-fake:/out" \
        -v speculaire-registry:/usr/local/cargo/registry -v "speculaire-musl-{{ arch() }}:/target" \
        -e CARGO_TARGET_DIR=/target localhost/speculaire-build \
        sh -c 'cargo build --release --locked --target "$1" -p speculaire-fake-runtime \
            && cp "/target/$1/release/fake-runtime" /out/' sh '{{ arch() }}-unknown-linux-musl'
    golang="$({{ just_executable() }} hub-pull 'docker.io/library/golang:{{ golang }}')"
    {{ container }} run --rm -e CONFORMANCE_REV='{{ conformance_rev }}' -v "$(pwd)/$bin:/usr/bin/speculaire:ro" \
        -v "$(pwd)/target/musl-fake/fake-runtime:/usr/bin/fake-runtime:ro" \
        -v "$(pwd)/conformance:/conformance:ro" -v "$(pwd)/packaging:/packaging:ro" \
        -v "$(pwd)/target/conformance:/results" -v speculaire-go-mod:/go/pkg/mod \
        -v "speculaire-go-build-{{ arch() }}:/root/.cache/go-build" "$golang" sh /conformance/run.sh

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
    {{ just_executable() }} image build
    mkdir -p "target/musl/{{ target }}"
    {{ container }} run --rm -v "$(pwd):/src:ro" -v "$(pwd)/target/musl/{{ target }}:/out" \
        -v speculaire-registry:/usr/local/cargo/registry -v "speculaire-musl-{{ arch() }}:/target" \
        -e CARGO_TARGET_DIR=/target localhost/speculaire-build \
        sh -c 'cargo auditable build --release --locked --target "$1" -p speculaire \
            && cp "/target/$1/release/speculaire" /out/ \
            && rust-audit-info /out/speculaire | grep -q "\"name\":\"speculaire\"" \
            && file /out/speculaire | tee /dev/stderr | grep -q "static-pie linked"' \
        sh "{{ target }}"

# D33's load against one reflector (D104): the musl `speculaire` and `speculaire-loadgen`, in the build image with the
# open-files limit raised and every local port open to the agents' connections; a missed target fails. Arguments go to
# `speculaire-loadgen`, such as `--agents 2000` on a laptop, and `RUST_LOG` filters its logs. Needs
# `just musl <arch>-unknown-linux-musl`.
# Run the load scenario and report D33's targets: just load
load *args:
    #!/usr/bin/env bash
    set -euo pipefail
    target='{{ arch() }}-unknown-linux-musl'
    bin="target/musl/$target/speculaire"
    if [[ ! -x "$bin" ]]; then
        echo "load: no $bin: run just musl $target" >&2
        exit 1
    fi
    mkdir -p target/musl-load
    {{ just_executable() }} image build
    {{ container }} run --rm -v "$(pwd):/src:ro" -v "$(pwd)/target/musl-load:/out" \
        -v speculaire-registry:/usr/local/cargo/registry -v "speculaire-musl-{{ arch() }}:/target" \
        -e CARGO_TARGET_DIR=/target localhost/speculaire-build \
        sh -c 'cargo build --release --locked --target "$1" -p speculaire-loadgen \
            && cp "/target/$1/release/speculaire-loadgen" /out/' sh "$target"
    echo 'load: the open-files limit is raised to 1048576, and the local ports to 1024-65535, in the container' >&2
    {{ container }} run --rm -e RUST_LOG --ulimit nofile=1048576:1048576 --sysctl net.ipv4.ip_local_port_range='1024 65535' \
        -v "$(pwd)/$bin:/usr/bin/speculaire:ro" \
        -v "$(pwd)/target/musl-load/speculaire-loadgen:/usr/bin/speculaire-loadgen:ro" \
        localhost/speculaire-build speculaire-loadgen {{ args }} -- /usr/bin/speculaire

# Needs Docker, and the binary of `just musl <arch>-unknown-linux-musl`, which it installs on each node.
# Build the node image, start the cluster, run the suites, delete the cluster (D63): just e2e crio 1.37
e2e runtime version kubernetes="": e2e-tools
    #!/usr/bin/env bash
    set -euo pipefail
    # A failed run saves the journals first, for CI to keep.
    trap 'status=$?; (( status == 0 )) || {{ just_executable() }} e2e-journals {{ runtime }} {{ version }} {{ quote(kubernetes) }} || true
        {{ just_executable() }} e2e-down {{ runtime }} {{ version }} {{ quote(kubernetes) }}' EXIT
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
    # Docker Hub's images through its mirrors (D120, D122). The Containerfile's alpine, which Renovate moves, is a named
    # context of the one pulled.
    pull() { {{ just_executable() }} hub-pull "$1"; }
    alpine="$(sed -n 's/^FROM \(docker\.io\/[^ ]*\) AS download$/\1/p' 'e2e/node/{{ runtime }}/Containerfile')"
    base="$(pull "docker.io/kindest/node:$node")"
    download="$(pull "$alpine")"
    image="localhost/speculaire-node:{{ runtime }}-$release-k$kubernetes"
    docker build --quiet --build-arg "NODE=$base" --build-arg "RELEASE=$release" \
        --build-context "$alpine=docker-image://$download" -t "$image" \
        -f 'e2e/node/{{ runtime }}/Containerfile' 'e2e/node/{{ runtime }}' >/dev/null
    mkdir -p '{{ e2e_dir }}'
    config="{{ e2e_dir }}/$cluster.yaml"
    {
        if [[ "$family" == dual ]]; then
            printf 'networking:\n  ipFamily: dual\n'
        fi
        cat e2e/kind.yaml
        if [[ '{{ runtime }}' == crio ]]; then
            cat e2e/node/crio/kind-patches.yaml
        fi
    } >"$config"
    kind create cluster --name "$cluster" --image "$image" --config "$config" --wait 180s
    # The upstreams, the test images on each, and each node's runtime config for them (D94, D112).
    SPECULAIRE_E2E_CLUSTER="$cluster" SPECULAIRE_E2E_RUNTIME='{{ runtime }}' SPECULAIRE_E2E_RELEASE="$release" \
        SPECULAIRE_E2E_KUBERNETES="$kubernetes" SPECULAIRE_E2E_IP_FAMILY="$family" \
        cargo run -p e2e --locked --quiet --bin upstreams
    # The peer harness (D94): a load balancer in front of the reflectors, the agents of the control plane and of the
    # first worker. Every container of the cluster has its label, for `e2e-down`.
    labels=(--network kind --label speculaire-e2e --label "speculaire-e2e.cluster=$cluster")
    address() { # <container>: its address on kind's network, IPv6 on a dual-stack cluster
        local field=IPAddress
        [[ "$family" == dual ]] && field=GlobalIPv6Address
        docker inspect -f "{{{{(index .NetworkSettings.Networks \"kind\").$field}}" "$1"
    }
    socket() { # <address> <port>
        [[ "$1" == *:* ]] && echo "[$1]:$2" || echo "$1:$2"
    }
    docker rm -f -v "$cluster-lb" >/dev/null 2>&1 || true
    members=''
    envoy_config="{{ e2e_dir }}/$cluster-envoy.yaml"
    listen='address: 0.0.0.0'
    [[ "$family" == dual ]] && listen='address: "::", ipv4_compat: true'
    cat >"$envoy_config" <<EOF
    static_resources:
      listeners:
        - name: reflectors
          address:
            socket_address: { $listen, port_value: 7483 }
          filter_chains:
            - filters:
                - name: envoy.filters.network.tcp_proxy
                  typed_config:
                    "@type": type.googleapis.com/envoy.extensions.filters.network.tcp_proxy.v3.TcpProxy
                    stat_prefix: reflectors
                    cluster: reflectors
      clusters:
        - name: reflectors
          connect_timeout: 1s
          type: STATIC
          lb_policy: ROUND_ROBIN
          health_checks:
            - { timeout: 1s, interval: 1s, no_traffic_interval: 1s, unhealthy_threshold: 1, healthy_threshold: 1, tcp_health_check: {} }
          load_assignment:
            cluster_name: reflectors
            endpoints:
              - lb_endpoints:
    EOF
    for node in "$cluster-control-plane" "$cluster-worker"; do
        a="$(address "$node")"
        members+="${members:+, }{ node = \"$node\", address = \"$(socket "$a" 7483)\" }"
        echo "              - endpoint: { address: { socket_address: { address: \"$a\", port_value: 7483 } } }" >>"$envoy_config"
    done
    envoy="$(pull 'docker.io/envoyproxy/envoy:{{ envoy }}')"
    docker create --name "$cluster-lb" "${labels[@]}" "$envoy" >/dev/null
    docker cp "$envoy_config" "$cluster-lb:/etc/envoy/envoy.yaml"
    docker start "$cluster-lb" >/dev/null
    url="https://$(socket "$(address "$cluster-lb")" 7483)"
    # The reference config, at log.filter "info" so that a healthy start leaves entries in the journal, with peers on.
    agent_config="{{ e2e_dir }}/$cluster.toml"
    sed -e 's/^#filter = "warn"$/filter = "info"/' -e "s|^#url = \"\"$|url = \"$url\"|" \
        -e "s|^#members = \[\]$|members = [$members]|" packaging/config.toml >"$agent_config"
    grep -q '^filter = "info"$' "$agent_config"
    grep -q '^url = ' "$agent_config"
    grep -q '^members = ' "$agent_config"
    # The packages' paths: the binary, the unit and the config (D69).
    for node in $(kind get nodes --name "$cluster"); do
        docker cp "$bin" "$node:/usr/bin/speculaire"
        docker cp packaging/speculaire.service "$node:/usr/lib/systemd/system/speculaire.service"
        docker exec "$node" mkdir -p /etc/speculaire
        docker cp "$agent_config" "$node:/etc/speculaire/config.toml"
        if [[ "$node" == "$cluster-control-plane" || "$node" == "$cluster-worker" ]]; then
            docker exec "$node" sed -i 's/^#role = "agent"$/role = "reflector"/' /etc/speculaire/config.toml
            docker exec "$node" grep -q '^role = "reflector"$' /etc/speculaire/config.toml
        fi
        # The admin's step of docs/operations.md § Install (D55): the mirror's certificates and the runtime's entries
        # come before the agent, whose preflight looks for them.
        docker exec "$node" speculaire configure
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
        SPECULAIRE_E2E_RELEASE="$release" SPECULAIRE_E2E_KUBERNETES="$kubernetes" SPECULAIRE_E2E_IP_FAMILY="$family" \
        cargo test -p e2e --locked -- --ignored {{ args }}

# Save each node's journal, the agent's with every field, and the load balancer's log into target/e2e/journals/<cluster>:
# just e2e-journals crio 1.37
e2e-journals runtime version kubernetes="":
    #!/usr/bin/env bash
    set -euo pipefail
    export PATH="{{ e2e_path }}:$PATH"
    eval "$({{ just_executable() }} e2e-cluster {{ runtime }} {{ version }} {{ quote(kubernetes) }})"
    dir="{{ e2e_dir }}/journals/$cluster"
    mkdir -p "$dir"
    for node in $(kind get nodes --name "$cluster"); do
        docker exec "$node" journalctl --no-pager -o short-iso-precise >"$dir/$node.log"
        docker exec "$node" journalctl --no-pager -u speculaire -o json >"$dir/$node.speculaire.json"
    done
    docker logs "$cluster-lb" >"$dir/$cluster-lb.log" 2>&1
    echo "e2e: journals in $dir" >&2

# The cluster's upstream and load balancer go too; without arguments, so do the containers a killed suite left.
# Delete the e2e cluster `just e2e-up` made with the same arguments and SPECULAIRE_E2E_IP_FAMILY, or every e2e
# cluster: just e2e-down
e2e-down runtime="" version="" kubernetes="":
    #!/usr/bin/env bash
    set -euo pipefail
    export PATH="{{ e2e_path }}:$PATH"
    pattern='speculaire-*'
    label=speculaire-e2e
    if [[ -n '{{ runtime }}' ]]; then
        eval "$({{ just_executable() }} e2e-cluster {{ runtime }} {{ version }} {{ quote(kubernetes) }})"
        pattern="$cluster"
        label="speculaire-e2e.cluster=$cluster"
    fi
    for c in $(kind get clusters 2>/dev/null); do
        # Unquoted: a glob.
        if [[ "$c" == $pattern ]]; then
            kind delete cluster --name "$c"
        fi
    done
    docker ps -aq --filter "label=$label" | xargs -r docker rm -f -v >/dev/null

# Print the shell variables of an e2e cluster: `release`, `kubernetes`, `node` (the kindest/node tag and digest),
# `family` and `cluster`. CRI-O runs on its own Kubernetes minor; containerd on the one named, by default the newest
# (D63). SPECULAIRE_E2E_IP_FAMILY=dual makes a dual-stack cluster, whose name ends in `-dual` (D94).
[private]
e2e-cluster runtime version kubernetes="":
    #!/usr/bin/env bash
    set -euo pipefail
    family="${SPECULAIRE_E2E_IP_FAMILY:-ipv4}"
    case "$family" in
        ipv4) suffix='' ;;
        dual) suffix=-dual ;;
        *) echo "e2e: SPECULAIRE_E2E_IP_FAMILY is $family: ipv4 or dual" >&2; exit 1 ;;
    esac
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
    printf 'release=%s\nkubernetes=%s\nnode=%s\nfamily=%s\ncluster=%s\n' "$release" "$kubernetes" "$node" "$family" \
        "speculaire-{{ runtime }}{{ replace(version, ".", "") }}-k${kubernetes//./}$suffix"

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
    # A runner's network fails now and then: each download retries for about half a minute.
    get() { curl -fsSL --retry 5 --retry-all-errors --retry-delay 2 --connect-timeout 10 "$@"; }
    fetch() { # <dir> <name> <url> <sha256 url>
        [[ -x "$1/$2" ]] && return
        mkdir -p "$1"
        get -o "$1/$2.part" "$3"
        want="$(get "$4" | cut -d' ' -f1)"
        got="$(shasum -a 256 "$1/$2.part" | cut -d' ' -f1)"
        [[ "$want" == "$got" ]] || { echo "e2e-tools: $3: sha256 $got, want $want" >&2; exit 1; }
        chmod +x "$1/$2.part"
        mv "$1/$2.part" "$1/$2"
    }
    kind='https://github.com/kubernetes-sigs/kind/releases/download/v{{ kind_version }}'
    fetch '{{ e2e_dir }}/kind-{{ kind_version }}' kind "$kind/kind-$os-$arch" "$kind/kind-$os-$arch.sha256sum"
    kubectl="https://dl.k8s.io/release/v{{ kubectl_version }}/bin/$os/$arch/kubectl"
    fetch '{{ e2e_dir }}/kubectl-{{ kubectl_version }}' kubectl "$kubectl" "$kubectl.sha256"

# Needs a cluster-admin kubeconfig. The samples and results.json go to target/bench/<UTC time>, the tables to stdout.
# Each node runs the binary of `just musl` for its architecture. The bench images are amd64 only: arm64 nodes run them
# through binfmt_misc.
# Bench speculaire against no mirror and Spegel (D35, D106): just bench ~/.kube/config 10MB-1
bench kubeconfig *sets="10MB-1 10MB-4 100MB-1 100MB-4": e2e-tools bench-tools
    #!/usr/bin/env bash
    set -euo pipefail
    export PATH="{{ e2e_path }}:{{ bench_path }}:$PATH"
    BENCH_NODE='docker.io/library/debian:{{ bench_node }}' SPEGEL_VERSION='{{ spegel_version }}' \
        bench/bench.sh {{ quote(kubeconfig) }} "target/bench/$(date -u +%Y%m%dT%H%M%SZ)" {{ sets }}

# Download the pinned benchmark and helm into target/bench-tools, checking their published SHA-256.
[private]
bench-tools:
    #!/usr/bin/env bash
    set -euo pipefail
    os="$(uname -s | tr '[:upper:]' '[:lower:]')"
    case "$(uname -m)" in
        x86_64 | amd64) arch=amd64 ;;
        aarch64 | arm64) arch=arm64 ;;
        *) echo "bench-tools: no benchmark for $(uname -m)" >&2; exit 1 ;;
    esac
    get() { curl -fsSL --retry 5 --retry-all-errors --retry-delay 2 --connect-timeout 10 "$@"; }
    fetch() { # <dir> <name> <tarball url> <checksums url> <path in the tarball>
        [[ -x "$1/$2" ]] && return
        mkdir -p "$1"
        get -o "$1/$2.tar.gz" "$3"
        want="$(get "$4" | awk -v file="${3##*/}" '$2 == file { print $1 }')"
        got="$(shasum -a 256 "$1/$2.tar.gz" | cut -d' ' -f1)"
        [[ -n "$want" && "$want" == "$got" ]] || { echo "bench-tools: $3: sha256 $got, want $want" >&2; exit 1; }
        tar -xzOf "$1/$2.tar.gz" "$5" >"$1/$2.part"
        rm "$1/$2.tar.gz"
        chmod +x "$1/$2.part"
        mv "$1/$2.part" "$1/$2"
    }
    benchmark='https://github.com/spegel-org/benchmark/releases/download/v{{ benchmark_version }}'
    fetch '{{ bench_dir }}/benchmark-{{ benchmark_version }}' benchmark \
        "$benchmark/benchmark_{{ benchmark_version }}_${os}_$arch.tar.gz" \
        "$benchmark/benchmark_{{ benchmark_version }}_checksums.txt" benchmark
    helm="https://get.helm.sh/helm-v{{ helm_version }}-$os-$arch.tar.gz"
    fetch '{{ bench_dir }}/helm-{{ helm_version }}' helm "$helm" "$helm.sha256sum" "$os-$arch/helm"

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

# The reflector's index under Shuttle's randomised schedules (D97), in its own target directory: `--cfg shuttle`
# rebuilds every crate.
shuttle:
    RUSTFLAGS='--cfg shuttle' CARGO_TARGET_DIR=target/shuttle cargo test -p speculaire-reflect --lib --locked schedules

# Replay every target's seeds, their truncations and bit flips on stable (part of `just check`).
fuzz-smoke:
    cargo test --manifest-path fuzz/Cargo.toml --lib --locked
