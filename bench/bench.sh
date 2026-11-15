#!/usr/bin/env bash
# D35's benchmark, as D106 runs it: spegel-org/benchmark's `measure` of each image set with no mirror, then with
# Spegel, then with speculaire, on the cluster of a cluster-admin kubeconfig. Each node is reset before each run.
# Writes the samples and results.json into the output directory, and the tables in Markdown to stdout.
#
# Usage, from the repository's root: bench/bench.sh <kubeconfig> <output dir> <set>..., a set being
# <size>-<layers> such as 100MB-4. kubectl, helm, benchmark and jq come from PATH; BENCH_NODE names the node pod's
# image, SPEGEL_VERSION the Spegel chart's version. Each node's speculaire is the binary of `just musl` for its
# architecture.
set -euo pipefail

kubeconfig="$1" out="$2"
shift 2
sets=("$@")
ns=speculaire-bench
runs=(baseline spegel speculaire)

k() { kubectl --kubeconfig "$kubeconfig" "$@"; }
log() { echo "bench: $*" >&2; }
die() {
    log "$*"
    exit 1
}
pod() { # <node>: its node pod
    awk -v node="$1" '$1 == node { print $2 }' "$out/pods.tsv"
}
on() { # <node> <command>...: runs the command in the node's host namespaces, with this script's stdin
    local pod
    pod="$(pod "$1")"
    shift
    k -n "$ns" exec -i "$pod" -- nsenter -t 1 -a -- "$@"
}
binary() { # <node>: the speculaire binary for the node's architecture
    case "$(jq -r --arg n "$1" '.items[] | select(.metadata.name == $n) | .status.nodeInfo.architecture' "$out/nodes.json")" in
        amd64) echo target/musl/x86_64-unknown-linux-musl/speculaire ;;
        arm64) echo target/musl/aarch64-unknown-linux-musl/speculaire ;;
        *) die "$1: no speculaire for its architecture" ;;
    esac
}
socket() { # <address> <port>
    [[ "$1" == *:* ]] && echo "[$1]:$2" || echo "$1:$2"
}

reset() { # every node to no mirror, no bench image, a cold page cache (D35)
    if helm --kubeconfig "$kubeconfig" status --namespace spegel spegel >/dev/null 2>&1; then
        helm --kubeconfig "$kubeconfig" uninstall --namespace spegel spegel --wait --timeout 5m >/dev/null
    fi
    k delete namespace spegel spegel-benchmark --ignore-not-found --wait >/dev/null
    for node in "${nodes[@]}"; do
        on "$node" bash -s <bench/node/reset.sh || die "$node: the reset failed"
    done
}

install_spegel() {
    helm --kubeconfig "$kubeconfig" upgrade --install --create-namespace --namespace spegel spegel \
        oci://ghcr.io/spegel-org/helm-charts/spegel --version "$SPEGEL_VERSION" --wait --timeout 5m >/dev/null
}

install_speculaire() { # the reflectors first, on the control-plane nodes, then the agents
    local url members='' node bin
    url="https://$(socket "$(jq -r '.[0].address' "$out/reflectors.json")" 7483)"
    for node in "${reflectors[@]}"; do
        members+="${members:+, }{ node = \"$node\", address = \"$(socket "$(jq -r --arg n "$node" \
            '.[] | select(.node == $n) | .address' "$out/reflectors.json")" 7483)\" }"
    done
    sed -e "s|^#url = \"\"$|url = \"$url\"|" -e "s|^#members = \[\]$|members = [$members]|" packaging/config.toml \
        >"$out/agent.toml"
    sed 's/^#role = "agent"$/role = "reflector"/' "$out/agent.toml" >"$out/reflector.toml"
    grep -q '^url = ' "$out/agent.toml"
    grep -q '^members = ' "$out/agent.toml"
    grep -q '^role = "reflector"$' "$out/reflector.toml"
    for node in "${reflectors[@]}" "${agents[@]}"; do
        bin="$(binary "$node")"
        on "$node" sh -c 'cat >/usr/bin/speculaire.part && chmod 0755 /usr/bin/speculaire.part &&
            mv /usr/bin/speculaire.part /usr/bin/speculaire' <"$bin"
        on "$node" sh -c 'cat >/usr/lib/systemd/system/speculaire.service' <packaging/speculaire.service
        if [[ " ${reflectors[*]} " == *" $node "* ]]; then
            on "$node" sh -c 'mkdir -p /etc/speculaire && cat >/etc/speculaire/config.toml' <"$out/reflector.toml"
        else
            on "$node" sh -c 'mkdir -p /etc/speculaire && cat >/etc/speculaire/config.toml' <"$out/agent.toml"
        fi
        on "$node" sh -c 'speculaire configure >/dev/null && systemctl daemon-reload &&
            systemctl enable --quiet --now speculaire.service' </dev/null
    done
    # Every agent streams to every reflector before the first pull.
    for node in "${nodes[@]}"; do
        for _ in $(seq 60); do
            connected="$(on "$node" sh -c 'curl -sf http://127.0.0.1:7482/metrics |
                grep -c "^speculaire_reflector_connected{.*} 1$"' </dev/null || true)"
            [[ "$connected" == "${#reflectors[@]}" ]] && continue 2
            sleep 1
        done
        die "$node: its agent streams to $connected of ${#reflectors[@]} reflectors"
    done
}

usage() { # <run>: "<node> <usec>" of the run's agent on each node that runs it
    [[ "$1" == baseline ]] && return
    for node in "${nodes[@]}"; do
        on "$node" bash -s -- "$1" cpu <bench/node/usage.sh | sed "s/^/$node /"
    done
}

sample() { # <run> <dir>: samples the memory of the run's agent on each node into <dir>/memory-<node>, until `peaks`
    sampling=()
    [[ "$1" == baseline ]] && return
    for node in "${nodes[@]}"; do
        # kubectl itself, not a function's subshell, so that killing it closes the sampler's output.
        kubectl --kubeconfig "$kubeconfig" -n "$ns" exec -i "$(pod "$node")" -- nsenter -t 1 -a -- \
            bash -s -- "$1" memory <bench/node/usage.sh >"$2/memory-$node" &
        sampling+=("$!")
    done
}

peaks() { # <dir>: stops the samplers, then prints "<node> <anon> <file>", the peaks of each node's samples
    local file
    ((${#sampling[@]} == 0)) || kill "${sampling[@]}" 2>/dev/null || true
    wait "${sampling[@]}" 2>/dev/null || true
    for file in "$1"/memory-*; do
        [[ -s "$file" ]] || continue
        awk -v node="${file##*/memory-}" '$1 > anon { anon = $1 } $2 > file { file = $2 }
            END { print node, anon + 0, file + 0 }' "$file"
    done
}

measure() { # <run>: each set, into $out/<run>/<set>.json
    local run="$1" set dir
    for set in "${sets[@]}"; do
        dir="$out/$run/$set"
        mkdir -p "$dir"
        log "$run: $set"
        usage "$run" >"$dir/usage-before"
        sample "$run" "$dir"
        benchmark measure --kubeconfig "$kubeconfig" --output-dir "$dir" \
            --images "ghcr.io/spegel-org/benchmark:v1-$set" "ghcr.io/spegel-org/benchmark:v2-$set" >"$dir/measure.log" 2>&1 ||
            die "$run: $set: benchmark measure failed: $dir/measure.log"
        usage "$run" >"$dir/usage-after"
        peaks "$dir" >"$dir/memory"
        # Nearest-rank percentiles of the pull durations, in seconds, and the agent's CPU seconds and peak anon and file
        # bytes on each node.
        jq -n --slurpfile bench <(cat "$dir"/benchmark-*.json) --rawfile before "$dir/usage-before" \
            --rawfile after "$dir/usage-after" --rawfile memory "$dir/memory" '
            def stats: map(.duration / 1e9) | sort
                | { p50: .[(length * 0.5 | ceil) - 1], p95: .[(length * 0.95 | ceil) - 1], max: .[-1] };
            def column($n): split("\n") | map(select(. != "") | split(" ") | { (.[0]): (.[$n] | tonumber) })
                | add // {};
            ($before | column(1)) as $start
            | { create: ($bench[0].create.samples | stats), update: ($bench[0].update.samples | stats),
                cpu_seconds: ($after | column(1) | with_entries(.value = (.value - $start[.key]) / 1e6)),
                memory: { anon: ($memory | column(1)), file: ($memory | column(2)) } }' >"$dir.json"
    done
}

for tool in kubectl helm benchmark jq; do
    command -v "$tool" >/dev/null || die "no $tool on PATH"
done
mkdir -p "$out"
k get nodes -o json >"$out/nodes.json"
mapfile -t nodes < <(jq -r '.items[].metadata.name' "$out/nodes.json")
jq '[.items[] | select(.metadata.labels | has("node-role.kubernetes.io/control-plane"))
    | { node: .metadata.name, address: first(.status.addresses[] | select(.type == "InternalIP") | .address) }]' \
    "$out/nodes.json" >"$out/reflectors.json"
mapfile -t reflectors < <(jq -r '.[].node' "$out/reflectors.json")
((${#reflectors[@]} > 0)) || die "no node labelled node-role.kubernetes.io/control-plane, for the reflectors"
mapfile -t agents < <(printf '%s\n' "${nodes[@]}" | grep -vxF -f <(printf '%s\n' "${reflectors[@]}") || true)
for node in "${nodes[@]}"; do
    bin="$(binary "$node")"
    [[ -x "$bin" ]] || die "$node: no $bin: run just musl $(basename "$(dirname "$bin")")"
done

sed "s|@image@|$BENCH_NODE|" bench/node.yaml | k apply -f - >/dev/null
k -n "$ns" rollout status daemonset/node --timeout=180s >/dev/null
k -n "$ns" get pods -l app=speculaire-bench-node \
    -o jsonpath='{range .items[*]}{.spec.nodeName}{"\t"}{.metadata.name}{"\n"}{end}' >"$out/pods.tsv"
trap 'kill $(jobs -p) 2>/dev/null || true; reset || true; k delete namespace "$ns" --ignore-not-found --wait >/dev/null || true' EXIT

for run in "${runs[@]}"; do
    log "$run: reset"
    reset
    case "$run" in
        spegel) install_spegel ;;
        speculaire) install_speculaire ;;
    esac
    measure "$run"
done

# results.json: per run, each set's pull seconds, and the agent's CPU seconds and peak memory per node.
for run in "${runs[@]}"; do
    for set in "${sets[@]}"; do
        jq --arg run "$run" --arg set "$set" '{ ($run): { sets: { ($set): . } } }' "$out/$run/$set.json"
    done
done | jq -s --arg spegel "$SPEGEL_VERSION" --arg speculaire "$(git rev-parse --short HEAD)" \
    --slurpfile nodes "$out/nodes.json" '
    { kubernetes: $nodes[0].items[0].status.nodeInfo.kubeletVersion,
      runtimes: ($nodes[0].items | map(.status.nodeInfo.containerRuntimeVersion) | unique),
      nodes: ($nodes[0].items | length), spegel: $spegel, speculaire: $speculaire,
      runs: (reduce .[] as $part ({}; . * $part)) }' >"$out/results.json"

jq -r --argjson sets "$(printf '%s\n' "${sets[@]}" | jq -R . | jq -s .)" '
    def s: . * 100 | round | tostring | if length < 3 then ("00" + .)[-3:] end | .[:-2] + "." + .[-2:];
    def pulls: "\(.p50 | s) / \(.p95 | s) / \(.max | s)";
    def most: [.[]] | max // null | if . == null then "-" else s end;
    . as $r
    | "### D35 bench: \($r.nodes) nodes, Kubernetes \($r.kubernetes), \($r.runtimes | join(", ")), Spegel v\($r.spegel), speculaire \($r.speculaire)",
      "",
      "Pull seconds, p50 / p95 / max, on the untainted nodes:",
      "",
      "| Set | Phase | No mirror | Spegel | speculaire |",
      "|---|---|---|---|---|",
      ($sets[] as $set | ("create", "update") as $phase
        | "| \($set) | \($phase) | \([$r.runs.baseline, $r.runs.spegel, $r.runs.speculaire]
            | map(.sets[$set][$phase] | pulls) | join(" | ")) |"),
      "",
      "Agent CPU seconds per set, and peak memory in MiB over the sets, on the node with the most: anon is the agent itself,",
      "file the page cache charged to it. The release bar compares anon (D114).",
      "",
      "| Agent | \($sets | join(" | ")) | Peak anon MiB | Peak file MiB |",
      "|---|\($sets | map("---") | join("|"))|---|---|",
      (("spegel", "speculaire") as $run | $r.runs[$run]
        | "| \($run) | \([$sets[] as $set | .sets[$set].cpu_seconds | most] | join(" | "))"
          + " | \([.sets[].memory.anon[] / 1048576] | most) | \([.sets[].memory.file[] / 1048576] | most) |")' \
    "$out/results.json"
