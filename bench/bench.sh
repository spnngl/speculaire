#!/usr/bin/env bash
# D35's benchmark, as D106 runs it: spegel-org/benchmark's `measure` of each image set with no mirror, then with
# Spegel, then with speculaire, its gate in audit with a policy that every bench image fails (D178), on the cluster of a
# cluster-admin kubeconfig. Each node is reset and checked before each run. Writes the samples and results.json into
# the output directory, and the tables in Markdown to stdout.
#
# Usage, from the repository's root: bench/bench.sh <kubeconfig> <output dir> <set>..., a set being
# <size>-<layers> such as 100MB-4. kubectl, helm, benchmark, jq and cargo come from PATH; BENCH_NODE names the node pod's
# image, SPEGEL_VERSION the Spegel chart's version. Each node's speculaire is the binary of `just musl` for its
# architecture, built when missing.
set -euo pipefail

kubeconfig="$1" out="$2"
shift 2
sets=("$@")
ns=speculaire-bench
runs=(baseline spegel speculaire)

protobuf='application/vnd.google.protobuf; proto=io.prometheus.client.MetricFamily; encoding=delimited'

k() { kubectl --kubeconfig "$kubeconfig" "$@"; }
# The samples of a native histogram over a set, and a percentile of them: e2e/src/bin/histogram.rs.
histogram() { cargo run -p e2e --locked --quiet --bin histogram -- "$@"; }
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
        left="$(on "$node" bash -s -- "$node" <bench/node/check.sh)" ||
            die "the reset left what the next run would see:"$'\n'"${left:-$node: the check failed}"
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
    # Every agent, a reflector being one, gates in audit with bench/policy.yaml (D178).
    sed -e "s|^#url = \"\"$|url = \"$url\"|" -e "s|^#members = \[\]$|members = [$members]|" \
        -e 's/^#mode = "audit"$/mode = "audit"/' packaging/config.toml >"$out/agent.toml"
    sed 's/^#role = "agent"$/role = "reflector"/' "$out/agent.toml" >"$out/reflector.toml"
    grep -q '^url = ' "$out/agent.toml"
    grep -q '^members = ' "$out/agent.toml"
    grep -q '^mode = "audit"$' "$out/agent.toml"
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
        on "$node" sh -c 'cat >/etc/speculaire/policy.yaml' <bench/policy.yaml
        on "$node" sh -c 'speculaire configure >/dev/null && systemctl daemon-reload &&
            systemctl enable --quiet --now speculaire.service' </dev/null
    done
    # Every agent streams to every reflector, and its gate is registered with the runtime's NRI, before the first pull.
    for node in "${nodes[@]}"; do
        for _ in $(seq 60); do
            on "$node" curl -sf http://127.0.0.1:7482/metrics </dev/null >"$out/metrics" || true
            connected="$(grep -c '^speculaire_reflector_connected{.*} 1$' "$out/metrics" || true)"
            registered=no
            grep -qx 'speculaire_nri_connected 1' "$out/metrics" && registered=yes
            [[ "$connected" == "${#reflectors[@]}" && "$registered" == yes ]] && continue 2
            sleep 1
        done
        die "$node: its agent streams to $connected of ${#reflectors[@]} reflectors; its gate registered with NRI: $registered"
    done
}

metrics() { # <run> <dir> <before|after>: each node's agent's metrics, in the text and the protobuf exposition
    local node
    [[ "$1" == speculaire ]] || return 0
    for node in "${nodes[@]}"; do
        on "$node" curl -sf http://127.0.0.1:7482/metrics </dev/null >"$2/metrics-$3-$node.txt"
        on "$node" curl -sf -H "Accept: $protobuf" http://127.0.0.1:7482/metrics </dev/null >"$2/metrics-$3-$node.pb"
    done
}

counter() { # <dir> <pattern>: how much the counters whose series match the pattern grew over the set, on all nodes
    local node when
    for node in "${nodes[@]}"; do
        for when in before after; do
            awk -v when="$when" -v pattern="$2" '$1 ~ pattern { sum += $2 }
                END { print (when == "before" ? -sum : sum) }' "$1/metrics-$when-$node.txt"
        done
    done | awk '{ sum += $1 } END { print sum + 0 }'
}

gate() { # <run> <dir>: the gate's decisions over the set and their p99, proving that it gated in audit with a policy
    local dir="$2" readings=() node decisions seconds rejected
    if [[ "$1" != speculaire ]]; then
        echo null
        return
    fi
    for node in "${nodes[@]}"; do
        readings+=("$dir/metrics-before-$node.pb" "$dir/metrics-after-$node.pb")
    done
    read -r decisions seconds < <(histogram speculaire_gate_seconds 99 "${readings[@]}") ||
        die "$1: no p99 of the gate's decisions"
    rejected="$(counter "$dir" '^speculaire_verifications_total\\{.*result="rejected"')"
    ((decisions > 0)) || die "$1: the gate decided no container"
    ((rejected > 0)) || die "$1: no verification rejected a bench image: does bench/policy.yaml match them?"
    jq -n --argjson decisions "$decisions" --argjson p99 "$seconds" --argjson rejected "$rejected" \
        '{ decisions: $decisions, p99_seconds: $p99, rejected: $rejected }'
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
        metrics "$run" "$dir" before
        sample "$run" "$dir"
        benchmark measure --kubeconfig "$kubeconfig" --output-dir "$dir" \
            --images "ghcr.io/spegel-org/benchmark:v1-$set" "ghcr.io/spegel-org/benchmark:v2-$set" >"$dir/measure.log" 2>&1 ||
            die "$run: $set: benchmark measure failed: $dir/measure.log"
        usage "$run" >"$dir/usage-after"
        metrics "$run" "$dir" after
        peaks "$dir" >"$dir/memory"
        gate "$run" "$dir" >"$dir/gate"
        # Nearest-rank percentiles of the pull durations, in seconds, the agent's CPU seconds and peak anon and file bytes
        # on each node, and the gate's decisions, over both phases.
        jq -n --slurpfile bench <(cat "$dir"/benchmark-*.json) --rawfile before "$dir/usage-before" \
            --rawfile after "$dir/usage-after" --rawfile memory "$dir/memory" --slurpfile gate "$dir/gate" '
            def stats: map(.duration / 1e9) | sort
                | { p50: .[(length * 0.5 | ceil) - 1], p95: .[(length * 0.95 | ceil) - 1], max: .[-1] };
            def column($n): split("\n") | map(select(. != "") | split(" ") | { (.[0]): (.[$n] | tonumber) })
                | add // {};
            ($before | column(1)) as $start
            | { create: ($bench[0].create.samples | stats), update: ($bench[0].update.samples | stats),
                cpu_seconds: ($after | column(1) | with_entries(.value = (.value - $start[.key]) / 1e6)),
                memory: { anon: ($memory | column(1)), file: ($memory | column(2)) }, gate: $gate[0] }' >"$dir.json"
    done
}

for tool in kubectl helm benchmark jq cargo; do
    command -v "$tool" >/dev/null || die "no $tool on PATH"
done
cargo build -p e2e --locked --quiet --bin histogram
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
    [[ -x "$bin" ]] || just musl "$(basename "$(dirname "$bin")")" >&2
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

# results.json: per run, each set's pull seconds, the agent's CPU seconds and peak memory per node, and its gate.
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
          + " | \([.sets[].memory.anon[] / 1048576] | most) | \([.sets[].memory.file[] / 1048576] | most) |"),
      "",
      "The gate of speculaire per set, both phases, over the nodes: its CreateContainer decisions, and their p99 in ms,",
      "the upper bound of a native histogram bucket.",
      "",
      "| Set | Decisions | Gate p99 ms |",
      "|---|---|---|",
      ($sets[] as $set | $r.runs.speculaire.sets[$set].gate
        | "| \($set) | \(.decisions) | \(.p99_seconds * 1000 | s) |")' \
    "$out/results.json"
