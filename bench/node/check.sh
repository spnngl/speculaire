# D35's check of a node after its reset, run in its host namespaces with the node's name: prints one line
# "<node>: <what>" for each thing a run left that changes the next one's pulls, and fails if there is any.
set -euo pipefail

node="$1"
left=()

# A mirror entry that the pulls of ghcr.io/spegel-org/benchmark would go through.
config_path="$(containerd config dump 2>/dev/null | awk -F "[\"']" '$1 ~ /^ *config_path = $/ { print $2; exit }')"
if [[ -n "$config_path" ]]; then
    for file in "$config_path/_default/hosts.toml" "$config_path/ghcr.io/hosts.toml"; do
        if [[ -f "$file" ]] && grep -q '^\[host\.' "$file"; then
            left+=("$file: a mirror entry is left")
        fi
    done
fi

# A blob of the bench images, which the next run would not pull.
content="$(ctr -n k8s.io content ls)"
blobs="$(grep -c 'spegel-org/benchmark' <<<"$content" || true)"
if ((blobs == 1)); then
    left+=("containerd's content store holds 1 blob of ghcr.io/spegel-org/benchmark")
elif ((blobs > 1)); then
    left+=("containerd's content store holds $blobs blobs of ghcr.io/spegel-org/benchmark")
fi

for what in "${left[@]}"; do
    echo "$node: $what"
done
((${#left[@]} == 0))
