# D35's reset of a node, run in its host namespaces: no mirror, no bench image, a cold page cache. It fails, naming
# the file, when a mirror entry or a bench blob is left.
set -euo pipefail

if systemctl cat speculaire.service >/dev/null 2>&1; then
    systemctl disable --now speculaire.service >/dev/null 2>&1
fi
if [[ -x /usr/bin/speculaire ]]; then
    /usr/bin/speculaire unconfigure >/dev/null
fi
rm -rf /usr/bin/speculaire /usr/lib/systemd/system/speculaire.service /etc/speculaire /var/lib/speculaire \
    /var/lib/spegel
systemctl daemon-reload

images="$(crictl images | awk '$1 == "ghcr.io/spegel-org/benchmark" { print $3 }')"
if [[ -n "$images" ]]; then
    # One ID per word.
    # shellcheck disable=SC2086
    crictl rmi $images >/dev/null
fi

config_path="$(containerd config dump 2>/dev/null | awk -F "[\"']" '$1 ~ /^ *config_path = $/ { print $2; exit }')"
if [[ -n "$config_path" ]]; then
    for file in "$config_path/_default/hosts.toml" "$config_path/ghcr.io/hosts.toml"; do
        if [[ -f "$file" ]] && grep -q '^\[host\.' "$file"; then
            echo "$file: a mirror entry is left" >&2
            exit 1
        fi
    done
fi

# containerd's garbage collector removes the blobs of a removed image a moment later.
for _ in $(seq 30); do
    left="$(ctr -n k8s.io content ls | grep -c 'spegel-org/benchmark' || true)"
    [[ "$left" == 0 ]] && break
    sleep 1
done
if [[ "$left" != 0 ]]; then
    echo "containerd's content store holds $left blobs of spegel-org/benchmark" >&2
    exit 1
fi

sync
echo 3 >/proc/sys/vm/drop_caches
