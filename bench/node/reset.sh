# D35's reset of a node, run in its host namespaces: no mirror, no bench image, a cold page cache. check.sh then
# checks what it left.
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

# containerd's garbage collector removes the blobs of a removed image a moment later.
for _ in $(seq 30); do
    [[ "$(ctr -n k8s.io content ls | grep -c 'spegel-org/benchmark' || true)" == 0 ]] && break
    sleep 1
done

sync
echo 3 >/proc/sys/vm/drop_caches
