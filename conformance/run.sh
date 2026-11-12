#!/bin/sh
# The distribution-spec conformance suite against the mirror (D85), run by `just conformance` in the Go image, in a
# container of its own: `speculaire configure` and the agent act on the container's root, as on a node.
#
# In: CONFORMANCE_REV, the commit of opencontainers/distribution-spec; /usr/bin/speculaire; /conformance (this
# directory) and /packaging (the reference config), read-only; /results, where the suite's output goes.
set -eu

apk add --no-cache git socat curl >/dev/null

# The suite, built from the pinned commit.
git clone --quiet --filter=blob:none https://github.com/opencontainers/distribution-spec /tmp/spec
git -C /tmp/spec checkout --quiet "$CONFORMANCE_REV"
(cd /tmp/spec/conformance && go build -o /usr/bin/oci-conformance .)

# What the node holds: an image index, an image manifest, its config and two layers, in containerd's content directory.
blobs=/var/lib/containerd/io.containerd.content.v1.content/blobs/sha256
mkdir -p "$blobs" /tmp/seed
put() { # file -> digest on stdout; the file is stored under its hash
    hex=$(sha256sum "$1" | cut -d' ' -f1)
    cp "$1" "$blobs/$hex"
    echo "sha256:$hex"
}
head -c 100000 /dev/urandom >/tmp/seed/layer1
head -c 3000 /dev/urandom >/tmp/seed/layer2
layer1=$(put /tmp/seed/layer1)
layer2=$(put /tmp/seed/layer2)
size() { wc -c <"$1" | tr -d ' '; }
printf '{"architecture":"amd64","os":"linux","rootfs":{"type":"layers","diff_ids":["%s","%s"]}}' "$layer1" "$layer2" >/tmp/seed/config
config=$(put /tmp/seed/config)
cat >/tmp/seed/manifest <<EOF
{"schemaVersion":2,"mediaType":"application/vnd.oci.image.manifest.v1+json","config":{"mediaType":"application/vnd.oci.image.config.v1+json","digest":"$config","size":$(size /tmp/seed/config)},"layers":[{"mediaType":"application/vnd.oci.image.layer.v1.tar","digest":"$layer1","size":$(size /tmp/seed/layer1)},{"mediaType":"application/vnd.oci.image.layer.v1.tar","digest":"$layer2","size":$(size /tmp/seed/layer2)}]}
EOF
manifest=$(put /tmp/seed/manifest)
cat >/tmp/seed/index <<EOF
{"schemaVersion":2,"mediaType":"application/vnd.oci.image.index.v1+json","manifests":[{"mediaType":"application/vnd.oci.image.manifest.v1+json","digest":"$manifest","size":$(size /tmp/seed/manifest),"platform":{"architecture":"amd64","os":"linux"}}]}
EOF
index=$(put /tmp/seed/index)

# The node: the reference config, `configure` (no runtime runs here), and the agent.
mkdir -p /etc/speculaire
cp /packaging/config.toml /etc/speculaire/config.toml
speculaire configure --runtime containerd
speculaire agent >/tmp/agent.log 2>&1 &
i=0
until curl -sf http://127.0.0.1:7482/readyz >/dev/null; do
    i=$((i + 1))
    [ "$i" -lt 100 ] || { cat /tmp/agent.log >&2; echo "the agent did not become ready" >&2; exit 1; }
    sleep 0.1
done

# The suite sends no client certificate: socat sends the one of the mirror's directory and speaks plain HTTP to it.
dir=/var/lib/speculaire/mirror
socat TCP-LISTEN:5000,fork,reuseaddr,bind=127.0.0.1 \
    "OPENSSL:127.0.0.1:7480,cert=$dir/client.pem,cafile=$dir/ca.crt,verify=1,commonname=127.0.0.1" &
sleep 0.5

# Pull only, on content that is there. The tag is one the mirror cannot resolve (D6): its tests fail, as listed.
export OCI_REGISTRY=127.0.0.1:5000 OCI_TLS=disabled OCI_RESULTS_DIR=/results OCI_VERSION=1.1 OCI_LOG=warn
export OCI_REPO1=conformance/repo1 OCI_REPO2=conformance/repo2
export OCI_API_PUSH=false OCI_API_BLOBS_DELETE=false OCI_API_MANIFESTS_DELETE=false OCI_API_TAGS_DELETE=false
export OCI_API_TAGS_LIST=false OCI_API_REFERRER=false
export OCI_RO_DATA_TAGS=latest
export OCI_RO_DATA_MANIFESTS="$index $manifest"
export OCI_RO_DATA_BLOBS="$config $layer1 $layer2"
rm -rf /results/*
# It exits 1 while a test fails, and panics writing its results.yaml when push is off: its console report is what counts.
oci-conformance >/results/console.txt 2>/results/stderr.txt || true
cat /results/console.txt
cd /conformance/check && go run . /results/console.txt /conformance/expected-failures.txt
