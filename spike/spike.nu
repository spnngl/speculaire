#!/usr/bin/env nu
# M0 spike harness (throwaway). Build and cluster plumbing for every spike, and `ci <step> <version>`.
#   nu spike.nu up 2.3          build the node image, create cluster spk-23
#   nu spike.nu build           cargo build --release inside rust:1.99.1-alpine, binaries into out/
#   nu spike.nu put hello spk-23-worker
#   nu spike.nu check 00 2.3
#   nu spike.nu down

const HERE = path self | path dirname
const PINNED = {"2.3": "2.3.7", "2.4": "2.4.2"}
const TEST_IMAGE = "docker.io/library/busybox:1.37"

def kind-bin [] {
    let local = $HERE | path join ".bin" "kind"
    if ($local | path exists) { $local } else { "kind" }
}

# 2.3 -> newest 2.3.x release, falling back to the pin when GitHub is unreachable.
def containerd-version [minor: string] {
    let pinned = $PINNED | get $minor
    try {
        http get --headers [User-Agent spike] "https://api.github.com/repos/containerd/containerd/releases?per_page=100"
        | where {|r| (not $r.prerelease) and ($r.tag_name | str starts-with $"v($minor).") }
        | get tag_name
        | each {|t| $t | str trim --left --char "v" }
        | each {|t| {t: $t, patch: ($t | split row "." | last | into int)} }
        | sort-by patch
        | last
        | get t
    } catch { $pinned }
}

def cluster-name [minor: string] { $"spk-($minor | str replace '.' '')" }

def nodes [minor: string] {
    ^(kind-bin) get nodes --name (cluster-name $minor) | lines | sort
}

def sh-node [node: string, cmd: string] {
    ^docker exec $node sh -c $cmd
}

# Build the node image and create the cluster.
def "main up" [minor: string] {
    let ver = containerd-version $minor
    let name = cluster-name $minor
    let img = $"spk-node:($ver)"
    print $"== containerd ($ver), image ($img), cluster ($name)"
    ^docker build --build-arg $"VERSION=($ver)" -t $img ($HERE | path join node)
    ^(kind-bin) create cluster --name $name --image $img --config ($HERE | path join kind.yaml) --wait 180s
}

# Build every crate in rust:1.99.1-alpine; binaries land in out/. Static musl, native architecture.
def "main build" [] {
    ^docker build -t spk-build ($HERE | path join build)
    mkdir ($HERE | path join out)
    ^docker run --rm -v $"($HERE):/src" -v spk-cargo:/usr/local/cargo/registry -v spk-target:/target -e CARGO_TARGET_DIR=/target spk-build sh -c r#'cargo build --release --workspace -j 4 && find /target/release -maxdepth 1 -type f -perm -u+x ! -name "*.*" -exec cp {} /src/out/ \;'#
}

# docker cp a built binary into a node.
def "main put" [bin: string, node: string] {
    ^docker cp ($HERE | path join out $bin) $"($node):/usr/local/bin/($bin)"
}

def "main down" [] {
    for m in ($PINNED | columns) {
        try { ^(kind-bin) delete cluster --name (cluster-name $m) }
    }
}

# Collect checks: each returns a list of {check, ok, detail}.
def check [name: string, ok: bool, detail: string] {
    {check: $name, ok: $ok, detail: ($detail | lines | str join " | " | str substring 0..400)}
}

def "main check 00" [minor: string] {
    let ver = containerd-version $minor
    let name = cluster-name $minor
    let ctx = $"kind-($name)"
    let nodes = nodes $minor
    mut r = []

    let k = ^kubectl --context $ctx get nodes -o json | from json | get items
    let ready = $k | where {|n| ($n.status.conditions | where type == "Ready" | first).status == "True" } | length
    $r = $r | append (check "3 Ready nodes" ($ready == 3) $"($ready) ready")

    for n in $nodes {
        let v = sh-node $n "containerd --version" | str trim
        $r = $r | append (check $"($n) containerd ($ver)" ($v | str contains $" v($ver) ") $v)
        let nri = sh-node $n "ls /var/run/nri/nri.sock" | str trim
        $r = $r | append (check $"($n) nri.sock" ($nri == "/var/run/nri/nri.sock") $nri)
        # 2.3: `crictl info` no longer lists the registry config; the merged config does.
        let dump = sh-node $n "containerd config dump 2>/dev/null"
        let cp = $dump | lines | where {|l| ($l | str trim) == "config_path = '/etc/containerd/certs.d'" } | length
        $r = $r | append (check $"($n) config_path" ($cp == 1) "containerd config dump")
        let nri = $dump | lines | where {|l| ($l | str trim) in ["disable = false" "disable_connections = false"] } | length
        $r = $r | append (check $"($n) nri enabled" ($nri == 2) "containerd config dump: disable, disable_connections")
    }

    # hello: static, and runs under the D53 unit inside a worker.
    let worker = $nodes | where {|n| $n | str contains worker } | first
    main put hello $worker
    ^docker cp ($HERE | path join hello.service) $"($worker):/etc/systemd/system/hello.service"
    let file = ^docker exec $worker sh -c "ls -l /usr/local/bin/hello; od -An -tx1 -N4 /usr/local/bin/hello" | str trim
    $r = $r | append (check "hello present" ($file | str contains "7f 45 4c 46") $file)
    let start = try { sh-node $worker "systemctl daemon-reload; systemctl start hello.service; echo started" | str trim } catch {|e| $e.msg }
    let journal = sh-node $worker "journalctl -u hello.service --no-pager -o cat | tail -20"
    let status = sh-node $worker "systemctl show hello.service -p Result -p ExecMainStatus" | lines | str join " "
    $r = $r | append (check "hello.service exits 0" ($status | str contains "ExecMainStatus=0") $"($status); ($journal | lines | str join ' | ')")

    let sec = sh-node $worker "systemd-analyze security hello.service --no-pager --json=short" | from json
    let have = $sec | where set == true | get name
    let want = [
        NoNewPrivileges PrivateTmp PrivateDevices ProtectSystem ProtectHome ProtectKernelTunables ProtectKernelModules
        ProtectKernelLogs ProtectControlGroups ProtectClock ProtectHostname RestrictNamespaces RestrictRealtime
        RestrictSUIDSGID LockPersonality MemoryDenyWriteExecute SystemCallArchitectures RestrictAddressFamilies
        CapabilityBoundingSet AmbientCapabilities SystemCallFilter
    ]
    let missing = $want | where {|w| not ($have | any {|h| $h | str starts-with $w }) }
    $r = $r | append (check "D53 settings applied" ($missing | is-empty) $"missing: ($missing | str join ' ')")

    # the test image runs.
    ^kubectl --context $ctx delete pod bb --ignore-not-found --wait=true
    ^kubectl --context $ctx run bb $"--image=($TEST_IMAGE)" --restart=Never -- sleep 3600
    let pod = try { ^kubectl --context $ctx wait --for=condition=Ready pod/bb --timeout=120s; "ready" } catch {|e| $e.msg }
    $r = $r | append (check "busybox Running" ($pod == "ready") $pod)
    ^kubectl --context $ctx delete pod bb --wait=false

    print $r
    if ($r | any {|c| not $c.ok }) { error make {msg: $"step 00 failed on ($minor)"} }
}

def pod-phase [ctx: string, pod: string, want: string, timeout: duration] {
    let deadline = (date now) + $timeout
    mut phase = ""
    while (date now) < $deadline {
        let raw = ^kubectl --context $ctx get pod $pod -o jsonpath='{.status.containerStatuses[0].state}' | str trim
        $phase = if ($raw | is-empty) { "none" } else { $raw | from json | columns | get 0? | default "none" }
        if $phase == $want { break }
        sleep 2sec
    }
    $phase
}

def run-pod [ctx: string, node: string, name: string, labels: string] {
    ^kubectl --context $ctx delete pod $name --ignore-not-found --wait=true o+e>| ignore
    let overrides = {spec: {nodeName: $node}} | to json --raw
    ^kubectl --context $ctx run $name $"--image=($TEST_IMAGE)" --restart=Never $"--labels=($labels)" $"--overrides=($overrides)" -- sleep 3600 o+e>| ignore
}

def start-plugin [node: string, args: string] {
    ^docker exec $node sh -c "pkill nri-spike; true"
    ^docker exec $node sh -c ("rm -f /tmp/nri-spike.log; (nri-spike " + $args + " > /tmp/nri-spike.log 2>&1 &); sleep 2; cat /tmp/nri-spike.log")
}

# Step 01: NRI plugin over our mux, then the default_validator with required_plugins.
def "main check 01" [minor: string] {
    let name = cluster-name $minor
    let ctx = $"kind-($name)"
    let node = $"($name)-worker"
    mut r = []

    # Idempotent: drop pods and a default_validator left by an earlier run.
    ^kubectl --context $ctx delete pod ok bad ok2 ok3 ok4 --ignore-not-found --wait=true o+e>| ignore
    sh-node $node "pkill nri-spike; sed -i '/default_validator/,$d' /etc/containerd/config.toml; systemctl restart containerd; sleep 3"
    main put nri-spike $node
    start-plugin $node "" | ignore
    # Synchronize can trail Configure by seconds just after a containerd restart (seen in CI).
    mut log = ""
    for _ in 1..30 {
        $log = ^docker exec $node cat /tmp/nri-spike.log
        if ($log | str contains "Synchronize") { break }
        sleep 500ms
    }
    $r = $r | append (check "registered < 5s" ($log | str contains "registered as speculaire-50") ($log | lines | first))
    let configure = $log | lines | where {|l| $l | str contains "Configure" } | get 0? | default ""
    $r = $r | append (check "Configure fields" ($configure | str contains "NRI_version=") $configure)
    let sync = $log | lines | where {|l| $l | str contains "Synchronize" } | get 0? | default ""
    let all = sh-node $node "crictl ps -a -q | wc -l" | str trim
    let running = sh-node $node "crictl ps -q | wc -l" | str trim
    $r = $r | append (check "Synchronize count" ($sync | str contains $"containers=($running) ") $"($sync); crictl ps -q=($running) -a=($all)")
    let journal = sh-node $node "journalctl -u containerd --no-pager -o cat | grep 'registered as' | tail -1" | lines | str join " | "
    $r = $r | append (check "containerd logs registration" ($journal | str contains "registered as") $journal)

    run-pod $ctx $node ok ""
    $r = $r | append (check "plain pod Running" ((pod-phase $ctx ok running 60sec) == "running") "pod ok")
    run-pod $ctx $node bad "spike/reject=true"
    let bad = pod-phase $ctx bad running 20sec
    let event = ^kubectl --context $ctx describe pod bad | lines | where {|l| $l | str contains "speculaire spike: rejected" } | get 0? | default "" | str trim
    $r = $r | append (check "labelled pod rejected" ($bad != "running" and ($event | is-not-empty)) $event)

    # default_validator: restarting containerd drops the plugin, so start it again.
    sh-node $node "printf '\n[plugins.\"io.containerd.nri.v1.nri\".default_validator]\n  enable = true\n  required_plugins = [\"speculaire\"]\n' >> /etc/containerd/config.toml; systemctl restart containerd; sleep 3"
    start-plugin $node "" | ignore
    run-pod $ctx $node ok2 ""
    $r = $r | append (check "validator: plugin present, pod runs" ((pod-phase $ctx ok2 running 60sec) == "running") "pod ok2")
    sh-node $node "pkill nri-spike; sleep 1"
    run-pod $ctx $node ok3 ""
    let down = pod-phase $ctx ok3 running 20sec
    let rejection = ^kubectl --context $ctx describe pod ok3 | lines | where {|l| $l | str contains "not present" } | get 0? | default "" | str trim
    $r = $r | append (check "validator: plugin stopped, pod rejected" ($down != "running" and ($rejection | is-not-empty)) $rejection)
    start-plugin $node "" | ignore
    $r = $r | append (check "plugin restart, blocked pod recovers" ((pod-phase $ctx ok3 running 90sec) == "running") "pod ok3, no containerd restart")
    run-pod $ctx $node ok4 ""
    $r = $r | append (check "plugin restart, new pod runs" ((pod-phase $ctx ok4 running 60sec) == "running") "pod ok4")

    # Leave the node as found, so later steps run without the plugin.
    ^kubectl --context $ctx delete pod ok bad ok2 ok3 ok4 --ignore-not-found --wait=false o+e>| ignore
    sh-node $node "pkill nri-spike; sed -i '/default_validator/,$d' /etc/containerd/config.toml; systemctl restart containerd; sleep 3"

    print ($r | each {|c| $"($c.ok): ($c.check): ($c.detail)" } | str join "\n")
    if ($r | any {|c| not $c.ok }) { error make {msg: $"step 01 failed on ($minor)"} }
}


const HOSTS_TOML = '
server = "https://registry-1.docker.io"

[host."https://127.0.0.1:7480"]
  capabilities = ["pull"]
  ca = "/var/lib/speculaire/mirror/ca.crt"
  client = "/var/lib/speculaire/mirror/client.pem"
  dial_timeout = "200ms"
'

def start-mirror [node: string] {
    ^docker exec $node sh -c "pkill mirror-spike; sleep 0.5; true"
    ^docker exec -d $node sh -c "mirror-spike serve > /tmp/mirror.log 2>&1"
    sleep 1sec
}

def mirror-log [node: string] { ^docker exec $node cat /tmp/mirror.log | lines | where {|l| ($l | str starts-with "GET") or ($l | str starts-with "HEAD") or ($l | str contains "handshake") } }

def pull-ms [node: string, image: string] {
    let start = date now
    ^docker exec $node crictl pull $image o+e>| ignore
    ((date now) - $start) / 1ms | math round
}

# The largest layer digest of an image the node holds, read from its content store.
def largest-layer [node: string, image: string] {
    let top = ^docker exec $node ctr -n k8s.io images ls $"name==($image)" | lines | skip 1 | first | split row -r '\s+' | get 2
    let index = ^docker exec $node ctr -n k8s.io content get $top | from json
    let arch = if (^docker exec $node uname -m | str trim) == "x86_64" { "amd64" } else { "arm64" }
    let digest = if ($index.manifests? | is-empty) { $top } else { $index.manifests | where {|m| $m.platform.architecture == $arch and $m.platform.os == "linux" } | get 0.digest }
    ^docker exec $node ctr -n k8s.io content get $digest | from json | get layers | sort-by size | last | get digest
}

# Steps 04 and 05: the TLS mirror, fall through, and manifest fetch by digest through a kubelet pod.
def "main check 04" [minor: string] {
    let name = cluster-name $minor
    let ctx = $"kind-($name)"
    let node = $"($name)-worker"
    let peer = $"($name)-worker2"
    mut r = []

    # Idempotent: every image below must be pulled for the first time on both nodes.
    ^kubectl --context $ctx delete pod tagged --ignore-not-found --wait=true o+e>| ignore
    let images = [hello-world:latest nginx:alpine alpine:3.18 alpine:3.19 alpine:3.20 busybox:1.35 busybox:1.36] | each {|i| $"docker.io/library/($i)" } | str join " "
    for n in [$node $peer] {
        sh-node $n $"rm -f /etc/containerd/certs.d/docker.io/hosts.toml; rm -rf /var/lib/speculaire/mirror; for i in ($images); do crictl rmi $i >/dev/null 2>&1; done; true"
    }

    main put mirror-spike $node
    $HOSTS_TOML | ^docker exec -i $node sh -c "mkdir -p /etc/containerd/certs.d/docker.io /var/lib/speculaire/mirror/blobs && cat > /etc/containerd/certs.d/docker.io/hosts.toml"
    ^docker exec $node mirror-spike certs | ignore
    start-mirror $node

    # Empty mirror: every request answered 404 with the client subject, the pull falls through.
    ^docker exec $node crictl pull docker.io/library/hello-world:latest o+e>| ignore
    let log = mirror-log $node
    let held = ^docker exec $node crictl images -q docker.io/library/hello-world:latest | str trim
    $r = $r | append (check "empty mirror: pull succeeds, 404 with client subject" (($held | is-not-empty) and ($log | is-not-empty) and ($log | all {|l| ($l | str contains "-> 404") and ($l | str contains "subject=[CN=speculaire containerd]") })) ($"($log | length) requests, first: " + ($log | first | default "")))

    # A blob the mirror holds is served from it; the rest comes from upstream.
    ^docker exec $peer crictl pull docker.io/library/nginx:alpine o+e>| ignore
    let layer = largest-layer $peer docker.io/library/nginx:alpine
    let hex = $layer | str replace "sha256:" ""
    ^docker cp $"($peer):/var/lib/containerd/io.containerd.content.v1.content/blobs/sha256/($hex)" $"($HERE)/out/blob"
    ^docker cp $"($HERE)/out/blob" $"($node):/var/lib/speculaire/mirror/blobs/sha256-($hex)"
    start-mirror $node
    ^docker exec $node crictl pull docker.io/library/nginx:alpine o+e>| ignore
    let log = mirror-log $node
    let served = $log | where {|l| $l | str contains "-> 200" }
    let missed = $log | where {|l| ($l | str contains "/blobs/") and ($l | str contains "-> 404") }
    $r = $r | append (check "held blob from mirror, rest upstream" (($served | length) == 1 and ($served | first | str contains $hex) and ($missed | is-not-empty)) $"200: ($served | length), 404 blobs: ($missed | length), layer ($layer)")

    let nocert = ^docker exec $node sh -c "curl -sS --cacert /var/lib/speculaire/mirror/ca.crt https://127.0.0.1:7480/v2/ 2>&1; true"
    $r = $r | append (check "no client certificate fails" ($nocert | str contains "certificate required") ($nocert | str trim))

    # Certificates regenerated, containerd untouched.
    let before = ^docker exec $node md5sum /var/lib/speculaire/mirror/ca.crt
    ^docker exec $node mirror-spike certs | ignore
    start-mirror $node
    ^docker exec $node crictl pull docker.io/library/alpine:3.18 o+e>| ignore
    let log = mirror-log $node
    let after = ^docker exec $node md5sum /var/lib/speculaire/mirror/ca.crt
    $r = $r | append (check "regenerated certificates used without restart" ($before != $after and ($log | any {|l| $l | str contains "/alpine/" })) $"($log | length) requests")

    # Step 05: a kubelet pod using a tag; the mirror must see digests only.
    start-mirror $node
    ^kubectl --context $ctx delete pod tagged --ignore-not-found --wait=true o+e>| ignore
    let overrides = {spec: {nodeName: $node}} | to json --raw
    ^kubectl --context $ctx run tagged --image=docker.io/library/busybox:1.36 --restart=Never $"--overrides=($overrides)" -- sleep 3600 o+e>| ignore
    let phase = pod-phase $ctx tagged running 90sec
    let log = mirror-log $node
    let manifests = $log | where {|l| $l | str contains "/manifests/" }
    $r = $r | append (check "pod by tag: manifests fetched by digest, no tag, pod Running" ($phase == "running" and ($manifests | length) >= 2 and ($manifests | all {|l| $l | str contains "manifests/sha256:" })) ($manifests | str join " | "))

    # Mirror stopped: extra time per image against a node with no hosts.toml.
    ^docker exec $node pkill mirror-spike
    let with = ["alpine:3.20" "busybox:1.35" "alpine:3.19"] | each {|i| pull-ms $node $"docker.io/library/($i)" } | math avg
    let without = ["alpine:3.20" "busybox:1.35" "alpine:3.19"] | each {|i| pull-ms $peer $"docker.io/library/($i)" } | math avg
    $r = $r | append (check "mirror stopped: pull still succeeds" (($with - $without) < 1000) $"mean ($with | math round) ms against ($without | math round) ms with no hosts.toml")

    print ($r | each {|c| $"($c.ok): ($c.check): ($c.detail)" } | str join "\n")
    if ($r | any {|c| not $c.ok }) { error make {msg: $"step 04 failed on ($minor)"} }
}

# Everything a CI leg does for one step.
# `all` runs 00, 01 and 04 (04 covers 05) on one cluster; 02, 03 and 06 are manual.
def "main ci" [step: string, minor: string] {
    let steps = if $step == "all" { ["00" "01" "04"] } else { [$step] }
    main up $minor
    main build
    try {
        for s in $steps {
            match $s {
                "00" => { main check 00 $minor }
                "01" => { main check 01 $minor }
                "04" => { main check 04 $minor }
                _ => { error make {msg: $"no checks for step ($s)"} }
            }
        }
    } catch {|e|
        main down
        error make {msg: $e.msg}
    }
    main down
}

def main [] { help main }
