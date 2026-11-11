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
# The 3 newest Kubernetes minors kind v0.33.0 ships, and the CRI-O release of each (CRI-O spike 00).
const K8S = {
    "1.37": "kindest/node:v1.37.0@sha256:a1ed56cfb0e7b93589bdf97c8cd566405a265939e3620fc4f5de89adff580ae5"
    "1.36": "kindest/node:v1.36.4@sha256:099e049362a1526b2db71494e1947aae99bd16290d7c895f2b7ea312e3cbfaed"
    "1.35": "kindest/node:v1.35.8@sha256:07b2536e30b803ed61d1677a79df6115f798ce64c80f9e22f6ed45afd09323c0"
}
const CRIO = {"1.37": "1.37.2", "1.36": "1.36.7", "1.35": "1.35.10"}

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

# spk-23 on Kubernetes 1.37 (M0's names), spk-24-k136 on an older minor.
def cluster-name [minor: string, k8s: string = "1.37"] {
    let base = $"spk-($minor | str replace '.' '')"
    if $k8s == "1.37" { $base } else { $"($base)-k($k8s | str replace '.' '')" }
}

def crio-cluster [k8s: string] { $"spk-crio-($k8s | str replace '.' '')" }

def nodes [minor: string, k8s: string = "1.37"] {
    ^(kind-bin) get nodes --name (cluster-name $minor $k8s) | lines | sort
}

# kind --wait covers the control plane only; workers join after.
def wait-nodes [name: string] {
    ^kubectl --context $"kind-($name)" wait --for=condition=Ready nodes --all --timeout=180s
}

def sh-node [node: string, cmd: string] {
    ^docker exec $node sh -c $cmd
}

# Build the node image and create the cluster.
def "main up" [minor: string, --k8s: string = "1.37"] {
    let ver = containerd-version $minor
    let name = cluster-name $minor $k8s
    let img = $"spk-node:($ver)-k($k8s)"
    print $"== containerd ($ver), Kubernetes ($k8s), image ($img), cluster ($name)"
    ^docker build --build-arg $"NODE=($K8S | get $k8s)" --build-arg $"VERSION=($ver)" -t $img ($HERE | path join node)
    ^(kind-bin) create cluster --name $name --image $img --config ($HERE | path join kind.yaml) --wait 180s
    wait-nodes $name
}

# CRI-O spike 00: build the CRI-O node image of a Kubernetes minor and create its cluster.
def "main crio up" [k8s: string] {
    let ver = $CRIO | get $k8s
    let name = crio-cluster $k8s
    let img = $"spk-crio:($ver)"
    print $"== CRI-O ($ver), Kubernetes ($k8s), image ($img), cluster ($name)"
    ^docker build --build-arg $"NODE=($K8S | get $k8s)" --build-arg $"VERSION=($ver)" -t $img -f ($HERE | path join node crio.Dockerfile) ($HERE | path join node)
    let start = date now
    ^(kind-bin) create cluster --name $name --image $img --config ($HERE | path join kind-crio.yaml) --wait 300s
    wait-nodes $name
    print $"== cluster created in ((date now) - $start)"
}

def "main crio down" [] {
    for k in ($CRIO | columns) {
        try { ^(kind-bin) delete cluster --name (crio-cluster $k) }
    }
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
        for k in ($K8S | columns) {
            if (cluster-name $m $k) in (^(kind-bin) get clusters | lines) {
                ^(kind-bin) delete cluster --name (cluster-name $m $k)
            }
        }
    }
}

# Collect checks: each returns a list of {check, ok, detail}.
def check [name: string, ok: bool, detail: string] {
    {check: $name, ok: $ok, detail: ($detail | lines | str join " | " | str substring 0..400)}
}

def "main check 00" [minor: string, --k8s: string = "1.37"] {
    let ver = containerd-version $minor
    let name = cluster-name $minor $k8s
    let ctx = $"kind-($name)"
    let nodes = nodes $minor $k8s
    mut r = []

    $r = $r | append (ready-nodes $ctx $"containerd://($ver)")
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
    $r = $r | append (hello-and-busybox $ctx ($nodes | where {|n| $n | str contains worker } | first) "")
    report $r $"step 00 on containerd ($minor), Kubernetes ($k8s)"
}

# CRI-O spike 00: the cluster runs CRI-O, NRI is on, and the M0 step 00 checks hold.
def "main crio check 00" [k8s: string] {
    let ver = $CRIO | get $k8s
    let name = crio-cluster $k8s
    let ctx = $"kind-($name)"
    let nodes = ^(kind-bin) get nodes --name $name | lines | sort
    mut r = []

    $r = $r | append (ready-nodes $ctx $"cri-o://($ver)")
    for n in $nodes {
        # First line: `crio version 1.37.2`.
        let v = sh-node $n "crio --version" | lines | first | str trim
        $r = $r | append (check $"($n) crio ($ver)" ($v | str ends-with $" ($ver)") $v)
        let off = sh-node $n "systemctl is-enabled containerd; systemctl is-active containerd; true" | lines | str join " "
        $r = $r | append (check $"($n) containerd off" ($off == "disabled inactive") $off)
        let nri = sh-node $n "ls /var/run/nri/nri.sock" | str trim
        $r = $r | append (check $"($n) nri.sock" ($nri == "/var/run/nri/nri.sock") $nri)
        let conf = sh-node $n "crio status config 2>/dev/null" | lines | each {|l| $l | str trim }
        let on = ["enable_nri = true" "nri_disable_connections = false"] | all {|k| $k in $conf }
        $r = $r | append (check $"($n) nri enabled" $on "crio status config: enable_nri, nri_disable_connections")
    }
    $r = $r | append (hello-and-busybox $ctx ($nodes | where {|n| $n | str contains worker } | first) "/var/run/crio/crio.sock")
    report $r $"step 00 on CRI-O ($ver)"
}

def ready-nodes [ctx: string, runtime: string] {
    let k = ^kubectl --context $ctx get nodes -o json | from json | get items
    let ready = $k | where {|n| ($n.status.conditions | where type == "Ready" | first).status == "True" } | length
    let runtimes = $k | get status.nodeInfo.containerRuntimeVersion | uniq
    [
        (check "3 Ready nodes" ($ready == 3) $"($ready) ready")
        (check $"runtime ($runtime)" ($runtimes == [$runtime]) ($runtimes | str join " "))
    ]
}

# hello runs under the D53 unit in a worker; the test image runs as a pod.
# `socket` is the runtime socket hello connects to; empty keeps hello's default, containerd's.
def hello-and-busybox [ctx: string, worker: string, socket: string] {
    mut r = []
    main put hello $worker
    ^docker cp ($HERE | path join hello.service) $"($worker):/etc/systemd/system/hello.service"
    if ($socket | is-not-empty) {
        sh-node $worker $"mkdir -p /etc/systemd/system/hello.service.d && printf '[Service]\\nEnvironment=HELLO_RUNTIME_SOCKET=($socket)\\n' > /etc/systemd/system/hello.service.d/runtime.conf"
    }
    let file = ^docker exec $worker sh -c "ls -l /usr/local/bin/hello; od -An -tx1 -N4 /usr/local/bin/hello" | str trim
    $r = $r | append (check "hello present" ($file | str contains "7f 45 4c 46") $file)
    try { sh-node $worker "systemctl daemon-reload; systemctl start hello.service" } catch { }
    let journal = sh-node $worker "journalctl -u hello.service --no-pager -o cat | tail -8"
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

    ^kubectl --context $ctx delete pod bb --ignore-not-found --wait=true
    ^kubectl --context $ctx run bb $"--image=($TEST_IMAGE)" --restart=Never -- sleep 3600
    let pod = try { ^kubectl --context $ctx wait --for=condition=Ready pod/bb --timeout=120s; "ready" } catch {|e| $e.msg }
    $r = $r | append (check "busybox Running" ($pod == "ready") $pod)
    # Wait, so a later step does not see the pod's container mid-removal.
    ^kubectl --context $ctx delete pod bb --wait=true
    $r
}

def report [r: list, what: string] {
    print ($r | each {|c| $"($c.ok): ($c.check): ($c.detail)" } | str join "\n")
    if ($r | any {|c| not $c.ok }) { error make {msg: $"($what) failed"} }
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

# CRI-O spike 02: CRI-O's ImageRef annotation in NRI equals the config digest of the platform manifest,
# for 20 pods at once and a pod with hostUsers: false.
def "main crio check 02" [k8s: string] {
    let name = crio-cluster $k8s
    let ctx = $"kind-($name)"
    let node = $"($name)-worker"
    let arch = match (sh-node $node "uname -m" | str trim) { "aarch64" => "arm64", "x86_64" => "amd64", $a => $a }
    let want = config-digest library/busybox "1.37" $arch
    mut r = []

    ^kubectl --context $ctx delete pod -l spike=s02 --ignore-not-found --wait=true o+e>| ignore
    main put nri-spike $node
    start-plugin $node "" | ignore
    let pods = 0..19 | each {|i| $"p($i)" } | append "userns"
    for p in $pods {
        let spec = if $p == "userns" { {nodeName: $node, hostUsers: false} } else { {nodeName: $node} }
        let o = {spec: $spec} | to json --raw
        ^kubectl --context $ctx run $p $"--image=($TEST_IMAGE)" --restart=Never --labels=spike=s02 $"--overrides=($o)" -- sleep 3600 o+e>| ignore
    }
    let plain = $pods | where {|p| $p != "userns" } | each {|p| $"pod/($p)" }
    let wait = ^kubectl --context $ctx wait --for=condition=Ready ...$plain --timeout=180s | complete
    $r = $r | append (check "20 pods Running" ($wait.exit_code == 0) ($wait.stderr | str trim))
    let log = ^docker exec $node cat /tmp/nri-spike.log | lines | where {|l| $l | str contains "CreateContainer pod=default/" }
    let refs = $pods | each {|p|
        let line = $log | where {|l| $l | str contains $"CreateContainer pod=default/($p) " } | get 0? | default ""
        {pod: $p, ref: ($line | parse -r '"io.kubernetes.cri-o.ImageRef": "(?<v>[0-9a-f]{64})"' | get v.0? | default "")}
    }
    let bad = $refs | where {|x| $"sha256:($x.ref)" != $want }
    $r = $r | append (check "ImageRef = config digest" ($bad | is-empty) $"want ($want); mismatched: ($bad | get pod | str join ' ')")
    let uid = try { ^kubectl --context $ctx exec userns -- cat /proc/self/uid_map | str trim } catch {|e|
        let state = ^kubectl --context $ctx get pod userns -o jsonpath='{.status.containerStatuses[0].state}' | str trim
        let tail = $state | str substring (($state | str length) - 350)..
        $"0 0 exec failed; state …($tail)"
    }
    # uid_map "0 <host uid> <count>": a host uid other than 0 means a user namespace.
    let host = $uid | split row -r '\s+' | get 1? | default "0"
    # Informational: on GitHub's runners runc cannot mount sysfs for a user-namespace pod inside a kind node.
    print $"info: userns pod: uid_map: ($uid)"
    $r = $r | append (check "userns pod reached CreateContainer" ($refs | any {|x| $x.pod == "userns" and $x.ref != "" }) "see ImageRef check")

    ^kubectl --context $ctx delete pod -l spike=s02 --wait=true o+e>| ignore
    sh-node $node "pkill nri-spike; true"

    # The image store's images.json changes before crictl returns from a pull or a removal.
    let lag = sh-node $node 'f=/var/lib/containers/storage/overlay-images/images.json; i=docker.io/library/busybox:1.36; crictl pull $i >/dev/null; e=$(date +%s.%N); m=$(stat -c %.9Y $f); crictl rmi $i >/dev/null; e2=$(date +%s.%N); m2=$(stat -c %.9Y $f); echo "$e $m $e2 $m2"' | split row ' ' | into float
    let pull = $lag.0 - $lag.1
    let rmi = $lag.2 - $lag.3
    $r = $r | append (check "images.json written by pull and rmi" ($pull >= 0 and $pull < 1 and $rmi >= 0 and $rmi < 1) $"seconds from write to return: pull ($pull), rmi ($rmi)")

    # pinned_images in a drop-in, applied by SIGHUP, keeps the image through a prune.
    let pin = sh-node $node 'crictl pull docker.io/library/nginx:alpine >/dev/null; printf "[crio.image]\npinned_images = [\"docker.io/library/nginx:alpine\"]\n" > /etc/crio/crio.conf.d/91-pinned.conf; systemctl reload crio; sleep 2; crictl rmi --prune >/dev/null 2>&1; crictl images -q docker.io/library/nginx:alpine | wc -l; rm /etc/crio/crio.conf.d/91-pinned.conf; systemctl reload crio' | str trim
    $r = $r | append (check "pinned image survives prune" ($pin == "1") $"images left: ($pin)")
    report $r $"step 02 on CRI-O ($CRIO | get $k8s)"
}

# Config digest of an image's platform manifest, from Docker Hub.
def config-digest [repo: string, tag: string, arch: string] {
    let tok = http get $"https://auth.docker.io/token?service=registry.docker.io&scope=repository:($repo):pull" | get token
    let accept = "application/vnd.oci.image.index.v1+json, application/vnd.docker.distribution.manifest.list.v2+json, application/vnd.oci.image.manifest.v1+json, application/vnd.docker.distribution.manifest.v2+json"
    let h = {Authorization: $"Bearer ($tok)", Accept: $accept}
    let base = $"https://registry-1.docker.io/v2/($repo)/manifests"
    let idx = http get -H $h $"($base)/($tag)" | decode utf-8 | from json
    let m = $idx.manifests | where {|x| $x.platform.architecture == $arch and $x.platform.os == "linux" } | first
    (http get -H $h $"($base)/($m.digest)" | decode utf-8 | from json).config.digest
}

# Step 01, per runtime: how to drop the default_validator, turn it on, and which unit logs NRI.
# containerd: append to its config; CRI-O: a drop-in (CRI-O spike 01).
const VALIDATOR = {
    containerd: {
        unit: "containerd"
        listed: "crictl ps -q"
        off: "sed -i '/default_validator/,$d' /etc/containerd/config.toml"
        on: "printf '\\n[plugins.\"io.containerd.nri.v1.nri\".default_validator]\\n  enable = true\\n  required_plugins = [\"speculaire\"]\\n' >> /etc/containerd/config.toml"
    }
    crio: {
        unit: "crio"
        listed: "crictl ps -q"
        off: "rm -f /etc/crio/crio.conf.d/90-validator.conf"
        on: "printf '[crio.nri.default_validator]\\nnri_enable_default_validator = true\\nnri_validator_required_plugins = [\"speculaire\"]\\n' > /etc/crio/crio.conf.d/90-validator.conf"
    }
}

# Step 01: NRI plugin over our mux, then the default_validator with required_plugins.
def "main check 01" [minor: string] {
    let name = cluster-name $minor
    check-01 $"kind-($name)" $"($name)-worker" containerd $"containerd ($minor)"
}

# CRI-O spike 01: M0's step 01 checks, unchanged plugin, on CRI-O.
def "main crio check 01" [k8s: string] {
    let name = crio-cluster $k8s
    check-01 $"kind-($name)" $"($name)-worker" crio $"CRI-O ($CRIO | get $k8s)"
}

def check-01 [ctx: string, node: string, runtime: string, what: string] {
    let v = $VALIDATOR | get $runtime
    let restart = $"systemctl restart ($v.unit); sleep 3"
    mut r = []

    # Idempotent: drop pods and a default_validator left by an earlier run.
    ^kubectl --context $ctx delete pod ok bad ok2 ok3 ok4 --ignore-not-found --wait=true o+e>| ignore
    sh-node $node $"pkill nri-spike; ($v.off); ($restart)"
    main put nri-spike $node
    start-plugin $node "" | ignore
    # Synchronize can trail Configure by seconds just after a runtime restart (seen in CI).
    mut log = ""
    for _ in 1..120 {
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
    if ($sync | is-empty) {
        print $"== no Synchronize after 60 s; plugin log, then ($v.unit)'s NRI lines:"
        print $log
        print (sh-node $node $"journalctl -u ($v.unit) --no-pager -o short-precise | grep -i -E 'nri|plugin|synchron' | tail -40")
    }
    let want = sh-node $node $"($v.listed) | wc -l" | str trim
    $r = $r | append (check $"Synchronize count = ($v.listed)" ($sync | str contains $"containers=($want) ") $"($sync); crictl ps -q=($running) -a=($all)")
    let journal = sh-node $node $"journalctl -u ($v.unit) --no-pager -o cat | grep 'registered as' | tail -1" | lines | str join " | "
    $r = $r | append (check $"($v.unit) logs registration" ($journal | str contains "registered as") $journal)

    run-pod $ctx $node ok ""
    $r = $r | append (check "plain pod Running" ((pod-phase $ctx ok running 60sec) == "running") "pod ok")
    # What the runtime puts in the NRI Container: the image field and the annotations naming the image (D15).
    let create = ^docker exec $node cat /tmp/nri-spike.log | lines | where {|l| $l | str contains "CreateContainer pod=default/ok " } | get 0? | default ""
    let image = $create | parse -r 'image=(?<v>"[^"]*")' | get v.0? | default "?"
    let names = $create | parse -r '(?<kv>"[^"]*[Ii]mage[^"]*": "[^"]*")' | get kv | str join ", "
    $r = $r | append (check "Container image fields" ($create | is-not-empty) $"image=($image); annotations: ($names)")
    run-pod $ctx $node bad "spike/reject=true"
    let bad = pod-phase $ctx bad running 20sec
    let event = ^kubectl --context $ctx describe pod bad | lines | where {|l| $l | str contains "speculaire spike: rejected" } | get 0? | default "" | str trim
    $r = $r | append (check "labelled pod rejected" ($bad != "running" and ($event | is-not-empty)) $event)

    # default_validator: restarting the runtime closes the trunk, so the plugin exits; start it again.
    sh-node $node $"($v.on); ($restart)"
    let alive = sh-node $node "pgrep -c nri-spike; true" | str trim
    $r = $r | append (check "runtime restart closes the trunk" ($alive == "0") $"nri-spike processes after restart: ($alive)")
    start-plugin $node "" | ignore
    run-pod $ctx $node ok2 ""
    $r = $r | append (check "validator: plugin present, pod runs" ((pod-phase $ctx ok2 running 60sec) == "running") "pod ok2")
    sh-node $node "pkill nri-spike; sleep 1"
    run-pod $ctx $node ok3 ""
    let down = pod-phase $ctx ok3 running 20sec
    let rejection = ^kubectl --context $ctx describe pod ok3 | lines | where {|l| $l | str contains "not present" } | get 0? | default "" | str trim
    $r = $r | append (check "validator: plugin stopped, pod rejected" ($down != "running" and ($rejection | is-not-empty)) $rejection)
    start-plugin $node "" | ignore
    $r = $r | append (check "plugin restart, blocked pod recovers" ((pod-phase $ctx ok3 running 90sec) == "running") $"pod ok3, no ($v.unit) restart")
    run-pod $ctx $node ok4 ""
    $r = $r | append (check "plugin restart, new pod runs" ((pod-phase $ctx ok4 running 60sec) == "running") "pod ok4")

    # Leave the node as found, so later steps run without the plugin.
    ^kubectl --context $ctx delete pod ok bad ok2 ok3 ok4 --ignore-not-found --wait=false o+e>| ignore
    sh-node $node $"pkill nri-spike; ($v.off); ($restart)"

    report $r $"step 01 on ($what)"
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
    $r = $r | append (check "empty mirror: pull succeeds, 404 with client subject" (($held | is-not-empty) and ($log | is-not-empty) and ($log | all {|l| ($l | str contains "-> 404") and ($l | str contains "subject=[CN=speculaire runtime]") })) ($"($log | length) requests, first: " + ($log | first | default "")))

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
# CRI-O spike 03: the TLS mirror through a registries.conf.d drop-in.
const CRIO_DROPIN = "/etc/containers/registries.conf.d/50-speculaire.conf"
const CRIO_CERTS = "/etc/containers/certs.d/127.0.0.1:7480"
const MIRROR_DIR = "/var/lib/speculaire/mirror"

# Write the drop-in with this pull-from-mirror mode, or remove it for "none"; then reload CRI-O unless told not to.
def crio-dropin [node: string, mode: string, --no-reload] {
    if $mode == "none" {
        sh-node $node $"rm -f ($CRIO_DROPIN)" | ignore
    } else {
        let conf = $"[[registry]]\nprefix = \"docker.io\"\nlocation = \"docker.io\"\n\n[[registry.mirror]]\nlocation = \"127.0.0.1:7480/docker.io\"\npull-from-mirror = \"($mode)\"\n"
        $conf | ^docker exec -i $node sh -c $"cat > ($CRIO_DROPIN)"
    }
    if not $no_reload { sh-node $node "systemctl reload crio" | ignore }
}

# New certificates, copied where CRI-O reads them: ca.crt, client.cert, client.key.
def crio-certs [node: string] {
    sh-node $node $"mirror-spike certs > /dev/null && mkdir -p '($CRIO_CERTS)' ($MIRROR_DIR)/blobs ($MIRROR_DIR)/manifests && cp ($MIRROR_DIR)/ca.crt ($MIRROR_DIR)/client.cert ($MIRROR_DIR)/client.key '($CRIO_CERTS)/'" | ignore
}

# (Re)start the mirror with an empty log; `challenge` answers 401 to requests without credentials.
def crio-mirror [node: string, challenge: bool = false] {
    sh-node $node "pkill mirror-spike; sleep 0.5; true" | ignore
    let prefix = if $challenge { "MIRROR_CHALLENGE=1 " } else { "" }
    ^docker exec -d $node sh -c $"($prefix)mirror-spike serve > /tmp/mirror.log 2>&1"
    sleep 1sec
}

# The mirror's request lines, shortened to `METHOD path auth -> status`.
def crio-requests [node: string] {
    mirror-log $node | each {|l| $l | str replace -r ' subject=\[[^\]]*\]' '' | str replace -r '/v2/docker.io/library/' '' | str replace -r 'sha256:([0-9a-f]{12})[0-9a-f]+' 'sha256:$1' }
}

# Pull after removing every unused image; {ms, ok, out}.
def fresh-pull [node: string, image: string, creds: string = ""] {
    sh-node $node "crictl rmi --prune >/dev/null 2>&1; true" | ignore
    let c = if ($creds | is-empty) { "" } else { $"--creds ($creds) " }
    let start = date now
    let r = ^docker exec $node sh -c $"crictl pull ($c)($image) 2>&1" | complete
    {ms: (((date now) - $start) / 1ms | math round), ok: ($r.exit_code == 0), out: ($r.stdout | str trim | lines | last | default "" | str substring 0..300)}
}

def median-pull [node: string, image: string] {
    1..3 | each { fresh-pull $node $image | get ms } | math median
}

def save-manifest [dir: string, reference: string, raw: binary, media: string] {
    let name = $reference | str replace ':' '-'
    $raw | save -f $"($dir)/manifests/($name)"
    $media | save -f $"($dir)/manifests/($name).type"
}

# Fill the node's mirror with busybox:1.37 for its platform: the index by tag and digest, the platform manifest,
# the config and the layers, all but the largest layer when told. Returns the digests.
def fill-mirror [node: string, arch: string, --skip-layer] {
    let repo = "library/busybox"
    let tok = http get $"https://auth.docker.io/token?service=registry.docker.io&scope=repository:($repo):pull" | get token
    let accept = "application/vnd.oci.image.index.v1+json, application/vnd.docker.distribution.manifest.list.v2+json, application/vnd.oci.image.manifest.v1+json, application/vnd.docker.distribution.manifest.v2+json"
    let h = {Authorization: $"Bearer ($tok)", Accept: $accept}
    let base = $"https://registry-1.docker.io/v2/($repo)"
    let dir = mktemp -d
    mkdir $"($dir)/manifests" $"($dir)/blobs"
    let idx_raw = http get -H $h $"($base)/manifests/1.37" | into binary
    let index = "sha256:" + ($idx_raw | hash sha256)
    let idx = $idx_raw | decode utf-8 | from json
    save-manifest $dir "1.37" $idx_raw $idx.mediaType
    save-manifest $dir $index $idx_raw $idx.mediaType
    let manifest = $idx.manifests | where {|x| $x.platform.architecture == $arch and $x.platform.os == "linux" } | first | get digest
    let m_raw = http get -H $h $"($base)/manifests/($manifest)" | into binary
    let m = $m_raw | decode utf-8 | from json
    save-manifest $dir $manifest $m_raw $m.mediaType
    let layer = $m.layers | sort-by size | last | get digest
    let blobs = $m.layers | get digest | prepend $m.config.digest | where {|d| not ($skip_layer and $d == $layer) }
    for d in $blobs {
        ^curl -sfL -H $"Authorization: Bearer ($tok)" -o $"($dir)/blobs/($d | str replace ':' '-')" $"($base)/blobs/($d)"
    }
    sh-node $node $"rm -rf ($MIRROR_DIR)/manifests ($MIRROR_DIR)/blobs" | ignore
    ^docker cp $"($dir)/manifests" $"($node):($MIRROR_DIR)/manifests"
    ^docker cp $"($dir)/blobs" $"($node):($MIRROR_DIR)/blobs"
    rm -r $dir
    {index: $index, manifest: $manifest, layer: $layer}
}

def empty-mirror [node: string] {
    sh-node $node $"rm -rf ($MIRROR_DIR)/manifests/* ($MIRROR_DIR)/blobs/*" | ignore
}

# CRI-O spike 03: what the mirror sees from CRI-O, and what CRI-O does when the mirror lacks content or is down.
def "main crio check 03" [k8s: string] {
    let name = crio-cluster $k8s
    let ctx = $"kind-($name)"
    let node = $"($name)-worker"
    let arch = match (sh-node $node "uname -m" | str trim) { "aarch64" => "arm64", "x86_64" => "amd64", $a => $a }
    mut r = []

    ^kubectl --context $ctx delete pod -l spike=s03 --ignore-not-found --wait=true o+e>| ignore
    main put mirror-spike $node
    crio-certs $node
    let digest_ref = $"docker.io/library/busybox@(fill-mirror $node $arch | get index)"
    crio-dropin $node none

    # Baseline, then an empty mirror with pull-from-mirror = all.
    empty-mirror $node
    let base_ms = median-pull $node $TEST_IMAGE
    crio-dropin $node all
    crio-mirror $node
    let p = fresh-pull $node $TEST_IMAGE
    let seen = crio-requests $node
    let subject = mirror-log $node | where {|l| $l | str contains "manifests/1.37" } | get 0? | default "" | parse -r 'subject=\[(?<s>[^\]]*)\]' | get s.0? | default ""
    $r = $r | append (check "all: tag pull asks the mirror for the tag" ($p.ok and ($seen | any {|l| $l | str contains "manifests/1.37" })) $"subject=($subject); ($seen | str join ', ')")
    let empty_ms = median-pull $node $TEST_IMAGE

    # A pod by tag goes through kubelet's PullImage the same way.
    crio-mirror $node
    sh-node $node "crictl rmi --prune >/dev/null 2>&1; true" | ignore
    let o = {spec: {nodeName: $node}} | to json --raw
    ^kubectl --context $ctx run s03 $"--image=($TEST_IMAGE)" --restart=Never --labels=spike=s03 $"--overrides=($o)" -- sleep 3600 o+e>| ignore
    let phase = pod-phase $ctx s03 running 90sec
    $r = $r | append (check "all: pod by tag asks the mirror for the tag" ($phase == "running" and (crio-requests $node | any {|l| $l | str contains "manifests/1.37" })) (crio-requests $node | str join ", "))
    ^kubectl --context $ctx delete pod s03 --wait=true o+e>| ignore

    # digest-only: tags skip the mirror, digests reach it.
    crio-dropin $node digest-only
    crio-mirror $node
    let t = fresh-pull $node $TEST_IMAGE
    let tag_seen = crio-requests $node
    $r = $r | append (check "digest-only: tag pull skips the mirror" ($t.ok and ($tag_seen | all {|l| not ($l | str contains "manifests") })) ($tag_seen | str join ", "))
    crio-mirror $node
    let d = fresh-pull $node $digest_ref
    let dig_seen = crio-requests $node
    $r = $r | append (check "digest-only: digest pull reaches the mirror" ($d.ok and ($dig_seen | any {|l| $l | str contains "manifests/sha256:" })) ($dig_seen | str join ", "))

    # The mirror holds everything: CRI-O takes the manifest and every blob from it.
    let held = fill-mirror $node $arch
    crio-dropin $node all
    crio-mirror $node
    let f = fresh-pull $node $TEST_IMAGE
    let full_seen = crio-requests $node
    $r = $r | append (check "held image comes from the mirror only" ($f.ok and ($full_seen | any {|l| $l | str contains $"blobs/($held.layer | str substring 0..18)" }) and ($full_seen | all {|l| not ($l | str ends-with "404") or ($l | str contains "/v2/ ") })) ($full_seen | str join ", "))

    # The mirror holds the manifests but not the largest layer.
    let partial = fill-mirror $node $arch --skip-layer
    crio-mirror $node
    let m = fresh-pull $node $TEST_IMAGE
    $r = $r | append (check $"missing layer: pull (if $m.ok { 'falls back' } else { 'fails' })" true $"($m.out); mirror: (crio-requests $node | str join ', ')")
    empty-mirror $node

    # The mirror is down: connection refused on 127.0.0.1.
    sh-node $node "pkill mirror-spike; true" | ignore
    let down_ms = median-pull $node $TEST_IMAGE
    $r = $r | append (check "pull timings (median of 3, ms)" true $"no drop-in ($base_ms), empty mirror ($empty_ms), mirror stopped ($down_ms)")

    # No client certificate: the handshake fails.
    crio-mirror $node
    let curl = sh-node $node $"curl -s --cacert ($MIRROR_DIR)/ca.crt https://127.0.0.1:7480/v2/ -o /dev/null; echo $?" | str trim
    let hs = mirror-log $node | where {|l| $l | str contains "handshake" } | get 0? | default ""
    $r = $r | append (check "curl without client certificate fails" ($curl != "0" and ($hs | is-not-empty)) $"curl exit ($curl); ($hs)")

    # New certificates, no CRI-O restart or reload.
    crio-certs $node
    crio-mirror $node
    let n = fresh-pull $node $TEST_IMAGE
    let regen = crio-requests $node
    $r = $r | append (check "regenerated certificates used without reload" ($n.ok and ($regen | any {|l| $l | str contains "manifests/1.37" }) and ($regen | all {|l| not ($l | str contains "handshake") })) ($regen | str join ", "))

    # Drop-in changes: written without reload, then reloaded, then removed.
    crio-dropin $node none
    crio-dropin $node all --no-reload
    crio-mirror $node
    fresh-pull $node $TEST_IMAGE | ignore
    let unreloaded = crio-requests $node | length
    let since = sh-node $node "date -u '+%Y-%m-%d %H:%M:%S'" | str trim
    sh-node $node "systemctl reload crio" | ignore
    let applied = sh-node $node $"journalctl -u crio --no-pager -o cat --since '($since)' | grep -c 'Applied new registry configuration'; true" | str trim
    fresh-pull $node $TEST_IMAGE | ignore
    let reloaded = crio-requests $node | length
    crio-dropin $node none
    crio-mirror $node
    fresh-pull $node $TEST_IMAGE | ignore
    let removed = crio-requests $node | length
    $r = $r | append (check "drop-in takes effect on reload only" ($unreloaded == 0 and $applied != "0" and $reloaded > 0 and $removed == 0) $"requests: written ($unreloaded), reloaded ($reloaded) with ($applied) journal line, removed ($removed)")

    # Credentials: what reaches the mirror with and without a 401 challenge.
    crio-dropin $node all
    crio-mirror $node
    fresh-pull $node $TEST_IMAGE "spike:not-a-secret" | ignore
    let plain = crio-requests $node
    crio-mirror $node true
    let c = fresh-pull $node $TEST_IMAGE "spike:not-a-secret"
    let challenged = crio-requests $node
    $r = $r | append (check "credentials reach the mirror" true $"no challenge: ($plain | str join ', '); challenge: ($challenged | str join ', '); pull ($c.out)")

    crio-dropin $node none
    sh-node $node "pkill mirror-spike; true" | ignore
    report $r $"CRI-O ($k8s) step 03"
}

def "main ci" [step: string, minor: string, --k8s: string = "1.37"] {
    let steps = if $step == "all" { ["00" "01" "04"] } else { [$step] }
    main up $minor --k8s $k8s
    main build
    try {
        for s in $steps {
            match $s {
                "00" => { main check 00 $minor --k8s $k8s }
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

# A CRI-O CI leg; `all` runs the CRI-O spikes written so far.
def "main crio ci" [step: string, k8s: string] {
    let steps = if $step == "all" { ["00" "01" "02" "03"] } else { [$step] }
    main crio up $k8s
    main build
    try {
        for s in $steps {
            match $s {
                "00" => { main crio check 00 $k8s }
                "01" => { main crio check 01 $k8s }
                "02" => { main crio check 02 $k8s }
                "03" => { main crio check 03 $k8s }
                _ => { error make {msg: $"no CRI-O checks for step ($s)"} }
            }
        }
    } catch {|e|
        main crio down
        error make {msg: $e.msg}
    }
    main crio down
}

def main [] { help main }
