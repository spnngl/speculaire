# The usage of the agent named by $1, speculaire or spegel, from its cgroup on this node: speculaire's unit, or Spegel's
# pod. With $2 = cpu, its CPU time in microseconds. With $2 = memory, "<anon> <file>" in bytes from memory.stat every
# second, until the output closes or two hours pass: anon is the agent's own memory, file the page cache charged to it
# (D114). Prints nothing when the agent does not run here.
set -euo pipefail

case "$1" in
    speculaire)
        cgroup="$(systemctl show -p ControlGroup --value speculaire.service)"
        ;;
    spegel)
        id="$(crictl ps -q --name '^registry$' --label io.kubernetes.pod.namespace=spegel)"
        [[ -n "$id" ]] || exit 0
        pid="$(crictl inspect -o go-template --template '{{.info.pid}}' "$id")"
        # The container's cgroup is a child of its pod's.
        cgroup="$(dirname "$(sed -n 's/^0:://p' "/proc/$pid/cgroup")")"
        ;;
    *)
        echo "usage.sh: no agent $1: speculaire or spegel" >&2
        exit 1
        ;;
esac
[[ -n "$cgroup" ]] || exit 0
dir="/sys/fs/cgroup$cgroup"
case "$2" in
    cpu) awk '$1 == "usage_usec" { print $2 }' "$dir/cpu.stat" ;;
    memory)
        # A write to the closed output ends the loop; the bound ends a sampler whose output never closes.
        for _ in $(seq 7200); do
            awk '$1 == "anon" { anon = $2 } $1 == "file" { file = $2 } END { print anon, file }' "$dir/memory.stat"
            sleep 1
        done
        ;;
    *)
        echo "usage.sh: no measure $2: cpu or memory" >&2
        exit 1
        ;;
esac
