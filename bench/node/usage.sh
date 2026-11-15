# The CPU time in microseconds and the peak memory in bytes of the agent named by $1, speculaire or spegel, from its
# cgroup on this node, as "<usec> <bytes>": speculaire's unit, or Spegel's pod. Prints nothing when the agent does not
# run here.
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
echo "$(awk '$1 == "usage_usec" { print $2 }' "/sys/fs/cgroup$cgroup/cpu.stat") $(cat "/sys/fs/cgroup$cgroup/memory.peak")"
