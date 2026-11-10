# Security model

Trust boundaries and accepted risks. Each item names the decision that enforces it. A change that moves a boundary updates this file in the same change.

- **Peers are untrusted for integrity** (*withhold, never forge*):
  - blobs are checked against their digest (D7);
  - artifacts are checked against their digest and signature (D8);
  - TUF metadata authenticates itself, so it can travel P2P (D26).
- **Peers are authenticated for identity.** Only holders of a kubelet client certificate from the cluster CA can talk to the peer API or a reflector, and a node can only announce content for itself (D16).
- **The local mirror is closed to other local processes.** containerd authenticates with a root-only client certificate, so `hostNetwork` pods cannot read cached layers through it (D14).
- **Every node verifies for itself.** Verdicts are never shared, and a compromised control plane cannot relax a node's policy (D26).
- **Saved verdicts are as trusted as memory.** `/run/speculaire` is root-only and cleared at reboot. A file with an unknown version or a bad checksum is discarded, and entries saved under another policy or trust root only serve as stale verdicts (D31).
- **Secrets never reach a log.** Registry credentials and tokens are `SecretString`s, and HTTP tracing never records headers (D37).
- **The audit log names pods and images.** It is off by default and goes to the root-readable journal (D37).
- **A bad config never loosens the gate.** Unknown keys stop startup, and an invalid reload keeps the previous config (D30).
- **Private layers are shared, as in Spegel (accepted).** Any node of the cluster can fetch any cached layer without pull secrets. mTLS keeps non-nodes out, but any node can read another node's private layers.
- **A joining node has no P2P.** Until its kubelet certificate exists, it pulls from upstream; the gate still enforces (D16).
- **The pause image is not gated.** NRI's `PodSandbox` carries no image.
- **On containerd 2.3, the identity check has a known gap (accepted).** A retag to an image with identical layers but a different config passes. The agent warns at startup; containerd 2.4 closes the gap (D15).
- **Images that no policy matches** are denied by default; `gate.unmatched = "allow"` lets them through unchecked (D23).
- **Admins must allow-list the gate's own dependencies.** With `enforce` + `required_plugins`, a stopped agent blocks every container creation on the node, including control-plane static pods. `gate.exempt` (D18) and the NRI tolerate annotation are the escape hatches. Admins configure them before turning on `enforce` (`docs/operations.md`). `unconfigure` refuses to run while `required_plugins` names speculaire (D32).
- **The tolerate annotation is a pod annotation (accepted).** Anyone who can create a pod can set it, and that pod starts ungated whenever the agent is not registered with NRI (`containerd/nri` `pkg/plugin/annotations.go:40-59`). v1 ships no admission policy to restrict it. The DaemonSet's own pod carries it (D44).
- **`.att` tags do not count.** Attestations are verified only as Sigstore bundles found as OCI referrers; `.att` and unsigned `.sbom` tags are ignored (D12, D43).
- **Metrics are readable by anyone on the node network.** `/metrics` is plain HTTP; it holds counts only, no secret and no pod or image label (D34, D42).
- **A gate timeout lets one container through (accepted).** NRI closes a plugin that misses `plugin_request_timeout` and starts that container ungated; D41 keeps the gate's answer under half the timeout and alerts on it.
- **The agent runs as root** with a hardened systemd unit, and the unit denies the io_uring syscalls (D4, D27).
