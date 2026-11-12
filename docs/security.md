# Security model

Trust boundaries and accepted risks. Each item names the decision that enforces it. A change that moves a boundary updates this file in the same change.

- **Peers are untrusted for integrity** (*withhold, never forge*):
  - blobs are checked against their digest, and a peer that sends a wrong one is skipped locally for a while; no node can evict another cluster-wide (D7, D52);
  - artifacts are checked against their digest and signature (D8);
  - TUF metadata authenticates itself, so it can travel P2P (D26).
- **Peers are authenticated for identity.** Only holders of a kubelet client certificate from the cluster CA can talk to the peer API or a reflector, and a node can only announce content for itself (D16).
- **The local mirror is closed to other local processes.** The runtime authenticates with a root-only client certificate, so `hostNetwork` pods cannot read cached layers through it. It listens on loopback only; startup refuses any other `mirror.address` (D14, D56). `configure` writes the keys by temporary file and rename at mode 0600, tightening a looser file, and drops the CA's key once it has signed the two certificates, so no key can issue another client certificate (D55, D82).
- **Pod pull secrets never reach the agent.** On CRI-O the mirror never answers 401, because CRI-O would then send it the pull's credentials, which belong to the upstream registry. It resolves tags only at upstream, with the node's own credentials, never from peers (D6, D66).
- **On CRI-O the agent is in every pull's path.** CRI-O takes an image whole from the mirror once it serves the manifest, so the agent relays what it fetches from upstream; when the agent is down, CRI-O pulls from upstream (D66). It keeps a blob in its *blob cache*, and so serves it to peers, only once its digest matches; it holds back the last chunk until then, so CRI-O never receives a whole wrong blob (D67).
- **Every node verifies for itself.** Verdicts are never shared, and a compromised control plane cannot relax a node's policy (D26).
- **Saved verdicts are as trusted as memory.** `/run/speculaire` is root-only and cleared at reboot. A file with an unknown version or a bad checksum is discarded, and entries saved under another policy or trust root only serve as stale verdicts (D31).
- **Secrets never reach a log.** Registry credentials and tokens are `SecretString`s, and HTTP tracing never records headers (D37).
- **The audit log names pods and images.** It is off by default and goes to the root-readable journal (D37).
- **A bad config never loosens the gate.** Unknown keys stop startup, and an invalid reload keeps the previous config (D30).
- **Private layers are shared, as in Spegel (accepted).** Any node of the cluster can fetch any cached layer without pull secrets. mTLS keeps non-nodes out, but any node can read another node's private layers.
- **A joining node has no P2P.** Until its kubelet certificate exists, it pulls from upstream; the gate still enforces (D16).
- **The pause image is not gated.** NRI's `PodSandbox` carries no image.
- **On containerd 2.3, the identity check has a known gap (accepted).** A retag to an image with identical layers but a different config passes. The agent warns at startup; containerd 2.4 closes the gap (D15).
- **On CRI-O, the image identity is CRI-O's image ID.** CRI-O sets the annotations that carry it after the pod's own, so a pod cannot forge them. CRI-O passes no pod-spec image name, so every name of the image selects policies (D65).
- **Images that no policy matches** are denied by default; `gate.unmatched = "allow"` lets them through unchecked (D23).
- **Admins must allow-list the gate's own dependencies.** With `enforce` + `required_plugins`, a stopped agent blocks every container creation on the node, including control-plane static pods. `gate.exempt` (D18) and the NRI tolerate annotation are the escape hatches. Admins configure them before turning on `enforce` (`docs/operations.md`). `unconfigure` refuses to run while `required_plugins` names speculaire (D32).
- **The tolerate annotation is a pod annotation (accepted).** Anyone who can create a pod can set it, and that pod starts ungated whenever the agent is not registered with NRI (`containerd/nri` `pkg/plugin/annotations.go:40-59`). v1 ships no admission policy to restrict it. The DaemonSet's own pod carries it (D44).
- **`.att` tags do not count.** Attestations are verified only as Sigstore bundles found as OCI referrers; `.att` and unsigned `.sbom` tags are ignored (D12, D43).
- **A BuildKit SBOM is trusted through the index signature.** It has no signature of its own; it counts only when the index digest that covers it has a passing signature (D12, D49).
- **Metrics are readable by anyone who can reach the node.** `/metrics` is plain HTTP on every address by default; it holds counts only, no secret and no pod or image label (D34, D42, D45, D50).
- **A gate timeout lets one container through (accepted).** NRI closes a plugin that misses `plugin_request_timeout` and starts that container ungated; D41 keeps the gate's answer under half the timeout and alerts on it.
- **The agent runs as root** with no capabilities, a read-only system and a syscall filter that denies io_uring (D4, D53).
- **The gate cannot be switched off.** No setting disables it, and a runtime with NRI disabled stops startup (D64); `audit` mode is the only way to admit everything, and it stays visible in metrics (D54).
