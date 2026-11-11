# Operations

For admins running speculaire on a node. Every setting is listed with its default in `packaging/config.toml` (D30), and every metric in `docs/metrics.md` (D34). Each rejection reason and each alert is listed here; a change that adds one updates this file.

## Install

1. Install the package. It doesn't touch containerd's config (D55).
2. Run `speculaire configure`. It creates the mirror certificates in `/var/lib/speculaire/mirror/` and adds the mirror entry to each `hosts.toml` (D14, D32).
3. Start `speculaire.service`. The agent refuses to start without the mirror certificates, with an error naming `speculaire configure` (D55). `/readyz` on port 7482 answers 200 once it is ready (D45).
4. Continue with "Before turning on `enforce`". The gate starts in `audit` mode (D47).

To move the mirror off port 7480, set `mirror.address` to another loopback `ip:port`, run `speculaire configure` again, then restart the agent (D56).

## Before turning on `enforce`

1. Run `gate.mode = "audit"` until `speculaire_gate_total{mode="audit"}` shows no `rejected`, `unverifiable` or `unmatched` results you did not expect.
2. Exempt images that must run without a signature with `gate.exempt` (D18). An exemption needs a running agent; while the agent is stopped, only the toleration annotation of step 3 lets a pod start.
3. Pick a toleration annotation for the static control-plane pods. Set it in the runtime's validator section, and add that annotation, set to `"true"`, to each static pod manifest. Without it, a stopped agent keeps the control plane from restarting (`containerd/nri` `plugins/default-validator/default-validator.go:53-65`).
   - containerd: `tolerate_missing_plugins_annotation` under `[plugins.'io.containerd.nri.v1.nri'.default_validator]`.
   - CRI-O: `nri_validator_tolerate_missing_plugins_annotation` under `[crio.nri.default_validator]`, in a file of `/etc/crio/crio.conf.d/`.
4. On every node, `speculaire check-config` exits 0. It exits 1 when a `hosts.toml` lacks the mirror entry, so `configure` has not run there or an edit removed it (D55).
5. Turn on fail-closed in the same section, then restart the runtime (D64):
   - containerd: `enable = true` and `required_plugins = ["speculaire"]`, then `systemctl restart containerd`.
   - CRI-O: `nri_enable_default_validator = true` and `nri_validator_required_plugins = ["speculaire"]`, then `systemctl restart crio`.

## Break glass: containers do not start

Work through these steps in order, and stop at the first one that helps.

1. **The gate rejects images it should allow.** Set `gate.mode = "audit"` and run `systemctl reload speculaire`. The mode reloads live (D30), and pods start on kubelet's next retry.
2. **The agent is down.** Run `systemctl restart speculaire`. If it does not start, run `speculaire check-config` and read `journalctl -u speculaire`.
3. **The agent cannot be started.** Remove `speculaire` from `required_plugins` and run `systemctl restart containerd`; on CRI-O, from `nri_validator_required_plugins`, then `systemctl restart crio`. Running containers survive a runtime restart. New containers then start ungated.

## Rejection reasons

Shown in `kubectl describe pod` under `CreateContainerError`.

| Reason | Meaning | Action |
|---|---|---|
| `verification pending` | The verdict was not ready within `gate.wait` (D22) | None; kubelet retries. Investigate if it persists |
| `image identity mismatch` | On containerd 2.3, the image name no longer resolves to the container's snapshot (D15) | Check for a retag between pull and create |
| `unverifiable: image ID is not a config digest` | On CRI-O, the image ID matches no verified manifest's config digest, as with `insecure_allow_unpredictable_image_contents = "true"` in `storage.conf` (D65) | Remove that option and pull the image again |
| `unmatched` | No policy matches the image, and `gate.unmatched = "deny"` (D23) | Add a policy, or exempt the image |
| `rejected: <detail>` | A signature, attestation or SBOM check failed (D20) | Fix the image; the verdict is final for this policy and trust root |
| `rejected: attestation <predicateType> missing (.att tags are not supported)` | The attestation exists only as a `.att` tag (D43) | Attest again with a current cosign, which attaches a bundle as a referrer |
| `unverifiable: <detail>` | Artifacts or the trust root could not be obtained (D17, D20) | Check upstream reachability and credentials; it is retried automatically |
| `unverifiable: upstream rate limited: <host>` | The registry answered `429`, or `503` with `Retry-After`; discovery to that host pauses until its `Retry-After`, at most 1 h (D38) | Add registry credentials, or wait |

## Logs and audit

- `journalctl -u speculaire` shows the agent's logs, at `warn` and above by default. Change `log.filter` (`EnvFilter` syntax) and reload to see more (D37).
- Set `audit.enabled = true` and reload to record one `gate` event per container creation, one `verdict` event per changed verdict, and one `peer` event per peer denied for a wrong digest (D52). Read them with `journalctl -t speculaire-audit` (D37).
- Registry credentials and tokens never appear in either.

## Stopping

`systemctl stop speculaire` withdraws the node from the reflectors, drains transfers for up to `shutdown.drain_timeout` (10 s), saves the cache, and disconnects from NRI last (D39). While it is stopped, pulls fall through to upstream, and with `required_plugins` set, container creation is rejected.

## Metrics to alert on

Histograms are native and served only over protobuf, so Prometheus must have native-histogram ingestion turned on (D34).

| Metric | Alert when |
|---|---|
| `speculaire_gate_total{mode="enforce",result=~"rejected\|unverifiable\|pending\|unmatched"}` | The rate rises above its usual level |
| `speculaire_peer_fetches_total{result="digest_mismatch"}` | It increases: a peer sent bytes that do not match their digest; the warning log, and the `peer` audit event if on, name its node (D52) |
| `speculaire_config_reload_failures_total` | It increases: the agent is still on its previous config (D30) |
| `speculaire_identity_path{path="annotation"}` | It is 1: the node runs containerd 2.3, with its known identity gap (D15) |
| `speculaire_trust_root_expiry_timestamp_seconds` | Less than 7 days away: once it passes, new verifications become `unverifiable`; cached verdicts keep serving |
| `speculaire_p2p_enabled` | 0 for more than 10 min: the node has no kubelet certificate and pulls only from upstream (D16) |
| `speculaire_reflector_connected` | 0 for any `member` for more than 5 min |
| `speculaire_nri_connected` | 0 for more than 1 min: with `required_plugins`, container creation is rejected (D41) |
| `speculaire_gate_seconds` | p99 above half of `plugin_request_timeout`: a timeout lets a container start ungated (D41) |

## Upgrade and removal

- **Support:** only the latest minor release gets fixes (D40).
- **Upgrade:** one minor at a time, reflectors (control-plane nodes) first, then the other nodes. A reflector accepts the previous protocol version (D2, D40), and verdicts survive the restart in `/run/speculaire` (D31), so nodes can upgrade one at a time.
- **Removal:** first remove `speculaire` from `required_plugins` (CRI-O: `nri_validator_required_plugins`) and restart the runtime. The package's removal script runs `speculaire unconfigure`, which refuses to run while `required_plugins` still names `speculaire` (D32).
