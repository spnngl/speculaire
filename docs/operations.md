# Operations

For admins running speculaire on a node. Every setting is listed with its default in `packaging/config.toml` (D30), and every metric in `docs/metrics.md` (D34). Each rejection reason and each alert is listed here; a change that adds one updates this file.

## Before turning on `enforce`

1. Run `gate.mode = "audit"` until `speculaire_gate_total{mode="audit"}` shows no `rejected`, `unverifiable` or `unmatched` results you did not expect.
2. Exempt images that must run without a signature with `gate.exempt` (D18). An exemption needs a running agent; while the agent is stopped, only the toleration annotation of step 3 lets a pod start.
3. Pick a toleration annotation for the static control-plane pods. Set `tolerate_missing_plugins_annotation` under `[plugins.'io.containerd.nri.v1.nri'.default_validator]`, and add that annotation, set to `"true"`, to each static pod manifest. Without it, a stopped agent keeps the control plane from restarting (`containerd/nri` `plugins/default-validator/default-validator.go:53-65`).
4. Turn on fail-closed: in the same section, set `enable = true` and `required_plugins = ["speculaire"]`, then restart containerd.

## Break glass: containers do not start

Work through these steps in order, and stop at the first one that helps.

1. **The gate rejects images it should allow.** Set `gate.mode = "audit"` and run `systemctl reload speculaire`. The mode reloads live (D30), and pods start on kubelet's next retry.
2. **The agent is down.** Run `systemctl restart speculaire`. If it does not start, run `speculaire check-config` and read `journalctl -u speculaire`.
3. **The agent cannot be started.** Remove `speculaire` from `required_plugins` and run `systemctl restart containerd`. Running containers survive a containerd restart. New containers then start ungated.

## Rejection reasons

Shown in `kubectl describe pod` under `CreateContainerError`.

| Reason | Meaning | Action |
|---|---|---|
| `verification pending` | The verdict was not ready within `gate.wait` (D22) | None; kubelet retries. Investigate if it persists |
| `image identity mismatch` | On containerd 2.3, the image name no longer resolves to the container's snapshot (D15) | Check for a retag between pull and create |
| `unmatched` | No policy matches the image, and `gate.unmatched = "deny"` (D23) | Add a policy, or exempt the image |
| `rejected: <detail>` | A signature, attestation or SBOM check failed (D20) | Fix the image; the verdict is final for this policy and trust root |
| `rejected: attestation <predicateType> missing (.att tags are not supported)` | The attestation exists only as a `.att` tag (D43) | Attest again with a current cosign, which attaches a bundle as a referrer |
| `unverifiable: <detail>` | Artifacts or the trust root could not be obtained (D17, D20) | Check upstream reachability and credentials; it is retried automatically |
| `unverifiable: upstream rate limited: <host>` | The registry answered `429`; discovery to that host pauses until its `Retry-After`, at most 1 h (D38) | Add registry credentials, or wait |

## Logs and audit

- `journalctl -u speculaire` shows the agent's logs, at `warn` and above by default. Change `log.filter` (`EnvFilter` syntax) and reload to see more (D37).
- Set `audit.enabled = true` and reload to record one `gate` event per container creation and one `verdict` event per changed verdict. Read them with `journalctl -t speculaire-audit` (D37).
- Registry credentials and tokens never appear in either.

## Stopping

`systemctl stop speculaire` withdraws the node from the reflectors, drains transfers for up to `shutdown.drain_timeout` (10 s), saves the cache, and disconnects from NRI last (D39). While it is stopped, pulls fall through to upstream, and with `required_plugins` set, container creation is rejected.

## Metrics to alert on

Histograms are native and served only over protobuf, so Prometheus must have native-histogram ingestion turned on (D34).

| Metric | Alert when |
|---|---|
| `speculaire_gate_total{mode="enforce",result=~"rejected\|unverifiable\|pending"}` | The rate rises above its usual level |
| `speculaire_config_reload_failures_total` | It increases: the agent is still on its previous config (D30) |
| `speculaire_identity_path{path="annotation"}` | It is 1: the node runs containerd 2.3, with its known identity gap (D15) |
| `speculaire_trust_root_expiry_timestamp_seconds` | Less than 7 days away: once it passes, verdicts become `unverifiable` |
| `speculaire_p2p_enabled` | 0 for more than 10 min: the node has no kubelet certificate and pulls only from upstream (D16) |
| `speculaire_reflector_connected` | 0 for any `member` for more than 5 min |
| `speculaire_nri_connected` | 0 for more than 1 min: with `required_plugins`, container creation is rejected (D41) |
| `speculaire_gate_seconds` | p99 above half of `plugin_request_timeout`: a timeout lets a container start ungated (D41) |

## Upgrade and removal

- **Support:** only the latest minor release gets fixes (D40).
- **Upgrade:** one minor at a time, reflectors (control-plane nodes) first, then the other nodes. A reflector accepts the previous protocol version (D2, D40), and verdicts survive the restart in `/run/speculaire` (D31), so nodes can upgrade one at a time.
- **Removal:** first remove `speculaire` from `required_plugins` and restart containerd. The package's removal script runs `speculaire unconfigure`, which refuses to run while `required_plugins` still names `speculaire` (D32).
