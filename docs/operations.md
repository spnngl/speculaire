# Operations

For admins running speculaire on a node. Every setting is listed with its default in `packaging/config.toml` (D30), and every metric in `docs/metrics.md` (D34). Each rejection reason and each alert is listed here; a change that adds one updates this file.

## Install

1. Install the package. It doesn't touch the runtime's config (D55).
2. Run `speculaire configure` as root, with the runtime running. It finds the runtime by its socket (D84), creates the mirror certificates in `/var/lib/speculaire/mirror/`, and adds the mirror entry first in each `hosts.toml` under containerd's `config_path`, creating `_default/hosts.toml` (D82). On CRI-O it writes `/etc/containers/registries.conf.d/99-speculaire.conf`, which copies your entry of each registry in `mirror.registries` and each prefix of your `registries.conf` with the mirror first, and the certificates in `/etc/containers/certs.d/127.0.0.1:7480/`, then reloads CRI-O (D66, D83). It prints each file it changes and any registry or directory it leaves alone, and running it again changes nothing. It changes nothing, naming the file, when a `hosts.toml` is not TOML, has a table of yours named like the mirror, a `host` key in another case, or a `[host.""]` as its first host table, which containerd ignores there and would read after the mirror's: remove that table (D82, D101). `--runtime containerd` or `--runtime cri-o` skips the socket probe, for an image build.
3. Start `speculaire.service`. The agent checks the node first and refuses to start, naming each file and key, in the cases of "Startup refusals" (D86). `/readyz` on port 7482 answers 503 until the mirror listens, then 200 (D45).
4. Continue with "Before turning on `enforce`". The gate starts in `audit` mode (D47).

To move the mirror off port 7480, set `mirror.address` to another loopback `ip:port`, run `speculaire configure` again, then restart the agent (D56). `configure` rewrites its own entries to the new address wherever they are, and remakes the certificates when the IP changed.

At `log.filter = "info"`, the agent logs the address each listener got as it opens, in an `address` field: `status listener open`, `mirror open`, `reflector open` and `peer API open`. Port 0 in `metrics.address`, `mirror.address`, `reflector.listen` or `peer.address` takes a port the kernel picks, which that line names; the tests listen this way. The reflectors are told the peer address as set, port 0 included, so other nodes cannot reach a peer API on port 0. The runtime reaches the mirror only on the port `configure` wrote.

To stop using the mirror, run `speculaire unconfigure`. It removes only what `configure` added, keeping every edit of yours, reloads CRI-O, and then deletes the certificates. It stops while the runtime's NRI config requires `speculaire`: remove it from `required_plugins` (containerd) or `nri_validator_required_plugins` (CRI-O) and restart the runtime first, or pass `--force` (D32, D84).

## The relay on CRI-O

On CRI-O every pull of a mirrored registry goes through the agent, which fetches from the registry as the node's own config says (`registries.conf`, its drop-ins, `certs.d`, the credential files; the auth file is the one `[crio.image] global_auth_file` names, read from CRI-O) and keeps each blob in `blob_cache.directory`, bounded by `blob_cache.max_size` (D66, D67, D88, D89). An edit of that config, or of containerd's `config.toml` and `hosts.toml` files, shows within `config.poll_interval` (10 s), with no signal; SIGHUP reads it at once (D91).

- A pull that fails with the agent down succeeds on kubelet's retry, straight from the registry.
- An image that needs a pod pull secret is pulled by CRI-O itself: the mirror answers 404 to its manifest.
- A registry whose `registries.conf` prefix has a port is not mirrored: `configure` lists it as left alone, and CRI-O pulls it directly (D88).
- `a registry does not answer the relay` (warning) names a failure to reach every endpoint of a source; `speculaire_mirror_requests_total{result="error"}` counts the requests the relay could not answer, and the agent stops at startup, naming the directory, when it cannot open `blob_cache.directory`.
- A credential that lives in a credential helper is not used (D80, D89): the log says which helper, and the registry is asked anonymously.
- A registry config that does not parse (`registry config reload failed`, one error naming the file, the line and the column) leaves the previous one in use and does not make the agent unready; fix the file, and the next poll reads it (D91).
- A credential, certificate or key file that cannot be used (`registry config reloaded with a file left out`, one error per file, naming it and the line and column) does not fail the config: the registries that need it are asked anonymously or without a client certificate, until the file is fixed and the next poll reads it (D92).

## Before turning on `enforce`

1. Run `gate.mode = "audit"` until `speculaire_gate_total{mode="audit"}` shows no `rejected`, `unverifiable` or `unmatched` results you did not expect.
2. Exempt images that must run without a signature with `gate.exempt` (D18). An exemption needs a running agent; while the agent is stopped, only the toleration annotation of step 3 lets a pod start.
3. Pick a toleration annotation for the static control-plane pods. Set it in the runtime's validator section, and add that annotation, set to `"true"`, to each static pod manifest. Without it, a stopped agent keeps the control plane from restarting (`containerd/nri` `plugins/default-validator/default-validator.go:53-65`).
   - containerd: `tolerate_missing_plugins_annotation` under `[plugins.'io.containerd.nri.v1.nri'.default_validator]`.
   - CRI-O: `nri_validator_tolerate_missing_plugins_annotation` under `[crio.nri.default_validator]`, in a file of `/etc/crio/crio.conf.d/`.
4. On every node, `speculaire check-config` exits 0. It exits 1, with the startup refusals below and each file that lacks what `configure` makes, when a `hosts.toml` lacks the mirror entry, so `configure` has not run there or an edit removed it (D55, D82), or when a certificate is missing, expires within 30 days or is not for `mirror.address`. On CRI-O it exits 1 when a later drop-in overrides speculaire's entry for a registry, or the admin changed their entry since `configure`; run `configure` again (D66).
5. Turn on fail-closed in the same section, then restart the runtime (D64):
   - containerd: `enable = true` and `required_plugins = ["speculaire"]`, then `systemctl restart containerd`.
   - CRI-O: `nri_enable_default_validator = true` and `nri_validator_required_plugins = ["speculaire"]`, then `systemctl restart crio`.

## Startup refusals

`speculaire agent` stops before it serves, and `speculaire check-config` exits 1, with one line per problem: `<file or socket>: <message>` (D86). Each message names the key. The last two rows come from `agent` only, which listens and opens the blob cache where `check-config` does not. Restart the runtime after changing its config.

| Message | Meaning | Action |
|---|---|---|
| `cannot connect to <socket>` / `<socket> did not answer ...` | The runtime does not answer the CRI `Version` call within 5 s | Start the runtime, or set `runtime.containerd_socket` or `runtime.crio_socket` |
| no runtime socket answers, or both | Neither or both runtimes run (D64) | Run one runtime, or point the keys at the right sockets |
| `answers as "<name>", not <runtime>` | The socket belongs to the other runtime | Fix `[runtime]` |
| `containerd <version> is older than 2.3.0` / `CRI-O <version> is older than 1.35.0` | The runtime is below the supported floor (D15, D63) | Upgrade it |
| `reports the version "<text>", which is no release` | The version is not `major.minor.patch` | Report it: the agent cannot tell what it runs on |
| `` `discard_unpacked_layers = true` `` | containerd deletes the layers it unpacked, so the node cannot serve them (D15) | Set it to `false` in `[plugins.'io.containerd.cri.v1.images']` (`[plugins.'io.containerd.grpc.v1.cri'.containerd]` in a config of version 2) |
| `` `config_path` is not set `` | containerd reads no `hosts.toml`: `mirrors` is in use (D14) | Set `config_path = "/etc/containerd/certs.d"` under `[plugins.'io.containerd.cri.v1.images'.registry]`, and move `mirrors` to `hosts.toml` files |
| `does not export the settings of the CRI image service` | containerd 2.4's `io.containerd.cri.v1.images` is disabled or failed to start | Fix containerd's own logs first |
| `` `disable = true` ``, `` `disable_connections = true` `` or `io.containerd.nri.v1.nri is in disabled_plugins` | containerd's NRI is off or closed to plugins that start on their own (D54) | Set the key to `false`, or remove the plugin from `disabled_plugins` |
| `` `enable_nri = false` `` or `` `nri_disable_connections = true` `` | CRI-O's NRI is off or closed (D54, D64) | Set `enable_nri = true` and `nri_disable_connections = false` under `[crio.nri]` |
| `CRI-O's inspect API answered ...` | `GET /config` on `crio.sock` failed | Check CRI-O |
| `cannot read containerd's config` | `config.toml` or an import is not valid | Fix the file named |
| `the registry section is invalid: ...` | containerd would refuse its registry section | Fix the section in the file named |
| `<mirror.directory>/<file>: is missing: run `speculaire configure`` (also: expires within 30 days, not for `mirror.address`, not issued by the CA, not a certificate followed by a key) | The mirror's certificates are absent or no longer fit (D55) | Run `speculaire configure` |
| `99-speculaire.conf: is missing` | CRI-O pulls do not go through the mirror (D66) | Run `speculaire configure` |
| `mirror.address` is not loopback | The mirror would listen beyond the node (D56) | Use a loopback address |
| `listening on mirror.address ...` (also `metrics.address`) | Another process holds the address | Free it or change the address (D56) |
| `opening the blob cache <directory>` | On CRI-O, the agent cannot create or read `blob_cache.directory` (D67) | Fix the directory or `blob_cache.directory` |

## Break glass: containers do not start

Work through these steps in order, and stop at the first one that helps.

1. **The gate rejects images it should allow.** Set `gate.mode = "audit"` and run `systemctl reload speculaire`. The mode reloads live (D30), and pods start on kubelet's next retry.
2. **The agent is down.** Run `systemctl restart speculaire`. If it does not start, run `speculaire check-config` and read `journalctl -u speculaire`: both give the refusals of "Startup refusals".
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

## Reflector refusals

A reflector ends an agent's `Announce` stream and counts the reason in `speculaire_reflector_announce_rejected_total{reason}`; its `warn` log names the node and the cause (D97). The agent reconnects (D33), and is refused again until the cause is fixed.

| Reason | Meaning | Action |
|---|---|---|
| `identity` | The `Hello` names another node than the TLS certificate's (D16) | Find the node: a bug, or a node forging announcements |
| `version` | The agent speaks a protocol version the reflector does not accept: not its own nor the previous one (D2) | Finish the rolling upgrade, reflectors first |
| `address` | The peer address is not an IP literal with a port | Report a bug |
| `size` | A message is over 4 MiB | Report a bug |
| `digests` | The node announces more than 100k digests | Prune the node's images, or report it if it holds that many legitimately |
| `malformed` | A message is not one the protocol allows there, such as a second `Hello` or a string that is not a digest | Report a bug |

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
| `speculaire_peer_fetches_total{result="digest_mismatch"}` | It increases: a peer sent bytes that do not match their digest, and is skipped until `peer.deny_ttl` passes; the warning log `a peer sent content that is not its digest`, and the `peer` audit event if on, name its node. On containerd the pull went on from another peer; on CRI-O it failed once and kubelet retried (D52, D102) |
| `speculaire_lookup_seconds_count{result="error"}` | It rises: lookups fail at every reflector asked, and pulls fall through to upstream (D102) |
| `speculaire_lookup_seconds_count{result="no_reflector"}` | It rises: the agent streams to no reflector, asks nobody, and pulls fall through to upstream (D103) |
| `speculaire_lookup_seconds_count{result="miss"}` | Its share of lookups rises while every `speculaire_reflector_connected` is 1: the reflectors answer, but lack what the nodes hold; look for refused streams (`speculaire_reflector_announce_rejected_total`) and for nodes whose `speculaire_p2p_enabled` is 0 (D103) |
| `speculaire_mirror_requests_total{result="error"}` | It increases: the mirror could not read content it may hold, and answered 404; the warning log names the error (D85) |
| `speculaire_config_reload_failures_total` | It increases: the agent is still on its previous config, or on its previous registry config, or a registry config read left a credential, certificate or key file out, or the kubelet certificate or the cluster CA cannot be loaded and the previous one stays; the error log names the file and the line (D30, D91, D92, D95) |
| `speculaire_identity_path{path="annotation"}` | It is 1: the node runs containerd 2.3, with its known identity gap (D15) |
| `speculaire_trust_root_expiry_timestamp_seconds` | Less than 7 days away: once it passes, new verifications become `unverifiable`; cached verdicts keep serving |
| `speculaire_p2p_enabled` | 0 for more than 10 min: the node has no usable kubelet certificate or cluster CA, or its certificate expired, and pulls only from upstream; the info log names an absent file, the error log a bad one (D16, D95) |
| `speculaire_identity_expiry_timestamp_seconds` | Less than a tenth of the certificate's lifetime away: kubelet renews it once 70 to 90% of its lifetime has passed, so it stopped renewing; once it passes, P2P stops on the node (D95) |
| `speculaire_reflector_connected` | 0 for any `member` for more than 5 min |
| `speculaire_reflector_announce_rejected_total` | It increases: a reflector refuses an agent's stream, whose announcements are then missing from lookups (§ Reflector refusals) |
| `speculaire_nri_connected` | 0 for more than 1 min: with `required_plugins`, container creation is rejected (D41) |
| `speculaire_gate_seconds` | p99 above half of `plugin_request_timeout`: a timeout lets a container start ungated (D41) |

## Upgrade and removal

- **Support:** only the latest minor release gets fixes (D40).
- **Upgrade:** one minor at a time, reflectors (control-plane nodes) first, then the other nodes. A reflector accepts the previous protocol version (D2, D40), and verdicts survive the restart in `/run/speculaire` (D31), so nodes can upgrade one at a time.
- **Removal:** first remove `speculaire` from `required_plugins` (CRI-O: `nri_validator_required_plugins`) and restart the runtime. The package's removal script runs `speculaire unconfigure`, which refuses to run while `required_plugins` still names `speculaire` (D32).
