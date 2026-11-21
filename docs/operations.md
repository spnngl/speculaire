# Operations

For admins running speculaire on a node. Every setting is listed with its default in `packaging/config.toml` (D30), and every metric in `docs/metrics.md` (D34). Each rejection reason and each alert is listed here; a change that adds one updates this file.

## Install

1. Install the package. It doesn't touch the runtime's config (D55).
2. Run `speculaire configure` as root, with the runtime running. It finds the runtime by its socket (D84), creates the mirror certificates in `/var/lib/speculaire/mirror/`, and adds the mirror entry first in each `hosts.toml` under containerd's `config_path`, creating `_default/hosts.toml` (D82). On CRI-O it writes `/etc/containers/registries.conf.d/99-speculaire.conf`, which copies your entry of each registry in `mirror.registries` and each prefix of your `registries.conf` with the mirror first, and the certificates in `/etc/containers/certs.d/127.0.0.1:7480/`, then reloads CRI-O (D66, D83). It prints each file it changes and any registry or directory it leaves alone, and running it again changes nothing. It changes nothing, naming the file, when a `hosts.toml` is not TOML, has a table of yours named like the mirror, a `host` key in another case, or a `[host.""]` as its first host table, which containerd ignores there and would read after the mirror's: remove that table (D82, D101). `--runtime containerd` or `--runtime cri-o` skips the socket probe, for an image build.
3. Start `speculaire.service`. The agent checks the node first and refuses to start, naming each file and key, in the cases of "Startup refusals" (D86). `/readyz` on port 7482 answers 503 until the mirror listens and the gate has registered with the runtime's NRI, and on a reflector until its kubelet certificate exists and the reflector API listens, then 200 (D45, D168). It answers 503 again while the gate registers anew, after a runtime restart.
4. Continue with "Before turning on `enforce`". The gate starts in `audit` mode (D47).

To move the mirror off port 7480, set `mirror.address` to another loopback `ip:port`, run `speculaire configure` again, then restart the agent (D56). `configure` rewrites its own entries to the new address wherever they are, and remakes the certificates when the IP changed.

At `log.filter = "info"`, the agent logs the address each listener got as it opens, in an `address` field: `status listener open`, `mirror open`, `reflector open` and `peer API open`. Port 0 in `metrics.address`, `mirror.address`, `reflector.listen` or `peer.address` takes a port the kernel picks, which that line names; the tests listen this way. The reflectors are told the peer address as set, port 0 included, so other nodes cannot reach a peer API on port 0. The runtime reaches the mirror only on the port `configure` wrote.

speculaire's image, `ghcr.io/spnngl/speculaire`, is one index for amd64 and arm64, signed by its `release` workflow with its SLSA build provenance and SBOM as referrers (D157). To check one before you run it, add the document of `packaging/policy/release.yaml` to the file `verify.policy` names (D142) and run `speculaire verify ghcr.io/spnngl/speculaire@<digest>` (D156). It prints `allow`, then the workflow's identity and a passing provenance attestation and SBOM, and exits 0. The policy accepts only runs on main or on a version tag. On a node, the agent applies the same policy to each pull of that image.

To stop using the mirror, run `speculaire unconfigure`. It removes only what `configure` added, keeping every edit of yours, reloads CRI-O, and then deletes the certificates. It stops while the runtime's NRI config requires `speculaire`: remove it from `required_plugins` (containerd) or `nri_validator_required_plugins` (CRI-O) and restart the runtime first, or pass `--force` (D32, D84).

## The relay on CRI-O

On CRI-O every pull of a mirrored registry goes through the agent, which fetches from the registry as the node's own config says (`registries.conf`, its drop-ins, `certs.d`, the credential files; the auth file is the one `[crio.image] global_auth_file` names, read from CRI-O) and keeps each blob in `blob_cache.directory`, bounded by `blob_cache.max_size` (D66, D67, D88, D89). An edit of that config, or of containerd's `config.toml` and `hosts.toml` files, shows within `config.poll_interval` (10 s), with no signal; SIGHUP reads it at once (D91).

- A pull that fails with the agent down succeeds on kubelet's retry, straight from the registry.
- An image that needs a pod pull secret is pulled by CRI-O itself: the mirror answers 404 to its manifest.
- A registry that limits the node reaches CRI-O as a 429 with the registry's `Retry-After`, which CRI-O waits out up to 5 times; one that fails, by a 5xx, a broken body or no answer, as a 502. Each is a warning, `upstream limits the relay: CRI-O gets a 429` or `upstream failed the relay: CRI-O gets a 502`, naming the host, the status or failure, the image and the reference, and `speculaire_mirror_requests_total{result="refused"}` counts it (D129). A 429 is the registry's limit on the node's address: add registry credentials, or a pull-through cache.
- A registry whose `registries.conf` prefix has a port is not mirrored: `configure` lists it as left alone, and CRI-O pulls it directly (D88).
- `a registry does not answer the relay` (warning) names a failure to reach every endpoint of a source; `speculaire_mirror_requests_total{result="error"}` counts the requests the relay could not answer, and the agent stops at startup, naming the directory, when it cannot open `blob_cache.directory`.
- A credential that lives in a credential helper is not used (D80, D89): the log says which helper, and the registry is asked anonymously.
- A registry config that does not parse (`registry config reload failed`, one error naming the file, the line and the column) leaves the previous one in use and does not make the agent unready; fix the file, and the next poll reads it (D91).
- A credential, certificate or key file that cannot be used (`registry config reloaded with a file left out`, one error per file, naming it and the line and column) does not fail the config: the registries that need it are asked anonymously or without a client certificate, until the file is fixed and the next poll reads it (D92).

## Before turning on `enforce`

1. Run `gate.mode = "audit"` until `speculaire_gate_total{mode="audit"}` shows no `rejected`, `unverifiable` or `unmatched` results you did not expect. A `subjectRegExp` or `issuerRegExp` must match the whole SAN or issuer, where cosign and policy-controller accept a part of it (D136): in a policy ported from them, write `https://github.com/myorg/.*`, not `https://github.com/myorg/`.
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

A policy file that does not parse stops both before any runtime check, with one line: `the policy file <path>: document <n>, <field>: <message>`, or the line and column of a YAML error. A field outside D142's subset, such as `keyless.url` or `key.kms`, is refused rather than ignored; `packaging/policy.yaml` shows the fields accepted. Without the file, no policy matches and `gate.unmatched` decides (D23).

A running agent reads the policy file and a pinned trust root again on SIGHUP and when they change. One that does not parse logs `the policy file reload failed; the previous one stays in use` (or `the pinned trust root reload failed`) with the same line, and the previous one serves. A change logs `the policies or the trust root changed: verifying again`: each image keeps its previous verdict, marked stale, for up to `verify.stale_max`, until it is verified again under `trigger="reverify"` (D154). The roots of running containers go first; a runtime that does not answer the CRI logs `the running containers are unknown: verifying again in no set order` (D155).

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
| `` `gate.wait = <wait> s` is not below half of `<key> = <timeout>` `` | The runtime could give up on the gate's answer, and fail the container, before the gate answers (D41, D64). The key is containerd's `plugin_request_timeout` (config and imports) or CRI-O's `nri_plugin_request_timeout`; unset or zero, it is NRI's 2 s | Lower `gate.wait`, or raise the key under `[plugins.'io.containerd.nri.v1.nri']` or `[crio.nri]` and restart the runtime |
| `CRI-O's inspect API answered ...` | `GET /config` on `crio.sock` failed | Check CRI-O |
| `cannot read containerd's config` | `config.toml` or an import is not valid | Fix the file named |
| `the registry section is invalid: ...` | containerd would refuse its registry section | Fix the section in the file named |
| `<mirror.directory>/<file>: is missing: run `speculaire configure`` (also: expires within 30 days, not for `mirror.address`, not issued by the CA, not a certificate followed by a key) | The mirror's certificates are absent or no longer fit (D55) | Run `speculaire configure` |
| `99-speculaire.conf: is missing` | CRI-O pulls do not go through the mirror (D66) | Run `speculaire configure` |
| `mirror.address` is not loopback | The mirror would listen beyond the node (D56) | Use a loopback address |
| `listening on mirror.address ...` (also `metrics.address`) | Another process holds the address | Free it or change the address (D56) |
| `opening the blob cache <directory>` | On CRI-O, the agent cannot create or read `blob_cache.directory` (D67) | Fix the directory or `blob_cache.directory` |
| `opening the artifact store <directory>` | The agent cannot create or read `artifacts.directory` (D121) | Fix the directory or `artifacts.directory` |

## Break glass: containers do not start

Work through these steps in order, and stop at the first one that helps.

1. **The gate rejects images it should allow.** Set `gate.mode = "audit"` and run `systemctl reload speculaire`. The mode reloads live (D30), and pods start on kubelet's next retry.
2. **The agent is down.** The runtime's validator rejects every container: `required plugin "speculaire" not present`. Run `systemctl restart speculaire`. If it does not start, run `speculaire check-config` and read `journalctl -u speculaire`: both give the refusals of "Startup refusals".
3. **The agent cannot be started.** Remove `speculaire` from `required_plugins` and run `systemctl restart containerd`; on CRI-O, from `nri_validator_required_plugins`, then `systemctl restart crio`. Running containers survive a runtime restart. New containers then start ungated.

## Rejection reasons

Shown in `kubectl describe pod` under `CreateContainerError`. On a node, `speculaire verify <name>@<digest>` gives an image's verdict in these words, then each matched policy, authority, attestation and SBOM check with its result and reason; `--json` gives the same as one object. It asks upstream through the runtime's registry config, never a peer, and exits 0 when the image is allowed, 1 when not, 2 when the config cannot be used (D156).

| Reason | Meaning | Action |
|---|---|---|
| `verification pending` | The verdict was not ready within `gate.wait`, CRI-O listed no image of that ID within it, or the gate held 256 requests already (D22, D172) | None; kubelet retries. Investigate if it persists |
| `rejected: image identity mismatch` | On containerd below NRI v0.12.2, the image the name annotation resolves to is not the one the container's snapshot rests on (D15, D170) | Check for a retag between pull and create |
| `unverifiable: image name not in containerd's image store` | On containerd below NRI v0.12.2, the agent's copy of the `k8s.io` image store has no image of the container's name (D170) | None when the image was just pulled; kubelet retries. Otherwise check `ctr -n k8s.io images ls` for the name |
| `unverifiable: image layers cannot be read` | On containerd below NRI v0.12.2, the image's index, manifest or config is missing from containerd's content store, unreadable, or has no image for the node's platform (D170) | Check the agent's debug log; pull the image again |
| `unverifiable: container snapshot cannot be read` | On containerd below NRI v0.12.2, the container's snapshot is not in the snapshotter of the pod's runtime handler as `config.toml` names it, or the `Stat` failed (D170, D171) | Check the handler's `snapshotter` in `config.toml` and the agent's debug log |
| `unverifiable: image ID is not a config digest` | On CRI-O, no manifest CRI-O lists for the image has the image ID as its config digest, or the node holds none of them to read it from (D65, D172) | Check `crictl images --digests` for the image; with `insecure_allow_unpredictable_image_contents` CRI-O's image IDs are no config digests |
| `unverifiable: no image identity in the request` | On containerd 2.4, `CreateContainer` named no image name or digest, on containerd below NRI v0.12.2 no parsable `io.kubernetes.cri.image-name`, or on CRI-O no `io.kubernetes.cri-o.ImageRef` (D169, D170) | Report it: a runtime that sends none is not supported |
| `unmatched` | No policy matches the image, and `gate.unmatched = "deny"` (D23) | Add a policy, or exempt the image |
| `rejected: <detail>` | A signature, attestation or SBOM check failed (D20) | Fix the image; the verdict is final for this policy and trust root |
| `rejected: attestation <predicateType> missing (.att tags are not supported)` | No bundle naming the image signs an in-toto statement of that predicate type, compared exactly; one that exists only as a `.att` tag is not read (D43, D149) | Attest again with a current cosign or `actions/attest`, which attach a bundle as a referrer |
| `rejected: attestation <predicateType>: <reason>` | A bundle attests that predicate type, but fails as a signature would, with one of the `signature invalid`, `certificate issuer` or `identity mismatch` reasons below (D149) | As for that reason |
| `rejected: no signature` | No Sigstore bundle names the image as its subject, and no `.sig` is stored for it (D145, D147) | Sign the image with cosign v3, which attaches a bundle as a referrer |
| `rejected: signature invalid: <cause>` | A bundle names the image but does not verify against the trust root: altered, without a transparency-log entry, or bound to another digest (D142, D145) | Sign the image again |
| `rejected: signature invalid: the .sig signs <digest>, not this image` | A `.sig` is stored for the image, but its simple signing payload names another image: a peer or a registry served another image's `.sig` (D147) | Sign the image itself; check which node or registry serves that `.sig` |
| `rejected: signature invalid: the .sig has no SET (annotation dev.sigstore.cosign/bundle)` | A `.sig` names the image but was never logged, as `cosign sign --tlog-upload=false` makes (D142, D147) | Sign again with the transparency log, or with cosign v3 |
| `rejected: identity mismatch: signed by <SAN> (issuer <issuer>)` | A bundle verifies, but its signer matches none of the authority's identities; `by a key` when a key signed it for a keyless authority, or another key (D136, D145) | Add that identity to the policy, or sign with the expected identity |
| `rejected: certificate issuer <DN> is unknown to the trust root` | Another Sigstore instance signed the bundle, such as GitHub's private one for private repositories (D43, D145) | Sign or attest on public-good Sigstore |
| `rejected: signature over sbom.max_size: <n> bytes` | A bundle's manifest lists it above `sbom.max_size`, so discovery left it out (D150) | Raise `sbom.max_size`, or attest a smaller SBOM |
| `rejected: SBOM missing` | The policy requires an SBOM, and no bundle attests one (`https://spdx.dev/Document`, `/v2.3` or `https://cyclonedx.org/bom`) nor does a BuildKit attestation manifest of the index hold one; a `.sbom` tag is not read (D12, D150) | Attest an SBOM with `cosign attest` or `actions/attest-sbom`, or build with `docker buildx --sbom=true` and sign the index |
| `rejected: SBOM unsigned: <reason>` | An SBOM exists, but its attestation, or the index holding the BuildKit one, fails the authorities' signers with that signature reason (D12, D49, D150) | As for that reason; sign the index for a BuildKit SBOM |
| `rejected: SBOM over sbom.max_size: <n> bytes` | The SBOM's manifest lists it above `sbom.max_size`, so discovery left it out (D150) | Raise `sbom.max_size`, or attest a smaller SBOM |
| `rejected: SBOM unparsable: <where>` | The SBOM is not SPDX 2.3 JSON or CycloneDX 1.4 or later JSON, as its predicate type says (D12, D150) | Generate it again with a current syft, Trivy or BuildKit |
| `rejected: SBOM without packages` | The SBOM lists no package but the image it describes: its generator found nothing (D12, D150) | Check the generator's scope; scan the image, not an empty directory |
| `unverifiable: trust root: <cause>` | The node holds no trust root: TUF and its cache both failed, or the first refresh is still running (D143) | Check that the node reaches `verify.tuf_url`; it is retried automatically |
| `unverifiable: <detail>` | Artifacts or the trust root could not be obtained (D17, D20); `artifacts unreachable` when no peer nor upstream served them | Check upstream reachability and credentials; it is retried 10 s later, then after twice the wait each time, up to 5 min (D151) |
| `unverifiable: upstream rate limited: <host>` | The registry answered `429`, or `503` with `Retry-After`; discovery to that host pauses, for every image, until its `Retry-After`, at most 1 h, and resumes by itself. The journal says it at `info` as `verdict of <digest> under <policies>: unverifiable: upstream rate limited: <host>`, and as `discovery of <digest>: …` for an image no policy matches (D38, D128, D151) | Add registry credentials, or wait |

## Reflector refusals

A reflector ends an agent's `Announce` stream with a `Refused` frame naming the reason (D105), and counts it in `speculaire_reflector_announce_rejected_total{reason}`; its `warn` log names the node and the cause (D97). The agent reconnects (D33), and is refused again until the cause is fixed.

| Reason | Meaning | Action |
|---|---|---|
| `identity` | The `Hello` names another node than the TLS certificate's (D16) | Find the node: a bug, or a node forging announcements |
| `version` | The agent speaks a protocol version the reflector does not accept: not its own nor the previous one (D2) | Finish the rolling upgrade, reflectors first |
| `address` | The peer address is not an IP literal with a port | Report a bug |
| `size` | A frame's length is over 4 MiB | Report a bug |
| `digests` | The node announces more than 100k digests | Prune the node's images, or report it if it holds that many legitimately |
| `malformed` | A frame does not decode, or holds a message the protocol does not allow there, such as a second `Hello` or a string that is not a digest | Report a bug |

## Tags from peers

A pull by tag asks the peers whose runtime lists that tag before upstream, so it works while upstream is down (D123). A peer can name any image for a tag, and a tag moved upstream keeps resolving to the image peers hold (`docs/security.md`). To resolve every tag upstream, as before, set `mirror.resolve_tags = false` and reload: the next tag request answers 404 and the runtime asks upstream. No restart and no `configure` is needed; containerd's `hosts.toml` keeps `resolve`. `speculaire_tag_lookups_total{result}` counts the tags peers resolved (`peer`) and missed (`miss`). On containerd, a node configured by an earlier release sends the mirror no tag until `speculaire configure` runs again and adds `resolve` to its `hosts.toml` entry (D82).

## Logs and audit

- `journalctl -u speculaire` shows the agent's logs, at `warn` and above by default. Change `log.filter` (`EnvFilter` syntax) and reload to see more (D37).
- At `log.filter = "debug"` (or `speculaire_mirror=debug,speculaire_reflect=debug`), set `log.timings = true` and reload to log each span as it closes, as JSON on stderr with `time.busy` and `time.idle`: `mirror request` (`kind`, `digest`, `source`, `result`) closes at the body's last byte, `peer fetch` (`peer`, `rank`, `result`) at the attempt's end, and `reflector connection` (`peer`, `node`) at the connection's end. Turn it off once read: each request writes a line.
- Set `audit.enabled = true` and reload to record one `gate` event per container creation, one `verdict` event per changed verdict, and one `peer` event per peer denied for a wrong digest (D52). Read them with `journalctl -t speculaire-audit` (D37); "Audit events" lists their fields.
- When the gate registers, it checks the containers already running: each one whose verdict lands as `rejected: …` or `unverifiable: …` gets one warning, `a container running since before the gate registered has a verdict that does not allow it`, naming its namespace, pod, container, image and reason, again only when the verdict changes. The gate stops none; its next start is decided as any (D175). `journalctl -u speculaire -p warning --grep 'running since before'` lists them.
- Registry credentials and tokens never appear in either.

## Audit events

Each event has a field `event` naming it. journald stores a field under its name in capitals behind `F_`: `journalctl -t speculaire-audit F_EVENT=gate -o json` gives the `gate` events with `F_NAMESPACE`, `F_POD` and the rest; without journald, the JSON on stderr has them in `fields` as named here (D37, D173). A field with nothing to name is empty.

kubelet retries a rejected container creation with a backoff, and each retry is a creation: a rejected pod leaves one `gate` event per retry, as `speculaire_gate_total` counts one per retry.

| Event | Field | Value |
|---|---|---|
| `gate` | `namespace` | The pod's namespace |
| `gate` | `pod` | The pod's name |
| `gate` | `container` | The container's name |
| `gate` | `image_name` | On containerd, the image as the pod names it; on CRI-O, which passes no such name, the repositories policies match, comma-separated (D65) |
| `gate` | `image_identity` | The image identity read: containerd's listed digest, CRI-O's image ID (D15); empty when none was read |
| `gate` | `identity_path` | `nri`, `annotation` or `image_id`, as `speculaire_identity_path` names it (D170) |
| `gate` | `matched_policies` | The names of the policies the image's names match, comma-separated |
| `gate` | `mode` | `gate.mode` |
| `gate` | `result` | As `speculaire_gate_total` labels it: `allow`, `rejected`, `unverifiable`, `pending`, `exempt`, `unmatched` or `overloaded` |
| `gate` | `reason` | The rejection reason `enforce` gives, under either mode ("Rejection reasons"); empty when it allows |
| `gate` | `stale` | Whether the verdict was stale (D21) |
| `gate` | `exemption` | `namespace` or `image`, the exemption that applied (D18) |
| `verdict` | `image_identity` | The manifest digest the verdict keys (D20) |
| `verdict` | `matched_policies` | The names of the policies verified, comma-separated |
| `verdict` | `trust_root_hash` | The trust root's hash, or `none` (D143) |
| `verdict` | `result` | `allow`, `rejected`, `unverifiable` or `pending` |
| `verdict` | `reason` | The verdict's reason; empty for `allow` |
| `verdict` | `signer_identities` | Each `<policy>: <subject> (issuer <issuer>)`, or `<policy>: a key`, that satisfied a policy, semicolon-separated |
| `peer` | `node` | The denied peer's node identity (D52) |
| `peer` | `peer` | Its address |
| `peer` | `digest` | The digest it sent other content for |
| `peer` | `until` | When its denial ends |

## Stopping

`systemctl stop speculaire` runs D39's steps in order (D177):

1. `/readyz` answers 503.
2. The mirror answers every request 404, so pulls fall through to upstream, and the peer API answers 503.
3. The node withdraws from the reflectors.
4. Transfers in flight get up to `shutdown.drain_timeout` (10 s) to finish; the agent logs `transfers still in flight at shutdown.drain_timeout are cut` for those it cuts.
5. The cache is saved.
6. The gate disconnects from NRI, and the agent exits.

Until step 6, the gate decides each container creation from memory, as when running. Keep `shutdown.drain_timeout` under the unit's `TimeoutStopSec=20s`, less the save, or systemd kills the agent before it saves. Once stopped, pulls fall through to upstream, and with `required_plugins` set, container creation is rejected.

## Metrics to alert on

Histograms are native and served only over protobuf, so Prometheus must have native-histogram ingestion turned on (D34).

| Metric | Alert when |
|---|---|
| `speculaire_gate_total{mode="enforce",result=~"rejected\|unverifiable\|pending\|unmatched"}` | The rate rises above its usual level |
| `speculaire_peer_fetches_total{result="digest_mismatch"}` | It increases: a peer sent bytes that do not match their digest, and is skipped until `peer.deny_ttl` passes; the warning log `a peer sent content that is not its digest`, and the `peer` audit event if on, name its node. On containerd the pull went on from another peer; on CRI-O it failed once and kubelet retried (D52, D102) |
| `speculaire_lookup_seconds_count{result="error"}` | It rises: lookups fail at every reflector asked, and pulls fall through to upstream (D102) |
| `speculaire_lookup_seconds_count{result="no_reflector"}` | It rises: the agent streams to no reflector, asks nobody, and pulls fall through to upstream (D103) |
| `speculaire_lookup_seconds_count{result="miss"}` | Its share of lookups rises while every `speculaire_reflector_connected` is 1: the reflectors answer, but lack what the nodes hold; look for refused streams (`speculaire_reflector_announce_rejected_total`) and for nodes whose `speculaire_p2p_enabled` is 0 (D103) |
| `speculaire_tag_conflicts_total` | It increases: two peers resolved one tag to different manifests; the warning log `two peers resolved a tag to different digests` names it. Usually a tag moved while nodes still hold the old image; else a node may lie (D123) |
| `speculaire_mirror_requests_total{result="error"}` | It increases: the mirror could not read content it may hold, and answered 404; the warning log names the error (D85) |
| `speculaire_mirror_requests_total{result="refused"}` | It rises on CRI-O: a registry limits the node (429) or fails (502), and pulls wait or fail; the warning logs name the host (D129) |
| `speculaire_config_reload_failures_total` | It increases: the agent is still on its previous config, registry config, policy file or pinned trust root, or a registry config read left a credential, certificate or key file out, or the kubelet certificate or the cluster CA cannot be loaded and the previous one stays; the error log names the file and the line (D30, D91, D92, D95, D154) |
| `speculaire_cache_loads_total{result="discarded"}` | It increases outside an upgrade that changed the file's format: `cache.bin` was damaged, and the agent started with no verdicts, so containers wait on verifications again; the warning log `saved verdicts discarded` names why (D165, D176) |
| `speculaire_identity_path{path="annotation"}` | It is 1: the node runs containerd 2.3, whose NRI names no image, with its known identity gap; the warning log `identity gap, D15` says so at each NRI registration (D15, D170) |
| `speculaire_trust_root_expiry_timestamp_seconds` | 0, or less than 3 days away: Sigstore re-signs its TUF timestamp each day for 7, so the agent cannot reach `verify.tuf_url` (the warning log `no trust root` says why) or a pinned root nears its end; once it passes, new verifications become `unverifiable`; cached verdicts keep serving (D143) |
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
