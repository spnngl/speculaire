# Metrics

Every metric speculaire exports or will export. `Runtime` names the runtime whose agents emit it: `both`, `containerd` or `CRI-O`. A row whose `Planned` cell names a milestone is not built yet, and the change that builds it removes the cell. Tests fail when the other rows and the metrics the code describes disagree, when `/metrics` holds a metric missing here or not for its runtime, and when the end-to-end suites of a leg never emit a row for its runtime (D34, D109, D182). Every histogram is native, so it appears only in the protobuf exposition. Labels hold only the values listed here. Alerts: `docs/operations.md`.

## Mirror

| Metric | Type | Labels | Runtime | Meaning |
|---|---|---|---|---|
| `speculaire_mirror_requests_total` | counter | `kind` = `manifest`\|`blob`\|`referrers`; `result` = `served`\|`fall_through`\|`refused`\|`error` | both | Requests from the runtime to the local mirror; `refused` is upstream's refusal the CRI-O relay passed on, a 429 or a 502 (D129) |
| `speculaire_mirror_bytes_total` | counter | `source` = `local`\|`peer`\|`upstream` | both | Blob bytes served to the runtime (D100); `upstream` stays 0 on containerd (D66) |
| `speculaire_blob_cache_bytes` | gauge | — | CRI-O | Size of the *blob cache* (D67) |
| `speculaire_blob_cache_evictions_total` | counter | — | CRI-O | Blobs evicted from the *blob cache* above `blob_cache.max_size` (D67) |
| `speculaire_mirror_first_byte_seconds` | histogram | `kind`; `source` = `local`\|`peer`\|`upstream`\|`fall_through` | both | Time from request to the response head: of an answer, by where its bytes come from, or of a 404, 429 or 502 (`fall_through`, errors and refusals included). On containerd, `peer` waits for the whole blob (D102) |
| `speculaire_mirror_body_seconds` | histogram | `kind`; `source` = `local`\|`peer`\|`upstream` | both | Time from request to the last byte of a body sent whole; a body cut off is not recorded |

## Peers

| Metric | Type | Labels | Runtime | Meaning |
|---|---|---|---|---|
| `speculaire_peer_fetches_total` | counter | `result` = `ok`\|`digest_mismatch`\|`busy`\|`timeout`\|`error` | both | Requests to other agents, each counted when it ends: `ok` and `digest_mismatch` once per whole body, the others per peer that failed; `error` includes a refused certificate and a `404`, `timeout` a stall (D7, D24, D52, D73, D102) |
| `speculaire_peer_fetch_seconds` | histogram | `result`, as `speculaire_peer_fetches_total` | both | Time from the start of a request to another agent to the end its `result` names: the whole body checked for `ok` and `digest_mismatch`, the failure for the others |
| `speculaire_peer_hedges_total` | counter | — | both | Requests to a further peer started because the first were slow to answer (D102) |
| `speculaire_tag_lookups_total` | counter | `result` = `peer`\|`miss` | both | Tags the mirror asked peers for: `peer` when a holder sent a manifest, `miss` when none did and the request fell through to upstream; not counted while `mirror.resolve_tags` is off (D123) |
| `speculaire_tag_conflicts_total` | counter | — | both | Tags two peers resolved to different manifests; the first answer is served (D123) |
| `speculaire_peer_uploads_total` | counter | `result` = `served`\|`busy` | both | Requests to the peer API that found what they named, every referrers list included; `busy` answered `503`, at `peer.max_uploads` or while the agent stops (D24, D39, D100, D124) |
| `speculaire_peer_uploads_in_flight` | gauge | — | both | Blob bodies now being sent, which `peer.max_uploads` caps (D24) |
| `speculaire_peer_upload_bytes_total` | counter | — | both | Blob bytes sent to other agents |
| `speculaire_peer_upload_seconds` | histogram | — | both | Time from a peer's request to the last byte of a blob body sent whole, ranges included |
| `speculaire_p2p_enabled` | gauge | — | both | 1 while the kubelet certificate and the cluster CA are loaded and the certificate has not expired, 0 otherwise (D16, D95) |
| `speculaire_identity_expiry_timestamp_seconds` | gauge | — | both | When the kubelet certificate in use expires, as a Unix time; absent until one is loaded (D95) |

## Reflector client (every agent)

| Metric | Type | Labels | Runtime | Meaning |
|---|---|---|---|---|
| `speculaire_reflector_connected` | gauge | `member` | both | 1 while the `Announce` stream to that reflector is up |
| `speculaire_reflector_reconnects_total` | counter | `member` | both | Stream reconnects (D33) |
| `speculaire_lookup_seconds` | histogram | `result` = `hit`\|`miss`\|`error`\|`no_reflector` | both | `Lookup` latency seen by the agent, hedge included; `miss` named no holder, `error` failed at every member asked, `no_reflector` asked nobody as no stream was up (D102, D103) |

## Reflector server (`role = "reflector"`)

| Metric | Type | Labels | Runtime | Meaning |
|---|---|---|---|---|
| `speculaire_reflector_agents` | gauge | — | both | Connected agents |
| `speculaire_reflector_digests` | gauge | — | both | Distinct digests in the index |
| `speculaire_reflector_pairs` | gauge | — | both | (digest, node) pairs in the index |
| `speculaire_reflector_lookup_seconds` | histogram | — | both | Server-side `Lookup` latency (D33 target: p99 at most 500 µs) |
| `speculaire_reflector_resync_seconds` | histogram | — | both | Time from accepting an agent's connection to holding its first snapshot, once per connection; after a restart, its largest sample is the refill (D103, D104) |
| `speculaire_reflector_announce_rejected_total` | counter | `reason` = `identity`\|`version`\|`address`\|`size`\|`digests`\|`malformed` | both | Refused `Announce` streams (D2, D16, D97); `docs/operations.md` § Reflector refusals |
| `speculaire_reflector_prewarm_sent_total` | counter | `stage` = `seed`\|`release` | both | `Prewarm`s queued: to a wave's seeds, or to a later round or an agent whose stream opened after its wave (D185, D186) |
| `speculaire_reflector_prewarm_rounds_total` | counter | `release` = `announced`\|`timeout` | both | Rounds of a wave ended: every agent of the round announced the image, or `prewarm.seed_timeout` passed (D185); `docs/operations.md` § Prewarm |
| `speculaire_reflector_prewarm_waves_total` | counter | `cause` = `list`\|`refresh`\|`start` | both | Waves started: a new `prewarm.images` entry, a tag whose platform manifests changed, or the list the reflector started with (D186) |
| `speculaire_reflector_prewarm_resolve_failures_total` | counter | — | both | Failed resolutions of a `prewarm.images` entry, each tried again later (D186); `docs/operations.md` § Prewarm |

## Verification

| Metric | Type | Labels | Runtime | Meaning | Planned |
|---|---|---|---|---|---|
| `speculaire_verifications_total` | counter | `result` = `allow`\|`rejected`\|`unverifiable`; `trigger` = `manifest`\|`event`\|`synchronize`\|`gate_miss`\|`reverify` | both | Completed verifications (D20, D22); `manifest` is the first of a root a fetch through the mirror made (D152), `event` follows any other discovery or a retry (D151); `gate_miss` the first of a root a container needed before a list named it, or before its listing's discovery reached it (D172, D174); `synchronize` the first of a root a container of NRI `Synchronize` runs before a list named it, as the list waits for those at start (D175); `reverify` follows a policy or trust-root change (D21) | |
| `speculaire_verification_seconds` | histogram | — | both | Time from trigger to verdict | |
| `speculaire_verdicts` | gauge | `state` = `allow`\|`rejected`\|`unverifiable`\|`pending` | both | Verdicts in memory, one per key (D151) | |
| `speculaire_artifact_fetches_total` | counter | `source` = `peer`\|`upstream`; `upstream`; `result` = `ok`\|`not_found`\|`digest_mismatch`\|`rate_limited`\|`error` | both | Artifact requests by outcome, one per request (D38, D121); `rate_limited` is a `429`, or a `503` with `Retry-After` (D128); `upstream` is a host with a `hosts.toml` directory, on CRI-O a `[[registry]]` table, else `other`, and empty for peer fetches (D50, D121); a peer fetch is one per manifest or blob asked of peers, `not_found` when none gave it, and a mismatch counts in `speculaire_peer_fetches_total` (D52, D126) | M4 |
| `speculaire_artifact_store_bytes` | gauge | — | both | Size of the *artifact store* | M4 |
| `speculaire_trust_root_expiry_timestamp_seconds` | gauge | — | both | When the trust root in use stops verifying, as a Unix time: the first expiry of its TUF metadata, or of a pinned root the latest end of its keys; 0 while none is held, absent for a pinned root whose keys have no end (D143) | |
| `speculaire_cache_loads_total` | counter | `result` = `loaded`\|`discarded` | both | Loads of `verify.cache`, `/run/speculaire/cache.bin`, at startup, one per start that finds the file; `discarded` when it cannot be read or fails its checks, and the agent starts with no verdicts (D31, D165, D176) | |

## Gate

| Metric | Type | Labels | Runtime | Meaning | Planned |
|---|---|---|---|---|---|
| `speculaire_gate_total` | counter | `mode` = `audit`\|`enforce`; `result` = `allow`\|`rejected`\|`unverifiable`\|`pending`\|`unmatched`\|`exempt`\|`overloaded`; `stale` = `true`\|`false` | both | Gate decisions (D18, D21, D23, D172): `pending` when no verdict came within `gate.wait`, `overloaded` when the gate held 256 requests already; `stale` marks a verdict kept before a policy or trust-root change and served while re-verified, up to `verify.stale_max` (D21) | |
| `speculaire_gate_seconds` | histogram | `path` = `nri`\|`annotation`\|`image_id` | both | `CreateContainer` handling time, waits included (target: p99 under 5 ms on a cached verdict, D107) | |
| `speculaire_identity_path` | gauge | `path` = `nri`\|`annotation`\|`image_id` | both | 1 for the image-identity path in use, set at NRI's `Configure`, and 0 for the one it replaces: `nri` on containerd from NRI v0.12.2, `annotation` below, `image_id` on CRI-O (D15, D169, D170) | |
| `speculaire_nri_connected` | gauge | — | both | 1 while registered with the runtime's NRI: from its `Configure` until the connection ends (D41, D64, D168) | |

## Process

| Metric | Type | Labels | Runtime | Meaning |
|---|---|---|---|---|
| `speculaire_build_info` | gauge | `version`, `runtime` = `containerd`\|`cri-o`, `runtime_version`, `nri_version` | both | 1 for the versions in use; the last three are empty until NRI's `Configure`, and a series a later `Configure` replaced is 0 (D68, D168); `nri_version` stays empty when NRI gives none and infers none, as on CRI-O 1.35 and 1.36 |
| `speculaire_runtime_alive_tasks` | gauge | — | both | Tasks alive in the agent's async runtime, read at each scrape |
| `speculaire_runtime_global_queue_depth` | gauge | — | both | Tasks waiting in the async runtime's global queue, read at each scrape: above zero for long, the workers cannot keep up |
| `speculaire_config_reload_failures_total` | counter | — | both | Reloads rejected, of the agent's config or of the node's registry config, which the previous one then serves, and registry config reloads that left a credential, certificate or key file out, once per reload, and reads of the kubelet certificate or the cluster CA that failed, once per file (D30, D91, D92, D95, D154) |

Memory, CPU and file descriptors come from node-exporter and systemd (D34); the async runtime's tasks, which they cannot see, come from the agent.
