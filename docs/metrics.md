# Metrics

Every metric speculaire exports or will export. A row whose `Planned` cell names a milestone is not built yet, and the change that builds it removes the cell. Tests fail when the other rows and the metrics the code describes disagree, and when `/metrics` holds a metric missing here (D34, D109). Every histogram is native, so it appears only in the protobuf exposition. Labels hold only the values listed here. Alerts: `docs/operations.md`.

## Mirror

| Metric | Type | Labels | Meaning |
|---|---|---|---|
| `speculaire_mirror_requests_total` | counter | `kind` = `manifest`\|`blob`\|`referrers`; `result` = `served`\|`fall_through`\|`error` | Requests from the runtime to the local mirror |
| `speculaire_mirror_bytes_total` | counter | `source` = `local`\|`peer`\|`upstream` | Blob bytes served to the runtime (D100); `upstream` stays 0 on containerd (D66) |
| `speculaire_blob_cache_bytes` | gauge | — | Size of the *blob cache*, on CRI-O (D67) |
| `speculaire_blob_cache_evictions_total` | counter | — | Blobs evicted from the *blob cache* above `blob_cache.max_size` (D67) |
| `speculaire_mirror_first_byte_seconds` | histogram | `kind`; `source` = `local`\|`peer`\|`upstream`\|`fall_through` | Time from request to the response head: of an answer, by where its bytes come from, or of a 404 (`fall_through`, errors included). On containerd, `peer` waits for the whole blob (D102) |
| `speculaire_mirror_body_seconds` | histogram | `kind`; `source` = `local`\|`peer`\|`upstream` | Time from request to the last byte of a body sent whole; a body cut off is not recorded |

## Peers

| Metric | Type | Labels | Meaning |
|---|---|---|---|
| `speculaire_peer_fetches_total` | counter | `result` = `ok`\|`digest_mismatch`\|`busy`\|`timeout`\|`error` | Requests to other agents, each counted when it ends: `ok` and `digest_mismatch` once per whole body, the others per peer that failed; `error` includes a refused certificate and a `404`, `timeout` a stall (D7, D24, D52, D73, D102) |
| `speculaire_peer_fetch_seconds` | histogram | `result`, as `speculaire_peer_fetches_total` | Time from the start of a request to another agent to the end its `result` names: the whole body checked for `ok` and `digest_mismatch`, the failure for the others |
| `speculaire_peer_hedges_total` | counter | — | Requests to a further peer started because the first were slow to answer (D102) |
| `speculaire_peer_uploads_total` | counter | `result` = `served`\|`busy` | Requests to the peer API that found what they named; `busy` answered `503`, at `peer.max_uploads` or while the agent stops (D24, D39, D100) |
| `speculaire_peer_uploads_in_flight` | gauge | — | Blob bodies now being sent, which `peer.max_uploads` caps (D24) |
| `speculaire_peer_upload_bytes_total` | counter | — | Blob bytes sent to other agents |
| `speculaire_peer_upload_seconds` | histogram | — | Time from a peer's request to the last byte of a blob body sent whole, ranges included |
| `speculaire_p2p_enabled` | gauge | — | 1 while the kubelet certificate and the cluster CA are loaded and the certificate has not expired, 0 otherwise (D16, D95) |
| `speculaire_identity_expiry_timestamp_seconds` | gauge | — | When the kubelet certificate in use expires, as a Unix time; absent until one is loaded (D95) |

## Reflector client (every agent)

| Metric | Type | Labels | Meaning |
|---|---|---|---|
| `speculaire_reflector_connected` | gauge | `member` | 1 while the `Announce` stream to that reflector is up |
| `speculaire_reflector_reconnects_total` | counter | `member` | Stream reconnects (D33) |
| `speculaire_lookup_seconds` | histogram | `result` = `hit`\|`miss`\|`error`\|`no_reflector` | `Lookup` latency seen by the agent, hedge included; `miss` named no holder, `error` failed at every member asked, `no_reflector` asked nobody as no stream was up (D102, D103) |

## Reflector server (`role = "reflector"`)

| Metric | Type | Labels | Meaning |
|---|---|---|---|
| `speculaire_reflector_agents` | gauge | — | Connected agents |
| `speculaire_reflector_digests` | gauge | — | Distinct digests in the index |
| `speculaire_reflector_pairs` | gauge | — | (digest, node) pairs in the index |
| `speculaire_reflector_lookup_seconds` | histogram | — | Server-side `Lookup` latency (D33 target: p99 at most 500 µs) |
| `speculaire_reflector_announce_rejected_total` | counter | `reason` = `identity`\|`version`\|`address`\|`size`\|`digests`\|`malformed` | Refused `Announce` streams (D2, D16, D97); `docs/operations.md` § Reflector refusals |

## Verification

| Metric | Type | Labels | Meaning | Planned |
|---|---|---|---|---|
| `speculaire_verifications_total` | counter | `result` = `allow`\|`rejected`\|`unverifiable`; `trigger` = `manifest`\|`event`\|`synchronize`\|`gate_miss`\|`reverify` | Completed verifications (D20, D22); `reverify` follows a policy or trust-root change (D21) | M5 |
| `speculaire_verification_seconds` | histogram | — | Time from trigger to verdict | M5 |
| `speculaire_verdicts` | gauge | `state` = `allow`\|`rejected`\|`unverifiable`\|`pending` | Verdicts in the cache | M5 |
| `speculaire_artifact_fetches_total` | counter | `source` = `peer`\|`upstream`; `upstream`; `result` = `ok`\|`not_found`\|`digest_mismatch`\|`rate_limited`\|`error` | Artifact fetches (D38); `upstream` is a host with a `hosts.toml` directory, else `other`, and empty for peer fetches (D50) | M4 |
| `speculaire_artifact_store_bytes` | gauge | — | Size of the *artifact store* | M4 |
| `speculaire_trust_root_expiry_timestamp_seconds` | gauge | — | When the current TUF metadata expires, as a Unix time | M5 |
| `speculaire_cache_loads_total` | counter | `result` = `loaded`\|`discarded` | Loads of `/run/speculaire/cache.bin` at startup (D31) | M6 |

## Gate

| Metric | Type | Labels | Meaning | Planned |
|---|---|---|---|---|
| `speculaire_gate_total` | counter | `mode` = `audit`\|`enforce`; `result` = `allow`\|`rejected`\|`unverifiable`\|`pending`\|`unmatched`\|`exempt`; `stale` = `true`\|`false` | Gate decisions (D18, D21, D23) | M6 |
| `speculaire_gate_seconds` | histogram | `path` = `nri`\|`annotation` | `CreateContainer` handling time (target: p99 under 5 ms on a cached verdict) | M6 |
| `speculaire_identity_path` | gauge | `path` = `nri`\|`annotation` | 1 for the image-identity path in use (D15) | M6 |
| `speculaire_nri_connected` | gauge | — | 1 while registered with the runtime's NRI (D41, D64) | M6 |

## Process

| Metric | Type | Labels | Meaning |
|---|---|---|---|
| `speculaire_build_info` | gauge | `version`, `runtime` = `containerd`\|`cri-o`, `runtime_version`, `nri_version` | Always 1; the last three are empty until NRI's `Configure` (D68) |
| `speculaire_runtime_alive_tasks` | gauge | — | Tasks alive in the agent's async runtime, read at each scrape |
| `speculaire_runtime_global_queue_depth` | gauge | — | Tasks waiting in the async runtime's global queue, read at each scrape: above zero for long, the workers cannot keep up |
| `speculaire_config_reload_failures_total` | counter | — | Reloads rejected, of the agent's config or of the node's registry config, which the previous one then serves, and registry config reloads that left a credential, certificate or key file out, once per reload, and reads of the kubelet certificate or the cluster CA that failed, once per file (D30, D91, D92, D95) |

Memory, CPU and file descriptors come from node-exporter and systemd (D34); the async runtime's tasks, which they cannot see, come from the agent.
