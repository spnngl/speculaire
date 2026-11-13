# Metrics

Every metric speculaire exports. A test fails when this list and `/metrics` disagree (D34). Every histogram is native, so it appears only in the protobuf exposition. Labels hold only the values listed here. Alerts: `docs/operations.md`.

## Mirror

| Metric | Type | Labels | Meaning |
|---|---|---|---|
| `speculaire_mirror_requests_total` | counter | `kind` = `manifest`\|`blob`\|`referrers`; `result` = `served`\|`fall_through`\|`error` | Requests from the runtime to the local mirror |
| `speculaire_mirror_bytes_total` | counter | `source` = `local`\|`peer`\|`upstream` | Bytes served to the runtime; `upstream` only on CRI-O (D66) |
| `speculaire_blob_cache_bytes` | gauge | — | Size of the *blob cache*, on CRI-O (D67) |
| `speculaire_blob_cache_evictions_total` | counter | — | Blobs evicted from the *blob cache* above `blob_cache.max_size` (D67) |
| `speculaire_mirror_first_byte_seconds` | histogram | `kind` | Time from request to first byte, or to the 404 of a *fall through* |

## Peers

| Metric | Type | Labels | Meaning |
|---|---|---|---|
| `speculaire_peer_fetches_total` | counter | `result` = `ok`\|`digest_mismatch`\|`busy`\|`timeout`\|`error` | Fetches from other agents; `timeout` includes a stalled one (D7, D24, D73) |
| `speculaire_peer_hedges_total` | counter | — | Hedged extra fetches started |
| `speculaire_peer_uploads_total` | counter | `result` = `served`\|`busy` | Requests to the peer API that found what they named; `busy` answered `503`, at `peer.max_uploads` or while the agent stops (D24, D39, D100) |
| `speculaire_peer_uploads_in_flight` | gauge | — | Blob bodies now being sent, which `peer.max_uploads` caps (D24) |
| `speculaire_peer_upload_bytes_total` | counter | — | Blob bytes sent to other agents |
| `speculaire_p2p_enabled` | gauge | — | 1 while the kubelet certificate and the cluster CA are loaded and the certificate has not expired, 0 otherwise (D16, D95) |
| `speculaire_identity_expiry_timestamp_seconds` | gauge | — | When the kubelet certificate in use expires, as a Unix time; absent until one is loaded (D95) |

## Reflector client (every agent)

| Metric | Type | Labels | Meaning |
|---|---|---|---|
| `speculaire_reflector_connected` | gauge | `member` | 1 while the `Announce` stream to that reflector is up |
| `speculaire_reflector_reconnects_total` | counter | `member` | Stream reconnects (D33) |
| `speculaire_lookup_seconds` | histogram | — | `Lookup` latency seen by the agent, hedge included |

## Reflector server (`role = "reflector"`)

| Metric | Type | Labels | Meaning |
|---|---|---|---|
| `speculaire_reflector_agents` | gauge | — | Connected agents |
| `speculaire_reflector_digests` | gauge | — | Distinct digests in the index |
| `speculaire_reflector_pairs` | gauge | — | (digest, node) pairs in the index |
| `speculaire_reflector_lookup_seconds` | histogram | — | Server-side `Lookup` latency (D33 target: p99 at most 500 µs) |
| `speculaire_reflector_announce_rejected_total` | counter | `reason` = `identity`\|`version`\|`address`\|`size`\|`digests`\|`malformed` | Refused `Announce` streams (D2, D16, D97); `docs/operations.md` § Reflector refusals |

## Verification

| Metric | Type | Labels | Meaning |
|---|---|---|---|
| `speculaire_verifications_total` | counter | `result` = `allow`\|`rejected`\|`unverifiable`; `trigger` = `manifest`\|`event`\|`synchronize`\|`gate_miss`\|`reverify` | Completed verifications (D20, D22); `reverify` follows a policy or trust-root change (D21) |
| `speculaire_verification_seconds` | histogram | — | Time from trigger to verdict |
| `speculaire_verdicts` | gauge | `state` = `allow`\|`rejected`\|`unverifiable`\|`pending` | Verdicts in the cache |
| `speculaire_artifact_fetches_total` | counter | `source` = `peer`\|`upstream`; `upstream`; `result` = `ok`\|`not_found`\|`digest_mismatch`\|`rate_limited`\|`error` | Artifact fetches (D38); `upstream` is a host with a `hosts.toml` directory, else `other`, and empty for peer fetches (D50) |
| `speculaire_artifact_store_bytes` | gauge | — | Size of the *artifact store* |
| `speculaire_trust_root_expiry_timestamp_seconds` | gauge | — | When the current TUF metadata expires, as a Unix time |
| `speculaire_cache_loads_total` | counter | `result` = `loaded`\|`discarded` | Loads of `/run/speculaire/cache.bin` at startup (D31) |

## Gate

| Metric | Type | Labels | Meaning |
|---|---|---|---|
| `speculaire_gate_total` | counter | `mode` = `audit`\|`enforce`; `result` = `allow`\|`rejected`\|`unverifiable`\|`pending`\|`unmatched`\|`exempt`; `stale` = `true`\|`false` | Gate decisions (D18, D21, D23) |
| `speculaire_gate_seconds` | histogram | `path` = `nri`\|`annotation` | `CreateContainer` handling time (target: p99 under 5 ms on a cached verdict) |
| `speculaire_identity_path` | gauge | `path` = `nri`\|`annotation` | 1 for the image-identity path in use (D15) |
| `speculaire_nri_connected` | gauge | — | 1 while registered with the runtime's NRI (D41, D64) |

## Process

| Metric | Type | Labels | Meaning |
|---|---|---|---|
| `speculaire_build_info` | gauge | `version`, `runtime` = `containerd`\|`cri-o`, `runtime_version`, `nri_version` | Always 1; the last three are empty until NRI's `Configure` (D68) |
| `speculaire_config_reload_failures_total` | counter | — | Reloads rejected, of the agent's config or of the node's registry config, which the previous one then serves, and registry config reloads that left a credential, certificate or key file out, once per reload, and reads of the kubelet certificate or the cluster CA that failed, once per file (D30, D91, D92, D95) |

Memory, CPU and file descriptors come from node-exporter and systemd (D34).
