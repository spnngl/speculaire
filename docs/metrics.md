# Metrics

Every metric speculaire exports. A test fails when this list and `/metrics` disagree (D34). Every histogram is native, so it appears only in the protobuf exposition. Labels hold only the values listed here. Alerts: `docs/operations.md`.

## Mirror

| Metric | Type | Labels | Meaning |
|---|---|---|---|
| `speculaire_mirror_requests_total` | counter | `kind` = `manifest`\|`blob`\|`referrers`; `result` = `served`\|`fall_through`\|`error` | Requests from containerd to the local mirror |
| `speculaire_mirror_bytes_total` | counter | `source` = `local`\|`peer` | Bytes served to containerd |
| `speculaire_mirror_first_byte_seconds` | histogram | `kind` | Time from request to first byte, or to the 404 of a *fall through* |

## Peers

| Metric | Type | Labels | Meaning |
|---|---|---|---|
| `speculaire_peer_fetches_total` | counter | `result` = `ok`\|`digest_mismatch`\|`busy`\|`timeout`\|`error` | Fetches from other agents (D7, D24) |
| `speculaire_peer_hedges_total` | counter | — | Hedged extra fetches started |
| `speculaire_peer_uploads_total` | counter | `result` = `served`\|`busy` | Requests served to other agents; `busy` answered `503` (D24) |
| `speculaire_peer_uploads_in_flight` | gauge | — | Uploads now in progress |
| `speculaire_peer_upload_bytes_total` | counter | — | Bytes served to other agents |
| `speculaire_p2p_enabled` | gauge | — | 1 once the kubelet certificate exists, 0 before (D16) |

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
| `speculaire_reflector_announce_rejected_total` | counter | `reason` = `identity`\|`version` | Rejected streams or announcements (D2, D16) |

## Verification

| Metric | Type | Labels | Meaning |
|---|---|---|---|
| `speculaire_verifications_total` | counter | `result` = `allow`\|`rejected`\|`unverifiable`; `trigger` = `manifest`\|`event`\|`synchronize`\|`gate_miss` | Completed verifications (D20, D22) |
| `speculaire_verification_seconds` | histogram | — | Time from trigger to verdict |
| `speculaire_verdicts` | gauge | `state` = `allow`\|`rejected`\|`unverifiable`\|`pending` | Verdicts in the cache |
| `speculaire_artifact_fetches_total` | counter | `source` = `peer`\|`upstream`; `upstream`; `result` = `ok`\|`not_found`\|`digest_mismatch`\|`rate_limited`\|`error` | Artifact fetches (D38); `upstream` is empty for peer fetches |
| `speculaire_artifact_store_bytes` | gauge | — | Size of the *artifact store* |
| `speculaire_trust_root_expiry_timestamp_seconds` | gauge | — | When the current TUF metadata expires, as a Unix time |
| `speculaire_cache_loads_total` | counter | `result` = `loaded`\|`discarded` | Loads of `/run/speculaire/cache.bin` at startup (D31) |

## Gate

| Metric | Type | Labels | Meaning |
|---|---|---|---|
| `speculaire_gate_total` | counter | `mode` = `audit`\|`enforce`; `result` = `allow`\|`rejected`\|`unverifiable`\|`pending`\|`unmatched`\|`exempt`; `stale` = `true`\|`false` | Gate decisions (D18, D21, D23) |
| `speculaire_gate_seconds` | histogram | `path` = `nri`\|`annotation` | `CreateContainer` handling time (target: p99 under 5 ms on a cached verdict) |
| `speculaire_identity_path` | gauge | `path` = `nri`\|`annotation` | 1 for the image-identity path in use (D15) |
| `speculaire_nri_connected` | gauge | — | 1 while registered with containerd's NRI (D41) |

## Process

| Metric | Type | Labels | Meaning |
|---|---|---|---|
| `speculaire_build_info` | gauge | `version`, `containerd_version`, `nri_version` | Always 1 |
| `speculaire_config_reload_failures_total` | counter | — | Reloads rejected; the previous config is still in use (D30) |

Memory, CPU and file descriptors come from node-exporter and systemd (D34).
