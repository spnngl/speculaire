# Decisions: verification

How artifacts become verdicts. Index: `docs/decisions/README.md`.

## D8: Crypto comes from sigstore-rust (amended by D43)

- **Decision:** use `sigstore-verify` and `sigstore-trust-root` (sigstore-rust, crates 0.16). We write OCI discovery, regex identity matching and the legacy `.sig` → v0.1-bundle conversion ourselves. The conversion also checks that the SimpleSigning payload's `critical.image.docker-manifest-digest` equals the image digest, since the bundle verifier only binds the signature to the payload. Attestations are verified only as bundles (D43).
- **Because:**
  - It verifies the SET, the inclusion proof and the checkpoint fully offline, handles bundles v0.1 to v0.3 and Rekor v2, has an offline TUF mode, and runs the conformance suite on every CI build.
  - sigstore-rs's generic verifier skips the inclusion proof and the SET (`verifier.rs:236,240` TODOs), and its referrer path rejects any predicate other than `cosign/sign/v1`.
  - **Measured** (M0 spike 06, `sigstore-verify` 0.16.0 with `default-features = false` on `sigstore-trust-root`, so no HTTP client or TUF code is linked): it verified the GitHub `attest-build-provenance` bundle of the `cli/cli` v2.103.3 release asset with `docker run --network none`, the public-good `trusted_root.json` from `gh attestation trusted-root`, and checked the certificate chain, the SCT, the inclusion proof and the checkpoint (`tlog_verified` and `certificate_verified` both true). The statement's subject digest binds the artifact: a modified asset fails with `artifact mismatch`. A wrong issuer fails with `issuer mismatch`, and a wrong trusted root with `No log key valid at integrated time`. The identity is exact-match only in the library, so the regex match on `result.identity()` stays ours. Its SAN was `https://github.com/cli/cli/.github/workflows/deployment.yml@refs/heads/trunk` and its issuer `https://token.actions.githubusercontent.com`: a workflow path plus a ref that may be a branch or a tag, which is the shape of D28's policy.
  - The GitHub *release* attestation (`in-toto.io/attestation/release/v0.2`, a v0.3 bundle with an RFC 3161 timestamp and no log entry) is rejected: `bundle must have an inclusion proof`. We don't use it.
- **Revisit when:** —

## D11: Policy shape and image matching (amended by D65, D81)

- **Decision:**
  - The policy is a file shaped like `ClusterImagePolicy`. *authorities* pass if any one passes; *attestations* pass only if all do. v1 conditions are predicateType presence plus the SBOM checks in D12; CEL comes later.
  - Images are matched by glob against the **pod-spec image name**: the `io.kubernetes.cri.image-name` annotation, normalised (`nginx` → `docker.io/library/nginx`). This holds on every containerd version.
  - An image matched by several policies must pass all of them.
- **Because:**
  - It is the most familiar shape and maps directly onto `VerificationPolicy`. `cel-interpreter` 0.10 (last release 2025-07) needs evaluation first.
  - NRI's `image.name` (containerd ≥ 2.4) is the first reference in containerd's image store, not necessarily the one the pod used (`docs/research/nri-and-verifiers.md` §1.3). One digest can carry several names that match different policies.
- **Revisit when:** —

## D12: SBOM validation has three tiers

- **Decision:**
  - **v1:** a policy can require an SBOM. It passes when either:
    - (a) a signed in-toto attestation whose predicateType is SPDX (`https://spdx.dev/Document`) or CycloneDX (`https://cyclonedx.org/bom`) has the image as subject and an allowed signer; or
    - (b) the image index carries a BuildKit attestation manifest with such a predicate, and the index digest itself has a passing signature (the one source outside D43's rule, D49).

    In both cases the SBOM must parse as SPDX 2.3 JSON or CycloneDX ≥ 1.4 JSON, stay under `sbom.max_size` (default 64 MiB), and list at least one package. Unsigned `.sbom` tags never count.
  - **Later:** package and license rules (a deny-list by purl and version range, a license allow-list), as CEL over a normalised package list.
  - **Not on the node:** vulnerability scanning. Later, accept a signed vulnerability attestation (cosign `https://cosign.sigstore.dev/attestation/vuln/v1`) or OpenVEX instead, with a maximum age and a severity threshold.
- **Because:**
  - A signature proves who produced the inventory. The parse check rejects the empty placeholder SBOMs that tools emit when they fail.
  - (b) is sound because a signed index digest covers the attestation manifest's digest. It also covers `docker buildx --sbom=true` images, which are common and carry no cosign attestation.
  - Content rules are site-specific, so they wait for CEL.
  - Vulnerability data changes daily while the image does not, which breaks verdicts cached per digest. A vulnerability database on every node is also heavy, and makes nodes disagree.
- **Revisit when:** users ask for content rules (CEL) or for vulnerability gating (that needs verdict expiry).

## D20: Verdict model (amended by D31, D38, D65)

- **Decision:**
  - `enum Verdict { Allow, Rejected { reason }, Unverifiable { reason, retry_at }, Pending }`.
  - The verdict key is `(image identity, matched-policies hash, trust-root hash)`.
  - `Rejected` is final for its key.
  - `Unverifiable` (upstream down, artifacts not found, credentials missing) is retried with exponential backoff, capped at 5 min, and again as soon as a matching artifact is announced.
  - In `enforce`, the gate denies both `Rejected` and `Unverifiable`, with distinct reasons and metric labels.
  - Signature results are cached separately, keyed by `(digest, trust-root hash)`, so a new policy match reuses them.
- **Because:**
  - "The signature is bad" and "upstream is down" need different retry behaviour. A single `Deny` would keep a transient outage cached.
  - The policy is part of the key because one digest can match different policies under different names (D11).
- **Revisit when:** —

## D21: Old verdicts keep serving while the policy or trust root changes (amended by D31, D65)

- **Decision:**
  - When the policy file or the trust root changes, the agent re-verifies every image in containerd's store in the background, running containers first.
  - Until the new verdict for an image exists, the gate serves the previous one, marked `stale` in logs and metrics.
  - A stale verdict older than `verify.stale_max` (default 1 h) counts as `Pending`.
- **Because:** both hashes are part of the verdict key, so without this a routine TUF refresh would make every verdict a miss, and the node would deny every new container until re-verification caught up.
- **Cost:** a tightened policy takes effect after re-verification (normally seconds), not instantly.
- **Revisit when:** —

## D22: Verification starts at the manifest fetch (amended by D65, D66, D121)

- **Decision:** triggers, earliest first:
  1. the mirror serving or forwarding `GET /v2/<repo>/manifests/<digest>` (containerd fetches manifests by digest through the mirror, even when it resolved the tag upstream, D6);
  2. containerd `/images/create|update` events;
  3. NRI `Synchronize`, for containers already running;
  4. a gate cache miss.
- **Because:**
  - starting at the manifest fetch lets verification run during the layer download. Otherwise a first start often misses `gate.wait`, is denied as pending, and waits for kubelet's retry delay (about 10 s).
  - **Measured** (M0 spike 05, containerd 2.3.7 and 2.4.2, kind): a kubelet pod using `docker.io/library/busybox:1.36` on a node without it made containerd send the mirror `GET /v2/library/busybox/manifests/sha256:<index digest>?ns=docker.io`, then the same path with the node platform's manifest digest, both with the client certificate. It sent no request for the tag, and it asked for the config and layers after those. With both answered 404, the pod reached `Running`. The `ns` query parameter carries the registry host.
- **Revisit when:** —

## D26: Policy and trust root are local files

- **Decision:**
  - The policy (`/etc/speculaire/policy.yaml`) and an optional pinned `trusted_root.json` are local files on each node, distributed by the admin's config management.
  - The reflector pushes only the prewarm list.
  - TUF metadata may still travel P2P, because it authenticates itself.
- **Because:** a compromised control plane must not be able to relax a node's policy, and systemd deployments already have config management.
- **Revisit when:** the DaemonSet phase starts. Then mount the policy from a ConfigMap.

## D31: Verdicts and signature results survive agent restarts in `/run/speculaire` (amends D20, D21)

- **Decision:**
  - The unit sets `RuntimeDirectory=speculaire`, `RuntimeDirectoryMode=0700` and `RuntimeDirectoryPreserve=yes`. systemd keeps `/run/speculaire` across stops and restarts, and the tmpfs is cleared at reboot.
  - The agent saves the verdict cache and the signature-result cache to `/run/speculaire/cache.bin`. It writes a temporary file and renames it, at most once per second while the caches change, and once more on stop.
  - It saves `Allow`, `Rejected` and signature results. `Unverifiable` and `Pending` are not saved.
  - The file starts with a format version and ends with a checksum. If the version is unknown, the checksum is wrong or the file doesn't parse, the agent discards it and starts with empty caches.
  - At startup, the agent loads the file before it registers with NRI. Entries whose policy or trust-root hash differs from the current one serve as *stale verdicts* (D21), and their `verify.stale_max` counts from load.
- **Because:**
  - Without it, every restart (upgrade, crash, watchdog) empties the caches. Every new container then waits `gate.wait` under the node-wide NRI lock, and is denied as pending.
  - The user chose systemd's runtime space. A reboot clears it, and a reboot also restarts containerd, whose `Synchronize` then reports every container again. So nothing in `/var/lib` holds old security state.
  - `yes`, not `restart`: package upgrades often stop the unit and then start it, and `RuntimeDirectoryPreserve=restart` deletes the directory on stop.
  - `Unverifiable` and `Pending` are short-lived and retried anyway.
- **Revisit when:** the DaemonSet phase starts. Then keep the file on a `hostPath` under `/run/speculaire`.

## D38: Upstream rate limits pause discovery per registry host (amends D20; amended by D43, D128)

- **Decision:**
  - An upstream `429`, or a `503` with `Retry-After`, makes the verdict `Unverifiable { reason: "upstream rate limited: <host>", retry_at }`. `retry_at` is the later of the next backoff step and `Retry-After` (seconds or HTTP date), capped at 1 h.
  - Until `retry_at`, discovery sends nothing to that registry host for any image. The artifact store and peers are still tried.
  - Discovery probes the `sha256-<hex>` fallback tag and the legacy `.sig` tag with `HEAD`, and sends a `GET` only for those that exist. `.att` is never probed (D43).
  - Such fetches count as `speculaire_artifact_fetches_total{result="rate_limited"}`.
- **Because:**
  - The user agreed. Retrying sooner than the registry asks only extends the ban, and the ban covers every image on that host, not only the one that hit it.
  - Docker Hub counts manifest `GET`s against its pull limit, but not `HEAD`s. Most images have no fallback or `.sig` tag, so probing with `HEAD` keeps verification from spending the node's pull budget.
- **Revisit when:** —

## D43: Attestations count only as Sigstore bundles; `.att` tags are ignored (amends D8, D38; amended by D49)

- **Decision:**
  - An attestation counts only as a Sigstore bundle (`application/vnd.dev.sigstore.bundle.v0.3+json`, as cosign v3 and GitHub attestations write it), found as an OCI referrer through the referrers API or the `sha256-<hex>` fallback tag.
  - cosign's `sha256-<hex>.att` tags and `application/vnd.dev.cosign.artifact.att.v1+json` referrers are never fetched and count as absent. A required attestation found only that way fails with `rejected: attestation <predicateType> missing (.att tags are not supported)`.
  - Signatures still count in both formats: Sigstore bundles, and legacy `.sig` tags through D8's conversion.
  - Bundles from GitHub's private-repository Sigstore instance need its trust root, which v1 does not load (D26). They fail with a reason that names the unknown issuer.
- **Because:**
  - The user chose to drop the old `.att` format and keep `.sig`.
  - Older cosign logged `.att` as Rekor `intoto` v0.0.1 entries, which sigstore-rust cannot verify (`docs/research/sigstore-and-referrers.md` §1). Accepting only the newer `.att` entries would make one tag format pass or fail depending on the cosign version that wrote it.
  - It removes the `.att` probe from every verification (D38).
- **Revisit when:** users need attestations that exist only as `.att` tags, or private GitHub attestations.

## D49: A BuildKit SBOM inside a signed index counts (amends D43)

- **Decision:**
  - D12(b) is the one exception to D43: an SBOM in a BuildKit attestation manifest of the image index counts, with no Sigstore bundle of its own, when the index digest has a passing signature.
  - Discovery reads the index from the artifact store, or fetches it by digest when the mirror didn't see it (D22). It finds the attestation manifest through its `vnd.docker.reference.digest` annotation and fetches it by digest, like any blob.
  - Any other in-toto statement without a bundle still counts as absent.
- **Because:**
  - The index signature covers the attestation manifest's digest, so its content is as authenticated as a bundle (D12).
  - `docker buildx --sbom=true` images carry no other SBOM, and they are common.
  - The mirror sees the index: containerd requests it by digest through the mirror before the platform manifest (D22, M0 spike 05), so discovery reads it from the artifact store.
- **Revisit when:** BuildKit attaches its attestations as Sigstore bundle referrers.

## D121: The image list starts discovery at M4; each root is asked of its repositories in list order, for Sigstore bundles and `.sig` only (amends D17, D22, D50, D90, D99; amended by D126, D127, D128, D131, D133, D134)

- **Decision:**
  - **Trait:** `Images` is the sixth trait a `Node` hands out. It sends the runtime's image list, each image as its ID and its repository digests, then each image listed or removed. containerd: CRI `ListImages`, read again at each `/images/create|update|delete` event in `k8s.io`. CRI-O: CRI `ListImages`, read again at each inotify event on the directory of `images.json` (D65). Both list in full every 60 s and whenever the event stream ends, and read the list once more 1 s after a watch starts: no answer tells when containerd holds the subscription, and an image pulled in between waited 60 s in CI. Once the agent stops, a follower that loses the runtime ends without a warning: the agent's own teardown cut it. The CRI-O relay protects the listed images from eviction through it.
  - **Trigger (M4):** each digest of the list is a root, discovered once: a root the artifact store has recorded is not asked again, and one no source served is asked again after 10 min. One root at a time; the roots of an image just listed go first, before those a full listing queued. The manifest fetch (D22) becomes a trigger at M5, with verification.
  - **Repositories:** the root is asked of each repository the list names it under, in list order, through each source `Registries::sources` gives, the node's own mirror removed. The first that answers `HEAD` of the root's manifest with `200` serves all its targets. When none does, discovery ends `artifacts unreachable` (D17). The root is fetched only when its media type is an index's.
  - **Fetched:** referrers that are Sigstore bundles, by `artifactType` or else their layer's media type, whose manifest names the target as `subject`; the legacy `.sig` manifest; the BuildKit attestation manifests of the platform manifest (D49); and every blob each names. Nothing else.
  - **Caps:** 64 referrers per target, 10 pages of the referrers API per target, 4 MiB per manifest or referrers index (D85), `sbom.max_size` per other blob (D12). A referrer listed above the manifest cap is dropped before the 64 are counted; a blob beyond its cap drops its artifact.
  - **Store:** in `artifacts.directory` (default `/var/lib/speculaire/artifacts`, restart key): `blobs/<algorithm>/<hex>` as in the blob cache, each written to `tmp/`, hashed in flight (D7) and linked into place; `roots/<algorithm>/<hex>.json` records each root's artifacts: target, manifest, kind and blobs. `/readyz` waits for the store to open. Stored artifacts are untrusted until M5 verifies them.
  - **`upstream` label on CRI-O (D50):** a host keeps its name when a `[[registry]]` table of `registries.conf` or a drop-in has the host, or a path below it, as prefix; any other host is `other`. The mirror's own drop-in does not count.
- **Because:**
  - containerd's image events carry the image name and no digest (v2.4.2 `api/events/image.proto:26-38`), so each is a hint to read the list again; its garbage collector publishes `/images/delete` too (`core/metadata/db.go:355-356`).
  - CRI-O writes `images.json` by rename (`go.podman.io/storage` v1.63.0 `images.go:566-586`): watching its directory sees every write. `rustix`, already in the tree and trusted (D71), gives inotify without `unsafe`.
  - Nothing verifies at M4, so the list is enough, and it covers images pulled before the agent started.
  - After a restart, the first listing queues every root not recorded, unreachable ones included; on CRI-O 1.37 a pull behind that backlog had its artifacts after 8.1 s. Putting a new image first bounds its wait to the discovery in flight.
  - CRI-O pairs each repository with each digest an image was pulled by (D65): some pairs were never served by that repository, so the first `200` in list order picks one that was.
  - A registry may list referrers it did not filter, and ghcr.io lists `application/vnd.oci.empty.v1+json` as their `artifactType` (sigstore-rs `src/cosign/client.rs:240-244`): the referrers index is a hint, and only a referrer whose manifest names the target as `subject` counts.
  - Docker Hub counts each `GET` of a manifest against its pull limit, and an image manifest names no target: `HEAD` suffices (D38).
  - The caps bound what one image's publisher can make every node fetch and keep.
- **Measured (M4 step 01, arm64, Docker, `just e2e containerd 2.4` and `just e2e crio 1.37`):** after `crictl pull` of `e2e/signed:1` from the private upstream, with only the runtime's registry config for login and CA, the store held its three bundles, the `.sig` manifest and their blobs 1.5 s later on containerd and 0.46 s later on CRI-O (8.1 s before new images went first). registry:2's access log showed `GET` of the referrers API answered 404, then `HEAD` and `GET` of the fallback tag, then of `.sig`, and no `.att`; zot's showed the API and no fallback tag. At `log.filter = "trace"` the journal held no password, no `Basic ` and no `eyJ`.
- **Revisit when:** M5 adds the manifest-fetch trigger; or a real image has more than 64 bundles.


## D126: Discovery asks the artifact store, then peers, then upstream; peers list referrers from a target's first 4 holders (amends D102, D121; amended by D134)

- **Decision:**
  - **Order:** for each root, each target's manifests and blobs come from the artifact store, else from peers, else not at all; upstream (D121) is asked only when the store and peers give no artifact of the root. The root's manifest comes from the node's content (containerd's, or the relay's blob cache), else the store, else peers; an index fetched so is kept in the store, so that the node serves it on (D49, D124).
  - **Lists:** the fetcher asks the first 4 holders of the target's digest, in lookup order, the denied skipped (D52), at once, for `GET /v2/speculaire/referrers/<target>`, each within `peer.stall_timeout`; their lists are unioned by digest in lookup order. No new reflector key: a holder of the target that discovered it holds the list.
  - **Kept:** a listed descriptor that may be a Sigstore bundle, or is listed as `application/vnd.dev.cosign.simplesigning.v1+json` (the `.sig`, D124), under the manifest cap and up to 64 per target (D121), is fetched by digest with the `Fetcher` (D102): raced, hashed in flight, a mismatch denying the peer. A fetched bundle is kept only when its manifest names the target as `subject`; a manifest without `subject` whose layer is a simple-signing payload is kept as the `.sig` of the target it was listed under, and M5 binds it (D8). Anything else is dropped. BuildKit attestation manifests come from the index, by digest.
  - **Startup:** the agent starts discovery once a reflector stream is up, or after 10 s, so that its first pass asks peers; a root no source served waits D121's 10 min.
  - **Metrics:** each manifest or blob asked of peers counts once in `speculaire_artifact_fetches_total{source="peer"}`: `ok`, `not_found` when no peer gave it, `error` when its body could not be read. A mismatch counts in `speculaire_peer_fetches_total` (D52).
- **Because:**
  - A node cut off from upstream, or limited by it (D38), still gets the artifacts of an image a peer discovered, as it gets the image's blobs.
  - The holders of the target are the nodes most likely to have discovered it, and 4 is the fetcher's width (D102); a union lets one holder that lacks an artifact cost nothing.
  - A peer's list is a hint (D124): the fetch by digest and the `subject` check make a peer able to withhold an artifact, never to forge one. Upstream is asked when peers list nothing; M5 asks it once more before a final `Rejected`, for an artifact peers withheld (ARCHITECTURE.md, Flows).
  - At startup the first listing comes before any reflector stream, and a root found unreachable then would wait 10 min.
- **Limit:** a peer that lists only some artifacts of a root hides the rest from this node until M5's upstream check. A `.sig` has no `subject`: any node can list any simple-signing manifest under a target, which M5's signature check rejects.
- **Measured (M4 step 04, locally on Docker Desktop arm64, kind, `just e2e containerd 2.4` and `just e2e crio 1.37`):** with zot as upstream, one node pulled and discovered the signed test image (3 bundles: signature, SLSA, SPDX; its `.sig`); the worker, its agent stopped, pulled the image, was cut off from zot and started its agent. Its store held every artifact 2.8 s after the agent started on containerd (agent start and first reflector stream included) and 0.26 s on CRI-O; each digest counted `source="peer",result="ok"`; zot logged no request from the worker after its agent started, and no request for the `.att` tag over the whole test. Each full local leg, cluster up and down included, took 318 s on containerd and 374 s on CRI-O.
- **Revisit when:** nodes that hold an image often lack its artifacts, then announce a key per target's referrers; or M5 finds peers withholding artifacts upstream has.

## D128: A refusal pauses its host for every discovery; the root waits for `retry_at` and the journal says why (amends D38, D121)

- **Decision:**
  - **Refusal:** `speculaire-registry` reads a refusal off a response: a `429`, with its `Retry-After` when that parses, or a `503` with a `Retry-After` that parses. `Retry-After` is whole seconds or an HTTP date (RFC 9110 §10.2.3), a date in the past being 0 s. The fuzz target `retry_after` covers the parser.
  - **Pauses:** one table of hosts, by endpoint authority, is shared by every discovery of the agent. A refused request pauses its host until the later of the next backoff step and `Retry-After`, capped at 1 h (D38). The backoff step is 30 s, doubled at each refusal in a row, capped at 5 min (D20); any other answer of the host clears its entry. A paused endpoint is skipped like an absent one: discovery tries the root's other sources, and the store and peers before them (D126).
  - **Outcome:** a refusal ends the root's discovery, nothing recorded, with `Unverifiable { reason: "upstream rate limited: <host>", retry_at }`; a root no source served ends `Unverifiable { reason: "artifacts unreachable", retry_at: now + 10 min }` (D121). The root is discovered again at its `retry_at`, by itself, without waiting for a listing. Until M5, the journal shows the outcome as one `info` line, `discovery of <digest>: unverifiable: <reason>`; M5's verdict takes the reason as it is.
  - **Relay:** the pauses do not hold the CRI-O relay. Its requests are the pull CRI-O would send itself, and it passes upstream's refusal on to CRI-O (D129).
  - **Counted** once per refused request as `speculaire_artifact_fetches_total{source="upstream",result="rate_limited"}`.
- **Because:**
  - Docker Hub's limit is per client address, not per image: an image that hits it means every image of that host would. A request sent before `Retry-After` extends the ban, and those that CRI-O's pulls need come first.
  - An artifact fetched halfway through a root would leave it recorded with a part of its artifacts, and a recorded root is never asked again (D121).
  - A root waiting for the next full listing after its `retry_at` would wait up to 60 s more.
  - The verdict, and the reason in it, come at M5; a journal line in its words lets an operator see the limit today.
- **Revisit when:** M5 produces verdicts, or a registry limits per image rather than per client.

## D131: The artifact store keeps only what the listed roots name, collected at each listing and each removal (amends D121, D124)

- **Decision:**
  - **Kept:** a listed root's index blob (D126), and every artifact manifest and blob of a listed root's record. A blob two roots name stays while either is listed, such as the empty config every Sigstore bundle names (D124).
  - **Collected:** the follower of the image list (D121) collects the store at each full listing, so at its first and every 60 s, and whenever a root leaves the list. It deletes each record of a root no longer listed, then each blob nothing kept names, a blob a failed discovery left included. Collection and discovery take turns in one task, and a root collected is discovered again once listed again.
  - **Announced:** each deleted blob is withdrawn through the holdings (D124), and `speculaire_artifact_store_bytes` drops by its size. The store lists what it holds to the holdings only after its first collection, so an image removed while the agent was stopped never has its artifacts announced. The first collection runs on the first listing, before discovery waits for a reflector stream (D126).
  - **Grace:** none. M4 discovers only listed images, so a root not yet listed has nothing in the store.
- **Because:**
  - The store holds what the node's images need checked (D22); an artifact of an image gone is weight on the disk and an answer for no reader.
  - A record goes before its blobs, and blobs before their withdrawal: a crash in between leaves blobs no record names, which the next collection deletes, and no record naming a blob the store lacks. A reflector forgets what a node announced once its stream ends, so what a crash left announced goes with it, and the restarted agent announces only what its first listing finds.
  - Discovery keeps a root's blobs before it records them (D121): a collection running beside it would delete them as named by nothing.
  - The kubelet's image garbage collection and `crictl rmi` remove images on either runtime without telling the agent: the image list does.
- **Limit:** a blob removed by hand stays announced until the agent restarts, and answers a 404 meanwhile. A root removed while its discovery runs is collected once that ends. A stream that connects before the store's first listing announces the store's blobs just after its snapshot.
- **Measured (M4 step 05, locally on Docker Desktop arm64, kind, `just e2e containerd 2.4` and `just e2e crio 1.37`):** with zot as upstream, every reflector named the worker for a bundle manifest 193 ms after its store kept it on containerd and 181 ms on CRI-O, and no longer 523 ms and 166 ms after `crictl rmi`, which deleted every artifact and the record. With a second signed image listed, the empty config both name stayed in the store and announced. After a restart, every reflector named the worker for the store's artifacts 851 ms and 887 ms after the agent started, and never for those of an image removed while it was stopped, whose files were gone. Each full local leg, cluster up and down included, took 441 s on containerd and 501 s on CRI-O.
- **Revisit when:** M5's manifest-fetch trigger (D22) stores artifacts of an image not yet listed, which then needs a grace; or the store must hold less than what the listed images name.

## D133: A referrers index whose `manifests` is `null` lists none (amends D121)

- **Decision:** a referrers index whose `manifests` is `null` lists no referrer, as `[]` does: the referrers API's answer, the fallback tag's index, and a peer's list (D126) alike. One without `manifests`, or with any other value, is still no index, dropped with a `warn` line.
- **Because:**
  - Google's Artifact Registry answers `200` with `{"schemaVersion":2,"mediaType":"application/vnd.oci.image.index.v1+json","manifests":null}` for a manifest without referrers, behind registry.k8s.io (a redirect to `us-central1-docker.pkg.dev`) and mirror.gcr.io (D120). The spec wants an empty list (distribution-spec v1.1.1-57-g9727462 `spec.md:636`); `null` is how Go writes an empty slice.
  - containerd and regclient decode the answer into a Go slice, which reads `null` as empty (containerd v2.3.7 `core/remotes/docker/referrers.go:54-65`; regclient v0.8.3 `scheme/reg/referrer.go:157-170`, `types/oci/v1/index.go:25`).
  - Dropped, the answer logged a `warn` line per target: each image of registry.k8s.io a CRI-O e2e node lists did at each agent start, and `the_journal_holds_structured_entries_and_nothing_at_warning` failed unless the journal was emptied first.
  - A missing `manifests` stays refused: an image manifest under the fallback tag, or an error body sent with `200`, is no list.
- **Measured (CI journals of CRI-O 1.36 and 1.37 legs, runs 43988938171, 43999798418, 44013579419):** the warning named 40 targets, `not an image index` each, all of registry.k8s.io's pause, etcd, coredns and kube-* images, or `kindest/kindnetd` through mirror.gcr.io. Asked again with `curl`, both hosts answered the `null` above; Docker Hub answered `"manifests":[]` for the same kindnetd digests.
- **Revisit when:** Artifact Registry answers `[]`.

## D134: A root no source served just after a reflector stream came up is asked again 3 times, 20 s apart (amends D121, D126)

- **Decision:**
  - **Trigger:** a discovery that starts at most 10 s after the latest reflector stream came up, on any reflector, and ends `artifacts unreachable` is tried again 20 s later, up to 3 times, then waits D121's 10 min. A refusal keeps its `retry_at` (D128). A root that leaves the list forgets its tries.
  - **Signal:** `speculaire_reflect::Client::last_up` gives the time the latest stream came up, replacing `Client::linked`; discovery starts once it holds a time, or after 10 s (D126).
- **Because:**
  - A reflector that restarted names no holder until each agent's stream to it is back: locally, the control plane's came back 4.5 s after the first worker's restart, and a node that started meanwhile, cut off from upstream, found no peer artifact for any root and would have waited 10 min.
  - 3 tries, 20 s apart, cover a minute of streams coming back, and cost upstream 3 more rounds of `HEAD` per root the node truly cannot reach, only after a stream came up.
  - A discovery's start, not its end, is when it asked the reflectors: an upstream timeout can end it long after.
- **Revisit when:** reflectors keep their index across a restart, or nodes cut off from upstream still wait 10 min after a reflector restart.
