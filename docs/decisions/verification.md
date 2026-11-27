# Decisions: verification

How artifacts become verdicts. Index: `docs/decisions/README.md`.

## D8: Crypto comes from sigstore-rust (amended by D43, D136, D139, D143, D145, D147)

- **Decision:** use `sigstore-verify` and `sigstore-trust-root` (sigstore-rust, crates 0.16). We write OCI discovery, regex identity matching and the legacy `.sig` → v0.1-bundle conversion ourselves. The conversion also checks that the SimpleSigning payload's `critical.image.docker-manifest-digest` equals the image digest, since the bundle verifier only binds the signature to the payload. Attestations are verified only as bundles (D43).
- **Because:**
  - It verifies the SET, the inclusion proof and the checkpoint fully offline, handles bundles v0.1 to v0.3 and Rekor v2, has an offline TUF mode, and runs the conformance suite on every CI build.
  - sigstore-rs's generic verifier skips the inclusion proof and the SET (`verifier.rs:236,240` TODOs), and its referrer path rejects any predicate other than `cosign/sign/v1`.
  - **Measured** (M0 spike 06, `sigstore-verify` 0.16.0 with `default-features = false` on `sigstore-trust-root`, so no HTTP client or TUF code is linked): it verified the GitHub `attest-build-provenance` bundle of the `cli/cli` v2.103.3 release asset with `docker run --network none`, the public-good `trusted_root.json` from `gh attestation trusted-root`, and checked the certificate chain, the SCT, the inclusion proof and the checkpoint (`tlog_verified` and `certificate_verified` both true). The statement's subject digest binds the artifact: a modified asset fails with `artifact mismatch`. A wrong issuer fails with `issuer mismatch`, and a wrong trusted root with `No log key valid at integrated time`. The identity is exact-match only in the library, so the regex match on `result.identity()` stays ours. Its SAN was `https://github.com/cli/cli/.github/workflows/deployment.yml@refs/heads/trunk` and its issuer `https://token.actions.githubusercontent.com`: a workflow path plus a ref that may be a branch or a tag, which is the shape of D28's policy.
  - The GitHub *release* attestation (`in-toto.io/attestation/release/v0.2`, a v0.3 bundle with an RFC 3161 timestamp and no log entry) is rejected: `bundle must have an inclusion proof`. We don't use it.
- **Revisit when:** —

## D11: Policy shape and image matching (amended by D65, D81, D136, D142, D149)

- **Decision:**
  - The policy is a file shaped like `ClusterImagePolicy`. *authorities* pass if any one passes; *attestations* pass only if all do. v1 conditions are predicateType presence plus the SBOM checks in D12; CEL comes later.
  - Images are matched by glob against the **pod-spec image name**: the `io.kubernetes.cri.image-name` annotation, normalised (`nginx` → `docker.io/library/nginx`). This holds on every containerd version.
  - An image matched by several policies must pass all of them.
- **Because:**
  - It is the most familiar shape and maps directly onto `VerificationPolicy`. `cel-interpreter` 0.10 (last release 2025-07) needs evaluation first.
  - NRI's `image.name` (containerd ≥ 2.4) is the first reference in containerd's image store, not necessarily the one the pod used (`docs/research/nri-and-verifiers.md` §1.3). One digest can carry several names that match different policies.
- **Revisit when:** —

## D12: SBOM validation has three tiers (amended by D150)

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

## D20: Verdict model (amended by D31, D38, D65, D145, D151)

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

## D21: Old verdicts keep serving while the policy or trust root changes (amended by D31, D65, D154)

- **Decision:**
  - When the policy file or the trust root changes, the agent re-verifies every image in containerd's store in the background, running containers first.
  - Until the new verdict for an image exists, the gate serves the previous one, marked `stale` in logs and metrics.
  - A stale verdict older than `verify.stale_max` (default 1 h) counts as `Pending`.
- **Because:** both hashes are part of the verdict key, so without this a routine TUF refresh would make every verdict a miss, and the node would deny every new container until re-verification caught up.
- **Cost:** a tightened policy takes effect after re-verification (normally seconds), not instantly.
- **Revisit when:** —

## D22: Verification starts at the manifest fetch (amended by D65, D66, D121, D152, D174, D175)

- **Decision:** triggers, earliest first:
  1. the mirror serving or forwarding `GET /v2/<repo>/manifests/<digest>` (containerd fetches manifests by digest through the mirror, even when it resolved the tag upstream, D6);
  2. containerd `/images/create|update` events;
  3. NRI `Synchronize`, for containers already running;
  4. a gate cache miss.
- **Because:**
  - starting at the manifest fetch lets verification run during the layer download. Otherwise a first start often misses `gate.wait`, is denied as pending, and waits for kubelet's retry delay (about 10 s).
  - **Measured** (M0 spike 05, containerd 2.3.7 and 2.4.2, kind): a kubelet pod using `docker.io/library/busybox:1.36` on a node without it made containerd send the mirror `GET /v2/library/busybox/manifests/sha256:<index digest>?ns=docker.io`, then the same path with the node platform's manifest digest, both with the client certificate. It sent no request for the tag, and it asked for the config and layers after those. With both answered 404, the pod reached `Running`. The `ns` query parameter carries the registry host.
- **Revisit when:** —

## D26: Policy and trust root are local files (amended by D210)

- **Decision:**
  - The policy (`/etc/speculaire/policy.yaml`) and an optional pinned `trusted_root.json` are local files on each node, distributed by the admin's config management.
  - The reflector pushes only the prewarm list.
  - TUF metadata may still travel P2P, because it authenticates itself.
- **Because:** a compromised control plane must not be able to relax a node's policy, and systemd deployments already have config management.
- **Revisit when:** the DaemonSet phase starts. Then mount the policy from a ConfigMap.

## D31: Verdicts and signature results survive agent restarts in `/run/speculaire` (amends D20, D21; amended by D165, D176, D204, D211)

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

## D43: Attestations count only as Sigstore bundles; `.att` tags are ignored (amends D8, D38; amended by D49, D145, D149)

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

## D121: The image list starts discovery at M4; each root is asked of its repositories in list order, for Sigstore bundles and `.sig` only (amends D17, D22, D50, D90, D99; amended by D126, D127, D128, D131, D133, D134, D146, D150, D151, D152, D207)

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


## D126: Discovery asks the artifact store, then peers, then upstream; peers list referrers from a target's first 4 holders (amends D102, D121; amended by D134, D147, D151)

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

## D128: A refusal pauses its host for every discovery; the root waits for `retry_at` and the journal says why (amends D38, D121; amended by D207)

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

## D131: The artifact store keeps only what the listed roots name, collected at each listing and each removal (amends D121, D124; amended by D144, D153)

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

## D136: Identity regexes match the whole SAN and issuer (amends D8, D11)

- **Decision:**
  - A policy's `subjectRegExp` matches only when it matches the certificate's whole SAN, and `issuerRegExp` the whole issuer: `https://github.com/myorg/.*` matches `https://github.com/myorg/app/...`, and `https://github.com/myorg/` matches nothing longer.
  - **How:** the policy loader parses each pattern alone with `regex-syntax`, puts the parsed expression between `Look::Start` and `Look::End` (`\A` and `\z`), and builds it with `regex-automata`'s `meta::Builder::build_from_hir`. A pattern that does not parse alone refuses the policy file.
  - `docs/operations.md` tells the admin porting a policy: a pattern that relied on a partial match now rejects in `audit`.
- **Because:**
  - Go's `MatchString` and Rust's `Regex::is_match` both match a substring. cosign and policy-controller match so: cosign v3.1.4 compiles `IssuerRegExp` and `SubjectRegExp` as written and calls `MatchString` on the issuer and on each SAN (`pkg/cosign/verify.go:483-485,501-506`); policy-controller v0.15.1 passes a `ClusterImagePolicy`'s identities to those `CheckOpts` (`pkg/webhook/validator.go:1364-1370`, cosign v3.0.5, the same code at `verify.go:457,478`); sigstore-go v1.4.0's `NewSANMatcher` and `NewIssuerMatcher` do the same (`pkg/verify/certificate_identity.go:97,130,137,165`).
  - A substring match lets a pattern written without anchors pass a SAN that only contains it: `https://github.com/myorg/` passes `https://github.com/myorg-evil/app/.github/workflows/release.yml@refs/heads/main`, and anyone can create the organisation `myorg-evil` and get a Fulcio certificate for a workflow in it. The safe reading should not depend on the admin writing `^…$`.
  - A policy ported from policy-controller can only get stricter: a pattern already anchored matches the same strings, and one that was not now rejects, which `audit` shows before `enforce`.
  - Parsing the pattern alone, then wrapping the parsed expression, keeps a pattern from closing the wrapper: spliced into `^(?:…)$` as text, `a)|(.*` would read as `^(?:a)|(.*)$`, and a `#` comment under `(?x)` would swallow the closing `)$`.
  - Rust's `\d`, `\w` and `\s` take Unicode classes where Go's take ASCII; on a SAN, which X.509 encodes as ASCII (`IA5String`), they match the same.
- **Revisit when:** sigstore-rust gains regex identity matching (D8), or admins need partial matches, then as an explicit setting.

## D139: Sigstore fixtures are recorded from public-good Sigstore (amends D8; amended by D164)

- **Decision:**
  - The gate's Sigstore fixtures come from public-good Sigstore. `.github/workflows/fixtures.yml` builds one `FROM scratch` image per case into `ghcr.io/spnngl/speculaire-fixtures:<case>`, signs and attests it the way the case names (cosign v3.1.3, `actions/attest-build-provenance`, `actions/attest-sbom`, syft, BuildKit's SBOM scanner), and exports each with its tags and referrers as an OCI layout. Beside them: the public key of the `key` case, the `trusted_root.json`, and a TUF snapshot of `tuf-repo-cdn.sigstore.dev` (the root chain, the top-level metadata and the trusted root target) in the repository's layout.
  - An oracle checks the export offline before the upload: cosign reads the layouts back from a registry on an internal Docker network, and `gh attestation verify` checks a bundle file against the manifest's bytes, both trusting only the exported trusted root. `expected.json` records each case's digest, signer, attached predicate types, checks and outcome. The run fails when an outcome is not the one the case's name promises: `unsigned`, `buildkit-unsigned` and `sbom-tag` fail, the others pass.
  - `spdx-empty` is syft's SPDX for an image with no package: it lists only the document root, the image itself, which the SBOM checks must not count as a package.
  - The workflow runs only by hand (`workflow_dispatch`): each run writes to the public Rekor log, and a new recording changes every digest and certificate the tests pin.
- **Because:**
  - sigstore-rust checks the SCT of a Fulcio certificate by default (`sigstore-verify` 0.16.0, `crates/sigstore-verify/src/verify.rs:262`). sigstore-go v1.4.0's `VirtualSigstore` (`pkg/testing/ca/ca.go:136`) issues leaf certificates whose only extension is the OIDC issuer (`ca.go:896-912`), so tests on it would turn off a check the gate makes.
  - A private Fulcio, Rekor and TUF repository (sigstore/scaffolding) costs a Kubernetes cluster per CI run, and tests our setup of them rather than what the gate meets.
  - A recording carries real certificates, SCTs, inclusion proofs and checkpoints, the artifacts' real shapes (GitHub's referrer bundles, BuildKit's attestation manifests, cosign's legacy tags), and the TUF metadata the agent fetches, all usable offline.
- **Revisit when:** a fixture's expired certificate or TUF metadata breaks a test that cannot pin the verification time, or sigstore-go's testing CA embeds SCTs.


## D142: The policy file holds `ClusterImagePolicy` documents of a subset, matched on the repository name (amends D11)

- **Decision:**
  - The policy file is one or more YAML documents, each a `ClusterImagePolicy` of `apiVersion: policy.sigstore.dev/v1beta1` holding only the fields below. Any other field, kind or version refuses the file, naming its document and field path (`document 1, spec.authorities[0].keyless.url`). An empty document is skipped; two policies with one `metadata.name` refuse the file. `serde-saphyr` 2.2 reads the YAML, duplicate keys refused.
    - `metadata.name`; `spec.images[].glob`; `spec.authorities[]`, each with an optional `name`, one of `key` and `keyless`, and `attestations[]` of `name` and `predicateType`.
    - `key.data` only: one PEM `PUBLIC KEY` inline. `kms`, `secretRef` and `hashAlgorithm` are refused.
    - `keyless.identities[]` only, each with one of `issuer` and `issuerRegExp` and one of `subject` and `subjectRegExp` (D136). `url`, `ca-cert`, `trustRootRef` and `insecureIgnoreSCT` are refused, as are the authority's `ctlog`, `rfc3161timestamp`, `source`, `signatureFormat` and `static`, `spec.mode`, `spec.match` and every `policy` (CUE, Rego).
    - `spec.sbom: required`, an extension, makes the image need an SBOM that passes D12's tiers.
  - Every authority needs a transparency-log entry; no field turns it off. An attestation requirement is met only by a Sigstore bundle (D43), and the missing-attestation reason says `(.att tags are not supported)`. An SBOM requirement accepts the SPDX predicate types `https://spdx.dev/Document` and `https://spdx.dev/Document/v2.3`.
  - A glob matches the reference's `name()` (D81): the normalised repository, without tag or digest. A glob naming a tag or a digest refuses the file. `crates/verify`'s `Glob` ports policy-controller v0.15.1's `glob.go`, `index.docker.io/` read as `docker.io/`; the fallback that matches the unnormalised text (`glob.go:91-95`) is not ported. `gate.exempt.images` (D18) uses the same `Glob`.
  - A missing policy file is no policy: no image matches, and `gate.unmatched` decides (D23). A file that exists and does not parse stops the agent at startup and makes `speculaire check-config` exit 1.
  - The *policy match* is keyed in a verdict (D20) by the SHA-256 of its policies' content hashes, sorted: file order, key order, layout and comments do not change it.
- **Because:**
  - Each refused field needs a cluster, a second trust root or an evaluator the node does not have: a node has one trust root (D26), reads no Kubernetes secret, and has no CUE or Rego. Refusing names what will not be checked; ignoring it would pass images the admin meant to reject.
  - policy-controller matches `ref.Name()` with the tag (`nginx` reads `index.docker.io/library/nginx:latest`). Matching the repository keeps a policy from depending on the tag a pod spec chose.
  - `serde_yaml` and `serde_yaml_ng` are unmaintained (RUSTSEC-2024-0449) and `serde_yml` unsound (RUSTSEC-2025-0068), so `cargo deny` refuses them. `serde-saphyr` is maintained and passes.
  - The bench (D106) and nodes without verification run with no file; a missing file is a choice, a broken one a mistake.
- **Revisit when:** an admin needs `kms`, a second trust root or CEL conditions (D11).

## D143: The trust root is a pinned file, or the one sigstore-tuf fetches over our client every 6 h (amends D8; amended by D145, D154)

- **Decision:**
  - A `verify.trusted_root` path pins a `trusted_root.json`, read at start: a missing or corrupt file stops the agent and makes `check-config` exit 1 (D30). No TUF runs then.
  - Otherwise `sigstore-tuf` 0.16, without its `client` feature, fetches the root through our `Repository` on `speculaire_registry::Client`: anonymous, on the system's trust, a 404 or 403 read as no such file, as sigstore-tuf's own transport does. The initial TUF root is version 16 of the public-good repository, `crates/verify/src/tuf_root.json`, a copy of sigstore-rust's `crates/sigstore-trust-root/repository/tuf_root.json` at `sigstore-verify-v0.16.0`. Settings: `verify.tuf_url = "https://tuf-repo-cdn.sigstore.dev"`, `verify.tuf_cache = "/var/lib/speculaire/tuf"`, `verify.tuf_refresh = 21600`. These three and `trusted_root` are restart keys (D47).
  - A refresh runs in the background at start, then every `tuf_refresh`, or 60 s after a failure. When the repository fails, the cache is refreshed again offline, every signature and expiry checked as if fetched. When both fail the node holds no trust root, and the reason names both (`TUF: …; the cache: …`); it holds none either until the first refresh ends. With none, verifications end `unverifiable` (D20).
  - The trust-root hash of a verdict's key (D20) is the SHA-256 of the `trusted_root.json` bytes. The root's expiry is the latest end among its keys whose end is known: a key's `validFor.end`, and for a certificate or timestamp authority also its chain's earliest `notAfter`. A root from TUF expires no later than the first of the root, timestamp, snapshot and targets metadata. `speculaire_trust_root_expiry_timestamp_seconds` shows it, 0 while no root is held.
  - `sigstore-verify` and `sigstore-bundle` enter the workspace with the verification that calls them.
- **Because:**
  - sigstore-trust-root's `tuf` feature hardwires reqwest, a second HTTP and TLS stack, and `directories`; the embedded TUF root sits behind it too. tough 0.24 would add a second TUF implementation and snafu. sigstore-tuf alone checks the same metadata and leaves the transport ours: the registry client's connections, trust and `User-Agent`.
  - The public-good root's current keys have no `validFor.end`, so their certificates give the only end there is.
  - The public-good timestamp is signed for 7 days and re-signed once 6 remain, so daily (`x-tuf-on-ci-expiry-period` 7, `x-tuf-on-ci-signing-period` 6, root v16): a TUF root always expires within 7 days, and the alert fires below 3 days, after 3 days or more without a refresh. A 6 h refresh tries about 28 times in a timestamp's life.
  - The pinned root and the refresh task are set up at start; re-verifying on a trust-root change is D21's.
- **Measured:** 23 crates enter `Cargo.lock` (sigstore-trust-root, sigstore-tuf, sigstore-types, sigstore-crypto, jiff, x509-cert and their dependencies), with no ring and no reqwest. A refresh from the recorded repository served in process, then from its cache, takes under 0.1 s.
- **Revisit when:** TUF travels P2P (D26), or sigstore-trust-root's `tuf` feature stops pulling reqwest.

## D144: The artifact store is collected beside a discovery, which keeps its root and what it holds (amends D131; amended by D146, D148)

- **Decision:**
  - **Collected:** the follower of the image list reads the list while a discovery runs, and collects the store at each full listing and whenever a root leaves the list, as D131 does between discoveries.
  - **Kept:** while a discovery runs, a collection keeps its root's record and every blob it found held or kept. The store forgets them once neither a discovery nor a collection runs, so a failed discovery's blobs go at the next collection, as in D131.
  - **Ended:** a root that left the list while being discovered is collected once its discovery ends.
- **Because:**
  - A discovery waits on peers and upstream for seconds. On PR #194's arm64 containerd 2.4 leg, the discovery of a root no source served ran 6.1 s, and the bundle of an image removed meanwhile was withdrawn 5.6 s after `crictl rmi`, where D131 measured half a second and the e2e suite allows 2 s.
  - The store checks whether a blob is held under the lock a collection holds through each deletion: the collection deletes the blob before the discovery looks, which then fetches it again, or keeps it.
  - A blob a discovery keeps is marked before it is linked: a collection running meanwhile never finds it unmarked.
- **Limit:** the artifacts of a root removed while its own discovery runs stay until that discovery ends.
- **Revisit when:** discoveries of different roots run in parallel, or a root's own discovery outlasts the 2 s often.

## D145: A bundle is verified once per trust root, with any identity, then matched to each authority (amends D8, D20, D43, D143; amended by D147)

- **Decision:**
  - `speculaire_verify::Signatures::check` reads each `Kind::Bundle` artifact whose subject is the image, its bundle the manifest's last blob, and returns one result per authority of the policy: who signed the bundle that satisfies it, or why none does. The policy's signature check passes when one authority passes (D11).
  - A bundle counts as a signature of the image its DSSE in-toto subject or its message digest names, whatever its predicate type, as `cosign verify` does with the new bundle format (cosign v3.1.3 `cmd/cosign/cli/verify/verify.go:239`). An image GitHub's `attest` alone signed passes the signature check.
  - A bundle holding a certificate is verified with `VerificationPolicy::any_identity()`: chain to the trust root's Fulcio at the log's integrated time, SCT, transparency-log entry (D142), signature. Its SAN and OIDC issuer are then matched against the authority's identities with D136's matchers. A bundle holding a public key is verified with `PublicKeyVerificationPolicy` and the authority's key, entry required; it satisfies key authorities only.
  - Before any crypto, the leaf certificate's issuer must be the subject of a certificate in one of the trust root's certificate-authority chains; otherwise the reason names that issuer, such as `O=GitHub, Inc., CN=Fulcio Intermediate l1` for GitHub's private instance (D43).
  - Results are kept in memory per (image digest, bundle digest, SHA-256 of the authority's key or none), for one trust root: a new trust-root hash empties them, and so does the 16 384th entry. A second check of the bundle under another policy matches identities only; `Signatures::hits()` counts it. Saving them in `cache.bin` is D31's, with the verdict cache.
  - An authority no bundle satisfies fails with the reason of the bundle that came closest, in this order: `identity mismatch: signed by <SAN> (issuer <issuer>)` (or `by a key`), `certificate issuer <DN> is unknown to the trust root`, `signature invalid: <cause>`, `no signature`. No trust root, or a bundle the store cannot give, makes the check `Unverifiable` (`trust root: <absent>`), never `Rejected` (D20).
  - Only `sigstore-verify` 0.16 enters the workspace: it re-exports sigstore-bundle's types, so `sigstore-bundle` is no direct dependency.
- **Because:**
  - Verifying with any identity first lets every authority and every policy share one verification; sigstore-verify matches identities exactly only (`verify.rs:156`), and D136's regular expressions need the SAN anyway.
  - cosign v3 signs with a DSSE bundle of predicate type `https://sigstore.dev/cosign/sign/v1`, and its verify accepts any verified bundle as a signature; requiring that predicate would reject images cosign passes. An attestation requirement still never counts the signature predicate.
  - GitHub's private bundles carry no transparency-log entry and chain to a CA the public trust root lacks: naming the CA tells the admin why, where sigstore-verify reports a chain or a log error.
  - The closest reason is the one an admin can act on: a mismatch names the signer to put in the policy.
- **Measured:** 8 crates enter `Cargo.lock` (sigstore-verify, sigstore-bundle, sigstore-rekor, sigstore-tsa, sigstore-merkle, cms, serde_json_canonicalizer, ryu-js). One verification takes 1.2 ms for the keyless fixture and 0.65 ms for the key fixture (release, Apple M5); parsing the trusted root with its verifier takes 0.25 ms.
- **Revisit when:** sigstore-verify matches identities by pattern, or cosign stops counting attestations as signatures.

## D146: The roots of an image just listed have a discovery lane of their own (amends D121, D144; amended by D148, D152, D174)

- **Decision:**
  - **Lanes:** the follower of the image list runs two discoveries at most, one per lane, each one root at a time. The roots of an image just listed go in the pulled lane, in the order they come. Those a full listing queues, and those due again after a failure (D128, D134), go in the backlog lane.
  - **Once:** a lane that comes to a root the other lane is discovering drops it: that discovery records it.
  - The store's guard of D144 counts discoveries: a collection keeps the roots and blobs of both lanes.
- **Because:**
  - With one lane, a pull waited for the discovery in flight, and that one can be of a root no source answers soon: a connect waits 15 s, a request 30 s. On PR #197's amd64 containerd 2.4 dual-stack leg, run 44380305182, an agent restarted at 19:55:17.85 began with one of kind's preloaded `docker.io/library/import-*` roots, whose sources are internet registries. `e2e/signed:1` was pulled at 19:55:18.46, and 10.5 s later the store held nothing and the agent had logged no discovery since its start, where every other start on that node logged its first within 0.7 s.
  - The roots a pull adds are those a node needs to run a pod, and soon to admit it at M5. A pull waits only for the discovery of another image just listed.
  - Two lanes bound what a restart and a burst of pulls ask of peers and upstreams at once.
- **Revisit when:** M5's manifest-fetch trigger needs a root discovered while its pull waits, or a pull often waits for another pulled image's discovery.

## D147: A legacy `.sig` layer is a signature once its payload names the image and its SET verifies (amends D8, D126, D145)

- **Decision:**
  - `Signatures::check` reads each layer of each `Kind::Signature` artifact whose target is the image, beside its bundles, and ranks their failures with theirs (D145). `speculaire_verify::legacy::verify(root, target, manifest, layer, payload, key)` checks one layer.
  - The layer's simple signing payload must name the image in `critical.image.docker-manifest-digest`, before any crypto, as `cosign verify` does (cosign v3.1.3 `pkg/cosign/verifiers.go:43-46`); otherwise `signature invalid: the .sig signs <digest>, not this image`. No other payload field is read.
  - The layer becomes a v0.1 bundle: its `dev.cosignproject.cosign/signature` as a message signature over the payload; its `dev.sigstore.cosign/certificate` leaf, or else a public key; its `dev.sigstore.cosign/bundle` annotation as a `hashedrekord` 0.0.1 entry whose SET is the inclusion promise. `dev.sigstore.cosign/chain` is ignored: the trust root holds the chain. It is then verified as a bundle is (D145).
  - A layer without that annotation fails with `signature invalid: the .sig has no SET (annotation dev.sigstore.cosign/bundle)`: D142's transparency-log entry is required of `.sig` too.
  - Results are kept per (image digest, `.sig` manifest digest and layer index, key hash), beside the bundles'.
- **Because:**
  - A `.sig` has no subject: any registry or peer can list any `.sig` under a target (D126). The payload digest is its only binding to the image, and the signature covers the payload.
  - sigstore-verify accepts a v0.1 bundle with a SET and no inclusion proof (sigstore-verify v0.16.0 `crates/sigstore-bundle/src/validation.rs:130-142`), and checks the SET and the `hashedrekord` body against the payload: the conversion adds no crypto of ours.
  - Each layer is one signature: cosign appends a layer per `cosign sign` of the same image.
- **Measured:** one layer of the `legacy-sig` fixture verifies in 0.56 ms (release, Apple M5).
- **Revisit when:** cosign drops `.sig` from `cosign verify`, or images signed with a key and a `.sig` need a fixture.

## D148: A discovery's holds end with it, whatever the other lane runs (amends D144, D146)

- **Decision:**
  - Each discovery holds its own root and blobs: `Store::discovering` returns a guard through which the discovery holds and keeps, and a collection keeps what any guard alive holds.
  - A guard dropped while a collection runs leaves its holds until no collection runs: that collection may have read the records before the discovery's.
  - Blobs kept outside a discovery, by `Store::keep` or `Writer::commit`, are held by none.
- **Because:**
  - D144 forgot the holds only once no discovery ran. With D146's backlog lane busy, the pulled lane's holds outlived its discovery, and the collection after `crictl rmi` skipped the root. On main's run 44430760175, arm64 containerd 2.4 k1.36, worker2 discovered `e2e/signed:1` at 00:54:55.280, containerd removed it at 00:54:55.796 while backlog discoveries ran until 00:54:56.549, and its bundle was deleted only at the agent's restart, 00:55:06.038; the e2e suite allows 2 s.
- **Revisit when:** a discovery spawns tasks that keep blobs without its guard.

## D149: An authority that requires attestations passes on bundles attesting each predicate type by its signer (amends D11, D43)

- **Decision:**
  - An attestation is a bundle naming the image (D145) whose DSSE envelope signs an in-toto statement, `_type` `https://in-toto.io/Statement/v1` or `v0.1`, of the required `predicateType`, compared exactly: cosign's short names, such as `slsaprovenance1`, are not read. The predicate type of a cosign signature, `https://sigstore.dev/cosign/sign/v1`, is never an attestation; a `.sig` layer never is.
  - An authority that requires attestations passes on them alone, as policy-controller does (v0.15.1 `pkg/webhook/validator.go:530-535`): every one needs a bundle of its predicate type by the authority's signer, and its signer is the authority's result. Each such bundle is a signature of the image (D145), so the signature check would add nothing. An authority without attestations passes on its signature.
  - The first attestation that fails gives the authority's reason (D11's all-of): `attestation <predicateType> missing (.att tags are not supported)` when no bundle attests it, whether or not a `.att` tag exists (D43), else `attestation <predicateType>: <reason>` with the reason of the bundle attesting it that came closest (D145's order). `Signatures::check` returns `Unmet::{Signature, Attestation}` per authority.
  - The predicate type is read from each bundle with its signature, kept beside its result (D145), whether or not the signature verifies: a tampered attestation names its predicate type.
  - `speculaire_verify::statement::Statement` borrows the payload: `_type`, `predicateType` and the raw `predicate`. Subjects are sigstore-verify's to bind (sigstore-verify v0.16.0 `crates/sigstore-verify/src/artifact.rs:50-101`). `Signatures::attested(store, target, artifacts, signer, root, predicate_type)` gives the attesting bundle's digest, and the statement is read from it again when needed: predicates are never kept, as SBOMs may be large.
- **Because:**
  - policy-controller's `ClusterImagePolicy`, whose shape D11 takes, checks attestations instead of signatures for such an authority; cosign maps a short name to a URI before comparing (cosign v3.1.3 `pkg/policy/attestation.go:62-66`), but a predicate type is a URI, and an unread short name fails closed.
  - A cosign v3 signature is a DSSE statement too: counting it would pass an attestation requirement with a plain signature.
  - Reading the predicate type of a bundle that fails tells the admin which attestation is broken, where `missing` would send them to attest again.
- **Measured:** `Statement::parse` takes 0.50 µs for the provenance fixture's 1 031-byte statement and 0.12 µs for a cosign signature's 230 bytes (release, Apple M5): beside a verification's 1.2 ms (D145), the attestation check costs nothing more.
- **Revisit when:** a policy needs a predicate's content (`policy:` in `ClusterImagePolicy`), or users ask for cosign's short names.

## D150: An SBOM passes in a signed attestation of three predicate types or a signed index's BuildKit layer, counted, its size as listed (amends D12, D121)

- **Decision:**
  - **Predicate types:** `https://spdx.dev/Document` (cosign), `https://spdx.dev/Document/v2.3` (GitHub, `actions/attest` v4.2.2 `src/sbom.ts:85`) and `https://cyclonedx.org/bom`, compared exactly; the type names the format.
  - **Tier (a):** the bundle `Signatures::attested` gives for an authority's signer and an SBOM predicate type (D149). **Tier (b):** a BuildKit attestation manifest (`Kind::Attestation`) the stored index lists; its in-toto layers are read unsigned (D49) and pass when an authority's signer signs the index. `Signatures::sbom(store, target, artifacts, policy, root)` gives `Listed { signed, packages }` or `speculaire_verify::sbom::Failure`.
  - **Counting:** our own parser borrows the document and skips every other value (`serde::de::IgnoredAny`). SPDX needs `spdxVersion` `SPDX-2.3` and counts its packages but the ones the document describes (`documentDescribes`, `DESCRIBES` from `SPDXRef-DOCUMENT`, `DESCRIBED_BY` to it): syft lists the image itself. CycloneDX needs `bomFormat` `CycloneDX` and `specVersion` 1.4 or later, and counts its top-level `components`.
  - **Reasons**, the closest of both tiers, in order: `SBOM missing`, `SBOM unsigned: <signature reason>`, `SBOM over sbom.max_size: <n> bytes`, `SBOM unparsable: <where>`, `SBOM without packages`. A `.sbom` tag alone is missing: discovery never fetches it (D121).
  - **Size (amends D121):** discovery records an artifact without the blobs its manifest lists above `sbom.max_size`, unfetched; a blob streaming beyond the cap against its listing still drops its artifact. The verifier reads the listed size: such a bundle fails as `signature over sbom.max_size: <n> bytes`, attesting the predicate type its manifest's `dev.sigstore.bundle.predicateType` annotation names (unverified, it only picks the reason, D149), and such a layer as `SBOM over sbom.max_size`. `Signatures::new(max_size)` takes the cap discovery used.
- **Because:**
  - spdx-rs and cyclonedx-bom build the whole document; counting builds none of it, so a 64 MiB SBOM costs one pass.
  - A dropped artifact reads as `SBOM missing` and sends the admin to attest again; the listed size names the cap. The manifest is under 4 MiB (D85), so recording it costs nothing.
  - The `spdx-empty` fixture is syft's output for an image without packages: one package, the image.
  - Only the signed index binds an attestation manifest; the record is untrusted.
- **Measured:** counting an 11.5 MB SPDX document of 50 000 packages takes 13 ms, against 29 ms to build it as a `serde_json::Value` (release, Apple M5).
- **Revisit when:** SPDX 3 or CycloneDX 2 JSON shows up in attestations, or content rules (D12's later) need the packages themselves.


## D151: The engine keeps verdicts in memory, per listed root, retried 10 s doubling to 5 min by its own discovery (amends D20, D121, D126; amended by D152, D154)

- **Decision:**
  - **Feed:** `speculaire_artifacts::follow` tells the engine, on an unbounded channel, each change of the listed roots and their names (`Found::Listed`) and the end of each discovery or a root found recorded (`Found::Ended`). The engine in `speculaire_verify::engine` verifies one root at a time in its own task.
  - **Keys:** the image identity is the listed manifest digest; the root's names are grouped by the match hash of the policies each name matches, one key per group (D11, D142), so a CRI-O image's repository digests give the same keys as containerd's images (D65). A name no policy matches has no verdict. A key is `Pending` from listing to its first verdict, and is forgotten with its root.
  - **Combining:** a key is `Allow` when every matched policy passes, `Rejected` when one fails, else `Unverifiable`. A failing policy gives the reason of its first authority (D145) or of its SBOM (D150), as the operations guide lists them; the verdict line names the policies. No trust root gives `trust root: <why>` under no root hash (D143).
  - **Retry (amends D20):** an `Unverifiable` key is verified again 10 s later, then after twice the wait each time, up to 5 min; a rate limit's `retry_at` is a floor (D38). While the root's artifacts are not recorded, the retry starts its own discovery, so D121's 10 min stays for roots no verdict waits on. Each discovery asks peers again. A peer's announcement does not trigger a retry yet.
  - **Upstream once more (amends D126):** before a first `Rejected`, the engine asks `Discovery::again` once per listed root: upstream only, its artifacts added to the record. The key stays `Pending` meanwhile; when upstream fails or adds nothing the rejection stands.
  - **Store:** `Verdicts`, a map from image to its kept keys under a `std::sync::RwLock`, held only to read or write the map. `Verdicts::get` takes a borrowed `Key` and clones an `Arc<str>` reason at most. A verdict under a new root hash replaces its key's. Verdicts live in memory; saving them to `cache.bin` is M6's (D31).
  - **Logs (amends D121):** each changed verdict logs one INFO line, `verdict of <digest> under <policies>: <verdict>`, and the `verdict` audit event (D37). Discovery's own `discovery of <digest>: unverifiable: <reason>` line stays, for roots without policies.
- **Because:**
  - Discovery owns the image list; one channel keeps verification out of its lanes, and an unbounded one never blocks them on a slow check.
  - Waiting 10 min (D121) on a root a pod waits for leaves it denied; 5 min caps the load a fleet's retries put on peers and upstream.
  - Asking upstream once more covers a store filled by peers before the signer's latest signature; once per root bounds what an attacker serving bad artifacts can make the node fetch.
  - A lookup without allocation keeps the gate's hot path off the allocator (D107).
- **Measured:** a lookup among 1 000 images' verdicts takes 29 ns, without allocation (`just bench-micro`, release, Apple M5).
- **Revisit when:** a peer's announcement should end a wait early (D20), or the gate needs verdicts across restarts before M6.


## D152: A manifest the mirror is asked for by digest, or serves by tag, is a discovery root before it is listed (amends D22, D66, D121, D146, D151)

- **Decision:**
  - **Requests:** the mirror tells discovery of each `GET` of a manifest by digest, before it answers and whatever it answers, and of each `GET` by tag it serves, under the digest it serves (`Docker-Content-Digest`). A `HEAD` never triggers. The name is the repository with its registry: containerd's `ns` before the path, CRI-O's path as it is. The mirror sends on an unbounded channel and never waits.
  - **Roots:** a manifest fetched becomes a root unless it is listed, fetched already, or named by the index of a root listed or fetched, held in the artifact store or by the node (containerd fetches the index, then its platform manifest: spike 05). It joins the lane of the roots just listed (D146). Once listed, it is a listed root alone.
  - **Verification:** `Found::Listed` becomes `Found::Roots { listed, fetched }`. The engine keys a root fetched by the name it was fetched under, as a listed one (D151). The first verification of a root a fetch made counts under `trigger="manifest"`, even when the root was listed during its discovery; later ones count under `event`.
- **Because:**
  - A pull's first manifest request comes seconds before the runtime lists the image: the verdict is there sooner, or already when the gate asks.
  - containerd asks the mirror by digest even for what it pulls upstream, a 404 sending it on (D22); the request names the root.
  - CRI-O asks by tag only, and the relay resolves it (D66): without the tag trigger, CRI-O would have none.
  - A `HEAD` checks presence; the `GET` that follows, if any, triggers.
  - A platform manifest as its own root would be discovered and verified a second time; the index's discovery covers it (D22).
  - The label names what started the verification: a listing during the discovery a fetch started starts no other.
- **Revisit when:** a platform manifest is fetched while its index is neither held nor fetched by this node, which makes it a root of its own.

## D153: The store keeps what a root fetched and not listed names for `artifacts.grace`, marked on disk (amends D131)

- **Decision:**
  - A root fetched (D152) is marked in the store, under `fetched/<alg>/<hex>`, with the second it was fetched. A collection keeps what a marked root names, as it does a listed one's, until `artifacts.grace` (600 s, restart) has passed since its mark; then the mark goes and the root is collected as D131 says, its blobs withdrawn.
  - A root listed loses its mark. A mark that names no time is spent.
  - When the first grace ends, discovery collects the store, from the first listing on.
- **Because:**
  - A curl, a pull that fails or a pull the runtime never lists would otherwise keep its artifacts forever, or lose them at the next listing before the runtime lists the image.
  - The mark on disk survives a restart, so a pull that spans one keeps its grace.
  - 10 min covers a large image's pull before the runtime lists it.
- **Revisit when:** pulls longer than the grace lose their artifacts before the runtime lists them.


## D154: The policy file and a pinned trust root reload as the config does; a changed key serves its previous verdict stale (amends D21, D30, D143, D151; amended by D155)

- **Decision:**
  - **Reload:** the policy file and a pinned `verify.trusted_root` are watched files (D93): SIGHUP reads them, a poll reads one whose stamp changed, or the policy file at a new `verify.policy`. A file refused keeps what was read before, is counted once in `speculaire_config_reload_failures_total` and logged with its reason. A TUF refresh that fails while a root is held keeps that root; one that brings the same hash is no change.
  - **Re-key:** on a change the engine swaps in the new policies or root whole, then re-keys each root whose match hash or root hash changed: a new key starts with the verdict its name's previous key held, marked stale since the change (a key stale already keeps its first time), or `Pending`. Unchanged keys stay as they are.
  - **Reverify:** each re-keyed root that discovery found is verified again, one per engine turn, under `trigger="reverify"`, asking upstream once more before a first `Rejected` (D151). A stale `Rejected` is not final: the new verdict replaces it.
  - **Lookup:** `Verdicts::get` answers a `Lookup { verdict, stale }`. A stale verdict answers until `verify.stale_max` (3600 s, live) has passed since the change, then `Pending`.
  - **Order:** roots go in the engine's order; running containers do not go first yet.
- **Because:**
  - The policy and the root are part of the key (D20): re-keying without the previous verdict would deny every new container until re-verification caught up (D21).
  - The stamps and the single count make a reload of the policy and the root behave and fail as the config's (D30, D93).
  - A failed TUF refresh, or the same root fetched again, should not make every verdict stale.
  - One root per turn keeps the engine answering discovery and retries while it verifies a whole store again.
- **Revisit when:** running containers must be verified first (D21): the engine needs the runtime's container list.


## D155: After a change, the roots running containers run are verified again first (amends D154; amended by D175)

- **Decision:**
  - On a change that queues roots, the engine asks the runtime over the CRI which containers run (`ListContainers`, filtered on `CONTAINER_RUNNING`), maps each one's `image_id` (its `image_ref` when the field is empty) to the image of `ListImages` with that ID, and takes each repository digest of those images as a running root. A stable sort puts the running roots first in the queue; the others keep their order.
  - A runtime that does not answer in 5 s leaves the queue in the engine's order, with a warning.
  - "Running" is the runtime's containers until NRI `Synchronize` comes with the gate (M6).
- **Because:**
  - D21 asks for running containers first: their images are the ones a restart or a new replica pulls again soonest.
  - Both runtimes fill `image_id` with the ID `ListImages` lists: containerd its config digest (`internal/cri/server/container_list.go:53-66` at v2.3.0), CRI-O its storage ID (`internal/oci/container.go:181-199` at v1.37.2), whose `image_ref` may be a `repository@digest` no registry served.
  - One CRI call per change, not per root, and none while nothing changed.
- **Revisit when:** the gate follows container stops and removals over NRI events (D175).

## D156: `speculaire verify` prints one image's verdict and each check's reason, without the agent (amends D62)

- **Decision:**
  - `speculaire verify [--config <path>] [--runtime <runtime>] [--json] <name>@<digest>` reads the config, the policy file and the trust root as the agent does, a TUF one through one refresh into `verify.tuf_cache` with the cache as fallback (D143). It matches the policies on the name, discovers the image's artifacts upstream through the runtime's registry config (D17) into an artifact store in a temporary directory, never a peer's nor the agent's, and checks them as the engine does.
  - It prints the verdict first, in the gate's words: `allow`, `rejected: <reason>`, `unverifiable: <reason>`, or `unmatched` when no policy matches. Then one line per matched policy, its authorities (by name, else by place from 1), the attestations each requires, and the SBOM when the policy requires one, each `pass`, `fail`, `unverifiable` or `not checked`, with its reason. An authority's attestations after the first that fails are not checked (D149), nor is the SBOM until an authority passes (D150). `--json` prints the same content as one object.
  - It exits 0 when the image is allowed, 1 otherwise, `unmatched` included, and 2 when it cannot verify as asked: arguments, the config, the policy file, a pinned trust root, the registry config, or a name without digest.
  - `speculaire_verify::report` holds each policy's per-check results, and the engine's verdict is computed from them, so the command and the agent cannot disagree over the same artifacts. The engine now checks every policy of a key rather than stopping at the first that fails; the verdict is the same.
  - D62 holds: the work is in `speculaire_agent::verify` and `speculaire_verify::Report`; the binary picks the exit code and the format.
- **Because:**
  - The agent's store is the agent's: `Store::open` clears its `tmp/`, where the agent writes, and the records the agent holds in memory are not re-read from disk. Upstream serves the artifacts discovery would fetch, and no connection to the agent is needed.
  - No peers: the command needs no node identity, and asking upstream shows what the node's registry config reaches.
  - The TUF cache writes atomically, each file renamed into place, so the agent and the command may refresh it at once (sigstore-tuf v0.16.0 `src/cache.rs:91-119`).
  - Text reads in a terminal and JSON in a script. Exit 2 apart from 1 tells a script "not allowed" from "could not verify".
- **Revisit when:** the agent serves its verdicts over the status listener, or peers hold artifacts upstream lacks.


## D165: `cache.bin` is a checksummed binary of sorted entries; a verdict saved under other policies loads stale under the current ones (amends D31)

- **Decision:**
  - **Layout:** `speculaire_verify::cache` writes an 85-byte header (format version, file size, the hash of all the policies held, the signature results' trust root, both counts), the `Allow` and `Rejected` verdicts, the signature results, and the SHA-256 of all before it. Integers are little-endian; fixed-size parts are `zerocopy` structs read in place (D107). A digest is saved as its text and parsed again at load. Both caches are saved sorted, so the same caches save the same bytes.
  - **Refusal:** `load` checks the version first, then the size the header holds, then the checksum, then parses everything before it replaces the caches. It answers why it refused: `Version`, `Size` (a file cut short), `Checksum` or `Malformed` naming the part.
  - **Staleness:** a stale verdict saves its age; load turns it back into an instant, and drops one that went stale before the monotonic clock's start. When the policies' hash in the header or a verdict's trust root differs from the current one, the verdict loads under the current root, stale since load unless it was already. A key whose policies match another set of policies after the change has no verdict until it is verified again, which the engine does for every root after a restart.
  - **Signature results** load with the trust root they were checked under; `Signatures` ignores them under another.
  - **Writing:** `write` puts the bytes in a temporary file of mode 0600 beside the target, syncs it, renames it over the target and syncs the directory.
- **Because:**
  - Each verdict already holds its match hash and root, the key of D20; one hash of all the policies in the header tells whether any policy changed without saving each policy's name.
  - A size in the header tells a truncated file, the common crash damage, from a corrupted one.
  - An `Instant` has no meaning in another process; an age does.
  - Sorted, deterministic bytes let the fuzz target `cache_bin` check that what loads saves the same again.
  - Measured on an Apple M5 (`just bench-micro`): saving 10k verdicts takes 1.24 ms and loading them 2.35 ms, for a file of 1.56 MB.
- **Revisit when:** the format changes: raise `VERSION`, and an older file is then discarded at the upgrade.


## D176: The agent loads `cache.bin` from `verify.cache` before the engine runs, and saves it at most once a second while the verdicts change (amends D31, D87, D175)

- **Decision:**
  - **Key:** `verify.cache`, a restart key, is the file's absolute path, `/run/speculaire/cache.bin` by default. D87's directory key arrives as this one file's path.
  - **Load:** `start_discovery` loads the file once the engine is built and before it runs, so that the load, which replaces both caches, races no verdict the engine keeps, and before the gate registers. The verdicts load under the hash of the policies and the trust root held then (D165). A missing file, as after a reboot, logs at `info` and counts nothing. A file that cannot be read, or that `load` refuses, is discarded: one warning whose `cause` is the I/O error or the refusal, `speculaire_cache_loads_total{result="discarded"}`, and the agent starts with no verdicts. A file loaded counts `result="loaded"` and logs both counts.
  - **Save:** a task waits for `Verdicts::changed`, saves, then waits a second before it waits again, and saves once more at stop, D39 step 5: after the drains, before the gate leaves NRI. Signature results change only during a verification, so the verdict it ends with wakes the save, and the stop save keeps those of a verification that ended `Unverifiable`. The task encodes on the async runtime and writes on the blocking pool; a failed write warns once until a write succeeds, and the agent goes on.
  - **Policies first:** the save reads the policies' hash before the caches; a policy change in between leaves the file under the previous hash, whose verdicts then load stale.
  - **Warnings of running containers:** a loaded verdict that does not allow a container of `Synchronize` warns of it at start, as any verdict landing does (D175). The agent does not keep which warnings it gave, so such a container is warned of once per agent start, and a verification landing the same verdict adds none.
  - `e2e/tests/gate.rs` restarts the agent during a rollout of `runnable`: the agent logs the load, counts `result="loaded"` once, and no new pod meets `verification pending`. The cold-node case flips one bit of the file, which the agent discards, counting `result="discarded"`, and then starts with no verdicts.
- **Because:**
  - The agent's tests run in a temporary directory, where `/run/speculaire` does not exist; a key for the file, rather than its directory, is the smallest thing that moves it.
  - A load after the engine's first keep would replace a fresh verdict with a saved one.
  - A missing file is the normal first start, not damage; counting it would alert on every reboot.
  - Saving per second bounds the writes of a busy node to one a second, under 2 ms of encoding for 10k verdicts (D165), and a restart loses at most the last second, which the engine verifies again.
  - Remembering warnings across restarts would need its own file for one log line per container per restart, and a restart already logs its own lines; the user's rule is one warning per verdict change, and an agent start is one.
- **Measured (M6 step 12, kind on arm64, Kubernetes 1.37):** the agent restarted during a rollout of two pods of `runnable` loads the file once, and no pod meets `verification pending`, on containerd 2.4 and CRI-O 1.37. The gate suite, with the restart, takes 68.7 s on containerd 2.4 (66.5 s before) and 81.0 s on CRI-O 1.37 (76.2 s before).
- **Revisit when:** encoding the caches shows in a profile of a busy node, or a key other than a verdict needs saving on its own change.

## D207: An upstream that does not answer a discovery request is an `info` line, not a warning (amends D121, D128)

- **Decision:** a discovery request that no candidate of its source answers, by a DNS, connect, TLS or timeout failure, logs `upstream does not answer for artifacts` at `info`, naming the path and the last candidate's error, and counts `speculaire_artifact_fetches_total{source="upstream",result="error"}` as before. Warnings stay for what asking again does not fix: a digest mismatch, a blob over `sbom.max_size`, an answer that is no index, a store failure.
- **Because:**
  - Discovery asks again whatever one failed request leaves: a root no source served ends `artifacts unreachable` and is retried (D121, D134), an `Unverifiable` key starts its own discovery 10 s later, doubling to 5 min, and a first `Rejected` asks upstream once more (D151). No retry count runs out, so there is no last attempt to warn at.
  - A runner's resolver failing for a moment (`public.ecr.aws: ... failed to lookup address information: Try again`, D120's second Docker Hub mirror) failed `the_journal_holds_structured_entries_and_nothing_at_warning` on main (run 45269308074, containerd 2.4, dual-stack pass). A node's resolver fails the same way; at the default `warn` filter (D37), each such request on each node would be a warning with nothing to do.
  - A lasting outage still shows: `unverifiable: artifacts unreachable` verdicts, the gate's warnings of running containers (D175), the counter's rate. Raised to `info`, the journal says which host failed and how.
- **Revisit when:** discovery stops asking again on its own, or operators need upstream reachability alerted, which is then the counter's alert, not a log level.
