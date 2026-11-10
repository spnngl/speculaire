# Decisions: verification

How artifacts become verdicts. Index: `docs/decisions/README.md`.

## D8: Crypto comes from sigstore-rust (amended by D43)

- **Decision:** use `sigstore-verify` and `sigstore-trust-root` (sigstore-rust, crates 0.16). We write OCI discovery, regex identity matching and the legacy `.sig` → v0.1-bundle conversion ourselves. The conversion also checks that the SimpleSigning payload's `critical.image.docker-manifest-digest` equals the image digest, since the bundle verifier only binds the signature to the payload. Attestations are verified only as bundles (D43).
- **Because:**
  - It verifies the SET, the inclusion proof and the checkpoint fully offline, handles bundles v0.1 to v0.3 and Rekor v2, has an offline TUF mode, and runs the conformance suite on every CI build.
  - sigstore-rs's generic verifier skips the inclusion proof and the SET (`verifier.rs:236,240` TODOs), and its referrer path rejects any predicate other than `cosign/sign/v1`.
- **Revisit when:** —

## D11: Policy shape and image matching

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

## D20: Verdict model (amended by D31, D38)

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

## D21: Old verdicts keep serving while the policy or trust root changes (amended by D31)

- **Decision:**
  - When the policy file or the trust root changes, the agent re-verifies every image in containerd's store in the background, running containers first.
  - Until the new verdict for an image exists, the gate serves the previous one, marked `stale` in logs and metrics.
  - A stale verdict older than `verify.stale_max` (default 1 h) counts as `Pending`.
- **Because:** both hashes are part of the verdict key, so without this a routine TUF refresh would make every verdict a miss, and the node would deny every new container until re-verification caught up.
- **Cost:** a tightened policy takes effect after re-verification (normally seconds), not instantly.
- **Revisit when:** —

## D22: Verification starts at the manifest fetch

- **Decision:** triggers, earliest first:
  1. the mirror serving or forwarding `GET /v2/<repo>/manifests/<digest>` (containerd fetches manifests by digest through the mirror, even when it resolved the tag upstream, D6);
  2. containerd `/images/create|update` events;
  3. NRI `Synchronize`, for containers already running;
  4. a gate cache miss.
- **Because:** starting at the manifest fetch lets verification run during the layer download. Otherwise a first start often misses `gate.wait`, is denied as pending, and waits for kubelet's retry delay (about 10 s).
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


## D38: Upstream rate limits pause discovery per registry host (amends D20; amended by D43)

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
  - Discovery reads the index already fetched for the pull; it finds the attestation manifest through its `vnd.docker.reference.digest` annotation and fetches it by digest, like any blob.
  - Any other in-toto statement without a bundle still counts as absent.
- **Because:**
  - The index signature covers the attestation manifest's digest, so its content is as authenticated as a bundle (D12).
  - `docker buildx --sbom=true` images carry no other SBOM, and they are common.
- **Revisit when:** BuildKit attaches its attestations as Sigstore bundle referrers.
