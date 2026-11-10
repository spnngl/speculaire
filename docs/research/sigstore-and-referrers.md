# Sigstore verification in Rust and OCI artifact discovery: research report

Facts below come from the cloned repos. Commit dates are as recorded by git in this environment. Kyverno and Connaisseur are not cloned locally, so the notes on them in §5 come from general knowledge, not from code.

---

## 1. sigstore-rs vs sigstore-rust

### How the two repos relate
| | `sigstore/sigstore-rs` (crate `sigstore`) | `sigstore/sigstore-rust` (workspace `sigstore-*`) |
|---|---|---|
| Origin | Original crate (2021). `src/lib.rs:21` says *"this library is still experimental. Its API can change at any time."* | A separate rewrite, not a fork. First commit `f8e5818 2025-11-20 Wolf Vollprecht "initial commit"`. 341 commits since. |
| Last commit | `3c6899b 2026-11-05` (release v0.15.0, `Cargo.toml:9`) | `55227ff 2026-11-09` (release v0.16.0, workspace `Cargo.toml`) |
| Main authors | Since 2026-01: Flavio Castelli (85), Víctor Cuadrado Juan (29), dependabot (39). This is the Kubewarden/SUSE team. | All-time: Wolf Vollprecht (234, prefix.dev/rattler), Jussi Kukkonen (38, Sigstore maintainer), William Woodruff (3), renovate |
| Layout | One crate with feature flags | 12 crates: `sigstore-verify`, `-trust-root`, `-bundle`, `-tuf`, `-rekor`, `-tsa`, `-merkle`, `-crypto`, `-types`, `-fulcio`, `-oidc`, `-sign` (README.md "Crates" table) |
| Conformance | `.github/workflows/conformance.yml:1` runs only `on: [workflow_dispatch]` (manual). The harness is `tests/conformance/conformance.rs:121` and contains `unimplemented!("sig/cert commands")`. | Runs on every CI build (`.github/workflows/ci.yml:115-133`, sigstore-conformance v0.0.29), plus mutation fuzzing (`ci.yml:146`) |
| Edition / MSRV | 2024 | 2021, Rust 1.86 |

### Feature matrix
| Capability | sigstore-rs 0.15 | sigstore-rust 0.16 |
|---|---|---|
| **Legacy cosign `.sig` tag** (SimpleSigning) | ✅ `src/cosign/client.rs:49-62` builds `sha256-<hex>.sig` via `triangulate()`. Fetch is at `client.rs:189`. Layer media type is `application/vnd.dev.cosign.simplesigning.v1+json` (`src/cosign/constants.rs:33`). Annotations: `dev.cosignproject.cosign/signature`, `dev.sigstore.cosign/bundle`, `dev.sigstore.cosign/certificate` (`constants.rs:34-36`). The SET in the annotation bundle is checked against Rekor keys (`src/cosign/bundle.rs:85-99`). | ❌ No OCI or registry code at all (grep for `oci\|registry\|referrer` returns nothing). |
| **Legacy `.att` / `.sbom` tags** | ❌ Not implemented (grep `\.att\|attestation\|\.sbom` in `src/` returns nothing). | ❌ |
| **OCI referrers** | ⚠️ Partial. `client.rs:220-283`: `pull_referrers(..., None)` with no artifactType filter (comment at `:240-244` notes that ghcr reports `application/vnd.oci.empty.v1+json`), then filters layers by `application/vnd.dev.sigstore.bundle.v0.3+json` (`constants.rs:39`). **It only accepts DSSE with predicateType `https://sigstore.dev/cosign/sign/v1`** (`src/bundle/intoto.rs:25,81-92`; called at `signature_layers.rs:447`). SLSA, vuln and SBOM attestations are rejected. | ❌ (you bring the bundle bytes yourself) |
| **Bundle v0.1/0.2/0.3** | Profile parsing at `src/bundle/verify/models.rs:498-507`. **The generic bundle `Verifier` does NOT verify the inclusion proof or the SET**: `src/bundle/verify/verifier.rs:236` `// TODO(tnytown): Merkle inclusion; sigstore-rs#285` and `:240` `// TODO SET verification`. Only the OCI-referrer path (`signature_layers.rs:632-744`) checks SET plus inclusion proof plus checkpoint. | ✅ All three versions with structural rules: v0.1 requires an SET, v0.2/v0.3 require an inclusion proof, v0.3 requires a single cert or public key (`crates/sigstore-bundle/src/validation.rs:91-96,129-178`) |
| **Keyless** (Fulcio chain, SCT, identity/issuer) | Chain plus SCT plus policy at `verifier.rs:166-207`. Identity matching: exact (`bundle/verify/policy.rs:249` `Identity::new`) and `AnyOf`/`AllOf` (`:174,205`). The legacy cosign path supports **regex** via `StringVerifier::Regex` (`cosign/verification_constraint/cert_subject_email_verifier.rs:129-138`). | ✅ Chain, validity at signing time, CODE_SIGNING EKU and SCT (`CertificatePolicy`, `crates/sigstore-verify/src/verify.rs:24-37`). Identity matching is **exact only**: `IdentityMatcher::{Exact,Email,Uri}` (`verify.rs:156-175`); `VerificationPolicy::new(identity, issuer)` at `:247`. **No regex or glob**, so you would add it yourself. Fulcio CI claims are parsed: `FulcioCiClaims` (`crates/sigstore-crypto/src/x509.rs:93`). |
| **Key-based** | ✅ Legacy `.sig` path (`cosign/mod.rs:199` `verify_blob_with_public_key`, verification constraints). The bundle verifier is keyless only. | ✅ `PublicKeyVerificationPolicy::new(DerPublicKey)` (`verify.rs:47-80`); the tlog is still verified unless `skip_tlog_unsafe()` (`:66`) |
| **Rekor offline: inclusion proof plus checkpoint** | Only in the referrer path (`signature_layers.rs:685-744`). Merkle code: `src/crypto/merkle/proof_verification.rs`. | ✅ `verify_entry_inclusion` (`verify_impl/tlog.rs:118`), `verify_checkpoint` (signed note, every matching key tried, `:169-214`), `verify_set` (`:233-283`). Rekor v2 (tiles) handled (`:46,217`). Entry-to-bundle consistency check against CVE-2022-36056 (`verify_impl/rekor.rs:18-177`: dsse v0.0.1, intoto v0.0.2, hashedrekord). |
| **RFC3161 TSA** | Not in the verifier | ✅ `sigstore-tsa` crate; listed in the verification steps (`verify.rs:579-605`) |
| **TUF trust root** | `SigstoreTrustRoot::new(cache_dir)` (`src/trust/sigstore/mod.rs:69-89`) uses `tough` and **always loads remote TUF metadata first** (`:77-86`). The cached target is only compared against the snapshot hash (`:173-186`), so it is not offline-capable. Offline alternatives: `from_trusted_root_json_unchecked` (`:99`) or `from_client_trust_config` (`:118`). | ✅ Custom TUF client (`crates/sigstore-tuf`). `TufConfig::with_cache_dir` (`trust-root/src/tuf.rs:208`). **`TufConfig::offline()`** (`:229-249`) re-runs the full TUF chain (root→timestamp→snapshot→targets) over the cache, with no network, and checks expiry at validation time (`from_tuf_at`, `:497`). `TufBootstrap::{TrustedRoot, UnsafeCachedRoot}` (`:102-117`). Embedded roots: `SIGSTORE_PRODUCTION_TRUSTED_ROOT` / `from_embedded` (`trust-root/src/lib.rs:48-61`). |
| **DSSE / in-toto** | Bundle verifier supports DSSE: any subject matching the digest, sha256 or sha512 (`verifier.rs:148-157`, tests at `:448-560`). | ✅ Payload type must be `application/vnd.in-toto+json`. The artifact is bound to the statement subject digest (`crates/sigstore-verify/src/artifact.rs:39-66`); PAE is verified (`verify.rs:806,959`). **The predicateType is not checked**; that is the caller's policy. |
| **Async / runtime** | Async API on tokio, with a `blocking::Verifier` wrapper (`verifier.rs:325-405`). Uses `oci-client 0.18`, `reqwest 0.13`, `cached` (in-memory 60s registry cache, `src/registry/oci_caching_client.rs:125`). | **Verification is synchronous** (`Verifier::new(&TrustedRoot)` at `verify.rs:460`, `verify()` at `:605`). Optional `verify_async_reader` (`:646`, uses futures-io). Tokio and reqwest are only needed for TUF fetching. |
| **TLS / crypto** | `default = ["full","native-tls"]` (`Cargo.toml:15`). native-tls pulls in **openssl** (`:47`); the `rustls-tls` alternative uses aws-lc-rs (`:57-62`). The `full` feature also brings in the mock client, fulcio, oauth and webbrowser. | aws-lc-rs plus rustls by default. Alternatives are `native-tls` and `rustls-no-provider`; a custom `CryptoProvider` lets you avoid aws-lc-sys (README "Cryptography and TLS Configuration"). Per-crate features are `default,rustls,rustls-no-provider,native-tls,aws-lc-rs,tuf`. |

### Recommendation
**Use `sigstore-verify` + `sigstore-trust-root` (sigstore-rust) for the cryptography, and write the OCI discovery layer yourself** (on `oci-client` or a thin HTTP client).
- Why:
  - Its tlog verification is complete and offline: SET, Merkle proof and checkpoint signature.
  - It handles every bundle version plus Rekor v2.
  - Its verify API is synchronous and pure, which suits a node agent working from a local cache.
  - It has a real offline TUF mode.
  - It runs the conformance suite on every build.
  - It sees active cross-ecosystem use (prefix/rattler, PyPI-style work).
- sigstore-rs problems:
  - Its generic bundle verifier skips inclusion proof and SET (TODO #285).
  - Its referrer path rejects any predicate other than `cosign/sign/v1`.
  - It has no `.att` support.
  - Its TUF loader needs the network.
- Gaps you will have to fill on sigstore-rust:
  1. OCI fetching (referrers plus legacy tags).
  2. Regex/glob identity matching (wrap `VerificationResult::identity()` / `issuer()` at `verify.rs:392-396`; you can pass `VerificationPolicy::any_identity()` (`:257`) and then apply your own matcher).
  3. Legacy `.sig` / `.att` support. Either reject them, or convert the annotations into a v0.1 bundle: cert plus signature plus the SET from `dev.sigstore.cosign/bundle`. Legacy artifacts carry **no inclusion proof, only an SET**. The caller must also check that the SimpleSigning payload's `critical.image.docker-manifest-digest` equals the image digest. An `.att` logged as a Rekor `intoto` v0.0.1 entry (older cosign) cannot be verified by sigstore-rust 0.16: it accepts `hashedrekord` 0.0.1/0.0.2, `dsse` 0.0.1 and `intoto` 0.0.2 only (`crates/sigstore-verify/src/verify_impl/rekor.rs:29-66`).
  4. Checking predicateType and predicate content.

---

## 2. How cosign stores signatures, attestations and SBOMs (cosign v3.1.3, HEAD `e2d25b54`)

**Legacy tag scheme**
- Tag format: `<alg>-<hex>.<suffix>`.
- Suffixes `sig` / `sbom` / `att`: `pkg/oci/remote/options.go:30-32`.
- Built by `suffixTag`: `pkg/oci/remote/remote.go:154-170`.
- `SignatureTag` / `AttestationTag` / `SBOMTag`: `remote.go:117,123,129`.

| Object | Manifest layer mediaType | Annotations |
|---|---|---|
| `.sig` | `application/vnd.dev.cosign.simplesigning.v1+json` (`pkg/types/media.go:28`) | `dev.cosignproject.cosign/signature`, `dev.sigstore.cosign/certificate`, `.../chain`, `.../bundle` (Rekor SET), `.../rfc3161timestamp` (`pkg/oci/static/signature.go:32-36`) |
| `.att` | `application/vnd.dsse.envelope.v1+json` (`pkg/types/payload.go:19`, set at `cmd/cosign/cli/attest/attest.go:200`) | `predicateType` (`attest.go:202,214`) plus the same sig/cert/bundle annotations |
| `.sbom` | Raw SBOM: `text/spdx`, `text/spdx+json`, `application/vnd.cyclonedx+json\|+xml`, `application/vnd.syft+json` (`media.go:25-30`). **Unsigned.** | none. `cosign attach sbom` (`cmd/cosign/cli/attach/sbom.go:63`) |

**OCI 1.1 referrers (new bundle format)**
- `WriteAttestationNewBundleFormat` (`pkg/oci/remote/write.go:404-422`) calls `WriteReferrer` (`:314-401`):
  - `artifactType` = `application/vnd.dev.sigstore.bundle.v0.3+json` (`pkg/cosign/bundle/constants.go:17`).
  - `config.mediaType` = `application/vnd.oci.empty.v1+json`.
  - One layer holding the bundle JSON, layer annotation `org.opencontainers.image.title: sha256-<hex>.sigstore.json`.
  - `subject` = the image descriptor.
  - Manifest annotations: `dev.sigstore.bundle.content: dsse-envelope`, `dev.sigstore.bundle.predicateType: <uri>` (key defined at `write.go:39`), `org.opencontainers.image.created`.
- **Signatures in v3 are also DSSE bundles** with predicateType `https://sigstore.dev/cosign/sign/v1` (`pkg/types/predicate.go:19`). `sign.go:227` calls the same writer.
- So you can filter attestations without pulling layers, using the manifest annotation `dev.sigstore.bundle.predicateType` (the referrers API copies annotations into the index; see §3).
- Other experimental artifactTypes:
  - `application/vnd.dev.cosign.artifact.{sig,sbom,att}.v1+json` (`internal/pkg/oci/remote/remote.go:23-25`).
  - Used by `--registry-referrers-mode=oci-1-1` (`cmd/cosign/cli/options/registry.go:181-221`), `attach sbom` (`attach/sbom.go:92`) and experimental signatures (`write.go:268`).
  - `WriteAttestationsReferrer` uses `application/vnd.in-toto+json` (`write.go:425-453`).
- Predicate URIs come from `cmd/cosign/cli/options/predicate.go:29-54`: slsaprovenance (v0.2 / v1), spdx, cyclonedx, vuln (`CosignVulnProvenanceV01`), openvex, custom.

**Version defaults** (`CHANGELOG.md`)
- **v2.4.0** (`:379-383`): the spec-compliant bundle format is introduced behind `--new-bundle-format`.
- **v2.5.0** (`:257`): attestation via referrers, still gated by the flag.
- **v3.0.0** (`:108-118`): bundle format, `--trusted-root` and OCI 1.1 referrer storage are **on by default**.
- Today `--new-bundle-format` defaults to `true` and is deprecated: *"this will be the only supported format in future versions"* (`options/sign.go:161-162`, `attest.go:129-130`, `verify.go:75-77`).
- Verify-side discovery: `GetBundles` (`pkg/cosign/verify.go:1748-1797`) calls `Referrers(digest, "")` with no filter, then tries to parse every referrer as a bundle and skips non-bundles (`:1781-1786`).
- The ≤v2 default was the legacy tags. Expect both in the wild for years. Policy-controller docs: bundle support since policy-controller v0.13, attestations only (`docs/content/en/policy-controller/overview.md:196-200`).

---

## 3. OCI referrers API and the `subject` field

**distribution-spec** (`spec.md`, HEAD `9727462`)
- Endpoints:
  - `GET /v2/<name>/referrers/<digest>` (end-12a, `spec.md:621,860`).
  - `GET /v2/<name>/referrers/<digest>?artifactType=<type>` (end-12b, `:680,861`).
- Response (`:625-664`):
  - `200` with `Content-Type: application/vnd.oci.image.index.v1+json`.
  - Each descriptor carries `artifactType`, taken from the manifest's `artifactType`, else from `config.mediaType`; it is omitted for indexes (`:632-634`).
  - **Manifest annotations are copied into the descriptors** (`:635`).
  - No matches gives an empty `manifests` list (`:636`).
  - A registry that supports the API MUST NOT return 404 (`:626`).
- Pagination: `Link: <...>; rel="next"` (`:666-668`).
- Filtering is a SHOULD (`:679`). It is applied only if the response header is `OCI-Filters-Applied: artifactType` (`:681`). **If that header is missing, the client must filter itself.**
- Fallback: if the API returns 404, the client MUST pull the tag `<alg>-<hex>` (e.g. `sha256-aaaa…`, with no suffix, so it does not collide with cosign's `.sig`) and expect an image index of the same shape (`:712-714,786-805`). If the tag is not a valid index, assume no referrers.
- Pushers without the API do read-modify-write on that tag (race-prone, `:552-561,809`).
- Registries that enable the API later must include manifests already listed in the tag index (`:816-823`).
- When processing a pushed manifest with a `subject`, the registry returns an `OCI-Subject` header (`:548`).
- A registry MUST accept a `subject` pointing to a manifest that does not exist (`:221`). Push order is therefore free; useful for P2P replication.

**image-spec**
- `subject` (`manifest.md:100-103`; for indexes `image-index.md:93-96`): a descriptor of another manifest. It creates a *weak* association (a separate Merkle DAG) and is what the referrers API indexes.
- `artifactType` (`manifest.md:29-34`): MUST be set when `config.mediaType` is the empty type. Unknown values MUST NOT cause errors.
- Empty descriptor `application/vnd.oci.empty.v1+json` (`:160-169`). Artifact guidance at `:180-264`. Tools must fall back to `config.mediaType` when `artifactType` is absent (`:264`).
- **Gotcha:** cosign writes `artifactType` both at the top level (`referrerManifest`, `write.go:461-464`) and inside `config` (`:379`). sigstore-rs notes that ghcr reports the referrer as `application/vnd.oci.empty.v1+json` (`sigstore-rs/src/cosign/client.rs:240-244`). Don't trust the server-side filter; filter by layer mediaType or by the annotation.

---

## 4. Offline verification: what the P2P node cache must hold

**Can it be fully offline? Yes, for v0.2/v0.3 bundles.**
- The bundle carries everything needed (`docs/content/en/about/bundle.md:59-93`):
  - the cert (or a key hint),
  - `tlogEntries[]` with `canonicalizedBody`, `inclusionPromise.signedEntryTimestamp` and `inclusionProof{logIndex, rootHash, treeSize, hashes[], checkpoint.envelope}`,
  - optional RFC3161 timestamps.
- Verifying it is pure computation against `trusted_root.json`:
  - SET signed by the Rekor key,
  - Merkle path to `rootHash`,
  - checkpoint signed note under the Rekor key,
  - cert chain to the Fulcio CA at `integratedTime` (or TSA time),
  - SCT under the CT log key.
- This mirrors `rekor/pkg/verify/verify.go:224-242` `VerifyLogEntry` (inclusion, checkpoint signature, SET), none of which touch the network.
- What does need the network: consistency between this checkpoint and the *current* log head (`ProveConsistency` / `VerifyCurrentCheckpoint`, `verify.go:40-115`). That is monitoring/anti-split-view, optional, and not done by cosign verify.
- sigstore-rust does everything offline in `Verifier::verify` (steps listed at `verify.rs:579-605`).
- **Legacy `.sig` / `.att` have an SET only, no inclusion proof.** They are still offline-verifiable, with a weaker guarantee (a promise of inclusion, not a proof).

**Cache contents, keyed by subject digest**
1. The image manifest digest (the subject). Store tag→digest resolutions separately; only digests are verifiable.
2. The referrers index for the digest (or the fallback `sha256-<hex>` tag index), plus every referrer manifest. Keep annotations, since `dev.sigstore.bundle.predicateType` lets you select without fetching layers.
3. Bundle layer blobs (`application/vnd.dev.sigstore.bundle.v0.3+json`). These are content-addressed, so integrity is checked by digest on P2P receive.
4. Legacy: `sha256-<hex>.sig` / `.att` manifests (the annotations hold the cert, chain and SET) plus their layer blobs (the SimpleSigning payload or DSSE envelope). Optionally `.sbom` (unsigned; only trust it via a signed SBOM attestation).
5. Trust material:
   - `trusted_root.json` (Fulcio CAs, Rekor/CT/TSA keys with validity windows).
   - Plus the TUF metadata (`root.json` chain, `timestamp`, `snapshot`, `targets`) if you want `TufConfig::offline()` (`sigstore-rust tuf.rs:229-249`).
   - Caveat: offline mode enforces TUF expiry at validation time. With long partitions, either:
     - refresh from a peer that has fetched fresh signed TUF metadata (TUF metadata is self-authenticating, so P2P distribution is safe), or
     - pin a `trusted_root.json` delivered by your control plane via `TrustedRoot::from_json`.
6. Rekor checkpoints: not needed separately (they are embedded in the bundle). Cache the latest verified checkpoints only if you add split-view or consistency checks later.
7. Verification verdict cache keyed by `(subject digest, bundle digest, policy hash, trusted_root hash)`.

---

## 5. Policy languages: which shape to mimic

**sigstore policy-controller `ClusterImagePolicy`** (`docs/content/en/policy-controller/overview.md:110-240,375-430`)
- Image match: `spec.images[].glob` (e.g. `"**"`, `ghcr.io/org/*`).
- `spec.authorities[]`: an image passes if *any* authority is satisfied (`:126-129`).
  - `key`: `{data | secretRef | kms, hashAlgorithm}` (`:131-157`).
  - `keyless`: `{url, ca-cert, trustRootRef, identities[]: {issuer|issuerRegExp, subject|subjectRegExp}}` (`:161-188`).
  - Also `ctlog`, `rfc3161timestamp.trustRootRef` (`:312-357`), `source[].oci` (repository override) with `signaturePullSecrets` (`:263-297`), and `static: {action: pass|fail}` (`:221-240`).
  - Per-authority `attestations[]: {name, predicateType, policy: {type: cue|rego, data}}` (`:217-219,390-396`).
- `signatureFormat: bundle` (`:197-216`).
- Every CIP matching an image is ANDed together (`:228-233`).

**Kyverno `verifyImages`** (from knowledge)
- `imageReferences` globs.
- `attestors[].entries[]`: `keys{publicKeys, rekor, ctlog}`, `keyless{subject, issuer (+regExp), rekor, roots}`, `certificates`.
- `attestations[]: {type/predicateType, attestors, conditions (JMESPath any/all)}`.
- Plus `mutateDigest`, `verifyDigest`, `required`.
- Newer: the `ImageValidatingPolicy` CRD with CEL.

**Connaisseur** (from knowledge)
- `validators[]: {name, type: cosign, trustRoots[{name, key | keyless{issuer, subject}}]}`.
- `policy[]: {pattern: "registry/repo:*", validator, with: {trustRoot, threshold, required[]}}`. The most specific pattern wins.

**Suggested shape for the node agent** (combines the above; CIP semantics map most directly onto the sigstore-rust API)
```yaml
policies:
- match: ["ghcr.io/myorg/**"]         # glob on repo; most-specific-wins or AND-all (pick one, document it)
  mode: enforce|warn
  authorities:                         # ANY-of
  - keyless: {issuer: "https://token.actions.githubusercontent.com",
              subjectRegExp: "^https://github.com/myorg/.+/\\.github/workflows/release\\.yml@refs/tags/.+$"}
    tlog: required                     # SET/proof required; tsa optional
  - key: {pem: "...", tlog: required}
  attestations:                        # ALL-of, each verified by the authorities above
  - predicateType: https://slsa.dev/provenance/v1
    conditions: CEL                    # e.g. builder.id, source repo
  - predicateType: https://cosign.sigstore.dev/attestation/vuln/v1
    conditions: CEL                    # e.g. no CRITICAL
  - predicateType: https://spdx.dev/Document   # SBOM attestation (CycloneDX: https://cyclonedx.org/bom)
  trustRoot: public-good | <custom trusted_root.json>
  sources: {legacy_tags: true, referrers: true}
```
Map an authority onto `sigstore-verify` as follows:
- keyless → `VerificationPolicy::any_identity()` + `verify()`, then your regex on `result.identity()` / `result.issuer()` (`verify.rs:392-396`). Or use `IdentityMatcher::Uri` for exact matches.
- key → `PublicKeyVerificationPolicy::new(key)`.
- attestations → parse the DSSE statement from the bundle, check `predicateType`, evaluate the predicate. sigstore-rust has already enforced that the subject digest equals the image digest (`artifact.rs:39-66`).