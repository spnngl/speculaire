# Recorded Sigstore fixtures

The gate's Sigstore fixtures (D139, D141), recorded from public-good Sigstore by `.github/workflows/fixtures.yml` in
run [44142408768](https://github.com/spnngl/speculaire/actions/runs/44142408768) on 2026-11-17, from commit `dd52dab`.
The files are its artifact `fixtures` as uploaded, byte for byte (`.gitattributes`).

- `layouts/<case>/`: one OCI layout per case, the image with its tags and referrers. The images are
  `ghcr.io/spnngl/speculaire-fixtures:<case>`, `linux/amd64` only.
- `expected.json`: each case's digest, signer, attached predicate types, checks and outcome, as the oracle found them.
- `trusted_root.json`: the public-good trusted root of the recording. `tuf/`: a snapshot of `tuf-repo-cdn.sigstore.dev`.
- `cosign.pub`: the key of the `key` case.
- `github-private-attestation.sigstore.json`: not recorded. A GitHub bundle from its private Sigstore instance, copied
  from sigstore-rust tag `sigstore-verify-v0.16.0`, `crates/sigstore-verify/test_data/bundles/`, Apache-2.0 (`NOTICE`).

Tests read them through the `testing` feature of `speculaire-artifacts`; `e2e` pushes them to its upstreams.

## Re-recording

Run `fixtures` by hand (`gh workflow run fixtures.yml`), only when a test cannot pin its verification time against an
expired certificate or TUF metadata (D139). Each run writes permanent entries to the public Rekor log and changes every
digest and certificate. Replace this directory with the run's artifact (`gh run download <run> -n fixtures`), update
the run above, then the digests the tests pin.
