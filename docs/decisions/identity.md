# Decisions: node identity

Who may talk to whom between nodes. Index: `docs/decisions/README.md`.

## D16: mTLS identity is the kubelet client certificate (amended by D60, D95)

- **Decision:**
  - Each agent and reflector loads `/var/lib/kubelet/pki/kubelet-client-current.pem` (certificate and key in one file). It trusts the cluster CA, kubeadm's `/etc/kubernetes/pki/ca.crt`. Both paths are configurable; kubeadm is the only supported layout.
  - Both TLS sides use custom rustls verifiers that check:
    - the chain to the cluster CA;
    - the `clientAuth` extended key usage;
    - `O=system:nodes` and `CN=system:node:<name>`.

    There is no hostname check.
  - The agent reloads the file when kubelet rotates it.
  - The reflector accepts announcements only for the stream's own node identity. Lookup returns node identities, and the fetcher checks each one against the peer's certificate.
  - **Bootstrap:** until the certificate file exists (that is, before the node joins), the agent runs without P2P. The gate, the mirror and *fall through* all work, and P2P starts when the file appears. A node must not depend on P2P to join.
- **Because:**
  - Every node already has this identity and kubelet rotates it, so there is no CA to run or distribute.
  - The certificate carries `clientAuth` only and no IP SANs, so stock server verification would reject it. The custom verifier checks it with client-auth key usage instead.
  - Binding addresses to node identity means a node can lie about its own content, but cannot impersonate another node.
  - **Measured** (M0 spike 03, kubeadm via kind, rustls 0.23 with `aws-lc-rs`, one verifier for both sides built on `rustls-webpki` `verify_for_usage(client_auth)` plus `x509-parser` for the subject):
    - The file is a symlink to `kubelet-client-<timestamp>.pem`, holding the certificate and an EC P-256 key. Subject `O=system:nodes, CN=system:node:<name>`, only `clientAuth`, no SANs. kind's 10-minute signing duration gave a 15-minute lifetime rotated every 7.5 minutes; kubelet deletes the older file on rotation.
    - Handshakes succeed in both directions, with the client-auth-only certificate as server certificate.
    - A certificate from another CA fails with `UnknownIssuer`, the apiserver's kubelet client certificate (no `O`) with `subject O=[] is not system:nodes`, and a certificate for the wrong node with `expected node <a>, certificate is for node <b>`. The same errors surface from either side.
    - Resolving the certificate by `fs::canonicalize` on the symlink target picked up a rotation in a running server: the next connection presented the new serial, and no connection failed.
    - TLS 1.3 reports the client's handshake as complete before the server verifies the client certificate. A rejection arrives as an alert on the first read, so peer code treats a read error as a failed connection.
  - The certificate appears only after TLS bootstrap. With `enforce` and `required_plugins`, an agent that waited for it would block every container on a joining node.
- **Revisit when:** non-Kubernetes hosts come into scope, or another distro (k3s, RKE2, EKS, GKE, Talos) is supported. These keep the CA and the certificate elsewhere.

## D95: The identity and the CA are held in memory and read again when their file's stamp changes (amends D16)

- **Decision:**
  - **Held:** `speculaire_pki::node::Credentials` holds the identity, a node name, an expiry and a `CertifiedKey` whose key matches its certificate, and the cluster CA. A reload swaps either in; a handshake reads them and no file. One `Verifier` checks both sides of a link: rustls' `WebPkiClientVerifier` for the chain, `clientAuth` and validity, then the subject, then, on the client side, the node dialled. Links are TLS 1.3 only.
  - **Rotation:** the certificate file and the CA file each have a stamp (D93), taken through the symlink, so kubelet's repointed link is a new inode. Each is read at startup and on SIGHUP, and on a poll of `config.poll_interval` when its stamp differs.
  - **CA:** read the same way, with its own stamp.
  - **A file that fails** is one error naming it, counted in `speculaire_config_reload_failures_total`; what was loaded before stays, and the same bad file is not read again until it changes (D93). An absent file is one `info` line; a loaded identity whose file goes stays.
  - **P2P on:** `speculaire_p2p_enabled` is 1 while both are loaded and the identity has not expired, set at each read and each poll. `speculaire_identity_expiry_timestamp_seconds` holds its expiry.
- **Because:**
  - A file read per handshake, as the spike's `fs::canonicalize` did, puts disk I/O on every connection, and races kubelet's update: it removes the link, then renames a new one over it (client-go `util/certificate/certificate_store.go:303-311`, kubernetes v1.38.0-alpha.3-218-ge3e26fc7ab7).
  - Stamps catch a rotation with no clock to race, as for the config (D93); kubelet writes each pair to a new dated file before repointing the link (same file, 204-245), so a read through the link sees a whole file.
  - `WebPkiClientVerifier` already makes D16's chain and `clientAuth` check, and its errors are rustls' own variants: no direct dependency on `rustls-webpki`.
  - kubelet renews once 70 to 90% of the lifetime has passed (`util/certificate/certificate_manager.go:737-738`, same version), so a poll's delay never presents an expired certificate.
- **Cost:**
  - A rotation reaches new handshakes up to one `config.poll_interval` late; a link open before it keeps the old certificate.
  - A poll between kubelet's remove and rename sees no file: one `info` line, and the pair in use stays.
  - kubeadm names every cluster CA `kubernetes`, so a certificate of another kubeadm cluster fails with `BadSignature`; `UnknownIssuer` comes only from a CA named otherwise.
  - The TLS 1.2 signature checks the verifier traits require never run, and no test reaches them: rustls makes no `DigitallySignedStruct` outside itself.
- **Measured (macOS arm64, local runs):** `rcgen` CA unit tests: every case of D16 fails as listed, from both sides; another node fails as `expected node b, certificate is for node c` on the client and passes on the server; a server-auth-only certificate fails with `InvalidPurposeContext`, an expired one with `ExpiredContext`. A handshake in memory after the files were deleted succeeds with the loaded pair. A repointed link presents the new certificate on the next poll. The agent with no certificate is ready with `speculaire_p2p_enabled 0`, and 1 after the file is written, within the 1 s poll of the test. `node_subject` fuzzed for 60 s: 246 684 runs, no crash.
- **Revisit when:** a peer link must outlive a rotation with the old certificate refused, or a distro keeps the certificate outside a file (D16).
