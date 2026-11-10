# Decisions: node identity

Who may talk to whom between nodes. Index: `docs/decisions/README.md`.

## D16: mTLS identity is the kubelet client certificate

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
  - The certificate appears only after TLS bootstrap. With `enforce` and `required_plugins`, an agent that waited for it would block every container on a joining node.
- **Revisit when:** non-Kubernetes hosts come into scope, or another distro (k3s, RKE2, EKS, GKE, Talos) is supported. These keep the CA and the certificate elsewhere.
