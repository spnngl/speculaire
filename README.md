# Spéculaire

A peer-to-peer container image mirror and supply-chain gate for containerd, written in Rust.

> **Status:** design only. Nothing is implemented or released yet; do not run this anywhere.

## What it does

- **Shares image layers between nodes,** so each layer is downloaded from the registry about once per cluster. When no node has the content, containerd falls back to the registry as usual.
- **Shares signatures, attestations and SBOMs** the same way, then verifies them on each node with Sigstore.
- **Blocks containers whose image fails your policy,** through a containerd NRI plugin. It starts in `audit` mode, and only rejects in `enforce`.
- **Uses the control-plane nodes as reflectors.** They know which node holds which content, so there is no DHT.
- **Prewarms** a list of images onto nodes before workloads need them.

It is inspired by [Spegel](https://github.com/spegel-org/spegel), which it is benchmarked against.

## Requirements

- Linux on x86_64 or aarch64
- containerd 2.3 or later; 2.4 or later is recommended, because 2.3 has a known identity gap in the gate
- a kubeadm cluster
- systemd; a Helm chart comes later

## Documentation

- [`ARCHITECTURE.md`](ARCHITECTURE.md): how it works, and the words it uses.
- [`docs/operations.md`](docs/operations.md): turning on the gate, break glass, alerts, upgrades.
- [`docs/security.md`](docs/security.md): what it trusts, and the risks it accepts.
- [`docs/decisions/`](docs/decisions/README.md): every design choice and its reason.
- [`SECURITY.md`](SECURITY.md): reporting a vulnerability.

## License

Apache-2.0. See [`LICENSE`](LICENSE).
