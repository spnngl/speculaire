# To decide

Open questions, each with a proposed default. Once a question is answered, record the answer as a decision (`docs/decisions/README.md`) and delete the question.

## Before M3

- **What does a negative `dial_timeout` in a containerd `hosts.toml` mean?** Go's `time.ParseDuration` accepts `"-1s"` (containerd v2.3.7 `core/remotes/docker/config/hosts.go:539-545`), and `net.Dialer` then sets a deadline in the past (`net/dial.go:252` at go1.26.1), so every dial to that host fails at once and containerd tries the next host. `crates/registry-config/src/go.rs:381` refuses it, which rejects the whole file and keeps the previous registry config. [Read a negative `dial_timeout` as a host that cannot be dialled: the relay skips it, as containerd does. Amends D78.]

## Not scheduled

- **Do peers prefer holders in their own zone?** Many clusters span zones, and traffic between zones costs more and takes longer: AWS bills about $0.01/GB each way, and a round trip takes about 0.1–0.3 ms within a zone against 0.5–2 ms between zones. Nothing in the swarm knows a node's zone: a lookup answers 8 holders from a random position (D97), and Linux itself has no notion of a zone. A hard split into one swarm per zone sends a zone that lacks a blob to upstream rather than to a peer in the next zone. [Each agent learns its zone from `peer.zone` (live): `"auto"` (default) reads the `topology.kubernetes.io/zone` label of its own `Node` from the apiserver with the kubelet credentials (D16), re-read until the label exists; any other string is the zone; `""` means none. The agent sends its zone in `Hello`; a lookup fills its 8 holders from the asker's zone first, then from the others; `peer.zones = "only"` [`"prefer"`] returns the asker's zone alone, for clusters whose upstream costs less than traffic between zones. The fetcher (D102) tries same-zone holders first. `prewarm.seeds` counts seeds per zone (D51). Peer metrics get a bounded `zone` label, `same` or `other` (D34). To check first: that the Node authorizer lets a kubelet certificate read its own `Node`. Amends D2, D51, D97, D102.]

- **Does the release bar's peak memory count page cache?** D35 compares the agents' `memory.peak`, which counts the page cache charged to the cgroup as well as the process's own memory. In the first kind run (D106) speculaire peaked at 215 to 233 MiB against Spegel's 31 to 33, and nothing yet tells the two apart. [`bench.sh` also samples `anon` and `file` from the cgroup's `memory.stat` every second during each set, the tables show the peak of each, and the bar compares the peak of `anon`. Amends D35.]

## Before M5

- **Do identity regexes match the whole string?** D8 makes regex identity matching ours, and no decision says whether a policy's `subjectRegExp` and `issuerRegExp` must cover the whole SAN and issuer. Rust's `Regex::is_match`, like Go's `MatchString` in policy-controller and cosign, matches a substring, so `https://github.com/myorg/` also matches `https://github.com/myorg-evil/`. [Each regex is compiled as `^(?:…)$`, so it matches the whole string. A policy ported from policy-controller can only become stricter, and `docs/operations.md` says so. Amends D11.]

## Before M7

- **When does a member release the rest of a prewarm wave?** D51 sends `Prewarm` to the other agents "once the seeds have announced the image's blobs", but a member knows only the image reference, not its blob digests. [The member resolves each `prewarm.images` entry through the registry config (D17) to its platform manifests and their layer digests, and releases the wave once every seed has announced every layer of its platform, or after `prewarm.seed_timeout` (default `"5m"`, live), whichever comes first. Amends D51.]
