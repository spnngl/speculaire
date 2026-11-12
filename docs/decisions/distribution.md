# Decisions: distribution

Image content flow between containerd, the local mirror, peers and upstream. Index: `docs/decisions/README.md`.

## D3: Every agent announces its own peer address and port (amended by D36)

- **Because:** Spegel assumes every peer listens on the same port as the local one (`docs/research/spegel.md` §3), which breaks mixed configurations.
- **Revisit when:** —

## D5: Serve blobs from containerd's content directory (amended by D67)

- **Decision:** read `/var/lib/containerd/io.containerd.content.v1.content/blobs/` directly (read-only), with a gRPC `Content.Read` fallback.
- **Because:** this is Spegel's proven path, and it is the cheapest one.
- **Revisit when:** —

## D6: Tag resolution is off by default (amended by D66)

- **Decision:** the mirror host gets capability `pull` only, never `resolve`.
- **Because:** with `resolve`, a peer could answer a tag with any digest it serves. Without it, tags resolve upstream (a small request) and blobs, the bulk of the bytes, still go P2P. Measured on containerd 2.3.7 and 2.4.2: the mirror sees no tag request, only manifests and blobs by digest (D22).
- **Revisit when:** users need tag pulls to survive an upstream outage. Then expose `resolve_tags = true`, documented as "trust all nodes".

## D7: Verify blob digests in flight (amended by D52, D67, D73)

- **Decision:** hash every full-blob response while streaming it; on mismatch, abort and deny the peer (D52).
- **Because:** it catches a bad peer early, so it can be reported. Otherwise the error only surfaces at containerd's commit.
- **Limit:** when containerd itself sends a `Range` request (resuming a download), the agent relays the range unhashed; containerd's commit check is then the only check.
- **Revisit when:** —

## D14: The mirror is TLS with client auth on loopback; the peer API is mTLS on the node IP (amended by D32, D56, D66)

- **Decision:**
  - The mirror listens on `127.0.0.1:7480` (`mirror.address`, D56) with TLS and requires a client certificate.
  - `speculaire configure` generates a local CA, a server certificate for `127.0.0.1` and a client certificate for containerd, in `/var/lib/speculaire/mirror/` (root, mode 0600).
  - It writes their paths as `ca` and `client` in each `hosts.toml` mirror entry.
  - The mirror accepts only client certificates signed by that local CA.
  - The peer API listens on the node IP, port 7481, with mTLS (D16).
- **Because:**
  - A plain loopback mirror lets any local process, including any `hostNetwork` pod, read every cached private layer.
  - containerd's `hosts.toml` supports `ca` and a combined-PEM `client`, and reads them on every resolve (containerd v2.3.7 `core/remotes/docker/config/hosts.go:78-79` returns a `RegistryHosts` function that rebuilds each host, `:260` reads `ca`, `:281` loads the `client` pair from one PEM).
  - **Measured** (M0 spike 04, kind node, containerd 2.3.7, a `hosts.toml` mirror entry with `capabilities = ["pull"]`, `ca`, `client`, `dial_timeout = "200ms"`):
    - containerd sends the mirror every manifest and blob request of the pull, with the client certificate (`?ns=docker.io` on each URL). A 404 falls through to upstream, and the pull succeeds.
    - With a blob in the mirror's directory (a 20 MB layer of `nginx:alpine`), that blob answered 200 from the mirror and the other nine requests 404 and went upstream.
    - A client without a certificate fails the TLS 1.3 handshake.
    - With the mirror stopped, a pull costs about 40 ms more per image (connection refused; busybox and alpine tags, 2.1 s against 2.07 s with no `hosts.toml`).
    - After regenerating the CA and certificates and restarting only the mirror, the next pull used them with containerd untouched.
  - **The kubelet client certificate is not used here.** Before the node joins the cluster the file does not exist, and containerd then fails every pull for that registry with "unable to read CERT file". That would break `kubeadm join`'s own image pulls.
  - A root-only local key gives the same protection: an attacker with root can read the content directory anyway.
  - systemd uses host networking, so loopback works. That removes Spegel's NodePort hop and its init-container chicken-and-egg problem.
  - Ports avoid 5000, which local kind registries commonly use.
- **Revisit when:** a benchmark shows loopback TLS costing more than 10% of the agent's serving CPU.

## D17: Upstream access reuses containerd's registry config (amended by D66, D78)

- **Decision:**
  - Artifact discovery, referrers and prewarm resolution reuse containerd's *registry config*, in containerd's own formats.
  - The agent parses `/etc/containerd/config.toml` and its `imports`, then reads `registry.config_path`, `registry.configs."<host>".auth` (`username`, `password`, `auth`, `identitytoken`) and `registry.headers`. These live under `plugins."io.containerd.grpc.v1.cri".registry` (config version 2) or `plugins."io.containerd.cri.v1.images".registry` (version 3).
  - It reads each `hosts.toml` for `server`, hosts, `capabilities`, `ca`, `client`, `skip_verify`, `header` and `override_path`, and skips its own mirror entries.
  - The `oci` crate implements the registry Bearer token challenge.
  - `speculaire configure` adds its mirror host at the top of each `hosts.toml` and keeps the existing entries.
  - Images that are pullable only with pod `imagePullSecrets` get no upstream artifact fetch. They verify from peers, or end `Unverifiable("artifacts unreachable")` (D20).
- **Because:**
  - There is one source of truth for registry access: whatever containerd can reach, the agent can reach with the same TLS and credentials.
  - With `config_path` set, containerd still uses `configs."<host>".auth` as fallback credentials and passes `headers` to its registry authorizers (v2.3.0 `internal/cri/server/images/image_pull.go:105-114`, `:504-507`); setting `mirrors` as well is a startup error (`internal/cri/config/config.go:503-506`). So the agent reads both files, and `configure` edits only `hosts.toml`.
  - Pull secrets travel with each CRI request (`image_pull.go:105-114`) and never reach a file the agent could read.
- **Revisit when:** users need pull-secret-only images verified. Then add kubelet credential-provider support.

## D78: One `registry-config` crate holds both runtimes' parsers, and reads what containerd reads (amends D17)

- **Decision:**
  - The *registry config* parsers are one crate, `crates/registry-config` (`speculaire-registry-config`), a module per runtime: `containerd::config` for `config.toml`, `containerd::hosts` for `hosts.toml` and the host directories; CRI-O's module lands with its parser.
  - It reads versions 1 to 4, what containerd v2.4.2 reads (`version.ConfigVersion` is 4, `version/version.go:41`), not only 2 and 3. A version 1 name (`plugins.cri`) becomes its URI, and below version 4 the image service's section takes `registry` from the CRI plugin's, as `configMigration` does (`plugins/cri/images/plugin.go:181`). A file of a newer version is refused. `imports` merge as `LoadConfigWithPlugins` does: plugin tables merge deep, any other value, an array too, is replaced.
  - Keys are matched in any case, as go-toml does (`Server`, `CA`). Map keys, host names and plugin names stay exact.
  - Credentials are not combined by the parser. `registry.configs."<host>".auth` and `registry.auths` (keyed by the host of the URL) give one `Auth` per host; `registry.headers` apply to every registry; each `hosts.toml` host keeps its own `header`. A reader that fetches from a host sends the host's `header`, and uses the `Auth` of that host only to answer a Bearer challenge, as containerd does. Every credential and header value is a `SecretString`; `Debug` prints none (D37).
  - Keys the parser does not read are ignored, never an error, and never in the typed result: containerd decodes into structs and drops them. A key it does read with the wrong type is an error that names the key and the position, as `ParseError` does (D60). Messages are not containerd's; whether there is an error is.
  - `parse_hosts_file` and `resolve` are ports of `core/remotes/docker/config/hosts.go` at v2.4.2 (D25), including its quirks: a `client` entry that is a lone string has the host directory as its key, an unreadable `hosts.toml` falls back to the certificate files, an `http` host with TLS settings is tried as `https`, then `http`. The Go standard library calls those files make (`url.Parse`, `path.Clean`, `filepath.Match`, `time.ParseDuration`, `net.SplitHostPort`) are ported at go1.27.4, the Go of the oracle image.
  - Where containerd is not deterministic, the parser picks one answer: two plugins that a version 1 migration renames to the same URI merge in Go's random map order; the port takes the sorted order, and the differential test skips a case whose upstream answer changes between runs (D79).
- **Because:**
  - Both runtimes' configs end in the same questions (which hosts, with what TLS and credentials), and `configure` and the mirror share their answers; one crate keeps the vocabulary and the secrecy rules in one place.
  - The kind node images ship version 2 configs and containerd 2.4 reads up to 4: a parser limited to 2 and 3 would refuse configs the runtime accepts.
  - Parsing what the runtime parses, no more, no less, is what makes "whatever containerd can reach, the agent can reach" true (D17).
- **Measured (M2 step 00, arm64, Docker):** the differential tests send 1199 `hosts` cases and 1266 `config` cases, made of the cases of `hosts_test.go` and the config tests, the e2e node configs, and 400 mutations of each fuzz seed. All 1199 `hosts` cases and the 1250 `config` cases with a stable answer agree with containerd; the 16 others are the random-order merges. `just fuzz containerd_config 60` ran 116575 execs and `just fuzz hosts_toml 60` 495568, with no finding. Divergences the mutations found, now fixed: Go 1.27 `url.Parse` refuses `[` outside a leading IP literal, requires an IPv6 address inside brackets and a single colon in an `http(s)` host; `filepath.Match` no longer checks the rest of a pattern once the name cannot match; go-toml refuses a byte order mark. CI run 43124137467 (the `oracle` job) shows the same two lines. A planted fault, the port swapping the first two hosts of a `hosts.toml` (throwaway PR 36, closed), turned the `oracle` job red in run 43123600342: `340 of 1199 hosts cases differ from containerd`.
- **Revisit when:** a containerd release changes the loader or `hosts.go` (the oracle's `containerd` pin moves, D70): the differential tests show the difference.

## D80: The CRI-O module reads what go.podman.io/image reads, from the files it searches (amends D66, D70)

- **Decision:**
  - `crates/registry-config`'s `crio` module ports, from go.podman.io/image v5.40.0 (the version of CRI-O v1.37.2, as vendored there) and go.podman.io/storage v1.63.0: `registries.conf` and its drop-ins (`registries`), the per-host certificate directories (`certs`) and the credential files (`auth`). The search paths are `pkg/configfile`'s, for Linux, and are not what D66 listed:
    - `registries.conf`: the first that exists of `$XDG_CONFIG_HOME/containers` (else `$HOME/.config/containers`), `/etc/containers` and `/usr/share/containers`; drop-ins of `registries.conf.d` of each, with `registries.rootful.conf.d` (uid 0) or `registries.rootless.conf.d/<uid>` and `registries.rootless.conf.d` before the plain one, by file name, a name of a higher-priority directory hiding the same name below; then `$CONTAINERS_REGISTRIES_CONF_OVERRIDE`. `$CONTAINERS_REGISTRIES_CONF`, or CRI-O's `registries_conf`, replaces the main file and must exist; the first also drops the drop-ins; CRI-O's `registries_conf_dir` replaces the drop-in directories.
    - certificates of a host: the first `<dir>/<host:port>` that exists among the user's, the administrator's and the system's `certs.d`, with the same rootful and rootless variants, then `/etc/docker/certs.d`.
    - credentials: `global_auth_file` alone when set, else `$XDG_RUNTIME_DIR/containers/auth.json` (`/run/containers/<uid>/auth.json` without it, under the root of the tests), `$XDG_CONFIG_HOME/containers/auth.json`, `$DOCKER_CONFIG/config.json` (`~/.docker/config.json`), and the legacy `~/.dockercfg`.
  - The oracle gains `registries` (the merged registries, and the registry and pull sources of each reference, from `FindRegistry` and `PullSourcesFromReference`), `certs` (`dockerCertDir`, reached by linkname, and `SetupCertificates`) and `auth` (`GetCredentials`). A case sets the process environment the library reads, and restores it. The oracle builds with `CGO_ENABLED=0` and the tags `containers_image_openpgp,exclude_graphdriver_btrfs,exclude_graphdriver_devicemapper` (`go_tags` of the justfile): without them the module wants gpgme through cgo. An `auth` case runs 64 times, and answers `unstable` when the answers differ: a small Go map starts at a random slot.
  - What those paths depend on is a `crio::Context`: the root, the uid, `$HOME` and the variables, CRI-O's three settings. The agent runs as root and cannot see CRI-O's environment, so it uses `Context::root()`: uid 0, `/root`, no variable. A CRI-O started with `CONTAINERS_REGISTRIES_CONF` or a `registries_conf` is outside what the agent follows until a setting names it. `global_auth_file` is CRI-O's, not the agent's: `docs/TODECIDE.md` asks where the agent learns it.
  - Keys read: `registry` with `prefix`, `location`, `insecure`, `blocked`, `mirror-by-digest-only`, and `mirror` with `location`, `insecure`, `pull-from-mirror`; `credential-helpers`. `unqualified-search-registries`, `short-name-mode` and `additional-layer-store-auth-helper` are checked as the library checks them and used for nothing; kubelet pulls fully qualified names. An alias (`[aliases]`) is read for its type only, and not parsed as a reference: a config with a malformed alias loads here and fails in CRI-O. Any other key is ignored, as the library ignores it. Keys match in any case, as BurntSushi/toml matches them; a byte order mark is skipped.
  - A format 1 file, with one `registries.search`, `registries.insecure` or `registries.block` list set, is refused, as in the library. A `[[registry]]` of a later file replaces the earlier one of its prefix whole, and a file's registries are sorted by prefix, the first of a prefix winning (`postProcessRegistries`, `updateWithConfigurationFrom`).
  - `find_registry` takes the repository name and `Registry::pull_sources` the normalized reference, as `docker_image_src.go` does. It does not parse each rewritten reference, so a location that is no valid name gives a source where the library gives an error.
  - `certs::setup` pairs `*.cert` with `*.key` and refuses a lone one, and reads each file; whether it holds PEM that matches is left to the TLS configuration built from it.
  - Credentials follow `GetCredentials`: files are searched in order, an entry whose `auth` has no `:` ends the search of its file, and an empty login is none. A credential helper is not run: a lookup that reaches one, from `credential-helpers` or `credHelpers`, answers `Lookup::Helper(name)`, where the library runs it. Where several entries of a file name one registry, the library picks by map order; the port takes the sorted order. The `auth` module holds every secret as a `SecretString` (D37).
- **Because:**
  - Reading what CRI-O's library reads is what keeps the mirror's upstream access, `check-config` and `configure` (D66) agreeing with CRI-O on every file; D66's list of paths was a summary, and the code is the source of truth.
  - A library's own checks decide whether CRI-O starts a pull at all: porting them, rather than reading with a looser TOML parser, lets `check-config` fail where CRI-O would.
  - Aliases need the reference grammar, which step 02 ports; they matter to short names only.
- **Measured (M2 step 01, arm64, Docker):** the differential tests send the oracle's `registries`, `certs` and `auth` subcommands 3796, 17 and 834 cases (the test data of go.podman.io/image v5.40.0, 100 mutations of each, layouts of the search directories, the e2e CRI-O node's files with and without an admin drop-in), and every case with a stable answer agrees: 3796 of 3796, 17 of 17, 791 of 834 (the rest has two entries for one registry, which the library picks from by map order). The 3796 `registries` cases include the e2e node's drop-in and the five registries of Done when (docker.io, registry.k8s.io, quay.io, ghcr.io, a private test registry). The first full run found one divergence, now fixed: a prefix `*foo.com` is a plain prefix, only `*.` makes a wildcard. `just fuzz registries_conf 60` ran 513294 execs and `just fuzz auth_json 60` 695838, with no finding.
- **Revisit when:** the agent follows a CRI-O that sets `registries_conf` or the environment variables, or short names matter (step 02's reference parser then lets aliases be checked).

## D24: Peers apply backpressure

- **Decision:** the peer API serves at most `peer.max_uploads` concurrent blob bodies (default: 4 × CPUs). Beyond that it answers `503` at once, and the fetcher treats `503` as a fast failure and moves to the next peer.
- **Because:** in a flash crowd every node finds the same first seed; Spegel has no limit, so one node's uplink becomes the cluster bottleneck.
- **Revisit when:** a flash-crowd benchmark shows one seed peer saturating. Then add multi-peer `Range` swarming.

## D36: The peer address is the local side of the reflector connection (amends D3; amended by D56)

- **Decision:**
  - By default, an agent announces as its peer address the local IP of its `Announce` stream to a member, as returned by `getsockname`, and listens on that IP, port 7481. The address is fixed at startup from the first such stream; the peer API starts listening only then. The load-balancer connection is never used: on a control-plane node that holds the load balancer's virtual IP, its local IP would be that VIP, which moves.
  - `peer.address` (`ip:port`, D56) overrides it, for nodes where peers must use another interface.
  - IPv4 and IPv6 work the same way; on a dual-stack node, the family is the one the reflector connection used.
- **Because:**
  - That IP is the one the cluster routes through to reach the control plane, which is the best guess on multi-NIC nodes without asking the admin.
  - Peers check each other by the node name in the certificate (D16), never by IP, so a wrong guess fails as an unreachable peer, which falls through, never as a trust problem.
- **Revisit when:** users report an interface the guess gets wrong on a common platform; then add that platform's rule.

## D52: A peer that sends a wrong digest is denied locally (amends D7, D37)

- **Decision:** on a digest mismatch (D7), the agent:
  1. aborts the fetch, counts `speculaire_peer_fetches_total{result="digest_mismatch"}`, and resumes from the next peer;
  2. skips that node identity in its own lookups for `peer.deny_ttl` (default 10 min, live);
  3. logs a warning and, with the audit on, writes a `peer` audit event (D37).

  Nothing is sent to the reflector.
- **Because:**
  - D2 has no reflector message for it, and one would let any node evict another from the whole cluster.
  - The bad peer gains nothing either way (*withhold, never forge*); the denial only saves the requester repeated wasted fetches.
  - A TTL bounds the cost of a false positive, such as a disk fault that is later fixed.
- **Revisit when:** mismatches from one node show up on many requesters; then add a reflector-side report with a quorum.

## D56: `mirror.address` and `peer.address` are `ip:port` settings (amends D14, D32, D36, D47)

- **Decision:**
  - `mirror.address = "127.0.0.1:7480"`, a restart key (D47). Startup refuses an address that is not loopback. After changing it, the admin runs `speculaire configure` again, then restarts the agent.
  - `peer.address = "auto"`, or an `ip:port`. `"auto"` is the IP of D36 on port 7481.
  - `configure` and `unconfigure` recognise their `hosts.toml` entries by the `ca` path under `/var/lib/speculaire/mirror/`, not by address. `configure` rewrites the address of an entry it recognises to the current `mirror.address`.
- **Because:**
  - A port taken on a node needs a way out without a new build.
  - Entries recognised by address are lost once the address changes. `unconfigure` would then leave them in place and delete their certificates, and containerd fails every pull for a registry whose `hosts.toml` names a missing `ca` (D14, D32).
  - Loopback keeps D14's boundary: only local processes reach the mirror, and the client certificate stops them.
  - It has the same form as `metrics.address` and `reflector.listen`.
- **Revisit when:** —

## D66: On CRI-O, a `registries.conf.d` drop-in sends every pull to the mirror, which resolves tags upstream (amends D6, D14, D17, D22, D32; amended by D80)

- **Decision:**
  - `speculaire configure` writes `/etc/containers/registries.conf.d/99-speculaire.conf`. For each registry it mirrors, the file holds one `[[registry]]` that copies the admin's effective entry for that prefix (`location`, `insecure`, `blocked`, its mirrors) and puts first `[[registry.mirror]] location = "<mirror.address>/<registry host>"` with `pull-from-mirror = "all"`.
  - It writes the mirror's `ca.crt`, `client.cert` and `client.key` to `/etc/containers/certs.d/<mirror.address>/`, each by temporary file and rename (D55).
  - After writing or removing the drop-in, `configure` and `unconfigure` run `systemctl reload crio`. `unconfigure` removes the drop-in, reloads, then deletes the certificates (D32). Both recognise their files by path.
  - `check-config` exits 1 when a mirrored registry's effective entry, after every drop-in, lacks the mirror first or differs from the admin's entry in another field. `configure` rewrites it.
  - The mirror answers `GET /v2/` with 200, and never answers 401.
  - A manifest request by tag: the mirror resolves the tag itself at upstream, with the node's registry config, never from peers (D6). It then serves that manifest, and the manifests and blobs below it, from peers or upstream. When it cannot resolve the tag, for example because upstream answers 401 to an image that needs a pod pull secret, it answers 404, and CRI-O pulls the whole image from upstream.
  - Once the mirror has served a manifest, it serves every blob below it, from peers, then upstream.
  - Upstream access on CRI-O (D17) reads `/etc/containers/registries.conf` and its drop-ins, skipping its own; per-host certificates in `/etc/containers/certs.d/`, then `/etc/docker/certs.d/`; and credentials from `global_auth_file`, else the files go.podman.io/image reads for root, starting with `/run/containers/0/auth.json`.
  - Verification starts when the mirror resolves a tag or serves a manifest (D22).
- **Because:**
  - CRI-O takes the manifest and every blob of an image from the first source that serves the manifest (go.podman.io/image v5.40.0 `docker/docker_image_src.go:56-165`). It has no per-request fallback like containerd's `hosts.toml`.
  - A later `[[registry]]` with the same prefix replaces an earlier one whole, and drop-ins load in file-name order (v5.40.0 `pkg/sysregistriesv2/system_registries_v2.go:933-942`). Hence the late name and the copied fields.
  - CRI-O reads drop-ins only on SIGHUP: `auto_reload_registries` is false by default in 1.35, 1.36 and 1.37 (v1.37.2 `pkg/config/config.go:769-772`, watcher `server/server.go:1193-1245`).
  - go.podman.io/image searches `certs.d` directories for each new client (`docker/docker_client.go:150-193`).
  - Resolving tags at upstream keeps D6's guarantee: no peer can answer a tag.
  - **Measured** (CRI-O spike 03, M0b, CRI-O 1.35.10, 1.36.7 and 1.37.2, locally on arm64 and in CI run 43021182508 on amd64 and arm64):
    - With `pull-from-mirror = "all"`, `crictl pull` and a kubelet pod by tag sent the mirror `GET /v2/`, then `GET /v2/docker.io/library/busybox/manifests/1.37`, the tag, with the client certificate. On a 404 the whole pull went upstream and succeeded.
    - With `digest-only`, a pull by tag sent the mirror nothing, and a pull by digest sent it the manifest by digest. Kubelet pulls most images by tag, so `digest-only` would bypass the mirror for them.
    - A mirror holding the index by tag, the platform manifest, the config and the layer served all four, and CRI-O fetched nothing upstream. A blob already in CRI-O's storage was not requested.
    - A mirror holding all but the layer failed the pull: `reading blob sha256:…: fetching blob: StatusCode: 404`.
    - A client without a certificate failed the handshake (`peer sent no certificates`).
    - Regenerated certificates were used by the next pull, with no reload of CRI-O.
    - A drop-in written without reload changed nothing. After `systemctl reload crio`, the journal logged `Applied new registry configuration` and pulls went to the mirror. After removal and reload, they did not.
    - With `crictl pull --creds`, CRI-O sent the mirror no `Authorization` header. After a 401 with a Basic challenge, it sent those credentials, meant for `docker.io`, to the mirror as Basic.
    - Neither the drop-in with an empty mirror nor a stopped mirror (connection refused) cost more than the noise of pulling from Docker Hub. Median of three pulls of `busybox:1.37`, without the drop-in, with an empty mirror, with the mirror stopped: 1520, 1482 and 1525 ms locally; within 65 ms of each other on every leg of the CI run. Earlier CI runs scattered by up to 760 ms either way.
- **Cost:** on CRI-O the agent sits in the path of every pull from a mirrored registry, and relays what it fetches from upstream. When it is down, CRI-O pulls from upstream.
- **Revisit when:** CRI-O gains a per-blob fallback across sources.

## D67: On CRI-O, the agent serves from its own blob cache, which the mirror fills (amends D5, D7)

- **Decision:**
  - On CRI-O, the *blob cache* `/var/lib/speculaire/blobs/` replaces D5's content directory. It holds, by digest, every manifest and blob the mirror served to CRI-O. The peer API and the mirror read from it.
  - The mirror fills it with what it fetches for CRI-O, from peers or upstream (D66). It streams each blob to CRI-O and to a temporary file at once while hashing it (D7), and holds back the last chunk until the digest matches. On a match it sends the chunk and keeps the file by rename. On a mismatch it deletes the file and closes the connection without the chunk, so CRI-O never receives a whole wrong blob, then treats the peer as D52 says.
  - A `Range` request for a blob the cache holds is served from the file. Any other `Range` request is relayed unhashed, as on containerd (D7's limit).
  - `blob_cache.max_size` (default `"20GiB"`, live) bounds it. Above the bound, the agent evicts the least recently served blobs first, and the blobs of images in CRI-O's image list (D65) last.
  - The agent announces each digest it keeps and withdraws each digest it evicts. At startup it deletes leftover temporary files and announces the rest.
  - `peer.max_uploads` (D24) bounds uploads from the cache as it does from containerd's content directory.
- **Because:**
  - CRI-O keeps no compressed blob: a layer keeps its compressed digest and size, and a tar-split of its uncompressed diff (go.podman.io/storage v1.63.0 `layers.go`). Peers need the compressed bytes, by digest.
  - Filling while serving costs CRI-O's pull nothing and fetches each blob once. Fetching again after CRI-O's pull would double upstream traffic.
  - go.podman.io/image resumes a short body with `Range: bytes=<offset>-`, and fails when the answer is not a matching `206` (v5.40.0 `docker/body_reader.go:139-190`). A wrong blob then ends in a failed pull, which kubelet retries with back-off, and D52 sends the retry to another peer.
  - **Measured** (CRI-O spike 04, M0b, CRI-O 1.35.10, 1.36.7 and 1.37.2, 1.37.2 locally on arm64 and all three in CI run 43032258229 on amd64 and arm64):
    - After a direct pull of `nginx:alpine` (8 layers, 26.3 MB compressed, 64.0 MB unpacked), no file in `/var/lib/containers/storage` of a layer's compressed size had its digest.
    - Two cold pulls each, direct, then through a proxying mirror with an empty cache. Locally: 2219 and 2023 ms direct, 2080 and 2017 ms proxied; CRI-O CPU 420 and 410 ms direct, 390 and 390 ms proxied; mirror CPU 250 and 240 ms. In CI, proxying added 20 to 560 ms to a pull of 1.0 to 1.9 s, CRI-O CPU did not grow, and the mirror used 260 to 460 ms of CPU. A warm pull from the cache took 603 ms locally and 703 to 1034 ms in CI. The cache held 26.3 MB: the layers, the config and two manifests.
    - Early CI runs stalled at the end of a response until the mirror flushed its TLS stream after each one: tokio-rustls 0.26.6 returns from a write with the tail still buffered when the socket is full (`src/common/mod.rs:278-312`).
    - A second node, whose mirror took the first node's mirror as its upstream over mTLS, pulled the image; the first node served every request from its cache and fetched nothing.
    - With the mirror flipping a byte of each blob, it kept nothing, and the pull failed: `parsing image configuration: unexpected EOF (after reconnecting, server did not process a Range: header, status 200)`. CRI-O had asked for the config blob twice.
- **Cost:** up to `blob_cache.max_size` of disk on each CRI-O node, on top of CRI-O's own storage, and 10 to 18 ms of agent CPU per MB proxied.
- **Revisit when:** CRI-O or go.podman.io/storage keeps compressed blobs.

## D73: A stalled peer fetch moves to the next peer (amends D7)

- **Decision:**
  - A peer fetch that receives no bytes for `peer.stall_timeout` (default `"5s"`, live) is aborted and counts `speculaire_peer_fetches_total{result="timeout"}`. The timer restarts with every chunk received, and covers the wait for the response's headers.
  - The agent then resumes from the next peer with `Range`, as for a peer that dies mid-copy, or falls through when no peer is left.
  - The stalled peer is not denied: D52 denies only a wrong digest, and a slow node may be busy rather than bad.
- **Because:**
  - A peer that keeps its connection open and sends nothing would otherwise hold the runtime's pull until its own timeout, which neither containerd nor CRI-O sets per blob.
  - A timer on silence, not on the whole transfer, does not penalise a large layer coming at a steady rate.
- **Revisit when:** M3's suite, which stalls a serving node with `tc qdisc … netem`, shows 5 s too short for a loaded node or too long for a pull.
