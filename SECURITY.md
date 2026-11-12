# Security policy

## Reporting a vulnerability

Report vulnerabilities privately through [GitHub private vulnerability reporting](https://github.com/spnngl/speculaire/security/advisories/new). Do not open a public issue.

Include the version, the runtime (containerd or CRI-O) and its version, and the steps or input that trigger the problem. You will get a reply on the advisory, and credit in it unless you ask otherwise.

In scope: any way to start a container that the policy should reject, to make a node serve or accept content that does not match its digest, to read content without a node identity, or to read secrets from logs or metrics. The trust boundaries and the risks we accept are in [`docs/security.md`](docs/security.md); an accepted risk listed there is not a vulnerability.

## Supported versions

Only the latest minor release gets fixes, security fixes included (D40 in [`docs/decisions/build.md`](docs/decisions/build.md)). No release exists yet.
