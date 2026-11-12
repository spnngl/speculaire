# To decide

Open questions, each with a proposed default. Once a question is answered, record the answer as a decision (`docs/decisions/README.md`) and delete the question.

## Before M5

- **Do identity regexes match the whole string?** D8 makes regex identity matching ours, and no decision says whether a policy's `subjectRegExp` and `issuerRegExp` must cover the whole SAN and issuer. Rust's `Regex::is_match`, like Go's `MatchString` in policy-controller and cosign, matches a substring, so `https://github.com/myorg/` also matches `https://github.com/myorg-evil/`. [Each regex is compiled as `^(?:…)$`, so it matches the whole string. A policy ported from policy-controller can only become stricter, and `docs/operations.md` says so. Amends D11.]

## Before M7

- **When does a member release the rest of a prewarm wave?** D51 sends `Prewarm` to the other agents "once the seeds have announced the image's blobs", but a member knows only the image reference, not its blob digests. [The member resolves each `prewarm.images` entry through the registry config (D17) to its platform manifests and their layer digests, and releases the wave once every seed has announced every layer of its platform, or after `prewarm.seed_timeout` (default `"5m"`, live), whichever comes first. Amends D51.]
