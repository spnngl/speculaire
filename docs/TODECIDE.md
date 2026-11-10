# To decide

Open questions, each with a proposed default. Once a question is answered, record the answer as a decision (`docs/decisions/README.md`) and delete the question.

## Before M7

- **When does a member release the rest of a prewarm wave?** D51 sends `Prewarm` to the other agents "once the seeds have announced the image's blobs", but a member knows only the image reference, not its blob digests. [The member resolves each `prewarm.images` entry through the registry config (D17) to its platform manifests and their layer digests, and releases the wave once every seed has announced every layer of its platform, or after `prewarm.seed_timeout` (default `"5m"`, live), whichever comes first. Amends D51.]
