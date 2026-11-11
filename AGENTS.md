# Spéculaire

A P2P image mirror and supply-chain gate for the CRI runtimes containerd and CRI-O, in Rust. Write the ASCII `speculaire` wherever "é" is not allowed: code, packages, units, metrics. [`ARCHITECTURE.md`](ARCHITECTURE.md) holds the scope, the vocabulary, the flows and the layout. [`REFERENCES.md`](REFERENCES.md) lists the research notes and upstream code to read before working in each area.

Before any task, read the decisions' index, `docs/decisions/README.md`, then the topic files the task touches. Record a new or changed decision in the same change as the code, in its topic file and in the index, following the index's rules. Open questions go to `docs/TODECIDE.md`.

`plan/` is local and git-ignored. It holds the milestones and their criteria. Read `plan/PLAN.md` when it is present. Anything worth keeping goes to `docs/` or to the files above.

## Rules

- Use the words in ARCHITECTURE.md § Vocabulary with exactly that meaning, in code, docs, metric names and commits.
- Write Rust per the `rs-coding` skill. Write agent-facing documents per the `writing-for-agents` skill: small, concise, one source of truth. Each `AGENTS.md` has a `CLAUDE.md` symlink beside it.
- Cite upstream behaviour as file:line in a clone at a named version (REFERENCES.md).
- Every parser of outside data gets a fuzz target. Outside data includes runtime config (containerd's, CRI-O's and `registries.conf`), NRI frames, registry responses, Sigstore bundles and peer protobuf.
- A change that moves a trust boundary updates `docs/security.md` in the same change.
- Hold credentials and tokens in `secrecy::SecretString`, and never log headers (D37). A new audit field goes in D37's event list.
- A change that could slow pulls runs `just bench` against Spegel before its minor release (D35).
- A breaking change, as D40 defines it, is marked `!` in its commit subject.
- A new setting goes in `packaging/config.toml` with its default (D30). A new metric goes in `docs/metrics.md`, under the label rules of D34. A new rejection reason or alert goes in `docs/operations.md`.
- Code ported from another project starts with a comment naming the upstream file and tag, and the first port from a project adds its copyright to `NOTICE` (D25).
- A change is done when `just check` (the check, D27, D48) passes.
- Commit with the `git-commit` skill, using Conventional Commit subjects (`type(scope)!: description`).
