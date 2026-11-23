# To decide

Open questions, each with a proposed default. Once a question is answered, record the answer as a decision (`docs/decisions/README.md`) and delete the question.

## Before D198 is built

- **Does the agent answer `fail_request = true` in `audit` mode?** D198 makes a call that fails or times out on the agent reject the creation. In `audit` mode, the default, the gate allows every container (D54), so a stalled agent would reject what its own answer would have allowed. The mode is a live key (D47), and NRI reads the failure policy only at `Configure` (v0.12.4 `pkg/adaptation/plugin.go:502`). [Only in `enforce`: a reload that changes the mode registers the agent with NRI again. Amends D54, D198.]
