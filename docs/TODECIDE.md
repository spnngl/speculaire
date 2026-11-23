# To decide

Open questions, each with a proposed default. Once a question is answered, record the answer as a decision (`docs/decisions/README.md`) and delete the question.

## Before D198 is built

- **Does the agent answer `fail_request = true` in `audit` mode?** D198 makes a call that fails or times out on the agent reject the creation. In `audit` mode, the default, the gate allows every container (D54), so a stalled agent would reject what its own answer would have allowed. The mode is a live key (D47), and NRI reads the failure policy only at `Configure` (v0.12.4 `pkg/adaptation/plugin.go:502`). [Only in `enforce`: a reload that changes the mode registers the agent with NRI again. Amends D54, D198.]

## Reflector memory

- **What is D33's memory goal?** D33 aims at 256 MiB for one reflector at its load. With D202 and D203 the peak is 363–366 MiB under D46's allocator, of which about 239 MB is heap (`docs/research/reflector-memory.md`). What is left: secure mode's padding and size classes, about 90 MiB; rustls's 4 KiB read buffer per connection, about 50 MiB, which only its unbuffered API or kernel TLS avoids; `Key` inline in the index, about 16 MB. musl's mallocng reaches 275–279 MiB, stops more heap attacks than secure mimalloc (dedens D152), but runs slower, and its resync took 91.7 s, beyond D33's 60 s, in one of two runs. [Goal 384 MiB, D46's allocator kept; the rustls rewrite only if the reflector must fit 256 MiB. Amends D33.]
