# To decide

Open questions, each with a proposed default. Once a question is answered, record the answer as a decision (`docs/decisions/README.md`) and delete the question.

## Reflector memory

- **What is D33's memory goal?** D33 aims at 256 MiB for one reflector at its load. With D202 and D203 the peak is 363–366 MiB under D46's allocator, of which about 239 MB is heap (`docs/research/reflector-memory.md`). What is left: secure mode's padding and size classes, about 90 MiB; rustls's 4 KiB read buffer per connection, about 50 MiB, which only its unbuffered API or kernel TLS avoids; `Key` inline in the index, about 16 MB. musl's mallocng reaches 275–279 MiB, stops more heap attacks than secure mimalloc (dedens D152), but runs slower, and its resync took 91.7 s, beyond D33's 60 s, in one of two runs. [Goal 384 MiB, D46's allocator kept; the rustls rewrite only if the reflector must fit 256 MiB. Amends D33.]