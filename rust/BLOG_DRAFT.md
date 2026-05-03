# Regipy Goes Rust: Opt-In Native Acceleration for Registry Forensics

> Draft — first person, in Martin's voice. ~900 words.

---

Six years ago, I started writing regipy because I was tired of waiting for
Windows to be available just to look inside a hive. Two years ago, I added
plugins. Last year, I added an MCP server so investigators could ask
questions in plain English instead of remembering plugin names. The throughline
has been the same the whole time: **make registry forensics quick to reach
for.**

There's been one nagging exception. When you point regipy at a 36 MB
`SOFTWARE` hive and ask it to walk every key and pull every value — for
example, to build a full timeline, or feed an LLM context window — it can
take *minutes*. Not because there's something fundamentally slow about
parsing REGF, but because parsing every single NK and VK record through
Python's `construct` library means allocating thousands of `Container`
objects per hive. The work is real, the per-object overhead is unavoidable
in pure Python.

I've been chipping away at this for a while. This week I decided to actually
benchmark how bad it is — and try a fix.

## The numbers, before anything else

I wrote a small Rust crate that parses REGF the same way regipy does (NK,
VK, lf/lh/li/ri lists, big data blocks), and walked all four of regipy's
test hives recursively. Then I measured the same walk in current Python
regipy.

| Hive | Pure Python regipy | Rust core | Speedup |
|------|-------------------:|----------:|--------:|
| NTUSER.DAT (768 KB) | 159 ms | 0.23 ms | **688×** |
| amcache.hve (2 MB) | 755 ms | 0.37 ms | **2,068×** |
| SYSTEM (11.7 MB) | 43 s* | 2.06 ms | **20,850×** |
| SOFTWARE (36 MB) | >100 s | 9.44 ms | **>10,000×** |

\* SYSTEM/values had wild Python variance — probably GC pressure during
   value decoding. Even taking the *fastest* Python run, it's 7.15 seconds.

That number doesn't lie, but it also doesn't tell you the right story for
a Python tool. The right story is: how fast does it get when you call the
Rust parser **from Python**, with all the regipy plugins still on top?

I added PyO3 bindings that yield one Python dict per visited key. Same walk,
same data, but the parser is Rust under the hood:

| Hive | Python regipy | Python via Rust (PyO3) | Speedup |
|------|--------------:|-----------------------:|--------:|
| NTUSER.DAT | 159 ms | 1.8 ms | **87×** |
| amcache.hve | 755 ms | 5.1 ms | **148×** |
| SYSTEM | 43 s | 31 ms | **1,371×** |
| SOFTWARE | >100 s | 110 ms | **>900×** |

Plugins that filter early — which is most of them — stay within a few
percent of native Rust speed, because they never materialize a Python
object for keys they don't care about. The boundary cost is ~0.4
microseconds per Python dict you actually create.

I'm not going to pretend I expected the values gap to be three orders of
magnitude on SYSTEM. The construct overhead is just that real on hives
where every walk touches tens of thousands of records.

## The plan: opt-in, not breaking

Before anyone asks: **`pip install regipy` is not changing.** Pure Python
regipy keeps working everywhere — Linux, macOS, Windows, weird Synology
NASes, your forensics workstation that hasn't been updated since 2021. No
Rust toolchain required, no platform-specific wheels to fight with, no
risk of breaking your environment.

The Rust acceleration ships as a separate wheel, `regipy-rs`, pulled in by
an extras flag:

```bash
# Same as before, no changes
pip install regipy

# New: same regipy, but with native parsing
pip install regipy[fast]
```

When `regipy[fast]` is installed, `regipy.registry.RegistryHive` quietly
becomes Rust-backed. Same class name, same dataclass shapes, same plugin
API. Every plugin in the repo continues to work without modification. The
MCP server gets the speedup for free.

When it isn't installed, regipy falls back to the construct-based parser
exactly as it does today. Plugins don't care which one is running.

This is the same model `cryptography`, `pydantic-core`, and `tokenizers`
use. It works because of two things:

1. **abi3 wheels.** A single Linux/macOS/Windows wheel per architecture
   covers Python 3.8 through whatever ships next year. We don't need to
   rebuild on every CPython release.
2. **A compatibility test matrix.** The existing pytest suite runs against
   *both* backends in CI. Anything that diverges blocks the merge.

I've already validated path-by-path equivalence on all four test hives —
152,161 keys, 288,959 values, every single (path, values_count) tuple
identical between the two implementations. That's the floor for shipping;
proper plugin parity testing is next.

## What's actually built right now

The proof of concept is in the `rust/` directory of the regipy repo, on
the `rust-poc` branch:

- `regipy-core` — REGF parser, hbin/cell walk, NK/VK records, lf/lh/li/ri.
  About 440 lines of Rust.
- `regipy-py` — PyO3 bindings exposing `RegistryHive`, `recurse_subkeys()`,
  `walk_stats()`.
- A bench harness comparing the three paths on real hives.

Out of scope for the POC, but on the path: transaction log replay, security
descriptors, big-data block reassembly with full type decoding (REG_SZ,
REG_DWORD, REG_MULTI_SZ, REG_FILETIME, etc.), and the regdiff backend.
The POC reads value bytes raw; full type decoding is the next milestone.

If you want to try it, clone the repo and run `cargo build --release` in
`rust/`, then `maturin develop --release` in `rust/regipy-py/` inside your
regipy venv. There's a `bench_pyo3.py` in the same directory that
reproduces all the numbers above.

I'm interested in hearing from anyone who has a hive where this *doesn't*
match Python regipy's output — the parser is wide enough to cover the
test set, but the test set isn't infinite. PRs welcome, as always. Bug
reports especially welcome on the `rust-poc` branch.

The point of regipy was never the parser. It was that registry forensics
should feel quick to reach for. Making it 100× faster means it stays
quick to reach for on the hives that actually show up in incidents — not
just the ones that fit in a tutorial.

---

GitHub: [github.com/mkorman90/regipy](https://github.com/mkorman90/regipy)
(branch: `rust-poc`)
