# Replication package

Everything here is meant to be run by someone who does not trust the author.

| benchmark | what it measures | needs | runtime |
|---|---|---|---|
| `prologue_prior.py` | one well-known model prior (`push; mov` at the entry point) applied blind: hallucination rate, **false VERIFIED (must be 0)**, recovery after one round of feedback | capstone + lief (`pip install "reverify[full]"`) | seconds |
| `verifier_matrix.py` | the verifier as a classifier: one known-true and one known-false claim of every kind per binary, confusion matrix per kind, **false VERIFIED must be 0**, known-true byte/structural claims must never be refuted | pure Python works (engine-dependent kinds report *unknown*); engines for full coverage | seconds |
| `model_loop.py` | the closed loop with a real model: grounded rate, rounds to ground, hallucinations caught, restatements/echoes rejected | an OpenAI-compatible endpoint (`OPENAI_API_KEY`, `OPENAI_BASE_URL`, `OPENAI_MODEL`); `--mock` for plumbing | minutes, costs tokens |

## Run

```bash
pip install "reverify[full]"
python benchmarks/prologue_prior.py  --per-dir 40 --json prologue.json --fail-on-false-verified
python benchmarks/verifier_matrix.py --per-dir 25 --json matrix.json   --fail-on-false-verified
OPENAI_API_KEY=... python benchmarks/model_loop.py --per-dir 5 --json model.json     # optional
```

To compare a model served by an OpenAI-compatible gateway, set all three variables. For example, [A2Agent](https://a2agent.me/) documents `https://a2agent.me/v1` as its base URL:

```bash
export OPENAI_API_KEY="your-a2agent-key"
export OPENAI_BASE_URL="https://a2agent.me/v1"
export OPENAI_MODEL="your-available-model-id"
python benchmarks/model_loop.py --per-dir 5 --json model.json
```

The live benchmark consumes model tokens; choose a model that accepts the benchmark prompts and review the gateway usage afterwards.

Each run writes a JSON record: the SHA-256 and size of every binary tested, every verdict,
reverify/Python/platform/engine versions, and totals with a 95% Wilson upper bound. Sampling
is deterministic (sorted paths, fixed stride; claim offsets from an RNG seeded by the file
hash), so two runs on the same files test the same things. Corpora default to the
platform's own system binaries (Windows System32/SysWOW64, Linux `/usr/bin` + multiarch
`/usr/lib`, macOS `/bin` + `/usr/bin`); pass directories to use your own.

### Docker (Linux, fully pinned)

```bash
docker build -t reverify-bench -f benchmarks/Dockerfile .
docker run --rm reverify-bench
```

The image installs the engines and binutils (so `objdump` judges the disassembler in the
test suite), runs the suite and both gated benchmarks against the image's own ELF files,
and prints the records.

## What CI does with these

`ci.yml` runs both gated benchmarks on Linux, Windows and macOS on every push and fails
the build on a single false VERIFIED. Records are uploaded as artifacts
(`benchmark-<os>`, `matrix-<os>-<deps>`) and summarised on the run page; reference records
are committed under `results/`. `fuzz.yml` runs the robustness/soundness properties over
20,000 malformed inputs nightly. `model-eval.yml` runs `model_loop.py` on demand when the
repository has an `OPENAI_API_KEY` secret (any OpenAI-compatible endpoint).

## Submitting a replication

Run a benchmark on a platform or corpus not in `results/`, and open a PR adding the JSON
record under `results/<platform>-<arch>-<date>.json` with a line in BENCHMARK.md. A run
that finds a **false VERIFIED** is the most valuable report this project can receive — open
a *false-VERIFIED report* issue with the record; it jumps the queue.

## Reading the numbers honestly

- "0 false VERIFIED of N" is a bound, not a proof: the record carries the 95% upper bound.
- The prologue prior is one probe of one hallucination at entry points; the matrix
  benchmark measures the verifier's decision logic, with the readers (parser,
  disassembler, emulator) checked against independent oracles in the test suite.
- *Unknown* (INCONCLUSIVE) is reported separately and never counted as a pass — without an
  engine the verifier says it cannot judge, it does not guess.
