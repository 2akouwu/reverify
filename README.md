<h1 align="center">Reverify</h1>

<p align="center">
  <strong>Stop your AI from making things up.</strong><br>
  It proposes; deterministic tools check every claim against ground truth, and only what's verified counts.
</p>

<p align="center">
  <a href="https://pypi.org/project/reverify/"><img src="https://img.shields.io/pypi/v/reverify?color=3fb950" alt="PyPI"></a>
  <img src="https://img.shields.io/pypi/pyversions/reverify" alt="Python">
  <a href="https://github.com/2akouwu/reverify/actions/workflows/ci.yml"><img src="https://github.com/2akouwu/reverify/actions/workflows/ci.yml/badge.svg" alt="CI"></a>
  <a href="https://codecov.io/gh/2akouwu/reverify"><img src="https://codecov.io/gh/2akouwu/reverify/graph/badge.svg" alt="Coverage"></a>
  <a href="https://scorecard.dev/viewer/?uri=github.com/2akouwu/reverify"><img src="https://api.scorecard.dev/projects/github.com/2akouwu/reverify/badge" alt="OpenSSF Scorecard"></a>
  <a href="LICENSE"><img src="https://img.shields.io/github/license/2akouwu/reverify" alt="MIT"></a>
  <img src="https://img.shields.io/github/stars/2akouwu/reverify?style=social" alt="Stars">
</p>

<p align="center">
  <a href="https://app.ona.com/#https://github.com/2akouwu/reverify">
    <img src="https://ona.com/build-with-ona.svg" alt="Build with Ona" />
  </a>
</p>

AI is confident and often wrong: it invents an API, a struct field, an offset, or what a
function does, and says it like fact. Reverify makes a deterministic tool the judge — the model
proposes a claim, the tool checks it against the actual artifact, and it comes back **VERIFIED /
REFUTED with evidence**. The model never gets to assert a fact on its own.

Two things it does today:

- **Keeps your AI honest** — every structural or behavioral claim is checked against ground
  truth, not trusted, and only what survives becomes a fact (`reverify verify`, or the MCP
  server your agent already talks to).
- **Keeps your AI's context from rotting** — instead of a lossy auto-summary, `reverify rollover`
  hands the session off to a file and starts a fresh one, so long tasks don't drift or need
  `/clear`. Works in Claude Code, Codex, Gemini CLI and OpenCode.

The hardest place to prove the first point is binary reverse engineering, where hallucination is
worst — so that's where the numbers come from. On 71 real Windows system files the AI's textbook
answer was wrong **97% of the time**; reverify caught every one and **never accepted a wrong
claim** (0 of 71; the same gate runs in CI on Linux and macOS every push, and an independent
aarch64 run found the same) ([EXAMPLE.md](EXAMPLE.md), [BENCHMARK.md](BENCHMARK.md);
`python benchmarks/prologue_prior.py`).

<p align="center">
  <img src="docs/demo.svg" alt="Reverify catches the model's hallucinated prologue on kernel32.dll, then verifies the corrected claim" width="760">
</p>

## The problem

Language models are great at reading code and unreliable at reverse engineering. Ask a
model to reconstruct a struct or an algorithm from a binary and it will confidently invent
offsets, sizes, and behavior. In binary analysis this hallucination problem is far worse
than in source code, and *"did the model just make that up?"* is the single biggest blocker
to using AI for real RE.

## What Reverify does

Reverify pairs a language model with a **deterministic, pure-Python RE toolkit** and makes the
toolkit the judge. The model proposes; the tools verify. A hypothesis about a structure or an
algorithm is only reported once it has been **checked against the actual bytes** — disassembled,
pattern-matched, or executed in the emulator — so the output is grounded in the binary instead
of the model's imagination.

- **Deterministic core** — PE/ELF/Mach-O parsing, x86/x64/ARM/ARM64 disassembly, AOB pattern
  scanning, CPU emulation, Protobuf/TLV dissection, Frida hook generation. Pure Python out of
  the box; installs clean with no Ghidra.
- **Mature engines, optional** — with `pip install "reverify[full]"` the toolkit upgrades
  itself in place to **capstone** (disassembly), **unicorn** (real CPU emulation), **lief**
  (PE/ELF/Mach-O) and **Z3** (proofs); `pip install "reverify[angr]"` adds **angr** for
  function boundaries, the call graph and cross-references. Not installed? It falls back to
  the pure-Python core. `reverify backends` shows what's active.
- **Grounded, not guessed** — structural claims are verified against the binary by the tools.
- **Not only binaries** — `reverify equiv <reference> <candidate> --lang python` (or C) runs a
  candidate implementation and a reference over shared inputs and checks they agree, so an AI's
  rewrite or refactor is *tested, not trusted* — a refutation comes back with the input and both
  outputs. The same rigour, aimed at ordinary source code.
- **Agent-native** — ships as an MCP server, so Claude Code, Cursor, and other agents can call
  the tools directly; also a plain CLI.

> Reverify is for **authorized** reverse engineering — malware analysis, CTF, interoperability
> research, and software you own or are permitted to analyze. See [SECURITY.md](SECURITY.md).

## Quick start

```bash
# Install the CLI + MCP server from PyPI:
pip install reverify        # pure-Python core; or "reverify[full]" for capstone+unicorn+lief
reverify auto sample.bin --json

# Or run straight from a checkout — pure standard library, nothing to install:
python reverify/cli.py auto sample.bin --json
python reverify/cli.py parse-pe sample.exe --json
python reverify/cli.py disasm 90505831C0C3 --arch x86_64
```

## The verification loop

This is what the name is about. A **claim** is any hypothesis about the binary; the
deterministic tools are the judge and hand back `VERIFIED`, `REFUTED`, or
`INCONCLUSIVE` together with the bytes they actually observed:

```bash
reverify verify sample.bin --claim '{
  "kind": "instructions", "offset": 4096,
  "mnemonics": ["push", "mov", "sub"], "note": "function prologue"
}'
```

```bash
# Check a reconstructed routine actually computes what the model claimed:
reverify verify - --claim '{
  "kind": "emulate_result", "code": "b805000000b90300000001c8c3",
  "arch": "x86", "expect_registers": {"eax": 8}
}'
```

Claims can be batched from a JSON file (`--claims-file claims.json`); the CLI exits
non-zero if **anything** is refuted, so an agent or CI job can gate on a grounded
reconstruction. Claim kinds: `bytes_at`, `u16_at` / `u32_at` / `u64_at` (typed reads, no
endianness math), `pattern_present`, `string_present`, `instructions` (mnemonics and
optionally operands), `emulate_result`, `behavior_equiv`, `prove_equiv`, `protobuf_field`,
`import_present`, `export_present`, `section_present`, and the semantic kinds
`function_at`, `calls`, `references`, `reachable_from_entry` (see
[The semantic layer](#the-semantic-layer-functions-calls-and-cross-references)). Offsets are file offsets unless a claim says
`"space": "rva"` or `"va"`; the verifier translates through the section table and echoes
all three addresses in the evidence, and a refuted `bytes_at` reports where the expected
bytes actually are. Set `"observe": true` (or omit `expected`) to have the tools *read* a
value instead of asserting one, and `"depends_on": [...]` so a refuted root invalidates
the claims built on it.

### Grounded means *informative*, not just "nothing refuted"

"Every claim verified" is trivially reachable: assert that the file starts with `MZ` and
that `.text` exists. So Reverify also weighs how much a verified set actually says. Each
result carries a `weight` — zero for claims that merely restate the fact sheet the model was
shown, for duplicates, for inline code/data that does not occur in the binary
(self-referential), and for echoes of the tools' own previous output; otherwise it is
**measured from the binary itself** — how often the expected content occurs in this file and
how much entropy it has — so zero padding, a ubiquitous prologue, or a pattern that matches
everywhere weigh almost nothing even though they verify, and emulation must actually execute
non-degenerate code. A reconstruction is **grounded** only when nothing
is refuted *and* the verified weight reaches `--min-information` (default 1.0). This follows
the CORE refinement of FActScore: credit only claims that are factual, informative and
non-repetitive. `reverify reconstruct --samples N` draws several proposals per round and
lets the verifier — not the model's confidence — select among them.

[EXAMPLE.md](EXAMPLE.md) walks through one run on `kernel32.dll` — the model
proposes the textbook prologue from prior, the verifier refutes it with the real
bytes, and the model corrects to grounded, with no API key and no specific model.
[BENCHMARK.md](BENCHMARK.md) is the reproducible measurement behind the numbers above.

## Evidence, not claims

Everything above is checkable without trusting the author:

- **The verifier is checked by independent judges**, not by its own tests: the pure
  parser against lief on real binaries, the disassembler against capstone, binutils
  `objdump` and hand-verified Intel vectors, the emulator against Unicorn, the semantic
  engine against the export table — plus fuzzing that a malformed file never crashes the
  reader and that a wrong claim is never VERIFIED. All of it runs in CI on Linux, Windows
  and macOS, with and without the engines; a nightly job fuzzes 20k inputs.
- **The benchmark runs in CI on every push, on each platform's own system binaries**, and
  **fails the build if a single wrong claim is VERIFIED**. Each run leaves a
  machine-readable record — SHA-256 of every binary, verdicts, tool versions — as an
  artifact; reference runs live in [`benchmarks/results/`](benchmarks/results/), and a
  third-party aarch64 replication is in [BENCHMARK.md](BENCHMARK.md).
- **The verifier is measured like a classifier**: for every claim kind, known-true and
  known-false claims on real binaries give a confusion matrix — 0 false VERIFIED of 475
  known-false claims, 0 known-true claims missed — gated in every CI job.
- **Every verdict carries a receipt**: `reverify verify --json` (and `re_verify_claim`)
  include the binary's SHA-256, the reverify version and which engines judged, so a report
  can be handed over and replayed rather than believed. Releases ship with a SLSA build
  provenance attestation.
- **A replication package**: [`benchmarks/README.md`](benchmarks/README.md) — one command
  per benchmark, a pinned Dockerfile, expected output, and how to submit a run; a
  model-in-the-loop benchmark anyone can run against any OpenAI-compatible endpoint.

## The ledger: state that survives a context reset

Every agent harness handles a full context window the same way — a model summarizes the
transcript, the rest is dropped, and the docs warn that repeated compactions degrade
accuracy. That loss is unavoidable for free-form conversation, because nothing in a
transcript says which parts were *state* and which were chatter.

Reverify's loop can do better for itself, because it already draws that line: the only
things that matter are what the tools **verified, observed, proved — and refuted**.
Everything else (the model's prose, its unverified guesses) was never trusted, so dropping
it loses nothing. Since v0.8.0 exactly that state is written to disk as it happens:

- **`.reverify/ledger/<sha256>.json` per binary** (content-keyed, so a renamed copy shares
  its ledger), checkpointed after **every** round — a crash, a `/clear`, an auto-compact or
  a new process all resume from the same grounded position.
- **Negative memory**: refutations come back as `KNOWN FALSE`, so a fresh context does not
  re-propose the same wrong prior — the part a summary usually drops.
- **Bounded in context, unbounded on disk**: the prompt shows the most recent `--max-facts`
  (proof-grade facts pinned), and a deterministic ladder trims the *shown* fact sheet to
  `--prompt-budget` characters (kernel32.dll: 43k chars fit a 20k budget with the section
  table, entry point and header intact). Scoring uses the full sheet, so hiding a fact never
  makes restating it profitable, and a claim already in the ledger scores zero (`known`).
- **Lazy hand-off**: the hook injects one index line per binary; the facts are pulled on
  demand, so recovering state costs a few dozen tokens, not a slice of the fresh window.

```bash
reverify reconstruct target.exe --goal "..."   # resumes from .reverify/ automatically
reverify ledger target.exe                     # what is established, what is known false
reverify ledger --hook                         # Claude Code SessionStart hook (compact|clear|resume)
```

Over MCP the same happens with no setup: `re_verify_claim` records every grounded result,
and `re_ledger` hands them back after the host compacts or clears its context (the
server's `instructions` tell the agent to do so). Nothing unverified is ever stored — claim
notes are excluded on purpose.

## The loop that never fills up: fresh sessions with a verified hand-off

For a long task the ledger is not enough on its own — something has to decide *when* to
drop the transcript and *what* the next context starts with. `reverify orchestrate` runs a
goal as a sequence of fresh-context sessions and keeps the model in charge of the timing:

```bash
reverify orchestrate target.exe --goal "map the loader: entry, imports it really uses, exports" \
  --driver claude           # Claude Agent SDK on your Claude Code login; or openai (OPENAI_* env), or mock
```

- The model works through a small JSON protocol: propose claims, take notes, update its
  hand-off, **ask for a rollover** when its context feels long or confused, or declare done.
- A rollover also happens on a **token budget** per session and on **drift** — when
  restatements (trivial, echo, already-known) dominate the last turns, the loop is going in
  circles and gets a fresh start.
- The next session opens with the fact sheet, a one-line ledger index and a bounded
  hand-off. **ESTABLISHED and KNOWN FALSE come from the ledger, never from the model**; the
  model's own decisions and notes travel labelled *unverified*. That is the difference from
  every "summarize and continue" loop: a hallucination cannot ride the hand-off into the
  next context as if it were a fact.
- The checkpoint (`.reverify/sessions/<task>/checkpoint.json`, with a history) resumes across
  runs (`--task <id>`). Over MCP, `re_checkpoint` saves and loads the same hand-off so an
  agent that lives in someone else's context (Claude Code, Cursor) can do the same before
  its host compacts or clears.

A real run with the Claude Agent SDK driver on `msimg32.dll` (2 sessions × 4 turns, no API
key): 15 grounded facts across the rollover — the real entry-point instructions, the machine
type, header pointers read through typed observes — 2 guessed call-stub patterns refuted, 0
false accepts, and the second session started from the ledger, not from a summary
([`benchmarks/results/orchestrate-claude-msimg32-2026-09-04.json`](benchmarks/results/orchestrate-claude-msimg32-2026-09-04.json)).

## Any agent CLI without compaction: `reverify rollover`

The same rule applied to an interactive session — Claude Code, Codex CLI, Gemini CLI or
OpenCode. Built-in compaction is turned off; the model hands off to files, and instead of a
model-written summary the session is *replaced* wherever the CLI lets a hook do that (Gemini
CLI, OpenCode) or a launcher owns the process. Where it does not (a plain `claude` or `codex`),
reverify keeps the context *lean* rather than pretending to clear it: bulky tool output goes to
files that stay re-readable, edits stay local, exploration goes to subagents, and the hand-off
is always current. We are asking those vendors for the missing primitive.

```bash
pip install reverify
reverify rollover install          # every CLI found on PATH (or --harness claude,codex,gemini,opencode); backups kept
reverify rollover doctor           # what is wired, whether the hook commands still resolve, recent events
```

Then use your CLI exactly as before. The hooks do the hand-off; Gemini CLI and OpenCode also
open the fresh session themselves. For Claude Code and Codex, or whenever you want the fresh
session to open automatically, start the CLI through the launcher instead:

```bash
reverify rollover claude                    # same arguments as the CLI itself, e.g.
reverify rollover codex --full-auto
reverify rollover instructions --write AGENTS.md   # optional: the protocol paragraph for the model
```

- **A session nobody can end keeps growing — check `doctor`.** The hooks can write the hand-off
  but cannot end a Claude Code or Codex session. If you start the CLI yourself, or through the
  desktop app, a background job (`claude --bg`), or Remote Control server mode, the hand-off is
  written and nothing follows it: with native compaction off the conversation has no ceiling (one
  measured session reached 909k tokens before its owner noticed). `reverify rollover doctor` now
  reports receipts that no launcher consumed. Either start the CLI through the launcher
  (`reverify rollover claude --remote-control` keeps phone/web access through Remote Control), or
  set `REVERIFY_ROLLOVER_SUCCESSOR=bg` in `~/.claude/settings.json` → `env`: every receipt then
  starts a fresh `claude --bg` session that opens with the hand-off and appears in your session
  list, and you switch to it. Neither route resumes or rewrites the old transcript. The successor
  starts in the old session's project directory (Claude Code keys trust and MCP approvals per
  project), and `doctor` names a successor that is stuck waiting on an approval.
- **Small windows stay safe.** Native compaction is off, so when the harness records the
  model's context window (Codex does) the threshold is capped at 75% of it and the hand-off is
  refreshed more often.
- **Guard.** At the harness's "turn finished" hook (Claude Code / Codex `Stop`, Gemini
  `AfterAgent`, OpenCode `session.idle` via a plugin) the guard measures the live context from
  the harness's own transcript. At the threshold (`REVERIFY_ROLLOVER_TOKENS`, default 200k),
  or when the model itself runs `reverify rollover request --reason ...`, it blocks one stop
  and asks the model to write the hand-off *file* — fixed sections, labelled UNVERIFIED — and
  its memory index. Nothing is summarized in the conversation.
- **Receipt, fail closed.** On the next stop the guard checks that the hand-off was really
  rewritten and is well-formed; only then does it write a receipt carrying the transcript's
  SHA-256 and the user's **verbatim** first and latest messages. A missing or malformed
  hand-off means no receipt and a re-arm 100k further up.
- **Fresh session.** Whoever can end the session does it: the launcher for any CLI (waits for
  the receipt, gives a queued user message a moment to land — if one did, that rollover is
  off — ends the session, starts a fresh one whose first message points at the hand-off and
  quotes the original request verbatim); Gemini CLI in-process through its own
  `clearContext`, with the opening injected on the next turn; OpenCode through the SDK
  (new session, opening prompt). The old transcript stays on disk as an audit trail and is
  never resumed; every decision is appended to `~/.reverify/rollover/events.jsonl`.
- **What `install` touches**, all with backups and reversible by `uninstall`: Claude Code
  `~/.claude/settings.json` (hooks, `autoCompactEnabled: false`); Codex `~/.codex/hooks.json`
  + `config.toml` (`[features] hooks = true`, a compaction limit no session reaches); Gemini
  `~/.gemini/settings.json` (hooks, `model.compressionThreshold` above 1); OpenCode
  `~/.config/opencode/plugins/reverify-rollover.js` + `opencode.json` (`compaction.auto: false`;
  the directory follows `OPENCODE_CONFIG_DIR` / `XDG_CONFIG_HOME` exactly as opencode does).

Compare with a compaction summary: the hand-off is written while the model still has the
whole context, into a file with a fixed shape, separated from verified facts (memory files,
the ledger) — and the conversation that produced it is dropped, not paraphrased. Zero
dependencies; the hooks fail open, the rollover fails closed.

## The semantic layer: functions, calls and cross-references

Bytes, instructions, imports and emulation are what the deterministic core can judge on
its own. The claims analysts actually make — *function X calls Y*, *this string is
referenced from that routine*, *this code is reachable from the entry point* — need
function boundaries and cross-references, which means a real program-analysis engine.
Reverify does not build one. It stands on **angr** (`pip install "reverify[angr]"`) and
keeps its own part thin: an engine-neutral view of functions, call edges, data references
and reachability, and four claim kinds checked against it.

```bash
reverify functions msimg32.dll                                 # what the engine recovered
reverify verify msimg32.dll \
  --claim '{"kind": "calls", "params": {"from": "AlphaBlend", "to": "SetLastError"}}' \
  --claim '{"kind": "references", "params": {"to": 12632, "space": "rva", "from": "AlphaBlend"}}' \
  --claim '{"kind": "function_at", "params": {"offset": 4112, "space": "rva"}}' \
  --claim '{"kind": "reachable_from_entry", "params": {"name": "DllInitialize"}}'
```

A refuted `calls` lists the function's real callees and a refuted `references` lists the
functions that do reference the address, so a model can fix the claim instead of guessing
again. `observe: true` reads instead of asserts (a function's size, blocks and callees; the
referencing functions of a string).

Honesty about strength: a recovered control-flow graph is *analysis-derived* — CFGFast is
heuristic and can miss or split functions — so semantic verdicts name the engine and are
recorded at a **`DERIVED`** tier below `VERIFIED`. Without an engine the pure fallback only
knows what is independently certain (the entry point and the exports are function starts)
and answers `INCONCLUSIVE` for everything else, never a guess. And the engine is checked the
way the readers are: the export table, parsed independently of angr, must agree with the
functions it recovers.

## The toolkit

| Command | What it does |
|---|---|
| `reconstruct` | **Closed loop: a model proposes claims, the tools verify, iterate until grounded** |
| `verify` | **Check a claim about the binary against the tools — VERIFIED / REFUTED / INCONCLUSIVE** |
| `verify` (behavior_equiv) | **Run the original function and a candidate over shared inputs; a mismatch returns a counterexample** |
| `auto` | Auto-triage: detect format, architecture, sections, top strings |
| `parse` | PE / ELF / Mach-O: arch, entry, sections, imports, exports (lief when installed) |
| `parse-pe` | PE32/PE32+ headers, imports, exports |
| `backends` | Show which engines are active (capstone / unicorn / lief) |
| `disasm` | x86/x64 disassembly of hex or a section |
| `pattern-scan` | AOB scan with `??` wildcards |
| `strings` | ASCII + UTF-16LE extraction with offsets |
| `emulate` | CPU register/stack micro-emulation |
| `decode-protobuf` / `decode-tlv` | schema-less wire-format dissection |
| `gen-hook` | Frida interceptor script generation |
| `hexdump` | aligned hex dump |
| `diff-patch` | binary diff / patch generation |
| `audit-boundary` | defensive filesystem/SSRF boundary audit |

## MCP server

Reverify exposes the toolkit to AI agents over the Model Context Protocol:

```bash
python reverify/mcp_server.py
```

Point Claude Code or Cursor at it and the agent can parse, disassemble, and scan binaries
directly — with the deterministic tools as ground truth. The `re_verify_claim` tool exposes
the verification loop, so an agent can have its own hypotheses judged against the bytes
before it reports them — and records every grounded result in the binary's ledger.
`re_ledger` restores that state after the host's own compaction or `/clear` (see
[The ledger](#the-ledger-state-that-survives-a-context-reset)); ledgers are also exposed as
`reverify://ledger/<sha>` resources.

## Status

**v0.9.0 — the semantic layer**, on [PyPI](https://pypi.org/project/reverify/)
(`pip install reverify`). The tool-grounded judge — a claim about the binary is checked
against the actual bytes and returned as `VERIFIED` / `REFUTED` / `INCONCLUSIVE` /
`OBSERVED` / `INVALIDATED` with evidence — ships as `reverify verify` and the
`re_verify_claim` MCP tool, and `reverify reconstruct` closes the loop. v0.3.0 brought the
mature engines (capstone, unicorn, lief); v0.4.x hardened the loop against gaming
(information-weighted scoring measured from the binary, address spaces, typed reads,
observe-then-assert, dependencies) and added a testbed that cross-checks the readers
themselves (pure parser vs lief on real binaries, disassembler/emulator vs capstone, Unicorn
and known-answer vectors, plus fuzzing). **v0.5.0** adds the strongest grounding — the
`behavior_equiv` claim runs the original function and a candidate reconstruction over shared
inputs and compares outputs, returning a concrete counterexample on a mismatch (the ExeBench /
LLM4Decompile re-executability methodology). **v0.6.0** makes the reconstruction loop two-stage
(observe, then hypothesize) with an established-facts ledger: only what the tools verified or
read is carried between rounds, so the model can't build on its own earlier guesses — the
defense against context hallucination. **v0.7.0** adds a proof tier: the `prove_equiv` claim uses
Z3 to prove two expressions equal for *all* inputs (verifying MBA deobfuscation), giving an honest
strength ladder — proven > tested > observed. **v0.8.0** makes the loop's state durable: a
per-binary ledger of what the tools verified, observed, proved and refuted, checkpointed every
round and restored after `/clear`, compaction or a restart — lossless by construction, because
nothing the model said on its own was ever kept. **v0.9.0** adds the semantic layer on angr:
function boundaries, the call graph and cross-references as `function_at` / `calls` /
`references` / `reachable_from_entry` claims, recorded at an honest `DERIVED` tier, with the
export table as an independent oracle for the engine. Tested with 208 unit tests, so the
verifier is not just trusted, it is checked.

## Community

Shared on [LINUX DO](https://linux.do). Bugs and false-accept reports: open an issue.

## License

MIT — see [LICENSE](LICENSE).
