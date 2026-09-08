#!/usr/bin/env python3
"""Closed verification loop: the model proposes, the tools judge, it iterates.

This drives the deterministic :class:`~reverify.verifier.Verifier` automatically.
Given a binary and a goal in plain language, the agent asks a language model to
propose structured *claims* about the bytes, checks every claim with the
Verifier, feeds the refutations and their observed evidence back, and asks the
model to revise — round after round — until the reconstruction is grounded or a
round cap is reached.

Hardened against the ways a model games a verifier:

- The model never sees raw bytes beyond a small addressed header; it works from
  a keyed fact sheet and can *observe* values through the tools instead.
- Claims that restate the fact sheet, duplicates, self-referential inline code,
  echoes of the tools' previous output, and restatements of facts already in
  the ledger all score zero, so "grounded" means the verified set actually
  says something (``information`` >= a threshold).
- Refuted claims come back with the address in every space and where the
  expected bytes really are, so the next proposal can fix the right parameter.
- ``samples`` > 1 draws several proposals per round and lets the verifier —
  not the model's confidence — select among them.

State lives outside the context. Every round rebuilds the prompt from the fact
sheet plus a bounded view of the :class:`~reverify.ledger.Ledger` (what the
tools verified, observed, proved — and refuted). The ledger is checkpointed to
disk after every round, so a run can be resumed by a later process, and the
prompt is kept under a character budget by trimming the *shown* fact sheet
(scoring still uses the full sheet, so hiding a fact never makes restating it
profitable). Clearing the context loses nothing that was ever trusted.

The language model is injected as a ``propose`` callable (``str -> str``) so the
loop is fully testable offline. :func:`openai_proposer` builds a default one.
"""

from __future__ import annotations

import copy
import json
import os
import re
import urllib.request
import uuid
from typing import Any, Callable, Dict, List, Optional, Tuple

try:  # package import
    from .verifier import Verifier, Claim, summarize, claim_key, OBSERVED, REFUTED, VERIFIED, _as_int
    from .binary import parse_binary, shannon_entropy
    from .ledger import (
        Ledger,
        echo_key as _echo_key,
        actual_repr as _actual_repr,
        expected_repr as _expected_repr,
        compact_evidence as _compact_evidence,
        describe_established as _describe_established,
    )
except ImportError:  # flat import (CLI / tests)
    from verifier import Verifier, Claim, summarize, claim_key, OBSERVED, REFUTED, VERIFIED, _as_int
    from binary import parse_binary, shannon_entropy
    from ledger import (
        Ledger,
        echo_key as _echo_key,
        actual_repr as _actual_repr,
        expected_repr as _expected_repr,
        compact_evidence as _compact_evidence,
        describe_established as _describe_established,
    )

Proposer = Callable[[str], str]

#: Whole-prompt budget in characters (~4 chars per token, so ~15k tokens).
PROMPT_BUDGET_DEFAULT = 60_000

CLAIM_KINDS_HELP = """Each claim is a JSON object: {"kind": <kind>, "params": {...}, "note": "<why>", "id"?: "<c1>", "depends_on"?: ["<c0>"], "observe"?: true}.
Offsets are FILE offsets unless params carry "space": "rva" or "va" (the verifier translates via the section table).
Kinds and params:
- bytes_at:        {"offset": <int>, "expected": "<hex>"}             (omit expected or set observe:true to read the bytes)
- u16_at/u32_at/u64_at: {"offset": <int>, "expected": <int>, "endian"?: "le|be"}   (typed reads; no endianness math needed)
- pattern_present: {"pattern": "<AOB hex with ?? wildcards>", "offset"?: <int>, "count"?: <int>}
- string_present:  {"value": "<text>", "offset"?: <int>, "encoding"?: "utf-8|utf-16le|..."}
- instructions:    {"offset": <int>, "length"?: <int>, "mnemonics": ["push","mov",...], "operands"?: ["rbp","rbp, rsp",...], "arch"?: "x86_64", "mode"?: "exact|contains"}
- emulate_result:  {"offset": <int>, "length"?: <int>, "arch"?: "x86_64", "expect_registers": {"rax": <int>}}   (offset into the binary; inline "code" not found in the binary scores zero)
- behavior_equiv:  {"offset": <int>, "length"?: <int>, "expr": "x0 + x1"}  (STRONGEST: reconstruct a function's behavior; the tools run the original at offset and your candidate over shared inputs and compare. Candidate is `expr` over x0,x1,... or `candidate_code` hex. A mismatch returns a concrete counterexample input.)
- prove_equiv:     {"a": "(x0 ^ x1) + 2*(x0 & x1)", "b": "x0 + x1", "bits"?: 64}  (PROOF-GRADE via Z3: prove two integer expressions equal for ALL inputs, e.g. an obfuscated expression simplifies correctly (MBA deobfuscation). Refutation gives a distinguishing input.)
- protobuf_field:  {"field": <int>, "type"?: "varint|string|...", "value"?: <any>, "offset"?: <int>}
- import_present:  {"function": "<symbol>", "lib"?: "<library>"}
- export_present:  {"name": "<symbol>"}
- section_present: {"name": "<.text|.data|...>", "virtual_address"?: <int>}
- function_at:     {"offset": <int>} or {"name": "<function|export>"}   (SEMANTIC, DERIVED tier: a function starts here per the analysis engine; observe:true reads its size/blocks/callees)
- calls:           {"from": <offset|name>, "to": <offset|name|import>}   (SEMANTIC: a call edge in the recovered call graph; "from" alone with observe:true lists the callees)
- references:      {"to": <offset>, "from"?: <offset|name>}              (SEMANTIC: code references the data at "to", e.g. a string; observe:true lists the referencing functions)
- reachable_from_entry: {"offset": <int>} or {"name": "..."}            (SEMANTIC: the function is reachable from the entry point in the call graph)"""

RULES = """RULES (how claims are scored):
- A claim that only restates BINARY FACTS or ESTABLISHED scores ZERO. Say something the facts do not already say.
- Prefer specific, falsifiable claims: bytes_at with 4+ bytes beyond the shown header, typed u32_at/u64_at reads, instructions with mode=exact (add operands), emulate_result with an offset into the binary.
- Never do offset arithmetic or endianness conversion yourself: use typed reads and "space": "rva"/"va".
- Unsure of a value? Ask the tools: set "observe": true (or omit expected). The value is added to the facts. Use it to build NEW claims (structure, dependents, what it points to); restating an observed value scores zero.
- Weight is measured from the binary: content that occurs many times (zero padding, a common prologue, a pattern matching everywhere) weighs almost nothing even if it verifies. Aim for content that is specific to this binary.
- Give claims an "id" and use "depends_on" when one rests on another (a struct layout on an image base), so a refuted root invalidates its dependents.
- Do not copy the tools' previously observed value back as an "expected" value; that is an echo and scores zero.
- The "note" field is never verified and is shown as unverified text.
- A goal about what a binary imports or exports, or a string / section / behavior it has? Reach for the structured kinds (import_present, export_present, string_present, section_present, behavior_equiv, prove_equiv) directly instead of guessing byte offsets with bytes_at."""


def _extract_ascii_strings(data: bytes, min_len: int = 5, limit: int = 20) -> List[str]:
    out = []
    for m in re.finditer(rb"[\x20-\x7e]{%d,}" % min_len, data):
        out.append(m.group().decode("latin1", errors="ignore"))
        if len(out) >= limit:
            break
    return out


def _shift_signals(data: bytes, info) -> Dict[str, Any]:
    """Distribution-shift detectors: tell the model (and scorer) when priors are unreliable."""
    entropies = info.section_entropies(data) if info.sections else {}
    high = [n for n, e in entropies.items() if e >= 7.0]
    import_count = sum(len(v) for v in info.imports.values())
    entry_section = None
    if info.entrypoint is not None and info.sections:
        rva = info.entrypoint if info.format != "ELF" else None
        if info.format == "ELF" and info.image_base is not None:
            rva = info.entrypoint - info.image_base
        if rva is not None:
            sec = info.section_containing_rva(rva)
            entry_section = sec.name if sec else None
    end = max((s.offset + s.raw_size for s in info.sections), default=0)
    overlay = max(0, len(data) - end) if info.sections else 0
    packed_likely = bool(high) and import_count <= 8
    return {
        "section_entropy": entropies,
        "high_entropy_sections": high,
        "import_count": import_count,
        "entry_section": entry_section,
        "overlay_bytes": overlay,
        "packed_or_encrypted_likely": packed_likely,
        "heuristic_note": ("High-entropy sections with few imports often mean packing or encryption; "
                           "typical-code priors may not apply. Prefer observe before asserting." if packed_likely else None),
    }


def binary_facts(data: bytes) -> Dict[str, Any]:
    """A compact, keyed, addressed snapshot of the binary to ground proposals."""
    facts: Dict[str, Any] = {
        "size": len(data),
        "magic_hex": data[:4].hex(),
        "first_32_bytes_hex": data[:32].hex(),
        "first_bytes": {hex(i): " ".join(f"{b:02x}" for b in data[i : i + 16]) for i in range(0, min(32, len(data)), 16)},
        "top_strings": _extract_ascii_strings(data[:65536]),
    }
    info = parse_binary(data)
    if info.format != "raw":
        facts["binary"] = info.summary()
        facts["imports"] = {k: v[:40] for k, v in info.imports.items()}
        facts["exports"] = info.exports[:40]
        facts["sections"] = [
            {
                "name": s.name,
                "file_offset": hex(s.offset),
                "rva": hex(s.virtual_address),
                "va": hex(info.image_base + s.virtual_address) if info.image_base is not None else None,
                "raw_size": s.raw_size,
                "virtual_size": s.virtual_size,
            }
            for s in info.sections
        ]
        facts["addressing"] = "Offsets default to file offsets. Use space:'rva' or 'va' to address by RVA/VA."
        facts["shift_signals"] = _shift_signals(data, info)
    return facts


def build_prompt(
    goal: str,
    facts: Dict[str, Any],
    established: Optional[List[str]] = None,
    feedback: str = "",
    known_false: Optional[List[str]] = None,
) -> str:
    parts = [
        "Reconstruct facts about a binary by proposing claims the deterministic tools "
        "verify against the actual bytes. Each round, work in two steps: "
        "(1) OBSERVE — for anything you need but do not know, add a claim with "
        "\"observe\": true and the tools will read it for you; "
        "(2) HYPOTHESIZE — propose new claims that go beyond what is already known "
        "and can be checked.",
        "",
        f"GOAL: {goal}",
        "",
        "BINARY FACTS (ground truth, already known — restating them scores zero):",
        json.dumps(facts, indent=1, ensure_ascii=False),
    ]
    if established:
        parts += [
            "",
            "ESTABLISHED (verified or read by the tools this session — the ONLY earlier "
            "results you may build on):",
            "\n".join(f"- {e}" for e in established),
        ]
    if known_false:
        parts += [
            "",
            "KNOWN FALSE (refuted by the tools earlier; these are wrong, do not propose them again):",
            "\n".join(f"- {e}" for e in known_false),
        ]
    parts += [
        "",
        RULES,
        "",
        CLAIM_KINDS_HELP,
        "",
        "Build ONLY on BINARY FACTS and ESTABLISHED. Anything you proposed earlier that is "
        "not in ESTABLISHED did not happen — do not treat it as true or refer back to it.",
        "",
        "Output ONLY a JSON array of claim objects. No prose, no code fences.",
    ]
    if feedback:
        parts += ["", "LAST ROUND — fix or replace what did not hold; propose new informative claims:", feedback]
    return "\n".join(parts)


def parse_claims(raw: str) -> List[Dict[str, Any]]:
    """Pull a JSON array of claim dicts out of a model response."""
    text = (raw or "").strip()
    if "```" in text:
        inner = text.split("```", 2)
        if len(inner) >= 2:
            body = inner[1]
            body = body[4:] if body.lower().startswith("json") else body
            text = body.strip()
    start, end = text.find("["), text.rfind("]")
    if start != -1 and end != -1 and end > start:
        text = text[start : end + 1]
    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        return []
    if isinstance(data, dict):
        data = [data]
    return [c for c in data if isinstance(c, dict) and "kind" in c]


def format_feedback(report: Dict[str, Any]) -> str:
    lines = []
    for r in report["results"]:
        v = r["verdict"]
        if v == OBSERVED:
            continue  # folded into the facts
        if v == VERIFIED and r.get("weight", 0) > 0:
            continue
        label = f"{r['kind']}" + (f" id={r['id']}" if r.get("id") else "")
        if v == VERIFIED:
            if r.get("known"):
                why = "already established in the ledger"
            elif r.get("echoed"):
                why = "echo of previous tool output"
            elif r.get("duplicate"):
                why = "duplicate"
            else:
                why = "restates the fact sheet"
            lines.append(f"- TRIVIAL {label}: passed but weight 0 ({why}). Propose something the facts do not say.")
            continue
        ev = json.dumps(_compact_evidence(r), ensure_ascii=False)
        lines.append(f"- {v} {label}: {r['detail']}. evidence={ev}")
    need = report.get("min_information", 1.0)
    lines.append(
        f"- SCORE: information {report.get('information', 0)} of {need} needed; "
        f"trivial={report.get('trivial_verified', 0)} echoed={report.get('echoed', 0)} "
        f"known={report.get('known', 0)} duplicates={report.get('duplicates', 0)}."
    )
    return "\n".join(lines)


# -- echo detection -----------------------------------------------------------

def _is_echo(kind: str, expected, actual) -> bool:
    if expected is None or actual is None:
        return False
    if kind == "instructions":
        return len(expected) > 0 and tuple(actual[: len(expected)]) == tuple(expected)
    if kind in ("u16_at", "u32_at", "u64_at"):
        try:
            return _as_int(expected) == _as_int(actual)
        except (ValueError, TypeError):
            return False
    return expected == actual


def _loc_key(obj: Claim) -> str:
    """Identity by kind + location, so a *revised* claim is not counted as dropped."""
    p = obj.params
    if "offset" in p:
        try:
            return f"{obj.kind}@{hex(_as_int(p['offset']))}"
        except (ValueError, TypeError):
            pass
    return claim_key(obj.kind, p)


# -- prompt budget: trim the shown fact sheet, never the state ----------------

def _trim_imports(facts: Dict[str, Any], per_lib: int, libs: int) -> None:
    imp = facts.get("imports")
    if not isinstance(imp, dict) or not imp:
        return
    total_libs = len(imp)
    total_funcs = sum(len(v) for v in imp.values())
    kept = {}
    for i, (lib, funcs) in enumerate(imp.items()):
        if i >= libs:
            break
        kept[lib] = list(funcs)[:per_lib]
    if kept == imp:
        return
    facts["imports"] = kept
    facts["imports_note"] = (f"trimmed for context budget: {len(kept)} of {total_libs} libraries, up to {per_lib} "
                             f"functions each of {total_funcs}; check any other with import_present")


def _trim_list(facts: Dict[str, Any], key: str, n: int) -> None:
    v = facts.get(key)
    if isinstance(v, list) and len(v) > n:
        facts[key] = v[:n]
        facts[f"{key}_note"] = f"trimmed for context budget: first {n} of {len(v)}"


def _trim_observed(facts: Dict[str, Any], n: int) -> None:
    obs = facts.get("observed")
    if isinstance(obs, dict) and len(obs) > n:
        facts["observed"] = dict(list(obs.items())[-n:])
        facts["observed_note"] = (f"trimmed for context budget: most recent {n} of {len(obs)} observed values "
                                  f"(all remain in the ledger; observe again if needed)")


COMPACTION_LADDER: List[Tuple[str, Callable[[Dict[str, Any]], None]]] = [
    ("imports:16x60", lambda f: _trim_imports(f, 16, 60)),
    ("strings:8", lambda f: _trim_list(f, "top_strings", 8)),
    ("observed:24", lambda f: _trim_observed(f, 24)),
    ("imports:6x24", lambda f: _trim_imports(f, 6, 24)),
    ("exports:12", lambda f: _trim_list(f, "exports", 12)),
    ("observed:10", lambda f: _trim_observed(f, 10)),
    ("imports:2x12", lambda f: _trim_imports(f, 2, 12)),
    ("strings:0", lambda f: _trim_list(f, "top_strings", 0)),
    ("sections:16", lambda f: _trim_list(f, "sections", 16)),
]


def compact_facts(
    facts: Dict[str, Any],
    budget: int,
    goal: str = "",
    established: Optional[List[str]] = None,
    feedback: str = "",
    known_false: Optional[List[str]] = None,
) -> Tuple[Dict[str, Any], List[str], int]:
    """Shrink the fact sheet *shown* to the model until the whole prompt fits ``budget`` chars.

    Deterministic ladder, most redundant material first (long import lists,
    strings, old observed values). Only the view is trimmed: the caller keeps
    scoring against the full sheet, so hiding a fact can never make restating it
    profitable, and everything trimmed stays observable through the tools.
    Returns ``(view, steps_applied, prompt_chars)``.
    """
    view = copy.deepcopy(facts)
    steps: List[str] = []
    size = len(build_prompt(goal, view, established, feedback, known_false))
    for name, fn in COMPACTION_LADDER:
        if size <= budget:
            break
        fn(view)
        new_size = len(build_prompt(goal, view, established, feedback, known_false))
        if new_size != size:
            steps.append(name)
        size = new_size
    return view, steps, size


class ReconstructionAgent:
    """Runs the propose -> verify -> revise loop until grounded or capped.

    The ledger is the state; the prompt is rebuilt from it every round and it
    is checkpointed to disk after every round (``ledger`` = a directory, a
    :class:`~reverify.ledger.Ledger`, or ``None`` for in-memory). ``resume``
    continues from whatever the ledger already holds for this binary;
    ``prompt_budget`` bounds the prompt in characters; ``max_facts`` bounds
    how much of the ledger is shown.
    """

    def __init__(
        self,
        data: bytes,
        propose: Proposer,
        max_rounds: int = 4,
        samples: int = 1,
        min_information: float = 1.0,
        max_facts: int = 40,
        ledger: Any = None,
        resume: bool = True,
        prompt_budget: int = PROMPT_BUDGET_DEFAULT,
        session: Optional[str] = None,
        file_path: Optional[str] = None,
    ):
        self.data = data
        self.verifier = Verifier(data)
        self.propose = propose
        self.max_rounds = max(1, int(max_rounds))
        self.samples = max(1, int(samples))
        self.min_information = float(min_information)
        self.max_facts = max(1, int(max_facts))  # cap the shown ledger so long runs don't self-pollute
        if isinstance(ledger, Ledger):
            self.ledger = ledger
        elif ledger:
            self.ledger = Ledger.for_bytes(data, directory=ledger, file_path=file_path)
        else:
            self.ledger = Ledger.for_bytes(data, persist=False, file_path=file_path)
        if file_path:
            self.ledger.remember_path(file_path)
        self.resume = bool(resume)
        self.prompt_budget = max(2000, int(prompt_budget))
        self.session = session or uuid.uuid4().hex[:8]

    def run(self, goal: str) -> Dict[str, Any]:
        if not self.resume:
            self.ledger.clear()  # explicit fresh start: discard what the ledger held for this binary
        resumed_facts = len(self.ledger.facts)
        facts = binary_facts(self.data)
        facts["observed"] = dict(self.ledger.observed)  # values the tools read earlier come back verbatim
        established = self.ledger.established(self.max_facts)
        known_false = self.ledger.known_false()
        self.ledger.start_run(goal, self.session)
        self.ledger.save()

        history: List[Dict[str, Any]] = []
        feedback = ""
        grounded = False
        prev_keys: set = set()
        prev_actual: Dict[str, Any] = {}
        compactions = 0
        over_budget = False

        for rnd in range(1, self.max_rounds + 1):
            view, steps, prompt_chars = compact_facts(
                facts, self.prompt_budget, goal, established, feedback, known_false
            )
            prompt = build_prompt(goal, view, established, feedback, known_false)
            if steps:
                compactions += 1
            if prompt_chars > self.prompt_budget:
                over_budget = True
            raw_claims: List[Dict[str, Any]] = []
            for _ in range(self.samples):
                raw_claims.extend(parse_claims(self.propose(prompt)))
            claim_objs: List[Claim] = []
            seen = set()
            for c in raw_claims:
                try:
                    obj = Claim.from_dict(c)
                except Exception:
                    continue
                k = claim_key(obj.kind, obj.params)
                if k in seen:
                    continue
                seen.add(k)
                claim_objs.append(obj)

            # Score against the FULL fact sheet, whatever the model was shown.
            report = self.verifier.verify_all(claim_objs, facts=facts, min_information=self.min_information)

            # Echo detection: a claim that parrots last round's observed value scores zero.
            # Known detection: a claim already in the ledger says nothing new either.
            echoed = known = 0
            known_keys = self.ledger.fact_keys()
            for r in report["results"]:
                k = _echo_key(r)
                if k and k in prev_actual and _is_echo(r["kind"], _expected_repr(r), prev_actual[k]):
                    r["echoed"] = True
                    echoed += 1
                if r["verdict"] == VERIFIED and claim_key(r["kind"], r.get("params", {})) in known_keys:
                    r["known"] = True
                    known += 1
            if echoed or known:
                report = summarize(report["results"], facts=facts, min_information=self.min_information)

            # Fold OBSERVED values into the facts; remember actuals for next round's echo check.
            new_actual: Dict[str, Any] = {}
            for r in report["results"]:
                k = _echo_key(r)
                act = _actual_repr(r)
                if k and r["verdict"] == OBSERVED and act is not None:
                    facts["observed"][k] = act if not isinstance(act, tuple) else list(act)
                if k and act is not None and r["verdict"] in (REFUTED, OBSERVED):
                    new_actual[k] = act

            # The ledger is the only memory carried forward: grounded results in,
            # refutations as known-false, the model's own prose never. Checkpoint now,
            # so a crash or a cleared context after this point loses nothing.
            added = self.ledger.record(report["results"], rnd=rnd, goal=goal, session=self.session)
            self.ledger.save()
            established = self.ledger.established(self.max_facts)
            known_false = self.ledger.known_false()

            keys_now = {_loc_key(o) for o in claim_objs}
            attrition = len(prev_keys - keys_now) if prev_keys else 0
            history.append({
                "round": rnd,
                "claims": [c for c in raw_claims],
                "report": report,
                "attrition": attrition,
                "echoed": echoed,
                "known": known,
                "prompt_chars": prompt_chars,
                "compaction": steps,
                "ledger_added": added,
            })
            prev_keys, prev_actual = keys_now, new_actual
            if report["grounded"]:
                grounded = True
                break
            feedback = format_feedback(report)

        final = history[-1]["report"] if history else None
        information = final["information"] if final else 0.0
        self.ledger.finish_run(len(history), grounded, information)
        self.ledger.save()
        return {
            "goal": goal,
            "grounded": grounded,
            "rounds_used": len(history),
            "information": information,
            "verified_claims": [
                r for r in (final["results"] if final else []) if r["verdict"] == VERIFIED and r.get("weight", 0) > 0
            ] if grounded else [],
            "observed": dict(facts["observed"]),
            "established": list(established),
            "resumed_facts": resumed_facts,
            "compactions": compactions,
            "over_budget": over_budget,
            "session": self.session,
            "ledger": self.ledger.summary(),
            "ledger_path": str(self.ledger.path) if self.ledger.path else None,
            "history": history,
            "final_report": final,
        }


def openai_proposer(
    model: Optional[str] = None,
    base_url: Optional[str] = None,
    api_key: Optional[str] = None,
    temperature: float = 0.7,
    timeout: int = 60,
) -> Proposer:
    """Proposer backed by an OpenAI-compatible chat-completions API.

    Temperature defaults to 0.7: under thin evidence a low temperature just
    re-emits the prior's modal guess round after round; diversity plus the
    deterministic verifier as selector works better.
    """
    api_key = api_key or os.getenv("OPENAI_API_KEY")
    model = model or os.getenv("OPENAI_MODEL") or "gpt-4o"
    base_url = base_url or os.getenv("OPENAI_BASE_URL") or "https://api.openai.com/v1"
    if not api_key:
        raise RuntimeError("OPENAI_API_KEY required for the live proposer (or inject your own).")

    def _propose(prompt: str) -> str:
        body = json.dumps({
            "model": model,
            "messages": [
                {"role": "system", "content": "You output only valid JSON arrays of claim objects."},
                {"role": "user", "content": prompt},
            ],
            "temperature": temperature,
        }).encode("utf-8")
        req = urllib.request.Request(
            f"{base_url.rstrip('/')}/chat/completions",
            data=body,
            headers={"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"},
        )
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            data = json.loads(resp.read().decode("utf-8"))
        return data["choices"][0]["message"]["content"]

    return _propose


def demo_proposer(data: bytes) -> Proposer:
    """Offline proposer for ``reverify reconstruct --mock``.

    On a binary of 40+ bytes it asserts the real last 8 bytes (an informative
    claim beyond the shown header) and observes a value; on tiny inputs it can
    only restate the header, which the scorer correctly treats as trivial.
    """
    claims: List[Dict[str, Any]] = []
    if len(data) >= 40:
        # Pick the most informative 8-byte window among a few candidates (avoid padding).
        cands = [o for o in (len(data) - 8, len(data) // 2, len(data) // 3, 64, 32) if 32 <= o <= len(data) - 8]
        off = max(cands, key=lambda o: shannon_entropy(data[o : o + 8]))
        claims.append({"kind": "bytes_at", "params": {"offset": off, "expected": data[off : off + 8].hex()},
                       "note": "an 8-byte window specific to this file (offline demo claim)", "id": "window"})
        claims.append({"kind": "u32_at", "params": {"offset": 32}, "observe": True, "note": "read a value the facts do not show"})
    else:
        claims.append({"kind": "bytes_at", "params": {"offset": 0, "expected": data[:4].hex()},
                       "note": "file header (restates the facts; expect weight 0)"})

    def _propose(_prompt: str) -> str:
        return json.dumps(claims)

    return _propose
