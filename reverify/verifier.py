#!/usr/bin/env python3
"""Tool-grounded claim verification — the core idea behind Reverify.

A *claim* is a hypothesis about a binary: "the bytes at 0x40 are `55 8B EC`",
"field 3 of this Protobuf message is the string 'admin'", "the routine at this
offset computes `eax = 6`". Language models are good at producing such claims
and bad at guaranteeing they are true. Reverify makes the **deterministic
toolkit the judge**: each claim is checked against the actual bytes with the
parsers, disassembler, emulator, pattern scanner, and protocol dissector, and is
only ever reported as ``VERIFIED`` when the binary itself backs it up.

Verdicts
--------
- ``VERIFIED``     — the bytes support the claim.
- ``REFUTED``      — the bytes contradict the claim.
- ``INCONCLUSIVE`` — the tools cannot decide (bad offset, malformed claim, a
                     format the relevant tool does not understand).
- ``OBSERVED``     — the claim asked the tools for a value instead of asserting
                     one (``observe: true`` or a missing ``expected``); the value
                     is reported but nothing is scored.
- ``INVALIDATED``  — the claim depended (``depends_on``) on a claim that was
                     refuted, so it cannot stand on its own.

Scoring (anti-gaming)
---------------------
"All claims verified" is easy to reach by asserting trivia — the file starts
with ``MZ``, ``.text`` exists — so a verified set is also **weighted by how much
it says**. Each result carries a ``weight``: zero for claims derivable from the
fact sheet the model was shown, for self-referential claims (inline code/data
that does not occur in the binary), for duplicates, and for echoes of the tool's
own previous output; otherwise a surprisal tier by claim kind and specificity.
The report exposes ``information`` (sum of weights of verified claims) and
``grounded`` = trustworthy **and** informative. This follows the CORE
refinement of FActScore (Jiang et al., 2024): credit only claims that are
factual, informative and non-repetitive.
"""

from __future__ import annotations

import hashlib
import json
import math
import platform
import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

try:  # package import (e.g. ``from reverify import Verifier``)
    from .disasm import Disassembler, pattern_scan, UnsupportedArch, PSEUDO_MNEMONICS
    from .emulator import make_emulator, EmulatorError
    from .protocol_parser import ProtobufDissector
    from .binary import parse_binary, shannon_entropy
    from .behavior import behavioral_equiv, prove_expr_equiv
    from .exebench import exebench_verify, functions_equiv_verify
    from .semantic import semantic_view, INSTALL_HINT as SEMANTIC_HINT
    from .backends import backend_report
    from ._version import __version__
except ImportError:  # flat import (CLI, MCP server, and the test suite)
    from disasm import Disassembler, pattern_scan, UnsupportedArch, PSEUDO_MNEMONICS
    from emulator import make_emulator, EmulatorError
    from backends import backend_report
    from _version import __version__
    from protocol_parser import ProtobufDissector
    from binary import parse_binary, shannon_entropy
    from behavior import behavioral_equiv, prove_expr_equiv
    from exebench import exebench_verify, functions_equiv_verify
    from semantic import semantic_view, INSTALL_HINT as SEMANTIC_HINT

VERIFIED = "VERIFIED"
REFUTED = "REFUTED"
INCONCLUSIVE = "INCONCLUSIVE"
OBSERVED = "OBSERVED"
INVALIDATED = "INVALIDATED"

_META_KEYS = ("kind", "note", "id", "depends_on", "observe")


class ClaimError(Exception):
    """Raised when a claim is structurally malformed (missing required keys)."""


@dataclass
class Claim:
    """A single hypothesis to be checked against the binary.

    Attributes:
        kind: one of the supported claim kinds (see ``Verifier.SUPPORTED``).
        params: kind-specific parameters. Offsets may carry ``space`` =
            ``"file"`` (default), ``"rva"`` or ``"va"``; the verifier translates
            through the section table and echoes all three in the evidence.
        note: free-text rationale. Never verified; rendered separately.
        id: optional identifier so other claims can ``depends_on`` it.
        depends_on: ids of claims this one rests on; a refuted dependency
            invalidates this claim.
        observe: ask the tools for the value instead of asserting one.
    """

    kind: str
    params: Dict[str, Any] = field(default_factory=dict)
    note: str = ""
    id: Optional[str] = None
    depends_on: List[str] = field(default_factory=list)
    observe: bool = False

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "Claim":
        if not isinstance(data, dict) or "kind" not in data:
            raise ClaimError("claim must be an object with a 'kind' field")
        params = data.get("params")
        if params is None:
            # Allow a flat form: everything except the meta keys is a parameter.
            params = {k: v for k, v in data.items() if k not in _META_KEYS}
        deps = data.get("depends_on") or []
        if isinstance(deps, str):
            deps = [deps]
        return cls(
            kind=str(data["kind"]),
            params=dict(params),
            note=str(data.get("note", "")),
            id=str(data["id"]) if data.get("id") is not None else None,
            depends_on=[str(d) for d in deps],
            observe=bool(data.get("observe", False)),
        )


def _clean_hex(text: str) -> bytes:
    cleaned = "".join(str(text).split()).replace("0x", "").replace("0X", "")
    return bytes.fromhex(cleaned)


def _as_int(value: Any) -> int:
    if isinstance(value, int):
        return value
    return int(str(value), 0)


def _norm_ops(s: str) -> str:
    return "".join(str(s).lower().split())


def _entropy_norm(buf: bytes) -> float:
    """Entropy of ``buf`` relative to the maximum possible for its length (0..1)."""
    n = len(buf)
    if n <= 1:
        return 1.0
    max_h = min(8.0, math.log2(n))
    return shannon_entropy(buf) / max_h if max_h > 0 else 1.0


def _occurrences(data: bytes, needle: bytes) -> int:
    if not needle:
        return 0
    count, start = 0, 0
    while True:
        idx = data.find(needle, start)
        if idx == -1:
            return count
        count += 1
        start = idx + 1


class Verifier:
    """Checks claims about one binary against the deterministic toolkit."""

    SUPPORTED = (
        "bytes_at",
        "u16_at",
        "u32_at",
        "u64_at",
        "pattern_present",
        "string_present",
        "instructions",
        "emulate_result",
        "behavior_equiv",
        "prove_equiv",
        "exebench",
        "functions_equiv",
        "protobuf_field",
        "import_present",
        "export_present",
        "section_present",
        "pe_import",  # alias of import_present
        # semantic layer (engine-derived): function boundaries, call graph, xrefs
        "function_at",
        "calls",
        "references",
        "reachable_from_entry",
    )

    def __init__(self, data: bytes):
        self.data = data
        self._bin_cache = None
        self._sem_cache = None
        self._sha_cache: Optional[str] = None

    def receipt(self) -> Dict[str, Any]:
        """Everything a third party needs to re-run these checks: which bytes, with which tools.

        Verdicts are deterministic given the same bytes and the same engines, so a
        report plus its receipt is evidence that can be handed over and replayed —
        not a claim that has to be taken on trust.
        """
        if self._sha_cache is None:
            self._sha_cache = hashlib.sha256(self.data).hexdigest()
        engines = backend_report()
        return {
            "binary_sha256": self._sha_cache,
            "binary_size": len(self.data),
            "reverify": __version__,
            "python": platform.python_version(),
            "platform": platform.platform(),
            "engines": {k: v.get("engine") for k, v in engines.items() if isinstance(v, dict) and "engine" in v},
            "generated": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "replay": "reverify verify <file> --claims-file <claims.json>",
        }

    def _binary(self):
        """Parsed view of the binary (lief when available), cached per verifier."""
        if self._bin_cache is None:
            self._bin_cache = parse_binary(self.data)
        return self._bin_cache

    # -- dispatch -----------------------------------------------------------

    def verify(self, claim: Claim) -> Dict[str, Any]:
        """Check a single claim and return a structured verdict."""
        handler = getattr(self, f"_check_{claim.kind}", None)
        if handler is None:
            return self._result(claim, INCONCLUSIVE, {}, f"unknown claim kind '{claim.kind}'")
        params = dict(claim.params)
        if claim.observe:
            params["observe"] = True
        try:
            verdict, evidence, detail = handler(params)
        except ClaimError as exc:
            return self._result(claim, INCONCLUSIVE, {}, f"malformed claim: {exc}")
        except Exception as exc:  # pragma: no cover - defensive
            return self._result(claim, INCONCLUSIVE, {}, f"tool error: {exc}")
        return self._result(claim, verdict, evidence, detail)

    def verify_all(
        self,
        claims: List[Claim],
        facts: Optional[Dict[str, Any]] = None,
        min_information: float = 1.0,
    ) -> Dict[str, Any]:
        """Check many claims, apply dependencies, and score how much they say.

        ``facts`` is the fact sheet the model was shown; claims derivable from
        it get zero weight. ``min_information`` is the weight sum a verified set
        must reach to count as informative.
        """
        results = [self.verify(c) for c in claims]
        _apply_dependencies(results)
        report = summarize(results, facts=facts, min_information=min_information)
        report["receipt"] = self.receipt()
        return report

    # -- addressing -----------------------------------------------------------

    def _resolve_offset(self, p: Dict[str, Any]) -> Tuple[Optional[int], Dict[str, Any]]:
        """Turn ``offset`` (+ optional ``space``) into a file offset with evidence."""
        space = str(p.get("space", "file")).lower()
        given = _as_int(p["offset"])
        info: Dict[str, Any] = {"space": space, "given": hex(given)}
        b = self._binary()
        parseable = b.format != "raw" and not b.error
        if space == "file":
            off = given
            if parseable:
                rva = b.offset_to_rva(off)
                if rva is not None:
                    info["rva"] = hex(rva)
                    if b.image_base is not None:
                        info["va"] = hex(b.image_base + rva)
        elif space in ("rva", "va"):
            if not parseable:
                return None, {**info, "error": "address translation needs a parseable binary"}
            if space == "va":
                if b.image_base is None:
                    return None, {**info, "error": "binary has no image base for VA translation"}
                rva = given - b.image_base
            else:
                rva = given
            off = b.rva_to_offset(rva)
            if off is None:
                return None, {**info, "error": "address is not inside any section"}
            info["rva"] = hex(rva)
            if b.image_base is not None:
                info["va"] = hex(b.image_base + rva)
        else:
            return None, {**info, "error": f"unknown address space '{space}' (use file|rva|va)"}
        info["file_offset"] = hex(off)
        return off, info

    # -- claim handlers -----------------------------------------------------
    # Each returns (verdict, evidence_dict, detail_str).

    def _check_bytes_at(self, p: Dict[str, Any]):
        """Claim: the bytes at ``offset`` equal ``expected`` (hex). ``observe`` reads them."""
        if "offset" not in p:
            raise ClaimError("bytes_at requires 'offset'")
        observe = bool(p.get("observe")) or "expected" not in p
        length = _as_int(p["length"]) if "length" in p else None
        expected = None if observe else _clean_hex(p["expected"])
        off, addr = self._resolve_offset(p)
        if off is None:
            return INCONCLUSIVE, {"address": addr, "file_size": len(self.data)}, addr.get("error", "bad address")
        n = length if length is not None else (len(expected) if expected is not None else 4)
        if n <= 0:
            # An empty assertion (zero bytes / zero length) is true everywhere and is never
            # evidence of anything: refuse it rather than hand back a bare VERIFIED.
            return INCONCLUSIVE, {"address": addr, "file_size": len(self.data)}, "empty assertion (no bytes claimed)"
        if off < 0 or off + n > len(self.data):
            return INCONCLUSIVE, {"address": addr, "file_size": len(self.data)}, "offset out of range"
        actual = self.data[off : off + n]
        evidence: Dict[str, Any] = {"address": addr, "actual": actual.hex()}
        if observe:
            return OBSERVED, evidence, "bytes read"
        evidence["expected"] = expected.hex()
        evidence["weight_basis"] = self._bytes_basis(expected)
        if actual == expected:
            return VERIFIED, evidence, "bytes match"
        evidence["nearest_offset_of_expected"] = self._nearest(expected, off)
        return REFUTED, evidence, "bytes differ"

    def _check_int_at(self, p: Dict[str, Any], size: int, kind: str):
        if "offset" not in p:
            raise ClaimError(f"{kind} requires 'offset'")
        observe = bool(p.get("observe")) or "expected" not in p
        endian = str(p.get("endian", "le")).lower()
        if endian not in ("le", "be"):
            raise ClaimError("endian must be 'le' or 'be'")
        off, addr = self._resolve_offset(p)
        if off is None:
            return INCONCLUSIVE, {"address": addr}, addr.get("error", "bad address")
        if off < 0 or off + size > len(self.data):
            return INCONCLUSIVE, {"address": addr, "file_size": len(self.data)}, "offset out of range"
        raw = self.data[off : off + size]
        actual = int.from_bytes(raw, "little" if endian == "le" else "big")
        evidence: Dict[str, Any] = {"address": addr, "raw": raw.hex(), "actual": hex(actual), "endian": endian}
        if observe:
            return OBSERVED, evidence, "value read"
        want = _as_int(p["expected"])
        evidence["expected"] = hex(want)
        want_bytes = want.to_bytes(size, "little" if endian == "le" else "big", signed=False) if 0 <= want < (1 << (8 * size)) else None
        if want_bytes:
            evidence["weight_basis"] = self._bytes_basis(want_bytes)
        if actual == want:
            return VERIFIED, evidence, "value matches"
        evidence["nearest_offset_of_expected"] = self._nearest(want_bytes, off) if want_bytes else None
        return REFUTED, evidence, "value differs"

    def _check_u16_at(self, p):
        return self._check_int_at(p, 2, "u16_at")

    def _check_u32_at(self, p):
        return self._check_int_at(p, 4, "u32_at")

    def _check_u64_at(self, p):
        return self._check_int_at(p, 8, "u64_at")

    def _bytes_basis(self, needle: bytes) -> Dict[str, Any]:
        """What the weight is measured from: how often the content occurs here, and its entropy."""
        return {
            "occurrences": _occurrences(self.data, needle),
            "length": len(needle),
            "entropy_norm": round(_entropy_norm(needle), 3),
        }

    def _nearest(self, needle: Optional[bytes], around: int, window: int = 256) -> Optional[str]:
        """Where the expected bytes actually sit, if anywhere within ±window."""
        if not needle:
            return None
        lo, hi = max(0, around - window), min(len(self.data), around + window + len(needle))
        idx = self.data.find(needle, lo, hi)
        return hex(idx) if idx != -1 else None

    def _check_pattern_present(self, p: Dict[str, Any]):
        """Claim: AOB ``pattern`` occurs (optionally at ``offset`` / ``count`` times)."""
        if "pattern" not in p:
            raise ClaimError("pattern_present requires 'pattern'")
        tokens = [t for t in str(p["pattern"]).split() if t not in ("?", "??")]
        if not tokens:
            # An all-wildcard or empty pattern matches every byte and is no claim at all.
            return INCONCLUSIVE, {}, "pattern has no fixed bytes (nothing to verify)"
        matches = pattern_scan(self.data, str(p["pattern"]))
        fixed = [t for t in str(p["pattern"]).split() if t not in ("?", "??")]
        evidence: Dict[str, Any] = {
            "match_offsets": [hex(m) for m in matches[:64]],
            "match_count": len(matches),
            "weight_basis": {"occurrences": len(matches), "length": len(fixed), "entropy_norm": 1.0},
        }
        if "offset" in p:
            want, addr = self._resolve_offset(p)
            evidence["address"] = addr
            if want is None:
                return INCONCLUSIVE, evidence, addr.get("error", "bad address")
            ok = want in matches
            return (VERIFIED if ok else REFUTED), evidence, (
                "pattern present at claimed offset" if ok else "pattern not at claimed offset"
            )
        if "count" in p:
            want = _as_int(p["count"])
            ok = len(matches) == want
            return (VERIFIED if ok else REFUTED), evidence, f"expected {want} matches, found {len(matches)}"
        if matches:
            return VERIFIED, evidence, "pattern present"
        return REFUTED, evidence, "pattern absent"

    def _check_string_present(self, p: Dict[str, Any]):
        """Claim: ``value`` appears as raw bytes (optionally at ``offset``)."""
        if "value" not in p:
            raise ClaimError("string_present requires 'value'")
        encoding = str(p.get("encoding", "utf-8"))
        try:
            needle = str(p["value"]).encode(encoding)
        except LookupError:
            raise ClaimError(f"unknown encoding '{encoding}'")
        if not needle:
            # The empty string is a substring of every byte sequence: not evidence.
            return INCONCLUSIVE, {}, "empty string makes no claim"
        all_offsets = []
        start = 0
        while True:
            idx = self.data.find(needle, start)
            if idx == -1:
                break
            all_offsets.append(idx)
            start = idx + 1
        evidence: Dict[str, Any] = {
            "found_offsets": [hex(o) for o in all_offsets[:64]],
            "occurrences": len(all_offsets),
            "weight_basis": self._bytes_basis(needle),
        }
        if "offset" in p:
            want, addr = self._resolve_offset(p)
            evidence["address"] = addr
            if want is None:
                return INCONCLUSIVE, evidence, addr.get("error", "bad address")
            ok = want in all_offsets
            return (VERIFIED if ok else REFUTED), evidence, (
                "string present at claimed offset" if ok else "string not at claimed offset"
            )
        if all_offsets:
            return VERIFIED, evidence, "string present"
        return REFUTED, evidence, "string absent"

    def _check_instructions(self, p: Dict[str, Any]):
        """Claim: disassembling ``length`` bytes at ``offset`` yields ``mnemonics``.

        ``mode='contains'`` accepts an ordered subsequence; the default
        ``mode='exact'`` requires the full sequence. Optional ``operands`` (one
        string per instruction, or null to skip) are compared too.
        """
        if "offset" not in p or "mnemonics" not in p:
            raise ClaimError("instructions requires 'offset' and 'mnemonics'")
        expected = [str(m).lower() for m in p["mnemonics"]]
        if not expected:
            # An empty instruction list is satisfied by every byte stream: no claim.
            return INCONCLUSIVE, {}, "empty mnemonics makes no claim"
        arch = str(p.get("arch", "x86_64"))
        mode = str(p.get("mode", "exact"))
        length = _as_int(p["length"]) if "length" in p else None
        off, addr = self._resolve_offset(p)
        if off is None:
            return INCONCLUSIVE, {"address": addr}, addr.get("error", "bad address")
        if off < 0 or off >= len(self.data):
            return INCONCLUSIVE, {"address": addr, "file_size": len(self.data)}, "offset out of range"
        code = self.data[off : off + length] if length else self.data[off : off + 64]
        base = _as_int(p["base"]) if "base" in p else 0x1000
        dis = Disassembler(arch=arch)
        try:
            insns = dis.disassemble(code, base_address=base)
        except UnsupportedArch as exc:
            # never judge non-x86 bytes with the x86-only fallback: that could accept a wrong claim
            return INCONCLUSIVE, {"address": addr, "arch": arch, "error": str(exc)}, str(exc)
        actual = [i.mnemonic.lower() for i in insns]
        if dis.engine != "capstone":
            window = actual if mode == "contains" else actual[: max(len(expected), 1)]
            if any(m in PSEUDO_MNEMONICS for m in window):
                # the pure decoder could not decode these bytes: unknown, not refuted (and never verified)
                hint = 'the pure-Python decoder does not handle these bytes; install capstone (pip install "reverify[capstone]") to judge this claim'
                return INCONCLUSIVE, {"address": addr, "arch": arch, "engine": dis.engine,
                                      "actual_mnemonics": actual[: max(len(expected) + 4, 8)], "error": hint}, hint
        actual_ops = [i.op_str for i in insns]
        matched = b"".join(bytes(i.bytes) for i in insns[: len(expected)])
        evidence: Dict[str, Any] = {
            "address": addr,
            "actual_mnemonics": actual[: max(len(expected) + 4, 8)],
            "actual_operands": actual_ops[: max(len(expected) + 4, 8)],
            "expected_mnemonics": expected,
            "weight_basis": self._bytes_basis(matched) if matched else None,
        }
        if mode == "contains":
            ok = _is_subsequence(expected, actual)
        else:
            ok = actual[: len(expected)] == expected if length is None else actual == expected
        if ok and p.get("operands"):
            wants = list(p["operands"])
            for i, w in enumerate(wants):
                if w is None:
                    continue
                if i >= len(actual_ops) or _norm_ops(actual_ops[i]) != _norm_ops(w):
                    ok = False
                    evidence["operand_mismatch_index"] = i
                    break
        return (VERIFIED if ok else REFUTED), evidence, f"mode={mode}"

    def _check_emulate_result(self, p: Dict[str, Any]):
        """Claim: emulating the code leaves registers at ``expect_registers``.

        Code comes from ``offset``/``length`` into the binary (preferred) or an
        inline ``code`` hex string. Inline code that does not occur in the binary
        is flagged ``self_referential`` and carries no weight. ``observe`` (or a
        missing ``expect_registers``) reports the register state instead.
        """
        arch = str(p.get("arch", "x86_64"))
        base = _as_int(p["base"]) if "base" in p else 0x1000
        max_steps = _as_int(p["max_steps"]) if "max_steps" in p else 1000
        observe = bool(p.get("observe")) or "expect_registers" not in p
        evidence: Dict[str, Any] = {}
        if "offset" in p:
            off, addr = self._resolve_offset(p)
            evidence["address"] = addr
            if off is None:
                return INCONCLUSIVE, evidence, addr.get("error", "bad address")
            length = _as_int(p["length"]) if "length" in p else 64
            if off < 0 or off >= len(self.data):
                return INCONCLUSIVE, {**evidence, "file_size": len(self.data)}, "offset out of range"
            code = self.data[off : off + length]
        elif "code" in p:
            code = _clean_hex(p["code"])
            evidence["self_referential"] = self.data.find(code) == -1 if code else True
        else:
            raise ClaimError("emulate_result requires 'offset' or 'code'")

        emu = make_emulator(arch=arch, prefer=str(p.get("backend", "auto")))
        emu.load_code(code, base_address=base)
        state = emu.run(max_steps=max_steps)
        evidence["steps_executed"] = emu.steps_executed
        evidence["backend"] = state.get("backend", "pure-python")
        evidence["weight_basis"] = {
            "steps": emu.steps_executed,
            "entropy_norm": round(_entropy_norm(code), 3),
            "inline": "code" in p,
        }
        if observe:
            evidence["registers"] = state.get("registers", {})
            return OBSERVED, evidence, "emulated; register state reported"

        expect = {str(k).lower(): _as_int(v) for k, v in dict(p["expect_registers"]).items()}
        observed = {name: emu.reg_read(name) for name in expect}
        mismatches = {
            name: {"expected": hex(want), "actual": hex(observed[name])}
            for name, want in expect.items()
            if observed[name] != want
        }
        evidence.update({
            "expect_registers": {k: hex(v) for k, v in expect.items()},
            "observed_registers": {k: hex(v) for k, v in observed.items()},
            "mismatches": mismatches,
        })
        if not mismatches:
            return VERIFIED, evidence, "register state matches"
        return REFUTED, evidence, f"{len(mismatches)} register(s) mismatched"

    def _check_behavior_equiv(self, p: Dict[str, Any]):
        """Claim: a candidate reconstruction behaves like the original function.

        Original code from ``offset``/``length`` into the binary (earns weight) or
        inline ``code`` (self-referential, weight 0). Candidate via ``candidate_code``
        (hex) or ``expr`` (a restricted integer expression over x0, x1, ...). The two
        are run over shared inputs and their outputs compared. A mismatch returns a
        concrete counterexample; agreement is reported as tested-not-proven.
        """
        arch = str(p.get("arch", "x86_64"))
        bits = _as_int(p["bits"]) if "bits" in p else (64 if "64" in arch or "amd" in arch else 32)
        arg_regs = list(p["arg_regs"]) if "arg_regs" in p else None
        ret_reg = str(p["ret_reg"]) if "ret_reg" in p else None
        evidence: Dict[str, Any] = {}

        if "offset" in p:
            off, addr = self._resolve_offset(p)
            evidence["address"] = addr
            if off is None:
                return INCONCLUSIVE, evidence, addr.get("error", "bad address")
            length = _as_int(p["length"]) if "length" in p else 256
            if off < 0 or off >= len(self.data):
                return INCONCLUSIVE, {**evidence, "file_size": len(self.data)}, "offset out of range"
            original = self.data[off : off + length]
        elif "code" in p:
            original = _clean_hex(p["code"])
            evidence["self_referential"] = self.data.find(original) == -1 if original else True
        else:
            raise ClaimError("behavior_equiv requires 'offset' or 'code' for the original")

        candidate_code = _clean_hex(p["candidate_code"]) if "candidate_code" in p else None
        expr = str(p["expr"]) if "expr" in p else None
        if candidate_code is None and expr is None:
            raise ClaimError("behavior_equiv requires 'candidate_code' or 'expr'")

        if expr is not None and "args" not in p and "inputs" not in p:
            import re as _re
            nargs = (max((int(m) for m in _re.findall(r"\bx(\d+)\b", expr)), default=-1) + 1) or 1
            if _re.search(r"\bx\b", expr):
                nargs = max(nargs, 1)
        else:
            nargs = _as_int(p["args"]) if "args" in p else (len(p["inputs"][0]) if p.get("inputs") else 2)

        res = behavioral_equiv(
            original,
            candidate_code=candidate_code,
            expr=expr,
            nargs=nargs,
            inputs=p.get("inputs"),
            arch=arch,
            bits=bits,
            arg_regs=arg_regs,
            ret_reg=ret_reg,
        )
        evidence["tested_inputs"] = res.get("tested", 0)
        evidence["candidate"] = ("code" if candidate_code is not None else f"expr:{expr}")
        evidence["weight_basis"] = {"inputs_tested": res.get("tested", 0), "entropy_norm": round(_entropy_norm(original), 3)}
        status = res["status"]
        if status == "equivalent":
            return VERIFIED, evidence, res["detail"]
        if status == "refuted":
            evidence["counterexample"] = res["counterexample"]
            return REFUTED, evidence, res["detail"]
        return INCONCLUSIVE, evidence, res["detail"]

    def _check_prove_equiv(self, p: Dict[str, Any]):
        """Claim: two integer expressions are equal for ALL inputs (proof-grade, via Z3).

        Params: ``a``/``expr`` and ``b``/``candidate`` (expressions over x0, x1, ...),
        optional ``bits`` (default 64), ``args``. Used to verify an obfuscated
        expression simplifies correctly (MBA deobfuscation). Proven means no
        distinguishing input exists — stronger than sampling.
        """
        a = p.get("a", p.get("expr"))
        b = p.get("b", p.get("candidate"))
        if a is None or b is None:
            raise ClaimError("prove_equiv requires two expressions ('a'/'expr' and 'b'/'candidate')")
        bits = _as_int(p["bits"]) if "bits" in p else 64
        nvars = _as_int(p["args"]) if "args" in p else None
        res = prove_expr_equiv(str(a), str(b), nvars=nvars, bits=bits)
        evidence: Dict[str, Any] = {"a": str(a), "b": str(b), "bits": bits, "proof": "z3"}
        status = res["status"]
        if status == "proven":
            return VERIFIED, evidence, res["detail"]
        if status == "refuted":
            evidence["counterexample"] = res.get("counterexample")
            return REFUTED, evidence, res["detail"]
        return INCONCLUSIVE, evidence, res["detail"]

    def _check_exebench(self, p: Dict[str, Any]):
        """Claim: a candidate C source reproduces a set of recorded I/O pairs (ExeBench).

        ``record`` is ``{"name": ..., "test_cases": [{"input": [...], "expected": int}]}``
        (or a list of ``[input, expected]`` pairs); ``c_source`` is the candidate C
        program, optionally compiled with ``cc`` (default ``gcc``). The candidate is
        compiled (gated on a C compiler being present) and re-run against every test
        case; a pass is tested-not-proven, a single mismatch is a definite
        refutation with the failing case as witness. Complements the Unicorn
        ``behavior_equiv`` path for source-level reconstructions.
        """
        if "c_source" not in p:
            raise ClaimError("exebench requires 'c_source' (candidate C program)")
        record = p.get("record") or p.get("test_cases") or {}
        cc = str(p.get("cc", "gcc"))
        res = exebench_verify(record, str(p["c_source"]), cc=cc)
        evidence: Dict[str, Any] = {
            "candidate": "c_source",
            "cc": cc,
            "passed": res["passed"],
            "total": res["total"],
            "native_execution": True,  # compiled and run on the host (opt-in), not emulated
            "weight_basis": {"inputs_tested": res["passed"]},
        }
        if res["status"] == "pass":
            return VERIFIED, evidence, res["detail"]
        if res["status"] == "fail":
            evidence["failing_cases"] = res["failures"]
            return REFUTED, evidence, res["detail"]
        return INCONCLUSIVE, evidence, res["detail"]

    def _check_functions_equiv(self, p: Dict[str, Any]):
        """Claim: a candidate implementation computes the same as a reference implementation.

        ``candidate_c`` (or ``candidate``) is the implementation to check; ``reference_c`` (or
        ``reference``) is the trusted one — both compiled and run over shared inputs (generated,
        or ``inputs``), outputs compared. This is the source-level "did the rewrite preserve
        behaviour?" check, one step up from ``exebench`` (whose oracle is recorded I/O). A pass
        is *tested, not proven*; a mismatch is a refutation with the input and both outputs as
        witness. Runs native code — off unless ``REVERIFY_ALLOW_NATIVE_EXEC=1`` (sandboxed).
        """
        candidate = p.get("candidate") or p.get("candidate_c") or p.get("candidate_py")
        if not candidate:
            raise ClaimError("functions_equiv requires 'candidate' (the implementation to check)")
        reference = p.get("reference") or p.get("reference_c") or p.get("reference_py")
        record = p.get("record") or p.get("test_cases")
        if not reference and not record:
            raise ClaimError("functions_equiv requires 'reference' (a reference implementation) or 'record'")
        lang = str(p.get("lang", "c"))
        cc = str(p.get("cc", "gcc"))
        res = functions_equiv_verify(
            str(candidate), reference=str(reference) if reference else None,
            record=record if isinstance(record, dict) else None, lang=lang,
            nargs=int(p.get("nargs", 2)), inputs=p.get("inputs"), cc=cc)
        evidence: Dict[str, Any] = {
            "candidate": "candidate", "oracle": "reference" if reference else "record", "lang": lang, "cc": cc,
            "passed": res["passed"], "total": res["total"], "native_execution": True,
            "weight_basis": {"inputs_tested": res["passed"]},
        }
        if res["status"] == "pass":
            return VERIFIED, evidence, res["detail"]
        if res["status"] == "fail":
            evidence["failing_cases"] = res["failures"]
            return REFUTED, evidence, res["detail"]
        return INCONCLUSIVE, evidence, res["detail"]

    def _check_protobuf_field(self, p: Dict[str, Any]):
        """Claim: Protobuf ``field`` has wire ``type`` and optionally ``value``."""
        if "field" not in p:
            raise ClaimError("protobuf_field requires 'field'")
        field_no = _as_int(p["field"])
        evidence: Dict[str, Any] = {}
        if "data" in p:
            source = _clean_hex(p["data"])
            evidence["self_referential"] = self.data.find(source) == -1 if source else True
        elif "offset" in p:
            off, addr = self._resolve_offset(p)
            evidence["address"] = addr
            if off is None:
                return INCONCLUSIVE, evidence, addr.get("error", "bad address")
            length = _as_int(p["length"]) if "length" in p else 512
            source = self.data[off : off + length]
        else:
            source = self.data
        tree = ProtobufDissector.dissect(source)
        key = f"field_{field_no}"
        if key not in tree:
            evidence["present_fields"] = list(tree.keys())
            return REFUTED, evidence, "field not present"
        entries = tree[key]
        evidence.update({"field": key, "entries": entries})
        want_type = str(p["type"]).lower() if "type" in p else None
        if want_type is not None:
            types = {e.get("type") for e in entries}
            if want_type not in types:
                return REFUTED, evidence, f"types present: {sorted(t for t in types if t)}"
        if "value" in p:
            want = p["value"]
            if not any(_value_matches(e, want) for e in entries):
                return REFUTED, evidence, "no entry matches claimed value"
        return VERIFIED, evidence, "field matches"

    def _not_parseable(self, info):
        if info.format == "raw" or info.error:
            return INCONCLUSIVE, {"format": info.format, "error": info.error}, "not a parseable binary"
        return None

    def _check_import_present(self, p: Dict[str, Any]):
        """Claim: the binary imports ``function`` (optionally from ``lib``/``dll``). PE, ELF, Mach-O."""
        lib = p.get("lib", p.get("dll"))
        if "function" not in p and lib is None:
            raise ClaimError("import_present requires 'function' and/or 'lib'")
        info = self._binary()
        bad = self._not_parseable(info)
        if bad:
            return bad
        evidence = {
            "format": info.format,
            "backend": info.backend,
            "imported_libs": list(info.imports.keys()),
            "libraries": info.libraries,
        }
        func = str(p["function"]) if "function" in p else None
        lib_s = str(lib).lower() if lib is not None else None
        lib_known = lib_s is not None and (
            any(l.lower() == lib_s for l in info.imports) or any(l.lower() == lib_s for l in info.libraries)
        )
        if func is None:
            return (VERIFIED if lib_known else REFUTED), evidence, "library import check"
        if lib_s is not None and info.format == "PE":
            ok = info.has_import(func, lib=lib_s)
        else:
            ok = info.has_import(func) and (lib_s is None or lib_known)
        return (VERIFIED if ok else REFUTED), evidence, ("import present" if ok else "import absent")

    def _check_pe_import(self, p: Dict[str, Any]):
        """Backward-compatible alias of ``import_present``."""
        return self._check_import_present(p)

    def _check_export_present(self, p: Dict[str, Any]):
        """Claim: the binary exports symbol ``name``."""
        if "name" not in p:
            raise ClaimError("export_present requires 'name'")
        info = self._binary()
        bad = self._not_parseable(info)
        if bad:
            return bad
        ok = info.has_export(str(p["name"]))
        evidence = {"format": info.format, "backend": info.backend, "export_count": len(info.exports), "exports_sample": info.exports[:32]}
        return (VERIFIED if ok else REFUTED), evidence, ("export present" if ok else "export absent")

    def _check_section_present(self, p: Dict[str, Any]):
        """Claim: a section named ``name`` exists (optionally with ``virtual_address``)."""
        if "name" not in p:
            raise ClaimError("section_present requires 'name'")
        info = self._binary()
        bad = self._not_parseable(info)
        if bad:
            return bad
        name = str(p["name"])
        # Mach-O (and some ELF) binaries carry several sections with the same name in
        # different segments (__TEXT,__const and __DATA_CONST,__const): judge against all
        # of them, not the first one found — caught by the matrix benchmark on macOS.
        matches = [s for s in info.sections if s.name == name]
        evidence = {"format": info.format, "backend": info.backend, "sections": [s.name for s in info.sections]}
        if not matches:
            return REFUTED, evidence, "section absent"
        want = _as_int(p["virtual_address"]) if "virtual_address" in p else None
        sec = next((s for s in matches if want is None or s.virtual_address == want), None)
        evidence["candidates"] = [hex(s.virtual_address) for s in matches]
        if sec is None:
            return REFUTED, evidence, (f"section present but at a different virtual address "
                                       f"({', '.join(hex(s.virtual_address) for s in matches)})")
        evidence["section"] = {
            "virtual_address": hex(sec.virtual_address),
            "virtual_size": sec.virtual_size,
            "raw_size": sec.raw_size,
            "offset": sec.offset,
        }
        return VERIFIED, evidence, "section present"

    # -- semantic layer: function boundaries, call graph, xrefs (engine-derived) --

    def _semantic(self):
        """Engine-derived view (angr when installed, pure fallback otherwise); cached per verifier."""
        if self._sem_cache is None:
            self._sem_cache = semantic_view(self.data)
        return self._sem_cache

    def _sem_evidence(self, view) -> Dict[str, Any]:
        return {
            "engine": view.engine,
            "engine_version": view.version,
            "strength": ("DERIVED: recovered by static analysis, not read from the bytes"
                         if view.complete else "pure fallback: only the entry point and exports are known"),
        }

    def _rva_evidence(self, rva: int) -> Dict[str, Any]:
        b = self._binary()
        out: Dict[str, Any] = {"rva": hex(rva)}
        if b.image_base is not None:
            out["va"] = hex(b.image_base + rva)
        off = b.rva_to_offset(rva)
        if off is not None:
            out["file_offset"] = hex(off)
        return out

    def _sem_target(self, p: Dict[str, Any], key: str) -> Tuple[Optional[int], Dict[str, Any]]:
        """Resolve ``p[key]`` (an address in file/rva/va space, or a function/import name) to an RVA."""
        val = p[key]
        try:
            _as_int(val)
            numeric = True
        except (ValueError, TypeError):
            numeric = False
        if not numeric:
            rva = self._semantic().resolve_name(str(val))
            if rva is None:
                return None, {"name": str(val), "error": "no function or import with that name"}
            return rva, {"name": str(val), **self._rva_evidence(rva)}
        off, info = self._resolve_offset({"offset": val, "space": p.get("space", "file")})
        if "rva" not in info:
            return None, info
        return int(info["rva"], 16), info

    def _check_function_at(self, p: Dict[str, Any]):
        """Claim: a function starts at ``offset`` (or the function ``name`` exists). ``observe`` reads it."""
        if "offset" not in p and "name" not in p:
            raise ClaimError("function_at requires 'offset' or 'name'")
        info = self._binary()
        bad = self._not_parseable(info)
        if bad:
            return bad
        view = self._semantic()
        evidence = self._sem_evidence(view)
        if "offset" in p:
            rva, addr = self._sem_target(p, "offset")
            evidence["address"] = addr
            if rva is None:
                return INCONCLUSIVE, evidence, "address is not inside any section"
        else:
            rva = view.resolve_name(str(p["name"]))
            if rva is None:
                if not view.complete:
                    return INCONCLUSIVE, evidence, f"'{p['name']}' is not an export or entry point; naming other functions needs an analysis engine ({SEMANTIC_HINT})"
                evidence["known_names_sample"] = view.names_sample()
                return REFUTED, evidence, f"no function or import named '{p['name']}'"
            evidence["address"] = self._rva_evidence(rva)
        f = view.function_at(rva)
        if f is not None:
            evidence["function"] = f.describe(view)
            if "name" in p and "offset" in p and str(p["name"]).strip().lower() != f.name.lower():
                return REFUTED, evidence, f"a function starts here but it is named {f.name}, not {p['name']}"
            if p.get("observe"):
                return OBSERVED, evidence, f"function {f.name} read"
            return VERIFIED, evidence, f"function {f.name} starts here"
        if not view.complete:
            return INCONCLUSIVE, evidence, f"not an export or the entry point; a function boundary here needs an analysis engine ({SEMANTIC_HINT})"
        cont = view.function_containing(rva)
        if cont is not None:
            evidence["inside_function"] = cont.describe(view)
            return REFUTED, evidence, f"no function starts here; the address is inside {cont.name}, which starts at rva {hex(cont.rva)}"
        near = view.nearest_function_start(rva)
        if near is not None:
            nf, dist = near
            evidence["nearest_function"] = {**nf.brief(view), "distance": dist}
            return REFUTED, evidence, f"no function starts here; the nearest function start is {nf.name} at rva {hex(nf.rva)} ({dist:+d} bytes)"
        return REFUTED, evidence, "no function starts here"

    def _check_calls(self, p: Dict[str, Any]):
        """Claim: the function containing ``from`` calls ``to`` (a function, or an import by name)."""
        if "from" not in p:
            raise ClaimError("calls requires 'from' (and 'to' unless observing)")
        info = self._binary()
        bad = self._not_parseable(info)
        if bad:
            return bad
        view = self._semantic()
        evidence = self._sem_evidence(view)
        src_rva, src_addr = self._sem_target(p, "from")
        evidence["from"] = src_addr
        if src_rva is None:
            if "error" in src_addr and "name" in src_addr and not view.complete:
                return INCONCLUSIVE, evidence, f"call graph needs an analysis engine ({SEMANTIC_HINT})"
            return (REFUTED if "name" in src_addr else INCONCLUSIVE), evidence, str(src_addr.get("error", "'from' could not be resolved"))
        if not view.complete:
            return INCONCLUSIVE, evidence, f"call graph needs an analysis engine ({SEMANTIC_HINT})"
        src = view.function_containing(src_rva)
        if src is None:
            return REFUTED, evidence, "'from' is not inside any recovered function"
        evidence["from_function"] = src.brief(view)
        callees = view.callees_of(src.rva)
        evidence["callees"] = [c.brief(view) for c in callees[:40]]
        evidence["callee_count"] = len(callees)
        if p.get("observe") or "to" not in p:
            return OBSERVED, evidence, f"{src.name} has {len(callees)} callees"
        dst_rva, dst_addr = self._sem_target(p, "to")
        evidence["to"] = dst_addr
        if dst_rva is None:
            if "name" in dst_addr:
                return REFUTED, evidence, f"no function or import named '{p['to']}' in this binary"
            return INCONCLUSIVE, evidence, "'to' address is not inside any section"
        dst = view.function_at(dst_rva) or view.function_containing(dst_rva)
        if dst is None:
            return REFUTED, evidence, "'to' is not a recovered function"
        evidence["to_function"] = dst.brief(view)
        if (src.rva, dst.rva) in view.edges:
            return VERIFIED, evidence, f"{src.name} calls {dst.name}"
        return REFUTED, evidence, f"{src.name} does not call {dst.name}; its callees are listed in the evidence"

    def _check_references(self, p: Dict[str, Any]):
        """Claim: code references the data/code at ``to`` (optionally from the function containing ``from``)."""
        if "to" not in p:
            raise ClaimError("references requires 'to' (the referenced address, e.g. a string)")
        info = self._binary()
        bad = self._not_parseable(info)
        if bad:
            return bad
        view = self._semantic()
        evidence = self._sem_evidence(view)
        dst_rva, dst_addr = self._sem_target(p, "to")
        evidence["to"] = dst_addr
        if dst_rva is None:
            return INCONCLUSIVE, evidence, str(dst_addr.get("error", "'to' could not be resolved"))
        if not view.complete:
            return INCONCLUSIVE, evidence, f"cross-references need an analysis engine ({SEMANTIC_HINT})"
        refs = view.references_to(dst_rva)
        evidence["referenced_by"] = [
            {"function": r.get("function"), "function_rva": hex(r["function_rva"]) if r.get("function_rva") is not None else None,
             "from_rva": hex(r["from_rva"]) if r.get("from_rva") is not None else None, "type": r.get("type")}
            for r in refs[:40]
        ]
        evidence["reference_count"] = len(refs)
        if p.get("observe"):
            return OBSERVED, evidence, f"{len(refs)} references read"
        if "from" not in p:
            return (VERIFIED if refs else REFUTED), evidence, (f"referenced from {len(refs)} places" if refs else "no code references this address")
        src_rva, src_addr = self._sem_target(p, "from")
        evidence["from"] = src_addr
        if src_rva is None:
            return (REFUTED if "name" in src_addr else INCONCLUSIVE), evidence, str(src_addr.get("error", "'from' could not be resolved"))
        src = view.function_containing(src_rva)
        if src is None:
            return REFUTED, evidence, "'from' is not inside any recovered function"
        evidence["from_function"] = src.brief(view)
        if any(r.get("function_rva") == src.rva for r in refs):
            return VERIFIED, evidence, f"{src.name} references rva {hex(dst_rva)}"
        return REFUTED, evidence, f"{src.name} does not reference rva {hex(dst_rva)}; the referencing functions are listed"

    def _check_reachable_from_entry(self, p: Dict[str, Any]):
        """Claim: the function at/containing ``offset`` (or named ``name``) is reachable from the entry point."""
        if "offset" not in p and "name" not in p:
            raise ClaimError("reachable_from_entry requires 'offset' or 'name'")
        info = self._binary()
        bad = self._not_parseable(info)
        if bad:
            return bad
        view = self._semantic()
        evidence = self._sem_evidence(view)
        key = "offset" if "offset" in p else "name"
        rva, addr = self._sem_target(p, key)
        evidence["address"] = addr
        if rva is None:
            return (REFUTED if key == "name" and view.complete else INCONCLUSIVE), evidence, str(addr.get("error", "address could not be resolved"))
        if not view.complete:
            return INCONCLUSIVE, evidence, f"reachability needs an analysis engine ({SEMANTIC_HINT})"
        ef = view.function_at(view.entry_rva) if view.entry_rva is not None else None
        evidence["entry"] = ef.brief(view) if ef else None
        evidence["reachable_functions"] = len(view.reachable)
        f = view.function_containing(rva)
        if f is None:
            return REFUTED, evidence, "address is not inside any recovered function"
        evidence["function"] = f.brief(view)
        if f.rva in view.reachable:
            return VERIFIED, evidence, f"{f.name} is reachable from the entry point"
        return REFUTED, evidence, f"{f.name} is not reachable from the entry point in the call graph"

    # -- helpers ------------------------------------------------------------

    def _result(self, claim: Claim, verdict: str, evidence: Dict[str, Any], detail: str) -> Dict[str, Any]:
        return {
            "id": claim.id,
            "kind": claim.kind,
            "note": claim.note,
            "depends_on": list(claim.depends_on),
            "verdict": verdict,
            "detail": detail,
            "evidence": evidence,
            "params": claim.params,
        }


# ---------------------------------------------------------------------------
# Dependencies, weighting and summary (module-level so the agent can rescore)
# ---------------------------------------------------------------------------

def _apply_dependencies(results: List[Dict[str, Any]]) -> None:
    """A claim whose dependency was refuted/invalidated cannot stand; mark it."""
    verdicts = {r["id"]: r["verdict"] for r in results if r.get("id")}
    for _ in range(2):  # two passes settle short chains
        for r in results:
            if r["verdict"] in (INVALIDATED,):
                continue
            bad = [d for d in r.get("depends_on", []) if verdicts.get(d) in (REFUTED, INVALIDATED)]
            if bad:
                r["verdict_before_invalidation"] = r["verdict"]
                r["verdict"] = INVALIDATED
                r["detail"] = f"depends on refuted claim(s): {', '.join(bad)}"
                if r.get("id"):
                    verdicts[r["id"]] = INVALIDATED


def claim_key(kind: str, params: Dict[str, Any]) -> str:
    """Stable identity of a claim for de-duplication."""
    clean = {k: v for k, v in params.items() if k != "observe"}
    return f"{kind}:{json.dumps(clean, sort_keys=True, default=str)}"


def derivable_from_facts(result: Dict[str, Any], facts: Optional[Dict[str, Any]]) -> bool:
    """True when the claim restates something the model was already shown."""
    if not facts:
        return False
    kind, p = result["kind"], result.get("params", {})
    first_hex = str(facts.get("first_32_bytes_hex", "") or "")
    shown_bytes = len(first_hex) // 2
    if kind in ("bytes_at", "u16_at", "u32_at", "u64_at"):
        if str(p.get("space", "file")).lower() != "file":
            return False
        try:
            off = _as_int(p.get("offset", 0))
        except (ValueError, TypeError):
            return False
        size = {"u16_at": 2, "u32_at": 4, "u64_at": 8}.get(kind)
        if size is None:
            size = len(_clean_hex(p["expected"])) if p.get("expected") else 0
        if off >= 0 and off + size <= shown_bytes:
            return True
        obs = (facts.get("observed") or {}).get(f"{kind}@{hex(off)}")
        if obs is not None and "expected" in p:
            want = p["expected"]
            try:
                if kind == "bytes_at":
                    return _clean_hex(want).hex() == str(obs).lower()
                return _as_int(want) == _as_int(obs)
            except (ValueError, TypeError):
                return False
        return False
    binary = facts.get("binary") or {}
    if kind == "string_present":
        return str(p.get("value")) in (facts.get("top_strings") or [])
    if kind == "section_present":
        return str(p.get("name")) in (binary.get("sections") or [])
    if kind in ("import_present", "pe_import"):
        imps = facts.get("imports") or {}
        fn = p.get("function")
        lib = p.get("lib", p.get("dll"))
        if fn and any(fn in (v or []) for v in imps.values()):
            return True
        if fn is None and lib and any(str(lib).lower() == str(k).lower() for k in imps):
            return True
        return False
    if kind == "export_present":
        return str(p.get("name")) in (facts.get("exports") or [])
    if kind == "pattern_present" and "offset" not in p and "count" not in p:
        pat = str(p.get("pattern", "")).replace(" ", "").lower()
        return bool(pat) and "?" not in pat and pat in first_hex.lower()
    return False


def base_weight(result: Dict[str, Any]) -> float:
    """How much a claim says (0..1), measured from the binary itself where possible.

    For content claims the weight is driven by ``evidence.weight_basis``: how
    often the expected content occurs in this binary (rarity) and how much
    entropy it has. Zero padding, ubiquitous prologues and patterns that match
    hundreds of places therefore weigh almost nothing even though they verify.
    For emulation the claim must actually execute (steps) over non-degenerate
    code (entropy). Structural kinds (imports/exports/sections/protobuf) keep a
    fixed tier until corpus base rates exist.
    """
    kind, p, ev = result["kind"], result.get("params", {}), result.get("evidence", {}) or {}
    if ev.get("self_referential"):
        return 0.0
    basis = ev.get("weight_basis") or {}
    occ = max(1, int(basis.get("occurrences", 1) or 1))
    rarity = (1.0 / occ) ** 0.5
    ent = max(0.0, float(basis.get("entropy_norm", 1.0))) ** 0.5

    if kind in ("bytes_at", "u16_at", "u32_at", "u64_at"):
        n = int(basis.get("length") or 0)
        if n == 0:
            try:
                n = len(_clean_hex(p["expected"])) if p.get("expected") else {"u16_at": 2, "u32_at": 4, "u64_at": 8}.get(kind, 0)
            except ValueError:
                n = 0
        return min(1.0, 0.3 + 0.1 * n) * rarity * ent
    if kind == "instructions":
        w = 0.8 if str(p.get("mode", "exact")) == "exact" else 0.4
        w = min(1.0, w + (0.1 if p.get("operands") else 0.0))
        return w * rarity
    if kind == "emulate_result":
        base = 1.0 if "offset" in p else 0.5
        steps = int(basis.get("steps", 0) or 0)
        return base * min(1.0, steps / 2.0) * ent
    if kind == "behavior_equiv":
        # behavioral equivalence is the strongest claim; scale by inputs tested and non-degenerate code
        base = 1.0 if "offset" in p else 0.5
        tested = int(basis.get("inputs_tested", 0) or 0)
        return base * min(1.0, tested / 8.0) * ent
    if kind in ("exebench", "functions_equiv"):
        # tested by native re-execution (recorded I/O, or against a reference); scale by cases passed
        tested = int(basis.get("inputs_tested", 0) or 0)
        return min(1.0, tested / 8.0)
    if kind == "prove_equiv":
        # proof-grade (for all inputs); zero if the two sides are the same expression
        a = str(p.get("a", p.get("expr", "")))
        b = str(p.get("b", p.get("candidate", "")))
        return 0.0 if _norm_ops(a) == _norm_ops(b) else 1.0
    if kind == "pattern_present":
        return (0.7 if ("offset" in p or "count" in p) else 0.4) * rarity
    if kind == "string_present":
        return (0.6 if "offset" in p else 0.4) * rarity
    # semantic kinds: engine-derived, fixed tier (relational claims say more than existence)
    if kind == "function_at":
        return 0.4 if ("name" in p and "offset" in p) else 0.3
    if kind == "calls":
        return 0.4
    if kind == "references":
        return 0.4 if "from" in p else 0.3
    if kind == "reachable_from_entry":
        return 0.3
    # structural kinds: fixed tier until corpus base rates exist
    if kind == "protobuf_field":
        return 0.6 if "value" in p else 0.3
    if kind in ("import_present", "pe_import", "export_present"):
        return 0.3
    if kind == "section_present":
        return 0.3 if "virtual_address" in p else 0.2
    return 0.3


def summarize(
    results: List[Dict[str, Any]],
    facts: Optional[Dict[str, Any]] = None,
    min_information: float = 1.0,
) -> Dict[str, Any]:
    """Weight results (CORE-style) and build the report.

    Sets ``weight``, ``trivial``, ``duplicate`` on each result in place; the
    agent may set ``echoed`` beforehand to zero a claim that merely copied the
    tools' previous output.
    """
    seen = set()
    for r in results:
        key = claim_key(r["kind"], r.get("params", {}))
        r["duplicate"] = key in seen
        seen.add(key)
        r["trivial"] = derivable_from_facts(r, facts)
        if r["verdict"] in (OBSERVED, INVALIDATED) or r["duplicate"] or r["trivial"] or r.get("echoed") or r.get("known"):
            r["weight"] = 0.0  # known = already in the ledger: restating it says nothing new
        else:
            r["weight"] = round(base_weight(r), 3)

    counts = {VERIFIED: 0, REFUTED: 0, INCONCLUSIVE: 0, OBSERVED: 0, INVALIDATED: 0}
    for r in results:
        counts[r["verdict"]] = counts.get(r["verdict"], 0) + 1
    scored = [r for r in results if r["verdict"] in (VERIFIED, REFUTED, INCONCLUSIVE)]
    information = round(sum(r["weight"] for r in results if r["verdict"] == VERIFIED), 3)
    weighted_total = round(sum(base_weight(r) for r in scored if not (r["duplicate"] or r["trivial"] or r.get("echoed") or r.get("known"))), 3)
    trivial_verified = sum(1 for r in results if r["verdict"] == VERIFIED and r["weight"] == 0.0)
    total = len(results)
    trustworthy = counts[REFUTED] == 0 and counts[INCONCLUSIVE] == 0 and counts[INVALIDATED] == 0 and counts[VERIFIED] > 0
    informative = information >= float(min_information)
    return {
        "total_claims": total,
        "verified": counts[VERIFIED],
        "refuted": counts[REFUTED],
        "inconclusive": counts[INCONCLUSIVE],
        "observed": counts[OBSERVED],
        "invalidated": counts[INVALIDATED],
        "grounded_ratio": round(counts[VERIFIED] / len(scored), 4) if scored else 0.0,
        "information": information,
        "grounded_score": round(information / weighted_total, 4) if weighted_total else 0.0,
        "trivial_verified": trivial_verified,
        "duplicates": sum(1 for r in results if r["duplicate"]),
        "echoed": sum(1 for r in results if r.get("echoed")),
        "known": sum(1 for r in results if r.get("known")),
        "min_information": float(min_information),
        "trustworthy": trustworthy,
        "informative": informative,
        "grounded": trustworthy and informative,
        "results": results,
    }


def _is_subsequence(needle: List[str], haystack: List[str]) -> bool:
    it = iter(haystack)
    return all(any(x == n for x in it) for n in needle)


def _value_matches(entry: Dict[str, Any], want: Any) -> bool:
    if "value" not in entry:
        return False
    ev = entry["value"]
    if isinstance(want, str) and isinstance(ev, str):
        return ev == want
    try:
        return _as_int(ev) == _as_int(want)
    except (ValueError, TypeError):
        return str(ev) == str(want)


def verify_claims(
    data: bytes,
    claims: List[Dict[str, Any]],
    facts: Optional[Dict[str, Any]] = None,
    min_information: float = 1.0,
) -> Dict[str, Any]:
    """Convenience: verify a list of plain-dict claims against ``data``."""
    verifier = Verifier(data)
    parsed = [Claim.from_dict(c) for c in claims]
    return verifier.verify_all(parsed, facts=facts, min_information=min_information)
