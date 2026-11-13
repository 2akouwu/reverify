#!/usr/bin/env python3
"""Unified CLI entrypoint for Reverse Engineering Toolkit."""

import argparse
import json
import os
import re
import sys
from pathlib import Path
from typing import Any, Dict, List

# Add parent directory to path so re_toolkit imports work when executed directly
toolkit_root = Path(__file__).resolve().parent.parent
if str(toolkit_root) not in sys.path:
    sys.path.insert(0, str(toolkit_root))

try:  # installed package (e.g. the ``reverify`` console script)
    from .pe_parser import PEParser, BinaryParseError
    from .disasm import Disassembler, pattern_scan, create_patch
    from .emulator import MicroEmulator, make_emulator
    from .binary import parse_binary
    from .apk import inspect_apk
    from .backends import backend_report
    from .protocol_parser import ProtobufDissector, TLVDissector, format_hexdump
    from .frida_bridge import FridaScriptGenerator
    from .boundary_auditor import run_full_security_audit, PathBoundaryAuditor, NetworkBoundaryAuditor
    from .verifier import Verifier, Claim
    from .agent import ReconstructionAgent, openai_proposer, demo_proposer
    from .ledger import Ledger, context_for_directory, hook_config, list_ledgers, ledger_dir
    from .semantic import semantic_view
    from .rollover import Orchestrator, MockDriver, make_driver, demo_scripts
    from .rollover_harness import main as claude_rollover_main
    from .exebench import functions_equiv_verify
except ImportError:  # run directly as a script: ``python reverify/cli.py ...``
    from pe_parser import PEParser, BinaryParseError
    from disasm import Disassembler, pattern_scan, create_patch
    from emulator import MicroEmulator, make_emulator
    from binary import parse_binary
    from apk import inspect_apk
    from backends import backend_report
    from protocol_parser import ProtobufDissector, TLVDissector, format_hexdump
    from frida_bridge import FridaScriptGenerator
    from boundary_auditor import run_full_security_audit, PathBoundaryAuditor, NetworkBoundaryAuditor
    from verifier import Verifier, Claim
    from agent import ReconstructionAgent, openai_proposer, demo_proposer
    from ledger import Ledger, context_for_directory, hook_config, list_ledgers, ledger_dir
    from semantic import semantic_view
    from rollover import Orchestrator, MockDriver, make_driver, demo_scripts
    from rollover_harness import main as claude_rollover_main
    from exebench import functions_equiv_verify


def load_input_bytes(input_val: str, offset: int = 0, length: int = 0) -> bytes:
    """Load bytes from a hex string or from a file path."""
    if os.path.exists(input_val):
        with open(input_val, "rb") as f:
            if offset > 0:
                f.seek(offset)
            if length > 0:
                return f.read(length)
            return f.read()
    else:
        # Treat as hex string
        clean_hex = "".join(input_val.split()).replace("0x", "").replace("0X", "")
        return bytes.fromhex(clean_hex)


def extract_strings(data: bytes, min_len: int = 4) -> List[Dict[str, Any]]:
    """Extract ASCII and UTF-16LE strings with file offsets."""
    results = []
    # ASCII strings
    ascii_re = re.compile(rb"[\x20-\x7e]{" + str(min_len).encode() + rb",}")
    for m in ascii_re.finditer(data):
        results.append({
            "offset": hex(m.start()),
            "type": "ASCII",
            "string": m.group().decode("latin1", errors="ignore"),
        })
    # Unicode (UTF-16LE) strings
    uni_re = re.compile(rb"(?:[\x20-\x7e]\x00){" + str(min_len).encode() + rb",}")
    for m in uni_re.finditer(data):
        try:
            s = m.group().decode("utf-16le", errors="ignore")
            results.append({
                "offset": hex(m.start()),
                "type": "UTF-16LE",
                "string": s,
            })
        except Exception:
            pass
    return sorted(results, key=lambda x: int(x["offset"], 16))


def auto_triage(data: bytes, filename: str = "") -> Dict[str, Any]:
    """Auto-detect binary format and extract top-level metadata."""
    report: Dict[str, Any] = {"filename": filename, "size": len(data), "magic": data[:4].hex()}
    info = parse_binary(data)
    if info.format in ("PE", "ELF", "MachO"):
        labels = {"PE": "Windows PE Binary (EXE/DLL/SYS)", "ELF": "Linux ELF Binary", "MachO": "Mach-O Binary"}
        report["type"] = labels[info.format]
        report["binary"] = info.summary()
        report["sections"] = [s.name for s in info.sections]
        report["imports"] = info.imports
        report["exports"] = info.exports[:25]
        if info.format == "PE":
            report["pe_summary"] = info.summary()  # backward-compatible key
        if info.error:
            report["parse_error"] = info.error
    elif data.startswith(b"PK\x03\x04"):
        apk = inspect_apk(data)
        if apk.get("is_apk"):
            report["type"] = "Android APK"
            report["apk"] = apk
        else:
            report["type"] = "ZIP Archive / Package"
    else:
        report["type"] = "Raw Binary / Memory Dump / Protocol Stream"
        # Try Protobuf
        pb = ProtobufDissector.dissect(data[:512])
        if pb and not any("error" in item for item in pb):
            report["protobuf_preview"] = pb[:5]
    # Extract top strings preview
    strings = extract_strings(data[:65536], min_len=5)
    report["top_strings"] = [s["string"] for s in strings[:15]]
    return report


def cmd_parse_pe(args: argparse.Namespace) -> None:
    data = load_input_bytes(args.file)
    parser = PEParser(data)
    if args.json:
        out = {
            "summary": parser.summary(),
            "sections": parser.sections,
            "imports": parser.imports,
            "exports": parser.exports,
        }
        print(json.dumps(out, indent=2, ensure_ascii=False))
    else:
        summary = parser.summary()
        print("=== PE Binary Summary ===")
        print(f"Format:       {summary['format']} ({summary['machine']})")
        print(f"64-bit:       {summary['is_64bit']}")
        print(f"EntryPoint:   {summary['entrypoint']}")
        print(f"ImageBase:    {summary['image_base']}")
        print(f"Sections:     {', '.join(summary['sections'])}")
        print(f"Imported DLLs: {', '.join(summary['imported_dlls'])}")
        print(f"Exports:      {summary['export_count']} exported symbols")


def cmd_disasm(args: argparse.Namespace) -> None:
    data = load_input_bytes(args.target, offset=args.offset, length=args.length)
    disasm = Disassembler(arch=args.arch)
    instructions = disasm.disassemble(data, base_address=args.base)
    if args.json:
        print(json.dumps([ins.to_dict() for ins in instructions], indent=2))
    else:
        for ins in instructions:
            print(ins)


def cmd_pattern_scan(args: argparse.Namespace) -> None:
    data = load_input_bytes(args.target)
    matches = pattern_scan(data, args.pattern)
    results = [{"offset": hex(m), "address": hex(args.base + m)} for m in matches]
    if args.json:
        print(json.dumps(results, indent=2))
    else:
        print(f"[+] Found {len(matches)} matches for pattern '{args.pattern}':")
        for r in results:
            print(f"  Offset: {r['offset']} | Address: {r['address']}")


def cmd_strings(args: argparse.Namespace) -> None:
    data = load_input_bytes(args.file)
    strings = extract_strings(data, min_len=args.min_len)
    if args.json:
        print(json.dumps(strings, indent=2, ensure_ascii=False))
    else:
        for s in strings:
            print(f"{s['offset']} [{s['type']}]: {s['string']}")


def cmd_diff_patch(args: argparse.Namespace) -> None:
    orig = load_input_bytes(args.orig)
    patched = load_input_bytes(args.patched)
    patches = create_patch(orig, patched, base_address=args.base)
    if args.json:
        print(json.dumps(patches, indent=2))
    else:
        print(f"[+] Found {len(patches)} patch differences:")
        for p in patches:
            print(f"  Offset: {p['offset']} ({p['length']} bytes): {p['original_bytes']} -> {p['patched_bytes']}")


def cmd_auto(args: argparse.Namespace) -> None:
    data = load_input_bytes(args.target)
    filename = os.path.basename(args.target) if os.path.exists(args.target) else "raw_input"
    report = auto_triage(data, filename=filename)
    if args.json:
        print(json.dumps(report, indent=2, ensure_ascii=False))
    else:
        print(f"=== Auto-Triage: {report.get('filename')} ({report.get('size')} bytes) ===")
        print(f"Detected Type: {report.get('type')}")
        if "binary" in report:
            b = report["binary"]
            print(f"Architecture: {b['arch']} ({b['bits']}-bit)  [parser: {b['backend']}]")
            print(f"Sections: {', '.join(report.get('sections', []))}")
            print(f"Imported libs: {', '.join(b.get('imported_libs', []))}")
        if "apk" in report:
            _print_apk_report(report["apk"])
        if "top_strings" in report and report["top_strings"]:
            print(f"Strings Preview: {', '.join(report['top_strings'][:8])}")


def cmd_decode_protobuf(args: argparse.Namespace) -> None:
    data = load_input_bytes(args.target)
    tree = ProtobufDissector.dissect(data)
    print(json.dumps(tree, indent=2, ensure_ascii=False))


def cmd_decode_tlv(args: argparse.Namespace) -> None:
    data = load_input_bytes(args.target)
    tlv_list = TLVDissector.dissect(data, type_len=args.type_len, length_len=args.len_len)
    print(json.dumps(tlv_list, indent=2, ensure_ascii=False))


def cmd_emulate(args: argparse.Namespace) -> None:
    data = load_input_bytes(args.code)
    emu = make_emulator(arch=args.arch, prefer=args.backend)
    emu.load_code(data, base_address=args.base)
    state = emu.run(max_steps=args.max_steps)
    print(json.dumps(state, indent=2, ensure_ascii=False))


def cmd_parse(args: argparse.Namespace) -> None:
    data = load_input_bytes(args.file)
    info = parse_binary(data, prefer=args.backend)
    if args.json:
        print(json.dumps(info.to_dict(), indent=2, ensure_ascii=False, default=str))
    else:
        s = info.summary()
        print(f"=== {s['format']} ({s['arch']}, {s['bits']}-bit)  [parser: {s['backend']}] ===")
        print(f"EntryPoint:   {s['entrypoint']}")
        print(f"ImageBase:    {s['image_base']}")
        print(f"Sections:     {', '.join(s['sections'])}")
        print(f"Imports:      {s['import_count']} functions from {len(s['imported_libs'])} libs")
        for lib, funcs in list(info.imports.items())[:12]:
            print(f"  {lib}: {', '.join(funcs[:8])}{' ...' if len(funcs) > 8 else ''}")
        print(f"Exports:      {s['export_count']}")
        if s.get("error"):
            print(f"Note:         {s['error']}")


def _print_apk_report(report: Dict[str, Any]) -> None:
    manifest = report.get("manifest") or {}
    print(f"=== APK: {report.get('size', 0)} bytes, {report.get('entries', 0)} entries ===")
    print(f"Package:      {manifest.get('package')}")
    print(f"Version:      {manifest.get('version_name')} (code {manifest.get('version_code')})")
    print(f"SDK:          min {manifest.get('min_sdk')} / target {manifest.get('target_sdk')}")
    permissions = manifest.get("permissions") or []
    print(f"Permissions:  {len(permissions)}{': ' + ', '.join(permissions) if permissions else ''}")
    activities = manifest.get("activities") or []
    for activity in activities[:12]:
        categories = []
        for intent_filter in activity.get("intent_filters", []):
            categories.extend(intent_filter.get("categories", []))
        suffix = f" [{', '.join(categories)}]" if categories else ""
        print(f"  activity:   {activity.get('resolved_name')}{suffix}")
    if len(activities) > 12:
        print(f"  ... {len(activities) - 12} more activities")
    for dex in report.get("dex", []):
        if dex.get("error"):
            print(f"DEX:          {dex.get('name')}: {dex['error']}")
        else:
            print(f"DEX:          {dex.get('name')}: {dex.get('class_count')} classes, {dex.get('method_count')} methods")
    signing = report.get("signing") or {}
    schemes = signing.get("schemes") or []
    if signing.get("error"):
        print(f"Signing:      unavailable: {signing['error']}")
    else:
        print(f"Signing:      {', '.join(schemes) if schemes else 'none'}")
    for cert in signing.get("certificates", []):
        print(f"  cert SHA-256: {cert['sha256']} ({', '.join(cert.get('schemes', []))})")
    for cert in signing.get("chain_certificates", []):
        print(f"  chain SHA-256: {cert['sha256']} ({', '.join(cert.get('schemes', []))})")
    for scheme in ("v1", "v2", "v3", "v3.1"):
        for error in (signing.get(scheme) or {}).get("errors", []):
            print(f"  signing note ({scheme}): {error}")
    if report.get("manifest_error"):
        print(f"Manifest note: {report['manifest_error']}")
    if report.get("error"):
        print(f"APK note:      {report['error']}")


def cmd_parse_apk(args: argparse.Namespace) -> None:
    data = load_input_bytes(args.file)
    report = inspect_apk(data)
    if args.json:
        print(json.dumps(report, indent=2, ensure_ascii=False))
    elif not report.get("is_apk"):
        print("Not an APK: expected a ZIP containing AndroidManifest.xml and classes*.dex")
    else:
        _print_apk_report(report)


def cmd_backends(args: argparse.Namespace) -> None:
    rep = backend_report()
    if args.json:
        print(json.dumps(rep, indent=2))
    else:
        print("=== Reverify backends ===")
        for k in ("disassembly", "emulation", "binary_parsing", "proof", "semantic"):
            v = rep.get(k) or {}
            ver = f" {v['version']}" if v.get("version") else ""
            print(f"{k:<16} {v.get('engine', '?')}{ver}")
        print(f"full fidelity:   {rep['full_fidelity']}")
        if rep["install_hint"]:
            print(f"upgrade:         {rep['install_hint']}")


def cmd_gen_hook(args: argparse.Namespace) -> None:
    script = FridaScriptGenerator.generate_function_hook(
        target_symbol=args.symbol,
        module_name=args.module,
        arg_count=args.args_count,
        log_backtrace=args.backtrace,
        replace_return=args.replace_ret,
    )
    if args.output:
        with open(args.output, "w", encoding="utf-8") as f:
            f.write(script)
        print(f"[+] Hook script saved to {args.output}")
    else:
        print(script)


def cmd_hexdump(args: argparse.Namespace) -> None:
    data = load_input_bytes(args.target, offset=args.offset, length=args.length)
    print(format_hexdump(data, base_address=args.base))


def cmd_reconstruct(args: argparse.Namespace) -> None:
    data = load_input_bytes(args.target)
    if args.mock:
        propose = demo_proposer(data)
    else:
        propose = openai_proposer(
            model=args.model, base_url=args.base_url, api_key=args.api_key, temperature=args.temperature
        )
    ledger = None if args.no_ledger else (args.ledger or os.environ.get("REVERIFY_LEDGER_DIR") or ".reverify")
    agent = ReconstructionAgent(
        data, propose, max_rounds=args.rounds, samples=args.samples, min_information=args.min_information,
        max_facts=args.max_facts, ledger=ledger, resume=not args.fresh, prompt_budget=args.prompt_budget,
        session=args.session, file_path=args.target if os.path.exists(args.target) else None,
    )
    result = agent.run(args.goal)

    if args.json:
        print(json.dumps(result, indent=2, ensure_ascii=False))
    else:
        print("=== Reverify: closed reconstruction loop ===")
        print(f"Goal: {result['goal']}")
        if result["resumed_facts"]:
            print(f"Resumed {result['resumed_facts']} grounded facts from the ledger ({result['ledger_path']})")
        for h in result["history"]:
            rep = h["report"]
            compacted = f" compacted[{','.join(h['compaction'])}]" if h.get("compaction") else ""
            print(
                f"  round {h['round']}: {rep['verified']} verified ({rep['trivial_verified']} trivial), "
                f"{rep['refuted']} refuted, {rep['inconclusive']} inconclusive, {rep['observed']} observed, "
                f"{rep['invalidated']} invalidated | information {rep['information']}/{rep['min_information']} "
                f"| echoed {h['echoed']} known {h.get('known', 0)} attrition {h['attrition']} "
                f"| prompt {h.get('prompt_chars', 0)} chars{compacted}"
            )
        final = result["final_report"]
        if result["grounded"]:
            status = "GROUNDED"
        elif final and final["trustworthy"] and not final["informative"]:
            status = "NOT grounded: every verified claim was trivial (restates the facts)"
        else:
            status = "NOT grounded"
        print(f"\n{status} after {result['rounds_used']} round(s).")
        if final:
            _print_results(final["results"])
        led = result["ledger"]
        if result["ledger_path"]:
            print(
                f"\nLedger: {result['ledger_path']} - {led['facts']} facts ({led['proven']} proven, "
                f"{led['tested']} tested, {led['observed']} observed), {led['refuted']} refuted. "
                f"Survives /clear, compaction and restarts; `reverify ledger {args.target}` shows it."
            )
    if not result["grounded"]:
        sys.exit(2)


def cmd_functions(args: argparse.Namespace) -> None:
    data = load_input_bytes(args.target)
    view = semantic_view(data)
    funcs = view.list_functions(limit=args.limit, imports=args.imports)
    if args.json:
        print(json.dumps({"summary": view.summary(), "functions": funcs}, indent=2, ensure_ascii=False))
        return
    s = view.summary()
    print(
        f"Engine: {s['engine']} {s['engine_version'] or ''} | functions {s['functions']} | "
        f"call edges {s['call_edges']} | xref targets {s['xref_targets']} | reachable from entry {s['reachable_from_entry']}"
    )
    if s.get("install_hint"):
        print(f"(partial: only the entry point and exports are known; {s['install_hint']} for boundaries, calls and xrefs)")
    for f in funcs:
        flag = "  export" if f.get("is_export") else ""
        print(f"  {f['rva']:>10}  {f['name']:<40} size {f.get('size', 0):>6}  blocks {f.get('blocks', 0):>4}{flag}")


def cmd_orchestrate(args: argparse.Namespace) -> None:
    data = load_input_bytes(args.target)
    if args.driver == "mock":
        driver = MockDriver(demo_scripts(data))
    else:
        driver = make_driver(args.driver, model=args.model)
    directory = None if args.no_ledger else (args.ledger or os.environ.get("REVERIFY_LEDGER_DIR") or ".reverify")
    orch = Orchestrator(
        data, driver, directory=directory, file_path=args.target if os.path.exists(args.target) else None,
        session_tokens=args.session_tokens, max_sessions=args.max_sessions, max_turns=args.max_turns,
        max_facts=args.max_facts, prompt_budget=args.prompt_budget, task_id=args.task,
    )
    result = orch.run(args.goal)
    if args.json:
        print(json.dumps(result, indent=2, ensure_ascii=False))
    else:
        print("=== Reverify: rollover controller (fresh context per session, verified hand-off) ===")
        print(f"Goal: {result['goal']}")
        for r in result["rollovers"]:
            print(f"  session {r.get('session')}: rollover — {r.get('reason')} (~{r.get('tokens')} tokens)")
        print(f"sessions used: {result['sessions']}  | done: {result['done']}")
        print(f"ledger: {result['facts']} facts, {result['refuted']} refuted"
              + (f"  ({result['ledger_path']})" if result.get("ledger_path") else ""))
        if result["established"]:
            print("established:")
            for e in result["established"][:12]:
                print(f"  - {e}")
        if result["known_false"]:
            print("known false:")
            for e in result["known_false"][:6]:
                print(f"  - {e}")
        cp = result["checkpoint"]
        if cp.get("decisions") or cp.get("todo"):
            print("hand-off (unverified, model-written): "
                  + "; ".join((cp.get("decisions") or [])[:4] + [f"todo: {t}" for t in (cp.get("todo") or [])[:4]]))
        if result.get("checkpoint_path"):
            print(f"checkpoint: {result['checkpoint_path']}")
        if result["summary"]:
            print(f"summary: {result['summary']}")
    if not result["done"]:
        sys.exit(2)


def cmd_ledger(args: argparse.Namespace) -> None:
    # Hook hosts read stdout as UTF-8; a legacy Windows code page must not garble or crash the hand-off.
    reconfigure = getattr(sys.stdout, "reconfigure", None)
    if callable(reconfigure):
        try:
            reconfigure(encoding="utf-8", errors="replace")
        except (ValueError, OSError):
            pass
    if args.hook:
        print(json.dumps(hook_config(), indent=2))
        return
    if args.context:
        text = context_for_directory(args.dir, mode="facts" if args.full else "index", max_facts=args.max_facts)
        if text:
            print(text)
        return
    if not args.target:
        leds = list_ledgers(args.dir)
        if args.json:
            print(json.dumps([l.summary() for l in leds], indent=2, ensure_ascii=False))
        elif leds:
            for l in leds:
                print(l.index_line())
        else:
            print(f"No ledgers under {ledger_dir(args.dir)}")
        return
    led = Ledger.for_file(args.target, directory=args.dir)
    if args.clear:
        led.clear()
        print(f"Cleared ledger for {args.target}")
        return
    if args.json:
        print(json.dumps({**led.summary(), "established": led.established(args.max_facts),
                          "known_false": led.known_false()}, indent=2, ensure_ascii=False))
    else:
        print(led.context_text(args.max_facts))


def cmd_verify(args: argparse.Namespace) -> None:
    data = load_input_bytes(args.target)

    claims_data: List[Dict[str, Any]] = []
    if args.claims_file:
        with open(args.claims_file, "r", encoding="utf-8") as f:
            loaded = json.load(f)
        claims_data = loaded if isinstance(loaded, list) else [loaded]
    elif args.claim:
        for raw in (args.claim if isinstance(args.claim, list) else [args.claim]):
            loaded = json.loads(raw)
            claims_data.extend(loaded if isinstance(loaded, list) else [loaded])
    else:
        raise SystemExit("verify requires --claim '<json>' or --claims-file <path>")

    verifier = Verifier(data)
    report = verifier.verify_all(
        [Claim.from_dict(c) for c in claims_data], min_information=args.min_information
    )

    if args.json:
        print(json.dumps(report, indent=2, ensure_ascii=False))
    else:
        print("=== Reverify: tool-grounded claim verification ===")
        _print_results(report["results"])
        print(
            f"\nVerified {report['verified']}/{report['total_claims']} "
            f"(refuted {report['refuted']}, inconclusive {report['inconclusive']}, "
            f"observed {report['observed']}, invalidated {report['invalidated']}). "
            f"Information {report['information']} (trivial {report['trivial_verified']}). "
            f"Trustworthy: {report['trustworthy']}  Grounded: {report['grounded']}"
        )
    # Non-zero exit if anything was refuted, so CI / agents can gate on it.
    if report["refuted"] > 0:
        sys.exit(2)


def _print_results(results: List[Dict[str, Any]]) -> None:
    symbols = {
        "VERIFIED": "[VERIFIED]", "REFUTED": "[REFUTED ]", "INCONCLUSIVE": "[INCONCL.]",
        "OBSERVED": "[OBSERVED]", "INVALIDATED": "[INVALID.]",
    }
    for r in results:
        mark = symbols.get(r["verdict"], r["verdict"])
        ident = f" #{r['id']}" if r.get("id") else ""
        w = r.get("weight")
        weight = f"  w={w}" if w is not None else ""
        flags = []
        if r.get("trivial"):
            flags.append("trivial")
        if r.get("echoed"):
            flags.append("echo")
        if r.get("duplicate"):
            flags.append("duplicate")
        if (r.get("evidence") or {}).get("self_referential"):
            flags.append("self-referential")
        flag = f"  [{', '.join(flags)}]" if flags else ""
        print(f"{mark} {r['kind']}{ident}{weight}{flag}")
        print(f"           {r['detail']}")
        ev = r.get("evidence") or {}
        if r["verdict"] == "OBSERVED":
            val = ev.get("actual")
            if val is None:
                val = ev.get("registers")
            if val is None:
                val = ev.get("raw")
            print(f"           observed: {val}")
        elif r["verdict"] == "REFUTED" and ev.get("nearest_offset_of_expected"):
            print(f"           expected bytes actually at: {ev['nearest_offset_of_expected']}")
        elif r["verdict"] == "REFUTED" and ev.get("counterexample"):
            ce = ev["counterexample"]
            if isinstance(ce, dict) and "input" in ce:
                print(f"           counterexample: input={ce.get('input')} original={ce.get('original')} candidate={ce.get('candidate')}")
            else:
                print(f"           counterexample: {ce}")
        basis = ev.get("weight_basis")
        if basis and r["verdict"] in ("VERIFIED", "REFUTED"):
            parts = [f"{k}={v}" for k, v in basis.items() if k in ("occurrences", "entropy_norm", "steps", "length")]
            print(f"           weight basis: {' '.join(parts)}")
        if r.get("note"):
            print(f"           note (unverified): {r['note']}")


def cmd_rollover(args: argparse.Namespace) -> None:
    """Rollover for any agent CLI: hooks + launcher (see reverify/rollover_harness.py)."""
    sys.exit(claude_rollover_main([args.action] + list(args.rest)))


def cmd_equiv(args: argparse.Namespace) -> None:
    """functions_equiv: do two implementations compute the same thing? Run both, compare outputs."""
    def read(x: str) -> str:
        return open(x, encoding="utf-8").read() if os.path.exists(x) else x

    res = functions_equiv_verify(
        read(args.candidate), reference=read(args.reference),
        lang=args.lang, nargs=args.nargs, cc=args.cc)
    status = res["status"]
    if args.json:
        print(json.dumps(res, indent=2, ensure_ascii=False))
    else:
        label = {"pass": "VERIFIED", "fail": "REFUTED", "inconclusive": "INCONCLUSIVE"}[status]
        print(f"{label}  {res['detail']}")
        if status == "fail" and res["failures"]:
            w = res["failures"][0]
            print(f"  witness: input {w['input']} -> reference {w['reference']}, candidate {w['candidate']}")
    sys.exit({"pass": 0, "fail": 2, "inconclusive": 3}[status])


def cmd_audit_boundary(args: argparse.Namespace) -> None:
    workspace = args.workspace or os.getcwd()
    urls = args.urls.split(",") if args.urls else None
    report = run_full_security_audit(workspace, urls)

    if args.json:
        print(json.dumps(report, indent=2, ensure_ascii=False))
    else:
        print(f"=== Security Boundary Audit Report ===")
        print(f"Status:          {report['status']}")
        print(f"Workspace Root:  {report['workspace_root']}")
        print(f"Summary:         {report['summary']}")
        print("\n--- Network Boundaries Evaluated ---")
        for net in report["network_audit"]:
            state = "SAFE" if net["is_safe"] else "BLOCKED"
            print(f"[{state}] {net['url']}")
            for finding in net["findings"]:
                print(f"       -> {finding}")


def main() -> None:
    parser = argparse.ArgumentParser(
        prog="reverify",
        description="Reverify - verified reverse engineering, protocol dissection, and emulation toolkit",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    # auto
    p_auto = subparsers.add_parser("auto", help="Automatically triage and inspect target binary")
    p_auto.add_argument("target", help="File path or hex stream")
    p_auto.add_argument("--json", action="store_true", help="Output full JSON triage report")
    p_auto.set_defaults(func=cmd_auto)

    # parse-pe
    p_pe = subparsers.add_parser("parse-pe", help="Parse PE32/PE32+ binary structure")
    p_pe.add_argument("file", help="Path to EXE/DLL/SYS file")
    p_pe.add_argument("--json", action="store_true", help="Output full JSON structure")
    p_pe.set_defaults(func=cmd_parse_pe)

    # pattern-scan
    p_scan = subparsers.add_parser("pattern-scan", help="Scan binary data for AOB hex pattern with wildcards")
    p_scan.add_argument("target", help="File path or hex string")
    p_scan.add_argument("--pattern", required=True, help="AOB pattern (e.g. '48 89 ?? 24 ?? 55')")
    p_scan.add_argument("--base", type=lambda x: int(x, 0), default=0, help="Base address")
    p_scan.add_argument("--json", action="store_true", help="Output JSON matches")
    p_scan.set_defaults(func=cmd_pattern_scan)

    # strings
    p_str = subparsers.add_parser("strings", help="Extract ASCII and Unicode strings from binary")
    p_str.add_argument("file", help="Path to binary file")
    p_str.add_argument("--min-len", type=int, default=4, help="Minimum string length")
    p_str.add_argument("--json", action="store_true", help="Output JSON list with offsets")
    p_str.set_defaults(func=cmd_strings)

    # diff-patch
    p_patch = subparsers.add_parser("diff-patch", help="Compare original and patched binaries and output patch diff")
    p_patch.add_argument("--orig", required=True, help="Path to original binary")
    p_patch.add_argument("--patched", required=True, help="Path to patched binary")
    p_patch.add_argument("--base", type=lambda x: int(x, 0), default=0, help="Base address")
    p_patch.add_argument("--json", action="store_true", help="Output JSON patches")
    p_patch.set_defaults(func=cmd_diff_patch)

    # disasm
    p_dis = subparsers.add_parser("disasm", help="Disassemble binary code or hex stream")
    p_dis.add_argument("target", help="Hex string or file path")
    p_dis.add_argument("--offset", type=lambda x: int(x, 0), default=0, help="File byte offset")
    p_dis.add_argument("--length", type=lambda x: int(x, 0), default=64, help="Byte length")
    p_dis.add_argument("--base", type=lambda x: int(x, 0), default=0x1000, help="Base address")
    p_dis.add_argument("--arch", default="x86_64", help="Architecture (x86, x86_64, arm, arm64)")
    p_dis.add_argument("--json", action="store_true", help="Output JSON instruction list")
    p_dis.set_defaults(func=cmd_disasm)

    # decode-protobuf
    p_pb = subparsers.add_parser("decode-protobuf", help="Dissect raw Protobuf binary stream")
    p_pb.add_argument("target", help="Hex string or file path")
    p_pb.set_defaults(func=cmd_decode_protobuf)

    # decode-tlv
    p_tlv = subparsers.add_parser("decode-tlv", help="Dissect TLV binary packet")
    p_tlv.add_argument("target", help="Hex string or file path")
    p_tlv.add_argument("--type-len", type=int, default=1, help="Type field length in bytes")
    p_tlv.add_argument("--len-len", type=int, default=2, help="Length field length in bytes")
    p_tlv.set_defaults(func=cmd_decode_tlv)

    # emulate
    p_emu = subparsers.add_parser("emulate", help="Emulate instruction execution")
    p_emu.add_argument("--code", required=True, help="Hex byte string of instructions")
    p_emu.add_argument("--base", type=lambda x: int(x, 0), default=0x1000, help="Base address")
    p_emu.add_argument("--arch", default="x86_64", help="Architecture (x86, x86_64)")
    p_emu.add_argument("--max-steps", type=int, default=100, help="Maximum execution steps")
    p_emu.add_argument("--backend", default="auto", choices=["auto", "unicorn", "pure"], help="Emulation engine")
    p_emu.set_defaults(func=cmd_emulate)

    # parse (generic: PE / ELF / Mach-O)
    p_parse = subparsers.add_parser("parse", help="Parse PE, ELF or Mach-O: arch, entry, sections, imports, exports")
    p_parse.add_argument("file", help="Path to the binary")
    p_parse.add_argument("--backend", default="auto", choices=["auto", "lief", "pure"], help="Parsing engine")
    p_parse.add_argument("--json", action="store_true", help="Output full JSON structure")
    p_parse.set_defaults(func=cmd_parse)

    # parse-apk
    p_apk = subparsers.add_parser("parse-apk", help="Inspect an APK: manifest, DEX classes/methods, signing certificates")
    p_apk.add_argument("file", help="Path to the APK")
    p_apk.add_argument("--json", action="store_true", help="Output full JSON structure")
    p_apk.set_defaults(func=cmd_parse_apk)

    # backends
    p_be = subparsers.add_parser("backends", help="Show which engines are active (capstone / unicorn / lief)")
    p_be.add_argument("--json", action="store_true")
    p_be.set_defaults(func=cmd_backends)

    # gen-hook
    p_hook = subparsers.add_parser("gen-hook", help="Generate Frida hook script")
    p_hook.add_argument("--symbol", required=True, help="Target function symbol or hex address")
    p_hook.add_argument("--module", help="Target module name (e.g. ntdll.dll)")
    p_hook.add_argument("--args-count", type=int, default=4, help="Number of arguments to log")
    p_hook.add_argument("--backtrace", action="store_true", help="Log accurate backtrace on enter")
    p_hook.add_argument("--replace-ret", help="Value/pointer to replace return value with")
    p_hook.add_argument("--output", help="Save script to file")
    p_hook.set_defaults(func=cmd_gen_hook)

    # hexdump
    p_hex = subparsers.add_parser("hexdump", help="Display formatted hexadecimal dump")
    p_hex.add_argument("target", help="Hex string or file path")
    p_hex.add_argument("--offset", type=lambda x: int(x, 0), default=0, help="File byte offset")
    p_hex.add_argument("--length", type=lambda x: int(x, 0), default=128, help="Byte length")
    p_hex.add_argument("--base", type=lambda x: int(x, 0), default=0, help="Base address")
    p_hex.set_defaults(func=cmd_hexdump)

    # reconstruct
    p_recon = subparsers.add_parser(
        "reconstruct",
        help="Closed loop: model proposes claims, the tools verify, iterate until grounded",
    )
    p_recon.add_argument("target", help="File path or hex stream to reconstruct facts about")
    p_recon.add_argument("--goal", required=True, help="What to reconstruct, in plain language")
    p_recon.add_argument("--rounds", type=int, default=4, help="Maximum propose/verify rounds")
    p_recon.add_argument("--model", help="Model name (defaults to OPENAI_MODEL or gpt-4o)")
    p_recon.add_argument("--api-key", help="API key (defaults to OPENAI_API_KEY env)")
    p_recon.add_argument("--base-url", help="API base URL (defaults to OPENAI_BASE_URL env)")
    p_recon.add_argument("--samples", type=int, default=1, help="Proposals per round; the verifier selects among them")
    p_recon.add_argument("--min-information", type=float, default=1.0, help="Weight sum verified claims must reach to count as grounded")
    p_recon.add_argument("--temperature", type=float, default=0.7, help="Sampling temperature for the live proposer")
    p_recon.add_argument("--mock", action="store_true", help="Offline demo proposer, no network")
    p_recon.add_argument("--json", action="store_true", help="Output the full JSON run report")
    p_recon.add_argument("--ledger", help="Ledger directory (default: $REVERIFY_LEDGER_DIR or .reverify); state is checkpointed here every round")
    p_recon.add_argument("--no-ledger", action="store_true", help="Keep the ledger in memory only (write nothing)")
    p_recon.add_argument("--fresh", action="store_true", help="Discard this binary's ledger and start over instead of resuming")
    p_recon.add_argument("--max-facts", type=int, default=40, help="Ledger facts shown per round (proof-grade facts are always kept)")
    p_recon.add_argument("--prompt-budget", type=int, default=60000, help="Whole-prompt budget in characters; the shown fact sheet is trimmed to fit")
    p_recon.add_argument("--session", help="Session label recorded in the ledger")
    p_recon.set_defaults(func=cmd_reconstruct)

    # functions (semantic layer)
    p_fn = subparsers.add_parser(
        "functions",
        help="List recovered functions: angr when installed, otherwise only the entry point and exports",
    )
    p_fn.add_argument("target", help="Binary path")
    p_fn.add_argument("--limit", type=int, default=200, help="Maximum functions to list")
    p_fn.add_argument("--imports", action="store_true", help="Include import stubs")
    p_fn.add_argument("--json", action="store_true", help="Output JSON")
    p_fn.set_defaults(func=cmd_functions)

    # orchestrate (rollover controller)
    p_orc = subparsers.add_parser(
        "orchestrate",
        help="Run a goal across fresh-context sessions: the model asks for rollovers, the hand-off is verified from the ledger",
    )
    p_orc.add_argument("target", help="Binary path")
    p_orc.add_argument("--goal", required=True, help="What to establish, in plain language")
    p_orc.add_argument("--driver", default="mock", choices=["mock", "openai", "claude"],
                       help="mock (offline demo), openai (OPENAI_* env), claude (Claude Agent SDK on your Claude Code login)")
    p_orc.add_argument("--model", help="Model name for the driver")
    p_orc.add_argument("--session-tokens", type=int, default=60000, help="Token budget per session before a forced rollover")
    p_orc.add_argument("--max-sessions", type=int, default=6, help="Maximum fresh-context sessions")
    p_orc.add_argument("--max-turns", type=int, default=30, help="Maximum turns per session")
    p_orc.add_argument("--max-facts", type=int, default=40, help="Ledger facts shown per session")
    p_orc.add_argument("--prompt-budget", type=int, default=40000, help="Opening prompt budget in characters")
    p_orc.add_argument("--ledger", help="Ledger/session directory (default: $REVERIFY_LEDGER_DIR or .reverify)")
    p_orc.add_argument("--no-ledger", action="store_true", help="Keep everything in memory")
    p_orc.add_argument("--task", help="Task id to resume a previous orchestration's checkpoint")
    p_orc.add_argument("--json", action="store_true", help="Output the full JSON result")
    p_orc.set_defaults(func=cmd_orchestrate)

    # ledger
    p_led = subparsers.add_parser(
        "ledger",
        help="Durable ledger of grounded facts per binary - the state that survives /clear, compaction and restarts",
    )
    p_led.add_argument("target", nargs="?", help="Binary whose ledger to show (omit to list all)")
    p_led.add_argument("--dir", help="Ledger base directory (default: $REVERIFY_LEDGER_DIR or .reverify)")
    p_led.add_argument("--max-facts", type=int, default=30, help="Facts to show (proof-grade facts are always kept)")
    p_led.add_argument("--context", action="store_true", help="Hand-off text for a fresh context: one index line per binary (see --full)")
    p_led.add_argument("--full", action="store_true", help="With --context: inline the bounded fact view instead of index lines")
    p_led.add_argument("--hook", action="store_true", help="Print a Claude Code SessionStart hook that re-injects the ledger index after compaction or /clear")
    p_led.add_argument("--clear", action="store_true", help="Discard the ledger for target")
    p_led.add_argument("--json", action="store_true", help="Output JSON")
    p_led.set_defaults(func=cmd_ledger)

    # verify
    p_verify = subparsers.add_parser(
        "verify",
        help="Verify claims about a binary against the deterministic tools (the core Reverify loop)",
    )
    p_verify.add_argument("target", help="File path or hex stream to check claims against")
    p_verify.add_argument("--claim", action="append", help="A claim as a JSON object, or a JSON array of claims (repeatable)")
    p_verify.add_argument("--claims-file", help="Path to a JSON file with a claim object or array")
    p_verify.add_argument("--min-information", type=float, default=1.0, help="Weight sum verified claims must reach to count as grounded")
    p_verify.add_argument("--json", action="store_true", help="Output the full JSON verdict report")
    p_verify.set_defaults(func=cmd_verify)

    # audit-boundary
    p_audit = subparsers.add_parser("audit-boundary", help="Audit filesystem path and network SSRF boundaries")
    p_audit.add_argument("--workspace", help="Target workspace path (defaults to current dir)")
    p_audit.add_argument("--urls", help="Comma-separated URLs to evaluate for SSRF / loopback filtering")
    p_audit.add_argument("--json", action="store_true", help="Output full JSON audit report")
    p_audit.set_defaults(func=cmd_audit_boundary)

    # rollover (Claude Code without compaction)
    p_roll = subparsers.add_parser(
        "rollover",
        help="Rollover for Claude Code / Codex / Gemini CLI / OpenCode: hooks that hand off to files "
             "instead of compacting, and a launcher that replaces the session with a fresh one",
    )
    p_roll.add_argument("action", choices=["install", "uninstall", "doctor", "run", "claude", "codex", "gemini", "opencode",
                                           "request", "status", "instructions", "hook", "stop", "session-start", "help"],
                        help="install/uninstall the hooks, run the launcher, request a rollover (from inside a session), status")
    p_roll.add_argument("rest", nargs=argparse.REMAINDER, help="options for the action; for run, arguments after -- go to claude")
    p_roll.set_defaults(func=cmd_rollover)

    # equiv (verified coding: do two implementations agree?)
    p_equiv = subparsers.add_parser(
        "equiv",
        help="Do two implementations compute the same thing? Run a candidate and a reference over "
             "shared inputs and compare. Runs the code — set REVERIFY_ALLOW_NATIVE_EXEC=1.",
    )
    p_equiv.add_argument("reference", help="reference (trusted) implementation: a file path or inline source")
    p_equiv.add_argument("candidate", help="candidate implementation to check: a file path or inline source")
    p_equiv.add_argument("--lang", default="c", choices=["c", "python", "py"], help="implementation language (default: c)")
    p_equiv.add_argument("--nargs", type=int, default=2, help="how many integer args the programs take (default: 2)")
    p_equiv.add_argument("--cc", default="gcc", help="C compiler for --lang c (default: gcc)")
    p_equiv.add_argument("--json", action="store_true", help="output the full JSON result")
    p_equiv.set_defaults(func=cmd_equiv)

    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
