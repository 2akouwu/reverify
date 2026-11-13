"""Reverse Engineering, Protocol Dissection, and Dynamic Instrumentation Toolkit."""

from ._version import __version__

from .pe_parser import PEParser, BinaryParseError
from .disasm import Disassembler, Instruction, pattern_scan, create_patch
from .emulator import MicroEmulator, UnicornEmulator, make_emulator, EmulatorError
from .binary import parse_binary, BinaryInfo, Section
from .apk import is_apk, inspect_apk, decode_axml, parse_dex, signing_report
from .backends import backend_report, HAS_CAPSTONE, HAS_UNICORN, HAS_LIEF
from .protocol_parser import ProtobufDissector, TLVDissector, format_hexdump, decode_varint, encode_varint
from .frida_bridge import FridaScriptGenerator
from .verifier import (
    Verifier, Claim, verify_claims, summarize, claim_key,
    VERIFIED, REFUTED, INCONCLUSIVE, OBSERVED, INVALIDATED,
)
from .agent import ReconstructionAgent, openai_proposer, demo_proposer, binary_facts, compact_facts
from .ledger import Ledger, list_ledgers, context_for_directory, hook_config, LEDGER_INSTRUCTIONS
from .behavior import behavioral_equiv, run_function, eval_expr, prove_expr_equiv
from .sandbox import run_sandboxed, SandboxLimits, SandboxResult, protections_active
from .exebench import exebench_verify, functions_equiv_verify, native_exec_allowed

__all__ = [
    "PEParser",
    "BinaryParseError",
    "Disassembler",
    "Instruction",
    "pattern_scan",
    "create_patch",
    "MicroEmulator",
    "UnicornEmulator",
    "make_emulator",
    "EmulatorError",
    "parse_binary",
    "BinaryInfo",
    "Section",
    "is_apk",
    "inspect_apk",
    "decode_axml",
    "parse_dex",
    "signing_report",
    "backend_report",
    "HAS_CAPSTONE",
    "HAS_UNICORN",
    "HAS_LIEF",
    "ProtobufDissector",
    "TLVDissector",
    "format_hexdump",
    "decode_varint",
    "encode_varint",
    "FridaScriptGenerator",
    "Verifier",
    "Claim",
    "verify_claims",
    "VERIFIED",
    "REFUTED",
    "INCONCLUSIVE",
    "OBSERVED",
    "INVALIDATED",
    "summarize",
    "claim_key",
    "ReconstructionAgent",
    "openai_proposer",
    "demo_proposer",
    "binary_facts",
    "compact_facts",
    "Ledger",
    "list_ledgers",
    "context_for_directory",
    "hook_config",
    "LEDGER_INSTRUCTIONS",
    "__version__",
    "behavioral_equiv",
    "run_function",
    "eval_expr",
    "prove_expr_equiv",
    "run_sandboxed",
    "SandboxLimits",
    "SandboxResult",
    "protections_active",
    "exebench_verify",
    "functions_equiv_verify",
    "native_exec_allowed",
]
