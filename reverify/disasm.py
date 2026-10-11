"""Disassembly, signature scanning, and binary patching engine."""

import re
from typing import Dict, Any, List, Optional, Tuple


class UnsupportedArch(ValueError):
    """The requested architecture needs capstone: the pure-Python decoder is x86/x64 only.

    Raised instead of silently decoding ARM/MIPS/... bytes as x86, which would
    let a wrong claim verify against junk (a false VERIFIED).
    """


_PURE_UNSUPPORTED = ("arm", "aarch", "mips", "ppc", "powerpc", "riscv", "sparc")

#: Pseudo-mnemonics the pure decoder emits for bytes it does not understand.
#: A verifier must never refute a claim on the strength of these.
PSEUDO_MNEMONICS = ("db", "rex")

_REG32 = ["eax", "ecx", "edx", "ebx", "esp", "ebp", "esi", "edi",
          "r8d", "r9d", "r10d", "r11d", "r12d", "r13d", "r14d", "r15d"]
_REG64 = ["rax", "rcx", "rdx", "rbx", "rsp", "rbp", "rsi", "rdi",
          "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15"]
_ALU_RM_R = {0x01: "add", 0x29: "sub", 0x31: "xor", 0x89: "mov"}   # op r/m, r
_ALU_R_RM = {0x03: "add", 0x2B: "sub", 0x33: "xor", 0x8B: "mov"}   # op r, r/m
_JCC = ["jo", "jno", "jb", "jnb", "jz", "jnz", "jbe", "jnbe",
        "js", "jns", "jp", "jnp", "jl", "jge", "jle", "jg"]


class Instruction:
    def __init__(self, address: int, size: int, mnemonic: str, op_str: str, raw_bytes: bytes):
        self.address = address
        self.size = size
        self.mnemonic = mnemonic
        self.op_str = op_str
        self.bytes = raw_bytes

    def __repr__(self) -> str:
        hex_bytes = self.bytes.hex()
        return f"0x{self.address:08X}:  {hex_bytes:<16}  {self.mnemonic:<8} {self.op_str}"

    def to_dict(self) -> Dict[str, Any]:
        return {
            "address": hex(self.address),
            "size": self.size,
            "bytes": self.bytes.hex(),
            "mnemonic": self.mnemonic,
            "op_str": self.op_str,
        }


class Disassembler:
    """Disassembler supporting pure-Python x86/x64 decoding with Capstone auto-switch."""

    def __init__(self, arch: str = "x86_64"):
        self.arch = arch.lower()
        self._capstone_cs = None
        self._init_capstone()

    @property
    def engine(self) -> str:
        return "capstone" if self._capstone_cs is not None else "pure-python"

    def _init_capstone(self) -> None:
        try:
            import capstone
            if "arm64" in self.arch or "aarch64" in self.arch:
                self._capstone_cs = capstone.Cs(capstone.CS_ARCH_ARM64, capstone.CS_MODE_ARM)
            elif "arm" in self.arch:
                self._capstone_cs = capstone.Cs(capstone.CS_ARCH_ARM, capstone.CS_MODE_ARM)
            elif "64" in self.arch or "x64" in self.arch or "amd64" in self.arch:
                self._capstone_cs = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
            else:
                self._capstone_cs = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
        except ImportError:
            self._capstone_cs = None

    def disassemble(self, code: bytes, base_address: int = 0x1000) -> List[Instruction]:
        if self._capstone_cs is not None:
            instructions = []
            for ins in self._capstone_cs.disasm(code, base_address):
                instructions.append(
                    Instruction(ins.address, ins.size, ins.mnemonic, ins.op_str, bytes(ins.bytes))
                )
            return instructions
        if any(tag in self.arch for tag in _PURE_UNSUPPORTED):
            raise UnsupportedArch(
                f"'{self.arch}' disassembly needs capstone (the pure-Python decoder is x86/x64 only): "
                'pip install "reverify[capstone]"'
            )
        return self._disassemble_pure_python(code, base_address)

    # -- pure-Python x86/x64 decoder ------------------------------------------
    #
    # Deliberately small and honest: it decodes the common register-direct forms
    # (prologues, moves, ALU on registers, branches) and emits ``db`` for anything
    # else — never a guess. Every byte is accounted for (sum of sizes == len).

    def _disassemble_pure_python(self, code: bytes, base_address: int) -> List[Instruction]:
        instructions: List[Instruction] = []
        is64 = ("64" in self.arch or "amd64" in self.arch) and "arm" not in self.arch
        offset = 0
        addr = base_address
        length = len(code)

        while offset < length:
            b0 = code[offset]
            prefix = 0
            rex = 0
            if is64 and 0x40 <= b0 <= 0x4F and offset + 1 < length:
                rex, prefix = b0, 1
            decoded = self._decode_one(code, offset + prefix, addr + prefix, is64, rex)
            if decoded is None:
                # undecodable: account for exactly one byte (the REX byte itself, if that is what we are on)
                instructions.append(Instruction(addr, 1, "rex" if prefix else "db", hex(b0), bytes([b0])))
                offset += 1
                addr += 1
                continue
            mnemonic, op_str, size = decoded
            total = prefix + size
            instructions.append(Instruction(addr, total, mnemonic, op_str, code[offset : offset + total]))
            offset += total
            addr += total

        return instructions

    @staticmethod
    def _decode_one(code: bytes, pos: int, addr: int, is64: bool, rex: int) -> Optional[Tuple[str, str, int]]:
        """Decode one instruction at ``pos`` (after any REX prefix). Returns (mnemonic, operands, size) or None."""
        if pos >= len(code):
            return None
        b0 = code[pos]
        rem = len(code) - pos
        rex_w, rex_r, rex_b = bool(rex & 8), bool(rex & 4), bool(rex & 1)
        wide = is64 and rex_w

        def reg(n: int, wide_: bool) -> str:
            return (_REG64 if wide_ else _REG32)[n]

        if b0 == 0x90:
            return "nop", "", 1
        if b0 == 0xCC:
            return "int3", "", 1
        if b0 == 0xC3:
            return "ret", "", 1
        if b0 == 0xC2 and rem >= 3:
            return "ret", hex(int.from_bytes(code[pos + 1 : pos + 3], "little")), 3
        if 0x50 <= b0 <= 0x57:   # push r: 64-bit operand size by default in long mode
            return "push", reg((b0 - 0x50) + (8 if rex_b else 0), is64), 1
        if 0x58 <= b0 <= 0x5F:
            return "pop", reg((b0 - 0x58) + (8 if rex_b else 0), is64), 1
        if b0 == 0x68 and rem >= 5:
            return "push", hex(int.from_bytes(code[pos + 1 : pos + 5], "little", signed=True)), 5
        if b0 == 0x6A and rem >= 2:
            return "push", hex(int.from_bytes(code[pos + 1 : pos + 2], "little", signed=True)), 2
        if 0xB8 <= b0 <= 0xBF:   # mov r, imm32 / imm64 (REX.W)
            imm_len = 8 if wide else 4
            if rem < 1 + imm_len:
                return None      # truncated immediate: leave the bytes as db, do not invent an operand
            imm = int.from_bytes(code[pos + 1 : pos + 1 + imm_len], "little")
            return "mov", f"{reg((b0 - 0xB8) + (8 if rex_b else 0), wide)}, {hex(imm)}", 1 + imm_len
        if (b0 in _ALU_RM_R or b0 in _ALU_R_RM) and rem >= 2:
            modrm = code[pos + 1]
            if modrm >> 6 != 3:
                return None      # memory operand: length depends on SIB/displacement — not decoded, never guessed
            r = ((modrm >> 3) & 7) + (8 if rex_r else 0)
            rm = (modrm & 7) + (8 if rex_b else 0)
            if b0 in _ALU_RM_R:
                mnemonic, dst, src = _ALU_RM_R[b0], rm, r
            else:
                mnemonic, dst, src = _ALU_R_RM[b0], r, rm
            return mnemonic, f"{reg(dst, wide)}, {reg(src, wide)}", 2
        if b0 == 0xEB and rem >= 2:
            rel = int.from_bytes(code[pos + 1 : pos + 2], "little", signed=True)
            return "jmp", hex(addr + 2 + rel), 2
        if b0 == 0xE9 and rem >= 5:
            rel = int.from_bytes(code[pos + 1 : pos + 5], "little", signed=True)
            return "jmp", hex(addr + 5 + rel), 5
        if b0 == 0xE8 and rem >= 5:
            rel = int.from_bytes(code[pos + 1 : pos + 5], "little", signed=True)
            return "call", hex(addr + 5 + rel), 5
        if 0x70 <= b0 <= 0x7F and rem >= 2:
            rel = int.from_bytes(code[pos + 1 : pos + 2], "little", signed=True)
            return _JCC[b0 - 0x70], hex(addr + 2 + rel), 2
        return None


def pattern_scan(data: bytes, pattern: str) -> List[int]:
    """Scan data for a hex pattern with wildcards (e.g. '48 89 5c 24 ?? 55')."""
    tokens = pattern.strip().split()
    regex_parts = []
    for t in tokens:
        if t in ("?", "??"):
            regex_parts.append(b".")
        else:
            byte_val = int(t, 16)
            regex_parts.append(re.escape(bytes([byte_val])))

    regex = b"".join(regex_parts)
    # Zero-width lookahead so overlapping hits count: "41 41" in b"AAAA" is at
    # 0, 1 and 2, the same as string_present's occurrence count.
    matches = [m.start() for m in re.finditer(b"(?=" + regex + b")", data, re.DOTALL)]
    return matches


def create_patch(original: bytes, patched: bytes, base_address: int = 0) -> List[Dict[str, Any]]:
    """Compare original and patched byte arrays and return diff offsets and values."""
    if len(original) != len(patched):
        raise ValueError("Original and patched data must be the same length")

    patches = []
    i = 0
    while i < len(original):
        if original[i] != patched[i]:
            start = i
            while i < len(original) and original[i] != patched[i]:
                i += 1
            patches.append({
                "offset": hex(start),
                "address": hex(base_address + start),
                "length": i - start,
                "original_bytes": original[start:i].hex(),
                "patched_bytes": patched[start:i].hex(),
            })
        else:
            i += 1
    return patches
