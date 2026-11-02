import unittest
import sys
from pathlib import Path

tools_root = Path(__file__).resolve().parent.parent
if str(tools_root) not in sys.path:
    sys.path.insert(0, str(tools_root))

from disasm import Disassembler, pattern_scan, create_patch


class TestDisassembler(unittest.TestCase):
    def test_disasm_basic_x86_64(self):
        # 90 (NOP), 50 (PUSH RAX), 58 (POP RAX), 31 C0 (XOR EAX, EAX), C3 (RET)
        code = bytes([0x90, 0x50, 0x58, 0x31, 0xC0, 0xC3])
        dis = Disassembler(arch="x86_64")
        ins = dis.disassemble(code, base_address=0x1000)

        self.assertEqual(len(ins), 5)
        self.assertEqual(ins[0].mnemonic, "nop")
        self.assertEqual(ins[1].mnemonic, "push")
        self.assertEqual(ins[2].mnemonic, "pop")
        self.assertEqual(ins[3].mnemonic, "xor")
        self.assertEqual(ins[4].mnemonic, "ret")

    def test_pattern_scan(self):
        data = b"\x48\x89\x5C\x24\x08\x55\x48\x83\xEC\x20\x90\x90\x48\x89\x5C\x24\x10\x55"
        pattern = "48 89 5c 24 ?? 55"
        matches = pattern_scan(data, pattern)
        self.assertEqual(matches, [0, 12])

    def test_pattern_scan_overlapping(self):
        # issue #28: re.finditer resumes after each match and drops overlapping
        # hits, so pattern_present reported a wrong offset/count. Wrapping the
        # regex in a zero-width lookahead reports a match at every start position.
        # "AA" (0x41 0x41) over b"AAAA" overlaps at 0,1,2.
        self.assertEqual(pattern_scan(b"AAAA", "41 41"), [0, 1, 2])
        # int3/nop padding: five consecutive 0xCC -> overlapping "CC CC" pairs.
        pad = bytes.fromhex("554889e5ccccccccccc3")
        self.assertEqual(pattern_scan(pad, "CC CC"), [4, 5, 6, 7])
        # wildcard overlap.
        self.assertEqual(pattern_scan(bytes.fromhex("413f413f41"), "41 ??"), [0, 2])
        # empty pattern still matches at every position (unchanged behaviour).
        self.assertEqual(pattern_scan(b"AB", ""), [0, 1, 2])

    def test_create_patch(self):
        orig = b"\x90\x90\x74\x05\x90\x90"
        patched = b"\x90\x90\xEB\x05\x90\x90"
        patches = create_patch(orig, patched, base_address=0x401000)

        self.assertEqual(len(patches), 1)
        self.assertEqual(patches[0]["address"], "0x401002")
        self.assertEqual(patches[0]["length"], 1)
        self.assertEqual(patches[0]["original_bytes"], "74")
        self.assertEqual(patches[0]["patched_bytes"], "eb")


class TestArchRouting(unittest.TestCase):
    """arm64/aarch64 must reach the ARM64 decoder, not be misread as x86_64.

    Regression for the capstone arch switch, which selected x86_64 on
    ``"64" in arch`` -- true for "arm64"/"aarch64" too -- and silently decoded
    ARM64 bytes as x86_64.
    """

    def _capstone_present(self):
        try:
            import capstone  # noqa: F401
            return True
        except ImportError:
            return False

    def test_arm64_routes_to_arm64(self):
        if not self._capstone_present():
            self.skipTest("capstone not installed")
        # aarch64: sub sp, sp, #0x10  ->  FF 03 00 D1 (little-endian of D10003FF)
        code = bytes([0xFF, 0x03, 0x00, 0xD1])
        for name in ("arm64", "aarch64"):
            ins = Disassembler(arch=name).disassemble(code)
            self.assertEqual([i.mnemonic for i in ins], ["sub"], name)

    def test_arm64_does_not_decode_as_x86(self):
        if not self._capstone_present():
            self.skipTest("capstone not installed")
        # Same bytes must NOT come out as x86 instructions under an arm64 decoder.
        code = bytes([0xFF, 0x03, 0x00, 0xD1])
        x86 = [i.mnemonic for i in Disassembler(arch="x86_64").disassemble(code)]
        arm = [i.mnemonic for i in Disassembler(arch="arm64").disassemble(code)]
        self.assertNotEqual(x86, arm)


if __name__ == "__main__":
    unittest.main()
