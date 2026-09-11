import struct
import unittest
import sys
from pathlib import Path

tools_root = Path(__file__).resolve().parent.parent
if str(tools_root) not in sys.path:
    sys.path.insert(0, str(tools_root))

from pe_parser import PEParser, BinaryParseError


def create_synthetic_pe32_plus() -> bytes:
    """Create a minimal synthetic PE32+ (x64) binary buffer."""
    buf = bytearray(1024)
    # DOS Header
    buf[0:2] = b"MZ"
    struct.pack_into("<I", buf, 0x3C, 0x80)  # e_lfanew = 128

    pe_offset = 0x80
    buf[pe_offset : pe_offset + 4] = b"PE\x00\x00"

    # File Header (Machine=AMD64 (0x8664), NumSections=2, SizeOfOptionalHeader=240, Char=0x0002)
    struct.pack_into("<HHIIIHH", buf, pe_offset + 4, 0x8664, 2, 0x12345678, 0, 0, 240, 0x0022)

    # Optional Header (Magic=0x20B (PE32+), EntryPoint=0x1000, ImageBase=0x140000000)
    opt_offset = pe_offset + 24
    struct.pack_into("<HBBIIIIIQII", buf, opt_offset, 0x20B, 14, 0, 0x1000, 0x2000, 0, 0x1000, 0x1000, 0x140000000, 0x1000, 0x200)

    # Section Headers
    sec1_offset = opt_offset + 240
    # .text
    buf[sec1_offset : sec1_offset + 8] = b".text\x00\x00\x00"
    struct.pack_into("<IIIIIIHHI", buf, sec1_offset + 8, 0x500, 0x1000, 0x600, 0x400, 0, 0, 0, 0, 0x60000020)

    # .data
    sec2_offset = sec1_offset + 40
    buf[sec2_offset : sec2_offset + 8] = b".data\x00\x00\x00"
    struct.pack_into("<IIIIIIHHI", buf, sec2_offset + 8, 0x200, 0x2000, 0x200, 0xA00, 0, 0, 0, 0, 0xC0000040)

    return bytes(buf)


class TestPEParser(unittest.TestCase):
    def test_invalid_magic(self):
        with self.assertRaises(BinaryParseError):
            PEParser(b"INVALID_HEADER_DATA_NOT_MZ")

    def test_synthetic_pe(self):
        data = create_synthetic_pe32_plus()
        parser = PEParser(data)
        self.assertTrue(parser.is_64bit)
        self.assertIn("x64", parser.file_header["MachineName"])
        self.assertEqual(len(parser.sections), 2)
        self.assertEqual(parser.sections[0]["Name"], ".text")
        self.assertEqual(parser.sections[1]["Name"], ".data")
        self.assertEqual(parser.optional_header["AddressOfEntryPoint"], "0x1000")

        summary = parser.summary()
        self.assertEqual(summary["format"], "PE")
        self.assertTrue(summary["is_64bit"])
        self.assertEqual(summary["sections"], [".text", ".data"])


def create_pe_with_truncated_export_names(num_names: int) -> bytes:
    """A PE whose export-name table runs off the end of the file.

    The table starts 8 bytes before EOF; with ``num_names`` larger than what the
    table can actually hold, a per-iteration bounds check must stop the walk
    instead of ``struct.unpack_from`` blowing up.
    """
    buf = bytearray(0x640)  # file deliberately ends at 0x640
    buf[0:2] = b"MZ"
    struct.pack_into("<I", buf, 0x3C, 0x80)
    buf[0x80:0x84] = b"PE\x00\x00"
    struct.pack_into("<HHIIIHH", buf, 0x84, 0x8664, 1, 0, 0, 0, 0xE0, 0x22)

    opt_offset = 0x84 + 20
    opt = struct.pack(
        "<HBBIIIIIQIIHHHHHHIIIIHHQQQQII", 0x20B, 0, 0, 0, 0, 0, 0x1000, 0x1000,
        0x400000, 0x1000, 0x200, 0, 0, 0, 0, 0, 0, 0, 0, 0x4000, 0x1000, 0, 0,
        64, 64, 64, 64, 0, 16,
    )
    buf[opt_offset : opt_offset + len(opt)] = opt
    # Data directory 0 = EXPORT at rva 0x1080 (file offset 0x280); directory 1 unused.
    struct.pack_into("<IIII", buf, opt_offset + 112, 0x1080, 0x100, 0, 0)

    sec = opt_offset + 0xE0
    buf[sec : sec + 8] = b".text\x00\x00\x00"
    struct.pack_into("<IIIIIIHHI", buf, sec + 8, 0x2000, 0x1000, 0x2000, 0x200, 0, 0, 0, 0, 0x60000020)

    # Export directory: num_functions = num_names = num_names, tables at rva
    # 0x1100 (funcs -> 0x300), 0x1400 (names -> 0x600, truncated), 0x1300 (ordinals -> 0x500).
    exp = struct.pack("<IIHHIIIIIII", 0, 0, 0, 0, 0x1030, 1, num_names, num_names, 0x1100, 0x1400, 0x1300)
    buf[0x280 : 0x280 + 40] = exp
    struct.pack_into("<II", buf, 0x600, 0x1030, 0x1030)      # only 8 bytes of the names table
    struct.pack_into("<16I", buf, 0x300, *([0x1000] * 16))   # function RVAs
    struct.pack_into("<120H", buf, 0x500, *([0] * 120))      # ordinals
    return bytes(buf)


class TestTruncatedExports(unittest.TestCase):
    def test_huge_num_names_does_not_walk_off_the_file(self):
        # Regression: the old bounds check did not scale with the loop index, so a
        # truncated names table + large num_names raised struct.error from
        # struct.unpack_from past the end of the buffer.
        parser = PEParser(create_pe_with_truncated_export_names(200))
        # Parsing must not raise; exports simply stop at the truncation point.
        self.assertLessEqual(len(parser.exports), 16)

    def test_small_num_names_parses_normally(self):
        parser = PEParser(create_pe_with_truncated_export_names(5))
        self.assertEqual(len(parser.exports), 5)

    def test_no_struct_error_through_binary_wrapper(self):
        from binary import parse_binary

        info = parse_binary(create_pe_with_truncated_export_names(200))
        self.assertEqual(info.format, "PE")
        # Without the per-iteration check this degraded path used to surface as a
        # struct.error error string; now it simply stops early.
        self.assertTrue(info.error is None or "unpack_from" not in info.error)


if __name__ == "__main__":
    unittest.main()
