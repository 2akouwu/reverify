import struct
import sys
import unittest
from pathlib import Path

tools_root = Path(__file__).resolve().parent.parent
if str(tools_root) not in sys.path:
    sys.path.insert(0, str(tools_root))

from verifier import Claim, Verifier, INCONCLUSIVE, REFUTED


def _synthetic_pe_no_imports() -> bytes:
    buf = bytearray(1024)
    buf[0:2] = b"MZ"
    struct.pack_into("<I", buf, 0x3C, 0x80)
    pe_offset = 0x80
    buf[pe_offset : pe_offset + 4] = b"PE\x00\x00"
    struct.pack_into("<HHIIIHH", buf, pe_offset + 4, 0x8664, 1, 0, 0, 0, 240, 0x0022)
    opt_offset = pe_offset + 24
    struct.pack_into("<HBBIIIIQQII", buf, opt_offset, 0x20B, 14, 0, 0x1000, 0x2000, 0,
                     0x1000, 0x1000, 0x140000000, 0x1000, 0x200)
    sec1 = opt_offset + 240
    buf[sec1 : sec1 + 8] = b".text\x00\x00\x00"
    struct.pack_into("<IIIIIIHHI", buf, sec1 + 8, 0x500, 0x1000, 0x600, 0x400,
                     0, 0, 0, 0, 0x60000020)
    return bytes(buf)


class TestImportClaimSchema(unittest.TestCase):
    def setUp(self):
        self.pe = _synthetic_pe_no_imports()

    def test_symbol_misspelling_is_rejected(self):
        r = Verifier(self.pe).verify(
            Claim("import_present", {"dll": "USER32.dll", "symbol": "ShowWindow"})
        )
        self.assertEqual(r["verdict"], INCONCLUSIVE)
        self.assertIn("symbol", r["detail"])
        for accepted in ("function", "lib", "dll"):
            self.assertIn(accepted, r["detail"])
        self.assertEqual(r["evidence"], {})

    def test_function_claim_still_checks_the_symbol(self):
        r = Verifier(self.pe).verify(
            Claim("import_present", {"function": "CreateFileW"})
        )
        self.assertEqual(r["verdict"], REFUTED)
        self.assertEqual(r["detail"], "import absent")

    def test_dll_alias_still_works(self):
        r = Verifier(self.pe).verify(Claim("import_present", {"dll": "kernel32.dll"}))
        self.assertEqual(r["verdict"], REFUTED)
        self.assertEqual(r["detail"], "library import check")

    def test_unknown_extra_field_is_rejected(self):
        r = Verifier(self.pe).verify(
            Claim("import_present", {"function": "CreateFileW", "extra": "ignored?"})
        )
        self.assertEqual(r["verdict"], INCONCLUSIVE)
        self.assertIn("extra", r["detail"])

    def test_pe_import_alias_uses_the_same_schema(self):
        r = Verifier(self.pe).verify(
            Claim("pe_import", {"lib": "USER32.dll", "symbol": "ShowWindow"})
        )
        self.assertEqual(r["verdict"], INCONCLUSIVE)
        self.assertIn("symbol", r["detail"])


class TestRelatedClaimSchemas(unittest.TestCase):
    def test_pattern_count_misspelling_is_rejected(self):
        r = Verifier(bytes.fromhex("4141")).verify(
            Claim("pattern_present", {"pattern": "41 41", "counts": 2})
        )
        self.assertEqual(r["verdict"], INCONCLUSIVE)
        self.assertIn("counts", r["detail"])
        self.assertIn("count", r["detail"])

    def test_section_virtual_address_misspelling_is_rejected(self):
        r = Verifier(_synthetic_pe_no_imports()).verify(
            Claim("section_present", {"name": ".text", "virtal_address": 0x9999})
        )
        self.assertEqual(r["verdict"], INCONCLUSIVE)
        self.assertIn("virtal_address", r["detail"])

    def test_protobuf_type_misspelling_is_rejected(self):
        r = Verifier(bytes.fromhex("089601")).verify(
            Claim("protobuf_field", {"field": 1, "kind_of_type": "varint"})
        )
        self.assertEqual(r["verdict"], INCONCLUSIVE)
        self.assertIn("kind_of_type", r["detail"])


if __name__ == "__main__":
    unittest.main()
