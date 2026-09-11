import struct
import sys
import unittest
from pathlib import Path

tools_root = Path(__file__).resolve().parent.parent
if str(tools_root) not in sys.path:
    sys.path.insert(0, str(tools_root))

from verifier import Verifier, Claim, verify_claims, VERIFIED, REFUTED, INCONCLUSIVE


class TestBytesAt(unittest.TestCase):
    def setUp(self):
        self.data = bytes.fromhex("deadbeefcafe")

    def test_bytes_match_is_verified(self):
        r = Verifier(self.data).verify(Claim("bytes_at", {"offset": 2, "expected": "beef"}))
        self.assertEqual(r["verdict"], VERIFIED)
        self.assertEqual(r["evidence"]["actual"], "beef")

    def test_bytes_differ_is_refuted(self):
        r = Verifier(self.data).verify(Claim("bytes_at", {"offset": 2, "expected": "0000"}))
        self.assertEqual(r["verdict"], REFUTED)
        self.assertEqual(r["evidence"]["actual"], "beef")

    def test_offset_out_of_range_is_inconclusive(self):
        r = Verifier(self.data).verify(Claim("bytes_at", {"offset": 99, "expected": "beef"}))
        self.assertEqual(r["verdict"], INCONCLUSIVE)


class TestPatternPresent(unittest.TestCase):
    def setUp(self):
        self.data = bytes.fromhex("00909043c3")

    def test_pattern_with_wildcard_present(self):
        r = Verifier(self.data).verify(Claim("pattern_present", {"pattern": "90 ?? 43"}))
        self.assertEqual(r["verdict"], VERIFIED)
        self.assertGreaterEqual(r["evidence"]["match_count"], 1)

    def test_pattern_absent_is_refuted(self):
        r = Verifier(self.data).verify(Claim("pattern_present", {"pattern": "11 22 33"}))
        self.assertEqual(r["verdict"], REFUTED)

    def test_pattern_at_claimed_offset(self):
        r = Verifier(self.data).verify(Claim("pattern_present", {"pattern": "90 90", "offset": 1}))
        self.assertEqual(r["verdict"], VERIFIED)

    def test_pattern_at_wrong_offset_refuted(self):
        r = Verifier(self.data).verify(Claim("pattern_present", {"pattern": "90 90", "offset": 0}))
        self.assertEqual(r["verdict"], REFUTED)


class TestStringPresent(unittest.TestCase):
    def setUp(self):
        self.data = b"xxADMINxxADMIN"

    def test_string_present(self):
        r = Verifier(self.data).verify(Claim("string_present", {"value": "ADMIN"}))
        self.assertEqual(r["verdict"], VERIFIED)
        self.assertEqual(r["evidence"]["occurrences"], 2)

    def test_string_at_offset(self):
        r = Verifier(self.data).verify(Claim("string_present", {"value": "ADMIN", "offset": 2}))
        self.assertEqual(r["verdict"], VERIFIED)

    def test_string_absent_refuted(self):
        r = Verifier(self.data).verify(Claim("string_present", {"value": "ROOT"}))
        self.assertEqual(r["verdict"], REFUTED)


class TestInstructions(unittest.TestCase):
    def setUp(self):
        # 55 = push, 90 = nop, C3 = ret (agrees between pure-python and capstone)
        self.data = bytes.fromhex("5590c3")

    def test_exact_sequence_verified(self):
        r = Verifier(self.data).verify(
            Claim("instructions", {"offset": 0, "mnemonics": ["push", "nop", "ret"]})
        )
        self.assertEqual(r["verdict"], VERIFIED)

    def test_wrong_sequence_refuted(self):
        r = Verifier(self.data).verify(
            Claim("instructions", {"offset": 0, "mnemonics": ["pop", "nop", "ret"]})
        )
        self.assertEqual(r["verdict"], REFUTED)
        self.assertEqual(r["evidence"]["actual_mnemonics"], ["push", "nop", "ret"])

    def test_contains_subsequence_verified(self):
        r = Verifier(self.data).verify(
            Claim("instructions", {"offset": 0, "mnemonics": ["push", "ret"], "mode": "contains"})
        )
        self.assertEqual(r["verdict"], VERIFIED)


class TestEmulateResult(unittest.TestCase):
    def test_add_result_verified(self):
        # mov eax,5 ; mov ecx,3 ; add eax,ecx ; ret  -> eax=8, ecx=3
        code = "b805000000b90300000001c8c3"
        r = Verifier(b"").verify(
            Claim("emulate_result", {"code": code, "arch": "x86", "expect_registers": {"eax": 8, "ecx": 3}})
        )
        self.assertEqual(r["verdict"], VERIFIED)

    def test_wrong_expectation_refuted(self):
        code = "b805000000b90300000001c8c3"
        r = Verifier(b"").verify(
            Claim("emulate_result", {"code": code, "arch": "x86", "expect_registers": {"eax": 99}})
        )
        self.assertEqual(r["verdict"], REFUTED)
        self.assertIn("eax", r["evidence"]["mismatches"])

    def test_emulate_from_offset(self):
        code = bytes.fromhex("b807000000c3")  # mov eax,7 ; ret
        data = b"\x00\x00" + code
        r = Verifier(data).verify(
            Claim("emulate_result", {"offset": 2, "length": 6, "arch": "x86", "expect_registers": {"eax": 7}})
        )
        self.assertEqual(r["verdict"], VERIFIED)


class TestProtobufField(unittest.TestCase):
    def setUp(self):
        # field 1: varint 150 (08 96 01); field 2: string "testing" (12 07 ...)
        self.data = bytes.fromhex("089601" + "1207" + b"testing".hex())

    def test_varint_field_value_verified(self):
        r = Verifier(self.data).verify(
            Claim("protobuf_field", {"field": 1, "type": "varint", "value": 150})
        )
        self.assertEqual(r["verdict"], VERIFIED)

    def test_string_field_value_verified(self):
        r = Verifier(self.data).verify(
            Claim("protobuf_field", {"field": 2, "type": "string", "value": "testing"})
        )
        self.assertEqual(r["verdict"], VERIFIED)

    def test_wrong_value_refuted(self):
        r = Verifier(self.data).verify(
            Claim("protobuf_field", {"field": 1, "type": "varint", "value": 999})
        )
        self.assertEqual(r["verdict"], REFUTED)

    def test_missing_field_refuted(self):
        r = Verifier(self.data).verify(Claim("protobuf_field", {"field": 9}))
        self.assertEqual(r["verdict"], REFUTED)


def _synthetic_pe_no_imports() -> bytes:
    buf = bytearray(1024)
    buf[0:2] = b"MZ"
    struct.pack_into("<I", buf, 0x3C, 0x80)
    pe_offset = 0x80
    buf[pe_offset : pe_offset + 4] = b"PE\x00\x00"
    struct.pack_into("<HHIIIHH", buf, pe_offset + 4, 0x8664, 1, 0, 0, 0, 240, 0x0022)
    opt_offset = pe_offset + 24
    struct.pack_into("<HBBIIIIQQII", buf, opt_offset, 0x20B, 14, 0, 0x1000, 0x2000, 0, 0x1000, 0x1000, 0x140000000, 0x1000, 0x200)
    sec1 = opt_offset + 240
    buf[sec1 : sec1 + 8] = b".text\x00\x00\x00"
    struct.pack_into("<IIIIIIHHI", buf, sec1 + 8, 0x500, 0x1000, 0x600, 0x400, 0, 0, 0, 0, 0x60000020)
    return bytes(buf)


class TestPeImport(unittest.TestCase):
    def test_non_pe_is_inconclusive(self):
        r = Verifier(b"not a pe file at all").verify(
            Claim("pe_import", {"function": "CreateFileW"})
        )
        self.assertEqual(r["verdict"], INCONCLUSIVE)

    def test_missing_import_refuted(self):
        r = Verifier(_synthetic_pe_no_imports()).verify(
            Claim("pe_import", {"dll": "kernel32.dll", "function": "CreateFileW"})
        )
        self.assertEqual(r["verdict"], REFUTED)


class TestAggregateAndEdgeCases(unittest.TestCase):
    def test_verify_all_summary(self):
        data = bytes.fromhex("deadbeef")
        report = verify_claims(
            data,
            [
                {"kind": "bytes_at", "offset": 0, "expected": "dead"},   # verified
                {"kind": "bytes_at", "offset": 0, "expected": "ffff"},   # refuted
            ],
        )
        self.assertEqual(report["total_claims"], 2)
        self.assertEqual(report["verified"], 1)
        self.assertEqual(report["refuted"], 1)
        self.assertFalse(report["trustworthy"])

    def test_all_verified_is_trustworthy(self):
        data = bytes.fromhex("deadbeef")
        report = verify_claims(data, [{"kind": "bytes_at", "offset": 0, "expected": "dead"}])
        self.assertTrue(report["trustworthy"])

    def test_unknown_kind_inconclusive(self):
        r = Verifier(b"x").verify(Claim("no_such_kind", {}))
        self.assertEqual(r["verdict"], INCONCLUSIVE)

    def test_malformed_claim_inconclusive(self):
        r = Verifier(b"x").verify(Claim("bytes_at", {}))  # missing offset/expected
        self.assertEqual(r["verdict"], INCONCLUSIVE)

    def test_flat_claim_dict_parsing(self):
        c = Claim.from_dict({"kind": "bytes_at", "offset": 0, "expected": "de", "note": "header"})
        self.assertEqual(c.kind, "bytes_at")
        self.assertEqual(c.params["expected"], "de")
        self.assertEqual(c.note, "header")


class TestVacuousClaimsNeverVerify(unittest.TestCase):
    """CONTRIBUTING: the verifier must never pass a claim that asserts nothing.

    The empty string is a substring of every byte stream, an all-wildcard pattern
    matches everywhere, zero bytes are equal everywhere, and an empty instruction
    list is satisfied by any code. All four used to come back VERIFIED (with a
    positive weight); they must now be refused instead.
    """

    def setUp(self):
        self.v = Verifier(b"hello world")

    def test_empty_string_present_is_not_verified(self):
        r = self.v.verify(Claim("string_present", {"value": ""}))
        self.assertEqual(r["verdict"], INCONCLUSIVE)

    def test_all_wildcard_pattern_is_not_verified(self):
        r = self.v.verify(Claim("pattern_present", {"pattern": "??"}))
        self.assertEqual(r["verdict"], INCONCLUSIVE)

    def test_empty_expected_bytes_is_not_verified(self):
        r = self.v.verify(Claim("bytes_at", {"offset": 3, "expected": ""}))
        self.assertEqual(r["verdict"], INCONCLUSIVE)

    def test_zero_length_bytes_is_not_verified(self):
        r = self.v.verify(Claim("bytes_at", {"offset": 3, "length": 0}))
        self.assertEqual(r["verdict"], INCONCLUSIVE)

    def test_empty_instructions_is_not_verified(self):
        r = self.v.verify(Claim("instructions", {"offset": 0, "mnemonics": []}))
        self.assertEqual(r["verdict"], INCONCLUSIVE)


if __name__ == "__main__":
    unittest.main()
