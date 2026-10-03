"""Regression tests for import_present parameter validation (#23)."""

import json
import unittest
from unittest import mock

from reverify import mcp_server
from reverify.verifier import INCONCLUSIVE, REFUTED, VERIFIED, Claim, Verifier


class _FakeBinary:
    format = "PE"
    backend = "test"
    error = None

    def __init__(self):
        self.imports = {"USER32.dll": ["MessageBoxW"]}
        self.libraries = ["USER32.dll"]

    def has_import(self, function, lib=None):
        library = next(
            (name for name in self.imports if lib is None or name.lower() == lib.lower()),
            None,
        )
        return library is not None and function in self.imports[library]


class TestImportPresentSchema(unittest.TestCase):
    def setUp(self):
        self.verifier = Verifier(b"not used")
        self.verifier._binary = lambda: _FakeBinary()

    def test_symbol_alias_cannot_degrade_to_library_only_verified(self):
        result = self.verifier.verify(Claim(
            "import_present",
            {"dll": "USER32.dll", "symbol": "ShowWindow"},
        ))
        self.assertEqual(result["verdict"], INCONCLUSIVE)
        self.assertIn("unknown parameter", result["detail"])
        self.assertNotEqual(result["verdict"], VERIFIED)

    def test_arbitrary_unknown_parameter_is_inconclusive(self):
        result = self.verifier.verify(Claim(
            "import_present",
            {"lib": "USER32.dll", "typo": "MessageBoxW"},
        ))
        self.assertEqual(result["verdict"], INCONCLUSIVE)
        self.assertIn("typo", result["detail"])

    def test_pe_import_alias_uses_same_strict_schema(self):
        result = self.verifier.verify(Claim(
            "pe_import",
            {"dll": "USER32.dll", "func": "MessageBoxW"},
        ))
        self.assertEqual(result["verdict"], INCONCLUSIVE)
        self.assertIn("func", result["detail"])

    def test_mcp_channel_does_not_record_miskeyed_import_as_verified(self):
        from pathlib import Path
        from tempfile import TemporaryDirectory

        with TemporaryDirectory() as directory:
            binary = Path(directory) / "sample.exe"
            binary.write_bytes(b"transport only")
            with mock.patch.object(Verifier, "_binary", return_value=_FakeBinary()):
                report = json.loads(mcp_server.handle_tool_call(
                    "re_verify_claim",
                    {
                        "file_path": str(binary),
                        "claims": [{
                            "kind": "import_present",
                            "params": {
                                "dll": "USER32.dll",
                                "symbol": "ShowWindow",
                            },
                        }],
                        "record": False,
                    },
                ))
        self.assertEqual(report["results"][0]["verdict"], INCONCLUSIVE)
        self.assertEqual(
            report["ledger"]["recorded"],
            {"facts": 0, "observed": 0, "refuted": 0},
        )

    def test_valid_library_only_claim_remains_verified(self):
        result = self.verifier.verify(Claim(
            "import_present", {"dll": "USER32.dll"}
        ))
        self.assertEqual(result["verdict"], VERIFIED)
        self.assertEqual(result["detail"], "library import check")

    def test_valid_function_claim_still_checks_the_symbol(self):
        present = self.verifier.verify(Claim(
            "import_present",
            {"dll": "USER32.dll", "function": "MessageBoxW"},
        ))
        absent = self.verifier.verify(Claim(
            "import_present",
            {"dll": "USER32.dll", "function": "ShowWindow"},
        ))
        self.assertEqual(present["verdict"], VERIFIED)
        self.assertEqual(absent["verdict"], REFUTED)


if __name__ == "__main__":
    unittest.main()
