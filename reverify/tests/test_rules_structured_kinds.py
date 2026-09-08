"""Regression test for issue #14: RULES must steer the model to the structured claim kinds.

Before the fix, the RULES block in reverify/agent.py only ever recommended the
raw kinds (bytes_at / u32_at / u64_at / instructions / emulate_result). Under an
open-ended goal the model then drifted to raw byte-guessing over the orchestrate
loop and never reached for the structured kinds, so the ledger filled with
OBSERVED byte reads and the run never converged (see #14).

This test pins that RULES references the structured kinds, so a future refactor
that drops the guidance cannot silently re-introduce the drift.
"""
import unittest

from reverify.agent import RULES


class TestRulesStructuredKinds(unittest.TestCase):
    # The structured claim kinds the model should reach for on
    # import / export / string / section / behavior goals (issue #14).
    STRUCTURED_KINDS = (
        "import_present",
        "export_present",
        "string_present",
        "section_present",
        "behavior_equiv",
        "prove_equiv",
    )

    def test_rules_references_structured_kinds(self):
        missing = [k for k in self.STRUCTURED_KINDS if k not in RULES]
        self.assertEqual(
            missing,
            [],
            "RULES should steer the model to the structured kinds (issue #14) "
            f"but omits: {missing}",
        )

    def test_raw_kinds_still_mentioned(self):
        # The nudge is additive: byte-level claims still live on the raw kinds,
        # so the guidance for them must survive the change (guard against
        # over-correcting by deleting the raw-kind line).
        for kind in ("bytes_at", "u32_at", "u64_at", "instructions", "emulate_result"):
            self.assertIn(kind, RULES, f"raw kind {kind} no longer mentioned in RULES")


if __name__ == "__main__":
    unittest.main()
