#!/usr/bin/env python3
"""Unit tests for Security Boundary Auditor."""

import os
import sys
import unittest
from pathlib import Path

# Add toolkit parent dir to path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from boundary_auditor import (
    PathBoundaryAuditor,
    NetworkBoundaryAuditor,
    EnvironmentBoundaryAuditor,
    StateIntegrityAuditor,
    run_full_security_audit,
)


class TestPathBoundaryAuditor(unittest.TestCase):
    """Test filesystem path canonicalization and boundary containment."""

    def setUp(self):
        self.base_dir = Path(__file__).resolve().parent

    def test_safe_relative_path(self):
        res = PathBoundaryAuditor.audit_path(self.base_dir, "test_pe_parser.py")
        self.assertTrue(res["is_safe"])
        self.assertEqual(len(res["findings"]), 0)

    def test_traversal_escape(self):
        res = PathBoundaryAuditor.audit_path(self.base_dir, "../../../../../Windows/System32")
        self.assertFalse(res["is_safe"])
        self.assertTrue(any("escape" in f.lower() for f in res["findings"]))

    def test_reserved_windows_device_names(self):
        for dev in ["NUL", "CON", "PRN", "AUX", "COM1", "LPT1"]:
            res = PathBoundaryAuditor.audit_path(self.base_dir, dev)
            self.assertFalse(res["is_safe"])
            self.assertTrue(any("reserved dos device" in f.lower() for f in res["findings"]))

    def test_nt_device_namespace(self):
        res = PathBoundaryAuditor.audit_path(self.base_dir, r"\\.\PhysicalDrive0")
        self.assertFalse(res["is_safe"])
        self.assertTrue(any("nt device namespace" in f.lower() for f in res["findings"]))

    def test_alternate_data_stream(self):
        res = PathBoundaryAuditor.audit_path(self.base_dir, "safe_file.txt:hidden_stream")
        self.assertFalse(res["is_safe"])
        self.assertTrue(any("alternate data stream" in f.lower() for f in res["findings"]))


class TestNetworkBoundaryAuditor(unittest.TestCase):
    """Test SSRF, cloud metadata, DNS rebinding, and loopback filtering."""

    def test_public_allowed_url(self):
        res = NetworkBoundaryAuditor.audit_url("https://api.openai.com/v1/chat/completions")
        self.assertTrue(res["is_safe"])
        self.assertEqual(len(res["findings"]), 0)

    def test_localhost_blocked(self):
        for host in ["localhost", "127.0.0.1", "0.0.0.0"]:
            res = NetworkBoundaryAuditor.audit_url(f"http://{host}:8000/api")
            self.assertFalse(res["is_safe"])
            self.assertTrue(any("localhost" in f.lower() or "loopback" in f.lower() or "restricted" in f.lower() for f in res["findings"]))

    def test_encoded_ip_formats_blocked(self):
        # Decimal 2130706433 = 127.0.0.1
        res = NetworkBoundaryAuditor.audit_url("http://2130706433/admin")
        self.assertFalse(res["is_safe"])
        self.assertTrue(any("loopback" in f.lower() or "restricted" in f.lower() for f in res["findings"]))

        # Hex 0x7f000001 = 127.0.0.1
        res = NetworkBoundaryAuditor.audit_url("http://0x7f000001/")
        self.assertFalse(res["is_safe"])
        self.assertTrue(any("loopback" in f.lower() or "restricted" in f.lower() for f in res["findings"]))

        # Octal 0177.0.0.1 = 127.0.0.1
        res = NetworkBoundaryAuditor.audit_url("http://0177.0.0.1/")
        self.assertFalse(res["is_safe"])
        self.assertTrue(any("loopback" in f.lower() or "restricted" in f.lower() for f in res["findings"]))

    def test_dns_rebinding_blocked(self):
        res = NetworkBoundaryAuditor.audit_url("http://custom.127.0.0.1.nip.io:8080/")
        self.assertFalse(res["is_safe"])
        self.assertTrue(any("dns rebinding" in f.lower() for f in res["findings"]))

    def test_cloud_metadata_blocked(self):
        res = NetworkBoundaryAuditor.audit_url("http://169.254.169.254/latest/meta-data/")
        self.assertFalse(res["is_safe"])
        self.assertTrue(any("cloud instance metadata" in f.lower() or "restricted" in f.lower() for f in res["findings"]))

    def test_private_rfc1918_blocked(self):
        for priv_ip in ["10.0.0.1", "172.16.5.10", "192.168.1.1"]:
            res = NetworkBoundaryAuditor.audit_url(f"http://{priv_ip}/admin")
            self.assertFalse(res["is_safe"])
            self.assertTrue(any("private" in f.lower() or "restricted" in f.lower() for f in res["findings"]))

    def test_sensitive_internal_ports_blocked(self):
        for port in [22, 2375, 6379, 27017]:
            res = NetworkBoundaryAuditor.audit_url(f"http://example.com:{port}/")
            self.assertFalse(res["is_safe"])
            self.assertTrue(any("sensitive internal service" in f.lower() for f in res["findings"]))

    def test_disallowed_schemes(self):
        for scheme in ["file:///etc/passwd", "gopher://127.0.0.1:6379/_", "dict://127.0.0.1:11211/"]:
            res = NetworkBoundaryAuditor.audit_url(scheme)
            self.assertFalse(res["is_safe"])
            self.assertTrue(any("disallowed url scheme" in f.lower() for f in res["findings"]))


class TestEnvironmentBoundaryAuditor(unittest.TestCase):
    """Test environment secrets redaction and auditing."""

    def test_secret_detection_and_redaction(self):
        env_dict = {
            "HOME": "/home/user",
            "OPENAI_API_KEY": "sk-proj-123456789012345678901234567890",
            "DB_PASSWORD": "SuperSecretPassword123!",
            "GITHUB_TOKEN": "ghp_123456789012345678901234567890123456",
        }
        res = EnvironmentBoundaryAuditor.audit_environment(env_dict)
        self.assertFalse(res["is_safe"])
        self.assertEqual(res["secret_count"], 3)
        self.assertIn("OPENAI_API_KEY", res["leaked_keys"])
        self.assertIn("DB_PASSWORD", res["leaked_keys"])
        self.assertIn("GITHUB_TOKEN", res["leaked_keys"])

        # Check sanitization
        sanitized = res["sanitized_preview"]
        self.assertEqual(sanitized["HOME"], "/home/user")
        self.assertEqual(sanitized["OPENAI_API_KEY"], "[REDACTED_SECRET]")
        self.assertEqual(sanitized["DB_PASSWORD"], "[REDACTED_SECRET]")
        self.assertEqual(sanitized["GITHUB_TOKEN"], "[REDACTED_SECRET]")


class TestStateIntegrityAuditor(unittest.TestCase):
    """Test state serialization and prototype pollution checks."""

    def test_valid_state_json(self):
        valid = {"version": "1.0", "status": "active", "items": [1, 2, 3]}
        res = StateIntegrityAuditor.audit_state_json(valid)
        self.assertTrue(res["is_safe"])
        self.assertEqual(len(res["findings"]), 0)

    def test_prototype_pollution_blocked(self):
        malicious = {"user": "admin", "__proto__": {"isAdmin": True}}
        res = StateIntegrityAuditor.audit_state_json(malicious)
        self.assertFalse(res["is_safe"])
        self.assertTrue(any("prototype pollution" in f.lower() for f in res["findings"]))


class TestFullAudit(unittest.TestCase):
    """Test end-to-end full audit report generation.

    ``env_snapshot`` is always passed explicitly here so these tests stay
    deterministic regardless of what the ambient process environment (CI runner,
    developer machine, ...) happens to contain — ``run_full_security_audit``
    defaults to the real ``os.environ`` only when the caller (e.g. the live CLI)
    doesn't supply a snapshot.
    """

    def test_full_security_audit_run(self):
        """A clean workspace and a secret-free environment snapshot audit as PASS."""
        report = run_full_security_audit(
            str(Path(__file__).resolve().parent),
            env_snapshot={"HOME": "/home/user"},
        )
        self.assertEqual(report["status"], "PASS")
        self.assertTrue(report["filesystem_audit"]["traversal_blocked"])
        self.assertTrue(len(report["network_audit"]) > 0)
        self.assertEqual(report["environment_audit"]["secrets_detected"], 0)
        self.assertTrue(report["environment_audit"]["sanitized_safe"])

    def test_full_security_audit_flags_leaked_secret(self):
        """A snapshot with no OPENAI_API_KEY at all must not crash (regression test:
        sanitized_safe used to be hardcoded to that one key's presence), and a real
        secret under any other key must still be detected and redacted.
        """
        report = run_full_security_audit(
            str(Path(__file__).resolve().parent),
            env_snapshot={"DB_PASSWORD": "SuperSecretPassword123!"},
        )
        self.assertEqual(report["environment_audit"]["secrets_detected"], 1)
        self.assertTrue(report["environment_audit"]["sanitized_safe"])

    def test_full_security_audit_survives_malformed_target_url(self):
        """A malformed IPv6-bracket literal makes urlparse(...).hostname raise
        ValueError. The audit must still complete (not crash) and treat the
        unparseable target as already handled by NetworkBoundaryAuditor's own
        is_safe=False classification, not as a fatal error.
        """
        report = run_full_security_audit(
            str(Path(__file__).resolve().parent),
            target_urls=["http://[::1", "https://api.openai.com/v1"],
            env_snapshot={},
        )
        self.assertEqual(len(report["network_audit"]), 2)
        self.assertFalse(report["network_audit"][0]["is_safe"])

    def test_full_security_audit_detects_dns_rebinding_target(self):
        """Both a nip.io DNS-rebinding target and a benign URL classify correctly,
        so the summary self-check must not flag a leak on either of them.
        """
        report = run_full_security_audit(
            str(Path(__file__).resolve().parent),
            target_urls=["http://attacker.127.0.0.1.nip.io/", "https://api.openai.com/v1"],
            env_snapshot={},
        )
        self.assertEqual(report["status"], "PASS")


if __name__ == "__main__":
    unittest.main()
