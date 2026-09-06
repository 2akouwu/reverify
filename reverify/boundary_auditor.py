#!/usr/bin/env python3
"""Security Boundary Auditor Module.

Provides defensive security checks and audits for:
1. Path Canonicalization & Symlink Containment (Filesystem Boundary)
2. Network Loopback, Private IP, DNS Rebinding & Metadata Filtering (SSRF Boundary)
3. State Serialization & Structured Snapshot Integrity (State Boundary)
4. Environment Variable & Secret Boundary Sanitization (Secret Boundary)
"""

import ipaddress
import json
import os
import re
import socket
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple, Union
from urllib.parse import urlparse


class PathBoundaryAuditor:
    """Audits and validates filesystem paths against containment rules."""

    RESERVED_WINDOWS_NAMES = {
        "CON", "PRN", "AUX", "NUL",
        "COM1", "COM2", "COM3", "COM4", "COM5", "COM6", "COM7", "COM8", "COM9",
        "LPT1", "LPT2", "LPT3", "LPT4", "LPT5", "LPT6", "LPT7", "LPT8", "LPT9",
    }

    @staticmethod
    def normalize_path(path_str: str) -> str:
        """Strip surrounding quotes and whitespace."""
        s = str(path_str).strip()
        while len(s) >= 2 and ((s[0] == '"' and s[-1] == '"') or (s[0] == "'" and s[-1] == "'")):
            s = s[1:-1].strip()
        return s

    @classmethod
    def is_safe_path(cls, base_dir: Union[str, Path], target_path: Union[str, Path]) -> bool:
        """Check if target_path resolves strictly within base_dir without escaping."""
        res = cls.audit_path(base_dir, target_path)
        return res["is_safe"]

    @classmethod
    def audit_path(cls, base_dir: Union[str, Path], target_path: Union[str, Path]) -> Dict[str, Any]:
        """Detailed path boundary security audit."""
        base_str = cls.normalize_path(str(base_dir))
        target_str = cls.normalize_path(str(target_path))

        findings: List[str] = []
        is_safe = True

        # Check reserved DOS device names
        path_obj = Path(target_str)
        for part in path_obj.parts:
            stem = part.split(".")[0].upper()
            if stem in cls.RESERVED_WINDOWS_NAMES:
                findings.append(f"Reserved DOS device name detected: {part}")
                is_safe = False

        # Check NT device namespace / UNC injection
        if target_str.startswith(("\\\\.\\", "\\\\?\\", "//./", "//?/")):
            findings.append("NT device namespace prefix detected")
            is_safe = False

        # Check NTFS Alternate Data Streams (ADS)
        if ":" in path_obj.name and len(path_obj.parts) > 0:
            if not (len(path_obj.parts) == 1 and path_obj.drive):
                findings.append(f"Potential NTFS Alternate Data Stream detected in '{path_obj.name}'")
                is_safe = False

        try:
            resolved_base = Path(base_str).resolve()
            if os.path.isabs(target_str):
                resolved_target = Path(target_str).resolve()
            else:
                resolved_target = (resolved_base / target_str).resolve()

            # Verify containment
            try:
                resolved_target.relative_to(resolved_base)
            except ValueError:
                findings.append(f"Path escape detected: '{resolved_target}' is outside base '{resolved_base}'")
                is_safe = False

        except Exception as e:
            findings.append(f"Path resolution error: {str(e)}")
            is_safe = False
            resolved_base = Path(base_str)
            resolved_target = Path(target_str)

        return {
            "is_safe": is_safe,
            "base_directory": str(resolved_base),
            "target_path": str(target_str),
            "resolved_target": str(resolved_target),
            "findings": findings,
        }


class NetworkBoundaryAuditor:
    """Audits network URLs and IP addresses to prevent SSRF and loopback leakage."""

    CLOUD_METADATA_IPS = {
        "169.254.169.254",  # AWS/GCP/Azure Instance Metadata
        "100.100.100.200",  # Alibaba Cloud Metadata
        "169.254.170.2",    # AWS ECS Task Metadata
    }

    DNS_REBINDING_DOMAINS = {
        "nip.io", "sslip.io", "traefik.me", "lvh.me", "localho.st",
    }

    SENSITIVE_INTERNAL_PORTS = {
        22: "SSH",
        2375: "Docker Daemon (Unencrypted)",
        2376: "Docker Daemon (TLS)",
        6379: "Redis",
        9200: "Elasticsearch",
        10250: "Kubelet API",
        27017: "MongoDB",
    }

    @classmethod
    def decode_numeric_ip(cls, host: str) -> Optional[str]:
        """Decode decimal, hex, or octal IPv4 string notations to canonical dotted quad."""
        # Decimal integer IP (e.g. 2130706433 -> 127.0.0.1)
        if host.isdigit():
            try:
                val = int(host)
                if 0 <= val <= 0xFFFFFFFF:
                    return str(ipaddress.IPv4Address(val))
            except Exception:
                pass

        # Hexadecimal IP (e.g. 0x7f000001)
        if host.lower().startswith("0x"):
            try:
                val = int(host, 16)
                if 0 <= val <= 0xFFFFFFFF:
                    return str(ipaddress.IPv4Address(val))
            except Exception:
                pass

        # Mixed / Octal notation (e.g. 0177.0.0.1 or 0x7f.0.0.1)
        if "." in host:
            parts = host.split(".")
            if len(parts) == 4:
                try:
                    octets = []
                    for p in parts:
                        if p.lower().startswith("0x"):
                            octets.append(int(p, 16))
                        elif p.startswith("0") and len(p) > 1 and p.isdigit():
                            octets.append(int(p, 8))
                        elif p.isdigit():
                            octets.append(int(p))
                        else:
                            return None
                    if all(0 <= o <= 255 for o in octets):
                        return ".".join(str(o) for o in octets)
                except Exception:
                    pass
        return None

    @classmethod
    def is_private_or_loopback_ip(cls, ip_str: str) -> Tuple[bool, str]:
        """Determine if an IP is loopback, private, link-local, or cloud metadata."""
        try:
            ip = ipaddress.ip_address(ip_str)
            # Handle IPv6-mapped IPv4 addresses (e.g. ::ffff:127.0.0.1)
            if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped:
                ip = ip.ipv4_mapped

            if str(ip) in cls.CLOUD_METADATA_IPS:
                return True, "Cloud Instance Metadata Endpoint"
            if ip.is_loopback:
                return True, "Loopback Address (Localhost)"
            if ip.is_private:
                return True, "Private / RFC1918 Network Address"
            if ip.is_link_local:
                return True, "Link-Local Address"
            if ip.is_multicast:
                return True, "Multicast Address"
            if ip.is_reserved:
                return True, "Reserved Network Address"
            return False, "Public / Routable Address"
        except ValueError:
            return False, "Invalid IP"

    @classmethod
    def audit_url(cls, url_str: str, allow_local: bool = False) -> Dict[str, Any]:
        """Audit a URL against network boundary security policies."""
        findings: List[str] = []
        is_safe = True

        try:
            parsed = urlparse(url_str)
            scheme = parsed.scheme.lower()
            hostname = parsed.hostname or ""
            port = parsed.port

            if scheme not in ("http", "https"):
                findings.append(f"Disallowed URL scheme: '{scheme}' (only HTTP/HTTPS permitted)")
                is_safe = False

            if not hostname:
                findings.append("Missing hostname in URL")
                is_safe = False
                return {
                    "is_safe": False,
                    "url": url_str,
                    "findings": findings,
                }

            # Check port sensitivities
            if port and port in cls.SENSITIVE_INTERNAL_PORTS:
                service = cls.SENSITIVE_INTERNAL_PORTS[port]
                findings.append(f"Target port {port} exposes sensitive internal service ({service})")
                is_safe = False

            # Check localhost aliases
            lower_host = hostname.lower()
            if lower_host in ("localhost", "localhost.localdomain", "127.0.0.1", "::1", "0.0.0.0"):
                if not allow_local:
                    findings.append(f"Localhost access target detected: '{hostname}'")
                    is_safe = False

            # Check DNS rebinding / wildcard domains
            for rebind in cls.DNS_REBINDING_DOMAINS:
                if lower_host == rebind or lower_host.endswith("." + rebind):
                    findings.append(f"DNS Rebinding wildcard domain detected: '{hostname}'")
                    is_safe = False
                    break

            # Check encoded IP representations
            decoded_ip = cls.decode_numeric_ip(hostname)
            eval_ip = decoded_ip or hostname

            # Evaluate IP classification
            try:
                is_priv, reason = cls.is_private_or_loopback_ip(eval_ip)
                if is_priv and not allow_local:
                    findings.append(f"Restricted network boundary access: {reason} ({eval_ip})")
                    is_safe = False
            except Exception:
                pass

        except Exception as e:
            findings.append(f"URL parse error: {str(e)}")
            is_safe = False

        return {
            "is_safe": is_safe,
            "url": url_str,
            "findings": findings,
        }


class EnvironmentBoundaryAuditor:
    """Audits and redacts secret tokens and credentials from environment snapshots."""

    SECRET_KEY_PATTERNS = [
        re.compile(r".*(?:api_key|apikey|secret|password|passwd|token|auth|credential|private_key).*", re.I),
        re.compile(r"^(?:AWS_SECRET_ACCESS_KEY|OPENAI_API_KEY|GITHUB_TOKEN|GH_TOKEN|ANTHROPIC_API_KEY)$", re.I),
    ]

    SECRET_VALUE_PATTERNS = [
        re.compile(r"^sk-[A-Za-z0-9_\-]{20,}$"),               # OpenAI / Service Keys
        re.compile(r"^ghp_[A-Za-z0-9]{30,}$"),                 # GitHub Personal Access Token
        re.compile(r"-----BEGIN [A-Z ]+ PRIVATE KEY-----"),     # PEM Private Keys
        re.compile(r"^Bearer\s+[A-Za-z0-9_\-\.]{20,}$", re.I), # JWT / Bearer Tokens
    ]

    @classmethod
    def is_secret(cls, key: str, value: str) -> bool:
        """Identify whether a key-value pair constitutes sensitive credential data."""
        for pat in cls.SECRET_KEY_PATTERNS:
            if pat.match(key):
                return True
        for pat in cls.SECRET_VALUE_PATTERNS:
            if pat.search(str(value)):
                return True
        return False

    @classmethod
    def sanitize_dict(cls, data: Dict[str, Any]) -> Dict[str, Any]:
        """Return a sanitized copy of a dictionary with sensitive keys redacted."""
        sanitized = {}
        for k, v in data.items():
            if isinstance(v, dict):
                sanitized[k] = cls.sanitize_dict(v)
            elif isinstance(v, str) and cls.is_secret(k, v):
                sanitized[k] = "[REDACTED_SECRET]"
            else:
                sanitized[k] = v
        return sanitized

    @classmethod
    def audit_environment(cls, env_dict: Dict[str, str]) -> Dict[str, Any]:
        """Audit environment snapshot and report exposed secret keys."""
        leaked_keys: List[str] = []
        for k, v in env_dict.items():
            if cls.is_secret(k, v):
                leaked_keys.append(k)

        return {
            "is_safe": len(leaked_keys) == 0,
            "secret_count": len(leaked_keys),
            "leaked_keys": leaked_keys,
            "sanitized_preview": cls.sanitize_dict(env_dict),
        }


class StateIntegrityAuditor:
    """Audits state serialization and receipt schemas."""

    FORBIDDEN_PROPERTIES = {"__proto__", "constructor", "prototype"}

    @classmethod
    def audit_state_json(cls, data: Union[str, bytes, dict, list]) -> Dict[str, Any]:
        """Audit serialized state data for injection and integrity violations."""
        findings: List[str] = []
        is_safe = True

        obj: Any = None
        if isinstance(data, (str, bytes)):
            try:
                obj = json.loads(data)
            except Exception as e:
                return {
                    "is_safe": False,
                    "findings": [f"Invalid JSON format: {str(e)}"],
                }
        else:
            obj = data

        def traverse(node: Any, path: str = ""):
            nonlocal is_safe
            if isinstance(node, dict):
                for k, v in node.items():
                    if k in cls.FORBIDDEN_PROPERTIES:
                        findings.append(f"Object prototype pollution key detected at '{path}.{k}'")
                        is_safe = False
                    if len(k) > 1024:
                        findings.append(f"Abnormally long dictionary key at '{path}' ({len(k)} chars)")
                        is_safe = False
                    traverse(v, f"{path}.{k}" if path else str(k))
            elif isinstance(node, list):
                if len(node) > 50000:
                    findings.append(f"List length exceeds security budget at '{path}' ({len(node)} items)")
                    is_safe = False
                for idx, item in enumerate(node[:100]):
                    traverse(item, f"{path}[{idx}]")

        traverse(obj)

        return {
            "is_safe": is_safe,
            "findings": findings,
        }


def run_full_security_audit(
    workspace_dir: str,
    target_urls: Optional[List[str]] = None,
    env_snapshot: Optional[Dict[str, str]] = None,
) -> Dict[str, Any]:
    """Execute a comprehensive boundary audit report across filesystem, network, and environment.

    ``env_snapshot`` defaults to the real process environment (``os.environ``) so a
    live ``reverify audit-boundary`` run audits the environment it actually runs in.
    Pass an explicit dict (as the test suite does) to audit a fixed, reproducible
    snapshot instead.
    """
    report: Dict[str, Any] = {
        "status": "PASS",
        "workspace_root": str(Path(workspace_dir).resolve()),
        "filesystem_audit": {},
        "network_audit": [],
        "environment_audit": {},
        "state_audit": {},
        "summary": "All security boundaries intact.",
    }

    # Filesystem audit on workspace
    ws_path = Path(workspace_dir)
    test_paths = [
        "valid_sub/file.txt",
        "../escaped.txt",
        "../../Windows/System32/config/SAM",
        "NUL",
    ]
    fs_results = []
    for p in test_paths:
        res = PathBoundaryAuditor.audit_path(ws_path, p)
        fs_results.append(res)
    report["filesystem_audit"] = {
        "traversal_blocked": not any(r["is_safe"] for r in fs_results if "escape" in str(r["findings"]) or "SAM" in r["target_path"]),
        "tests_evaluated": len(fs_results),
    }

    # Network audit
    urls_to_test = target_urls or [
        "https://api.openai.com/v1",
        "http://127.0.0.1:8080/admin",
        "http://169.254.169.254/latest/meta-data/",
        "http://[::1]:9000/metrics",
        "http://2130706433:80/",
        "http://attacker.127.0.0.1.nip.io/",
    ]
    net_results = []
    for u in urls_to_test:
        net_results.append(NetworkBoundaryAuditor.audit_url(u, allow_local=False))
    report["network_audit"] = net_results

    # Environment audit — the real process environment unless a snapshot is injected
    env_dict = dict(os.environ) if env_snapshot is None else env_snapshot
    env_res = EnvironmentBoundaryAuditor.audit_environment(env_dict)
    sanitized_preview = env_res["sanitized_preview"]
    report["environment_audit"] = {
        "secrets_detected": env_res["secret_count"],
        # Every key the auditor flagged as a secret must come back redacted in the
        # preview. Checking the general invariant (rather than one hardcoded key)
        # means this holds regardless of which secret-shaped variables are present.
        "sanitized_safe": all(
            sanitized_preview.get(k) == "[REDACTED_SECRET]" for k in env_res["leaked_keys"]
        ),
    }

    # Overall health
    has_fs_breach = not report["filesystem_audit"]["traversal_blocked"]
    # Match on the parsed hostname (exact or dotted-suffix), not a substring of the
    # raw URL: a plain `"nip.io" in url` check would also match an unrelated URL
    # that merely contains that text elsewhere (e.g. a query string or a longer
    # domain label), which is exactly the class of bug this replaces.
    has_net_leak = False
    for r in net_results:
        try:
            # .hostname raises ValueError on a malformed IPv6-bracket literal
            # (e.g. an unclosed "[::1" or an invalid address inside brackets).
            # NetworkBoundaryAuditor.audit_url() already caught that when it
            # produced r["is_safe"]/r["findings"]; this summary pass must not
            # re-raise on the same string, or a caller-supplied --urls value
            # could crash the whole audit-boundary command.
            host = (urlparse(r["url"]).hostname or "").lower()
        except ValueError:
            host = ""
        flagged_host = (
            host in ("127.0.0.1", "169.254.169.254", "::1")
            or host == "nip.io"
            or host.endswith(".nip.io")
            or NetworkBoundaryAuditor.decode_numeric_ip(host) in ("127.0.0.1", "169.254.169.254")
        )
        if flagged_host and r["is_safe"]:
            has_net_leak = True
            break

    if has_fs_breach or has_net_leak or not report["environment_audit"]["sanitized_safe"]:
        report["status"] = "FAIL"
        report["summary"] = "Security boundary violation detected."

    return report


if __name__ == "__main__":
    import pprint
    current_dir = os.getcwd()
    result = run_full_security_audit(current_dir)
    pprint.pprint(result)
