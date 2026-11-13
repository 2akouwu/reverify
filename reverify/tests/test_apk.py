import argparse
import contextlib
import hashlib
import io
import json
import struct
import sys
import unittest
from unittest import mock
import zipfile
from pathlib import Path

tools_root = Path(__file__).resolve().parent.parent
if str(tools_root) not in sys.path:
    sys.path.insert(0, str(tools_root))

from apk import (  # noqa: E402
    ANDROID_NS,
    APK_SIG_BLOCK_MAGIC,
    ApkError,
    _bool_value,
    _mutf8,
    decode_axml,
    inspect_apk,
    is_apk,
    parse_dex,
)
import apk as apk_module  # noqa: E402
from cli import auto_triage, cmd_auto, cmd_parse_apk  # noqa: E402
from verifier import (  # noqa: E402
    Claim,
    INCONCLUSIVE,
    OBSERVED,
    REFUTED,
    VERIFIED,
    Verifier,
)


def _len8(n: int) -> bytes:
    if n > 0x7F:
        return bytes([0x80 | (n >> 8), n & 0xFF])
    return bytes([n])


def _len16(n: int) -> bytes:
    if n > 0x7FFF:
        return struct.pack("<HH", 0x8000 | (n >> 16), n & 0xFFFF)
    return struct.pack("<H", n)


def _string_pool(strings):
    offsets = []
    payload = bytearray()
    for value in strings:
        offsets.append(len(payload))
        encoded = value.encode("utf-16le")
        payload += _len16(len(value)) + encoded + b"\x00\x00"
    while len(payload) % 4:
        payload += b"\x00"
    header_size = 28
    strings_start = header_size + len(strings) * 4
    chunk_size = strings_start + len(payload)
    chunk = bytearray(struct.pack("<HHI", 0x0001, header_size, chunk_size))
    chunk += struct.pack("<IIIII", len(strings), 0, 0, strings_start, 0)
    for offset in offsets:
        chunk += struct.pack("<I", offset)
    chunk += payload
    return bytes(chunk)


class _AxmlBuilder:
    def __init__(self):
        self.strings = []
        self._index = {}
        self.events = []

    def s(self, value: str) -> int:
        if value not in self._index:
            self._index[value] = len(self.strings)
            self.strings.append(value)
        return self._index[value]

    def start_ns(self, prefix: str, uri: str):
        self.events.append(("start_ns", prefix, uri))

    def end_ns(self, prefix: str, uri: str):
        self.events.append(("end_ns", prefix, uri))

    def start(self, name: str, attrs=()):
        self.events.append(("start", name, list(attrs)))

    def end(self, name: str):
        self.events.append(("end", name))

    def build(self) -> bytes:
        for event in self.events:
            if event[0] == "start_ns":
                self.s(event[1])
                self.s(event[2])
            elif event[0] == "end_ns":
                self.s(event[1])
                self.s(event[2])
            elif event[0] in ("start", "end"):
                self.s(event[1])
                if event[0] == "start":
                    for ns, name, value in event[2]:
                        if ns:
                            self.s(ns)
                        self.s(name)
                        if isinstance(value, str):
                            self.s(value)

        pool = _string_pool(self.strings)
        chunks = bytearray()
        for event in self.events:
            if event[0] == "start_ns":
                chunks += struct.pack("<HHI", 0x0100, 16, 24)
                chunks += struct.pack("<IIII", 1, 0xFFFFFFFF, self.s(event[1]), self.s(event[2]))
            elif event[0] == "end_ns":
                chunks += struct.pack("<HHI", 0x0101, 16, 24)
                chunks += struct.pack("<IIII", 1, 0xFFFFFFFF, self.s(event[1]), self.s(event[2]))
            elif event[0] == "end":
                chunks += struct.pack("<HHI", 0x0103, 16, 24)
                chunks += struct.pack("<IIII", 1, 0xFFFFFFFF, 0xFFFFFFFF, self.s(event[1]))
            else:
                name = self.s(event[1])
                attrs = event[2]
                records = bytearray()
                for ns, attr_name, value in attrs:
                    ns_idx = 0xFFFFFFFF if ns is None else self.s(ns)
                    raw_idx = 0xFFFFFFFF
                    if isinstance(value, int):
                        data_type, data = 0x10, value
                    else:
                        data_type, data = 0x03, self.s(value)
                    records += struct.pack("<IIIHBBI", ns_idx, self.s(attr_name), raw_idx,
                                           8, 0, data_type, data)
                size = 8 + 8 + 20 + len(records)
                chunks += struct.pack("<HHI", 0x0102, 16, size)
                chunks += struct.pack("<II", 1, 0xFFFFFFFF)
                chunks += struct.pack("<I", 0xFFFFFFFF)
                chunks += struct.pack("<I", name)
                chunks += struct.pack("<HHHHHH", 20, 20, len(attrs), 0, 0, 0)
                chunks += records
        return struct.pack("<HHI", 0x0003, 8, 8 + len(pool) + len(chunks)) + pool + bytes(chunks)


CUSTOM_NS = "http://example.com/custom"


def synthetic_manifest_axml(activity_name: str = ".MainActivity", custom_collision: bool = False) -> bytes:
    builder = _AxmlBuilder()
    if custom_collision:
        builder.start_ns("custom", CUSTOM_NS)
    builder.start_ns("android", ANDROID_NS)
    manifest_attrs = [
        (None, "package", "com.example.tv"),
        (ANDROID_NS, "versionCode", 42),
        (ANDROID_NS, "versionName", "1.2.3"),
        (ANDROID_NS, "compileSdkVersion", 33),
    ]
    if custom_collision:
        manifest_attrs.insert(0, (CUSTOM_NS, "package", "com.evil.package"))
    builder.start("manifest", manifest_attrs)
    builder.start("uses-sdk", [
        (ANDROID_NS, "minSdkVersion", 21),
        (ANDROID_NS, "targetSdkVersion", 30),
    ])
    builder.end("uses-sdk")
    permission_attrs = [(ANDROID_NS, "name", "android.permission.INTERNET")]
    if custom_collision:
        permission_attrs.insert(0, (CUSTOM_NS, "name", "custom.permission.FAKE"))
    builder.start("uses-permission", permission_attrs)
    builder.end("uses-permission")
    builder.start("application")
    activity_attrs = [(ANDROID_NS, "name", activity_name)]
    if custom_collision:
        activity_attrs.insert(0, (CUSTOM_NS, "name", ".FakeActivity"))
    builder.start("activity", activity_attrs)
    builder.start("intent-filter")
    builder.start("action", [(ANDROID_NS, "name", "android.intent.action.MAIN")])
    builder.end("action")
    builder.start("category", [(ANDROID_NS, "name", "android.intent.category.LEANBACK_LAUNCHER")])
    builder.end("category")
    builder.end("intent-filter")
    builder.end("activity")
    builder.start("activity-alias", [(ANDROID_NS, "name", ".AliasActivity")])
    builder.end("activity-alias")
    builder.end("application")
    builder.end("manifest")
    builder.end_ns("android", ANDROID_NS)
    if custom_collision:
        builder.end_ns("custom", CUSTOM_NS)
    return builder.build()


def _uleb(n: int) -> bytes:
    out = bytearray()
    while True:
        byte = n & 0x7F
        n >>= 7
        if n:
            out.append(byte | 0x80)
        else:
            out.append(byte)
            return bytes(out)


def synthetic_dex() -> bytes:
    strings = ["Lcom/example/Hello;", "Ljava/lang/Object;", "greet", "()V", "V"]
    string_ids_off = 0x70
    type_ids_off = string_ids_off + len(strings) * 4
    proto_ids_off = type_ids_off + 3 * 4
    method_ids_off = proto_ids_off + 12
    class_defs_off = method_ids_off + 8
    data_off = class_defs_off + 32
    string_data = bytearray()
    string_offsets = []
    for value in strings:
        string_offsets.append(data_off + len(string_data))
        encoded = value.encode("utf-8")
        string_data += _uleb(len(value)) + encoded + b"\x00"
    class_data_off = data_off + len(string_data)
    class_data = bytes([0, 0, 1, 0]) + _uleb(0) + _uleb(1) + _uleb(0)

    header = bytearray(0x70)
    header[0:8] = b"dex\n035\x00"
    struct.pack_into("<I", header, 32, data_off + len(string_data) + len(class_data))
    struct.pack_into("<I", header, 36, 0x70)
    struct.pack_into("<I", header, 40, 0x12345678)
    struct.pack_into("<I", header, 56, len(strings))
    struct.pack_into("<I", header, 60, string_ids_off)
    struct.pack_into("<I", header, 64, 3)
    struct.pack_into("<I", header, 68, type_ids_off)
    struct.pack_into("<I", header, 72, 1)
    struct.pack_into("<I", header, 76, proto_ids_off)
    struct.pack_into("<I", header, 88, 1)
    struct.pack_into("<I", header, 92, method_ids_off)
    struct.pack_into("<I", header, 96, 1)
    struct.pack_into("<I", header, 100, class_defs_off)
    struct.pack_into("<I", header, 104, len(string_data) + len(class_data))
    struct.pack_into("<I", header, 108, data_off)

    body = bytearray(header)
    for offset in string_offsets:
        body += struct.pack("<I", offset)
    body += struct.pack("<III", 0, 1, 4)  # types: Hello, Object, V
    body += struct.pack("<III", 4, 2, 0)  # shorty "V", return type "V"
    body += struct.pack("<HHI", 0, 0, 2)  # Hello.greet
    body += struct.pack("<IIIIIIII", 0, 1, 1, 0, 0xFFFFFFFF, 0, class_data_off, 0)
    body += string_data
    body += class_data
    return bytes(body)


def _lp(value: bytes) -> bytes:
    return struct.pack("<I", len(value)) + value


def _find_eocd(data: bytes):
    start = max(0, len(data) - 0xFFFF - 22)
    index = data.rfind(b"PK\x05\x06", start)
    while index >= 0:
        if index + 22 <= len(data):
            comment_len = struct.unpack_from("<H", data, index + 20)[0]
            if index + 22 + comment_len <= len(data):
                return index
        index = data.rfind(b"PK\x05\x06", start, index)
    return None


def _corrupt_signing_size(apk: bytes) -> bytes:
    eocd = _find_eocd(apk)
    central_dir = struct.unpack_from("<I", apk, eocd + 16)[0]
    size = struct.unpack_from("<Q", apk, central_dir - 24)[0]
    bad = bytearray(apk)
    struct.pack_into("<Q", bad, central_dir - 24, size + 1)
    return bytes(bad)


def _add_signing_block(apk: bytes, pairs) -> bytes:
    eocd = _find_eocd(apk)
    central_dir = struct.unpack_from("<I", apk, eocd + 16)[0]
    payload = bytearray()
    for pair_id, value in pairs:
        pair = struct.pack("<I", pair_id) + value
        payload += struct.pack("<Q", len(pair)) + pair
    size = len(payload) + 8 + 16
    block = struct.pack("<Q", size) + bytes(payload) + struct.pack("<Q", size) + APK_SIG_BLOCK_MAGIC
    out = bytearray(apk[:central_dir] + block + apk[central_dir:])
    struct.pack_into("<I", out, eocd + len(block) + 16, central_dir + len(block))
    return bytes(out)


def _v2_value(cert: bytes, chain=()) -> bytes:
    certs = b"".join(_lp(c) for c in (cert,) + tuple(chain))
    signed_data = _lp(b"") + _lp(certs) + _lp(b"")
    signer = _lp(signed_data) + _lp(b"") + _lp(b"public-key")
    return _lp(_lp(signer))


def _v3_value(cert: bytes, chain=()) -> bytes:
    certs = b"".join(_lp(c) for c in (cert,) + tuple(chain))
    signed_data = _lp(b"") + _lp(certs) + struct.pack("<II", 21, 30) + _lp(b"")
    signer = _lp(signed_data) + struct.pack("<II", 21, 30) + _lp(b"") + _lp(b"public-key")
    return _lp(_lp(signer))


def _der(tag: int, content: bytes) -> bytes:
    length = len(content)
    if length < 0x80:
        encoded = bytes([length])
    else:
        raw = length.to_bytes((length.bit_length() + 7) // 8, "big")
        encoded = bytes([0x80 | len(raw)]) + raw
    return bytes([tag]) + encoded + content


def _issuer_der() -> bytes:
    return _der(0x30, _der(0x31, _der(0x30, _der(0x06, bytes.fromhex("2A864886F70D010101"))
                                      + _der(0x0C, b"Test"))))


CERT_SERIAL = b"\x2a"


def cert_der(serial: bytes = CERT_SERIAL) -> bytes:
    tbs = _der(0x30, b"".join([
        _der(0xA0, _der(0x02, b"\x02")),  # version v3
        _der(0x02, serial),               # serialNumber
        _der(0x30, b""),                  # signatureAlgorithm placeholder
        _issuer_der(),                    # issuer
        _der(0x30, b""),                  # validity
        _der(0x30, b""),                  # subject
        _der(0x30, b""),                  # subjectPublicKeyInfo
    ]))
    return _der(0x30, tbs + _der(0x30, b"") + _der(0x03, b"\x00"))


def _signer_info() -> bytes:
    return _der(0x30, b"".join([
        _der(0x02, b"\x01"),  # version
        _der(0x30, _issuer_der() + _der(0x02, CERT_SERIAL)),  # IssuerAndSerialNumber
        _der(0x30, b""),  # digestAlgorithm
    ]))


def _pkcs7(cert: bytes, chain=()) -> bytes:
    signed_data_oid = _der(0x06, bytes.fromhex("2A864886F70D010702"))
    data_oid = _der(0x06, bytes.fromhex("2A864886F70D010701"))
    inner_content = _der(0x30, data_oid + _der(0xA0, _der(0x04, b"digest")))
    signed_data = _der(0x30, b"".join([
        _der(0x02, b"\x01"),
        _der(0x31, b""),
        inner_content,
        _der(0xA0, cert + b"".join(chain)),
        _der(0x31, _signer_info()),
    ]))
    return _der(0x30, signed_data_oid + _der(0xA0, signed_data))


def synthetic_apk(v1=False, v2=False, v3=False, v31=False, include_dex=True,
                  chain_cert=None, manifest_axml=None) -> bytes:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("AndroidManifest.xml", manifest_axml or synthetic_manifest_axml())
        if include_dex:
            zf.writestr("classes.dex", synthetic_dex())
            zf.writestr("classes2.dex", synthetic_dex())
        if v1:
            zf.writestr("META-INF/CERT.SF", "Signature-Version: 1.0\n")
            zf.writestr("META-INF/CERT.RSA", _pkcs7(cert_der(), (chain_cert,) if chain_cert else ()))
    data = buffer.getvalue()
    pairs = []
    if v2:
        pairs.append((0x7109871A, _v2_value(cert_der(), (chain_cert,) if chain_cert else ())))
    if v3:
        pairs.append((0xF05368C0, _v3_value(cert_der(), (chain_cert,) if chain_cert else ())))
    if v31:
        pairs.append((0x1B93AD61, _v3_value(cert_der(), (chain_cert,) if chain_cert else ())))
    if pairs:
        data = _add_signing_block(data, pairs)
    return data


class TestAxml(unittest.TestCase):
    def test_manifest_fields(self):
        manifest = decode_axml(synthetic_manifest_axml())
        self.assertEqual(manifest["package"], "com.example.tv")
        self.assertEqual(manifest["version_code"], 42)
        self.assertEqual(manifest["version_name"], "1.2.3")
        self.assertEqual(manifest["min_sdk"], 21)
        self.assertEqual(manifest["target_sdk"], 30)
        self.assertEqual(manifest["compile_sdk"], 33)
        self.assertEqual(manifest["permissions"], ["android.permission.INTERNET"])
        self.assertEqual(len(manifest["activities"]), 2)
        activity = manifest["activities"][0]
        self.assertEqual(activity["resolved_name"], "com.example.tv.MainActivity")
        self.assertIn("android.intent.category.LEANBACK_LAUNCHER",
                      activity["intent_filters"][0]["categories"])

    def test_rejects_non_axml(self):
        with self.assertRaises(ApkError):
            decode_axml(b"not binary xml")

    def test_rejects_truncated_axml(self):
        data = synthetic_manifest_axml()
        with self.assertRaises(ApkError):
            decode_axml(data[: len(data) // 2])

    def test_namespace_collision_is_ignored(self):
        manifest = decode_axml(synthetic_manifest_axml(custom_collision=True))
        self.assertEqual(manifest["package"], "com.example.tv")
        self.assertEqual(manifest["permissions"], ["android.permission.INTERNET"])
        self.assertEqual(manifest["activities"][0]["name"], ".MainActivity")
        self.assertEqual(manifest["activities"][0]["resolved_name"], "com.example.tv.MainActivity")

    def test_bool_value_is_not_truthiness(self):
        self.assertFalse(_bool_value("false"))
        self.assertTrue(_bool_value("true"))
        self.assertFalse(_bool_value(0))
        self.assertTrue(_bool_value(1))

    def test_string_pool_budget(self):
        with mock.patch.object(apk_module, "_MAX_DECODED_STRINGS", 1):
            with self.assertRaises(ApkError):
                decode_axml(synthetic_manifest_axml())


class TestDex(unittest.TestCase):
    def test_classes_and_methods(self):
        dex = parse_dex(synthetic_dex(), name="classes.dex")
        self.assertEqual(dex["version"], "035")
        self.assertEqual(dex["class_count"], 1)
        self.assertEqual(dex["method_count"], 1)
        klass = dex["classes"][0]
        self.assertEqual(klass["name"], "com.example.Hello")
        self.assertEqual(klass["superclass"], "java.lang.Object")
        self.assertEqual(klass["methods"][0]["name"], "greet")
        self.assertEqual(klass["methods"][0]["descriptor"], "()V")

    def test_rejects_non_dex(self):
        with self.assertRaises(ApkError):
            parse_dex(b"not a dex file")

    def test_mutf8_supplementary_and_null(self):
        self.assertEqual(_mutf8(bytes.fromhex("eda081edb080")), "\U00010400")
        self.assertEqual(_mutf8(b"a\xc0\x80b"), "a\x00b")
        self.assertEqual(_mutf8("\U00010400".encode("utf-8")), "\U00010400")

    def test_invalid_class_data_offset_is_an_error(self):
        data = bytearray(synthetic_dex())
        class_defs_off = struct.unpack_from("<I", data, 100)[0]
        struct.pack_into("<I", data, class_defs_off + 24, len(data) + 10)
        with self.assertRaises(ApkError):
            parse_dex(bytes(data))

    def test_string_budget(self):
        with mock.patch.object(apk_module, "_MAX_DECODED_STRINGS", 1):
            with self.assertRaises(ApkError):
                parse_dex(synthetic_dex())


class TestApkInspection(unittest.TestCase):
    def test_detect_and_decode(self):
        apk = synthetic_apk(v2=True, v3=True)
        self.assertTrue(is_apk(apk))
        report = inspect_apk(apk)
        self.assertTrue(report["is_apk"])
        self.assertEqual(report["manifest"]["package"], "com.example.tv")
        self.assertEqual([d["name"] for d in report["dex"]], ["classes.dex", "classes2.dex"])
        self.assertEqual(report["dex"][0]["classes"][0]["name"], "com.example.Hello")
        self.assertEqual(report["signing"]["schemes"], ["v2", "v3"])
        self.assertEqual(report["signing"]["certificates"][0]["sha256"],
                         hashlib.sha256(cert_der()).hexdigest())

    def test_zip_without_dex_is_not_apk(self):
        buffer = io.BytesIO()
        with zipfile.ZipFile(buffer, "w") as zf:
            zf.writestr("AndroidManifest.xml", synthetic_manifest_axml())
        self.assertFalse(is_apk(buffer.getvalue()))

    def test_v1_signing(self):
        apk = synthetic_apk(v1=True)
        report = inspect_apk(apk)
        self.assertIn("v1", report["signing"]["schemes"])
        self.assertEqual(report["signing"]["v1"]["certificates"][0]["sha256"],
                         hashlib.sha256(cert_der()).hexdigest())

    def test_v31_signing(self):
        report = inspect_apk(synthetic_apk(v31=True))
        self.assertEqual(report["signing"]["schemes"], ["v3.1"])
        self.assertEqual(report["signing"]["certificates"][0]["sha256"],
                         hashlib.sha256(cert_der()).hexdigest())

    def test_chain_certificates_are_not_signers(self):
        chain = cert_der(b"\x2b")
        apk = synthetic_apk(v2=True, chain_cert=chain)
        report = inspect_apk(apk)
        self.assertEqual(report["signing"]["certificates"][0]["sha256"],
                         hashlib.sha256(cert_der()).hexdigest())
        self.assertEqual(report["signing"]["chain_certificates"][0]["sha256"],
                         hashlib.sha256(chain).hexdigest())
        verifier = Verifier(apk)
        leaf = Claim.from_dict({"kind": "apk_signing_certificate",
                                "params": {"sha256": hashlib.sha256(cert_der()).hexdigest()}})
        issuer = Claim.from_dict({"kind": "apk_signing_certificate",
                                  "params": {"sha256": hashlib.sha256(chain).hexdigest()}})
        self.assertEqual(verifier.verify(leaf)["verdict"], VERIFIED)
        self.assertEqual(verifier.verify(issuer)["verdict"], REFUTED)

    def test_orphan_v1_block_is_not_a_signature(self):
        buffer = io.BytesIO()
        with zipfile.ZipFile(buffer, "w") as zf:
            zf.writestr("AndroidManifest.xml", synthetic_manifest_axml())
            zf.writestr("classes.dex", synthetic_dex())
            zf.writestr("META-INF/ORPHAN.RSA", _pkcs7(cert_der()))
        report = inspect_apk(buffer.getvalue())
        self.assertFalse(report["signing"]["v1"]["present"])
        self.assertEqual(report["signing"]["schemes"], [])
        self.assertEqual(report["signing"]["certificates"], [])

    def test_v1_chain_certificate_is_not_signer(self):
        chain = cert_der(b"\x2b")
        report = inspect_apk(synthetic_apk(v1=True, chain_cert=chain))
        self.assertEqual(report["signing"]["certificates"][0]["sha256"],
                         hashlib.sha256(cert_der()).hexdigest())
        self.assertEqual(report["signing"]["chain_certificates"][0]["sha256"],
                         hashlib.sha256(chain).hexdigest())

    def test_malformed_signing_block_is_an_error(self):
        apk = _corrupt_signing_size(synthetic_apk(v2=True))
        report = inspect_apk(apk)
        self.assertEqual(report["signing"]["schemes"], [])
        self.assertIn("error", report["signing"])
        verifier = Verifier(apk)
        claim = Claim.from_dict({"kind": "apk_signing_certificate",
                                 "params": {"sha256": hashlib.sha256(cert_der()).hexdigest(),
                                            "present": False}})
        self.assertEqual(verifier.verify(claim)["verdict"], INCONCLUSIVE)

    def test_truncated_manifest_does_not_verify_absence(self):
        axml = synthetic_manifest_axml()[:100]
        apk = synthetic_apk(manifest_axml=axml)
        report = inspect_apk(apk)
        self.assertIn("manifest_error", report)
        verifier = Verifier(apk)
        claim = Claim.from_dict({"kind": "apk_manifest",
                                 "params": {"field": "permissions",
                                            "expected": "android.permission.INTERNET",
                                            "present": False}})
        self.assertEqual(verifier.verify(claim)["verdict"], INCONCLUSIVE)

    def test_absurd_dex_filename_is_not_an_apk(self):
        buffer = io.BytesIO()
        with zipfile.ZipFile(buffer, "w") as zf:
            zf.writestr("AndroidManifest.xml", synthetic_manifest_axml())
            zf.writestr("classes" + "1" * 5000 + ".dex", b"x")
        data = buffer.getvalue()
        self.assertFalse(is_apk(data))
        self.assertFalse(inspect_apk(data)["is_apk"])
        self.assertEqual(auto_triage(data)["type"], "ZIP Archive / Package")

    def test_auto_triage_identifies_apk(self):
        report = auto_triage(synthetic_apk(), filename="app.apk")
        self.assertEqual(report["type"], "Android APK")
        self.assertEqual(report["apk"]["manifest"]["package"], "com.example.tv")

    def test_auto_triage_keeps_plain_zip(self):
        buffer = io.BytesIO()
        with zipfile.ZipFile(buffer, "w") as zf:
            zf.writestr("readme.txt", "hello")
        report = auto_triage(buffer.getvalue(), filename="x.zip")
        self.assertEqual(report["type"], "ZIP Archive / Package")

    def test_malformed_apk_degrades(self):
        self.assertFalse(is_apk(b"not a zip"))
        report = inspect_apk(b"not a zip")
        self.assertFalse(report["is_apk"])
        self.assertIn("error", report)


class TestApkCli(unittest.TestCase):
    def test_parse_apk_json(self):
        args = argparse.Namespace(file=synthetic_apk(v2=True).hex(), json=True)
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            cmd_parse_apk(args)
        report = json.loads(out.getvalue())
        self.assertTrue(report["is_apk"])
        self.assertEqual(report["manifest"]["package"], "com.example.tv")
        self.assertEqual(report["signing"]["schemes"], ["v2"])

    def test_auto_human_output(self):
        args = argparse.Namespace(target=synthetic_apk(v2=True).hex(), json=False)
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            cmd_auto(args)
        text = out.getvalue()
        self.assertIn("Detected Type: Android APK", text)
        self.assertIn("Package:      com.example.tv", text)
        self.assertIn("cert SHA-256", text)

    def test_parse_apk_rejects_non_apk(self):
        buffer = io.BytesIO()
        with zipfile.ZipFile(buffer, "w") as zf:
            zf.writestr("readme.txt", "hello")
        args = argparse.Namespace(file=buffer.getvalue().hex(), json=False)
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            cmd_parse_apk(args)
        self.assertIn("Not an APK", out.getvalue())

    def test_parse_apk_shows_signing_error(self):
        apk = _corrupt_signing_size(synthetic_apk(v2=True))
        args = argparse.Namespace(file=apk.hex(), json=False)
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            cmd_parse_apk(args)
        self.assertIn("Signing:      unavailable", out.getvalue())


class TestApkClaims(unittest.TestCase):
    def setUp(self):
        self.apk = synthetic_apk(v2=True, v3=True)
        self.verifier = Verifier(self.apk)

    def claim(self, kind, **params):
        return self.verifier.verify(Claim.from_dict({"kind": kind, "params": params}))

    def test_manifest_scalar(self):
        result = self.claim("apk_manifest", field="package", expected="com.example.tv")
        self.assertEqual(result["verdict"], VERIFIED)
        result = self.claim("apk_manifest", field="target_sdk", expected=30)
        self.assertEqual(result["verdict"], VERIFIED)
        result = self.claim("apk_manifest", field="version_code", expected=41)
        self.assertEqual(result["verdict"], REFUTED)

    def test_manifest_observe(self):
        result = self.claim("apk_manifest", field="min_sdk", observe=True)
        self.assertEqual(result["verdict"], OBSERVED)
        self.assertEqual(result["evidence"]["actual"], 21)

    def test_permission_present_and_absent(self):
        result = self.claim("apk_manifest", field="permissions",
                            expected="android.permission.INTERNET")
        self.assertEqual(result["verdict"], VERIFIED)
        result = self.claim("apk_manifest", field="permissions",
                            expected="android.permission.ACCESS_FINE_LOCATION", present=False)
        self.assertEqual(result["verdict"], VERIFIED)
        result = self.claim("apk_manifest", field="permissions",
                            expected="android.permission.ACCESS_FINE_LOCATION")
        self.assertEqual(result["verdict"], REFUTED)
        result = self.claim("apk_manifest", field="permissions",
                            expected=["android.permission.INTERNET",
                                      "android.permission.ACCESS_FINE_LOCATION"],
                            present=False)
        self.assertEqual(result["verdict"], REFUTED)

    def test_activity_and_leanback_category(self):
        result = self.claim("apk_manifest", field="activity", expected=".MainActivity")
        self.assertEqual(result["verdict"], VERIFIED)
        result = self.claim("apk_manifest", field="activity_category",
                            expected="android.intent.category.LEANBACK_LAUNCHER")
        self.assertEqual(result["verdict"], VERIFIED)
        result = self.claim("apk_manifest", field="activity_category",
                            expected="android.intent.category.LAUNCHER")
        self.assertEqual(result["verdict"], REFUTED)
        result = self.claim("apk_manifest", field="activity",
                            expected=[".MainActivity", ".Missing"], present=False)
        self.assertEqual(result["verdict"], REFUTED)

    def test_relative_activity_name_resolves_against_package(self):
        apk = synthetic_apk(manifest_axml=synthetic_manifest_axml(
            activity_name="com.example.tv.MainActivity"))
        verifier = Verifier(apk)
        claim = Claim.from_dict({"kind": "apk_manifest",
                                 "params": {"field": "activity", "expected": ".MainActivity"}})
        self.assertEqual(verifier.verify(claim)["verdict"], VERIFIED)
        claim = Claim.from_dict({"kind": "apk_manifest",
                                 "params": {"field": "activity_category",
                                            "activity": ".MainActivity",
                                            "expected": "android.intent.category.LEANBACK_LAUNCHER"}})
        self.assertEqual(verifier.verify(claim)["verdict"], VERIFIED)

    def test_class_and_method_presence(self):
        result = self.claim("apk_class_present", name="com.example.Hello")
        self.assertEqual(result["verdict"], VERIFIED)
        result = self.claim("apk_class_present", name="Lcom/example/Hello;")
        self.assertEqual(result["verdict"], VERIFIED)
        result = self.claim("apk_class_present", name="com.example.Missing", present=False)
        self.assertEqual(result["verdict"], VERIFIED)
        result = self.claim("apk_class_present", name="com.example.Missing")
        self.assertEqual(result["verdict"], REFUTED)

        result = self.claim("apk_method_present", **{"class": "com.example.Hello"},
                            method="greet", descriptor="()V")
        self.assertEqual(result["verdict"], VERIFIED)
        result = self.claim("apk_method_present", **{"class": "com.example.Hello"},
                            method="missing", present=False)
        self.assertEqual(result["verdict"], VERIFIED)
        result = self.claim("apk_method_present", **{"class": "com.example.Hello"},
                            method="greet", descriptor="(I)V")
        self.assertEqual(result["verdict"], REFUTED)

    def test_signing_certificate(self):
        digest = hashlib.sha256(cert_der()).hexdigest()
        result = self.claim("apk_signing_certificate", sha256=digest)
        self.assertEqual(result["verdict"], VERIFIED)
        result = self.claim("apk_signing_certificate", sha256=digest, scheme="v2")
        self.assertEqual(result["verdict"], VERIFIED)
        result = self.claim("apk_signing_certificate", sha256=digest, scheme="v1")
        self.assertEqual(result["verdict"], REFUTED)
        result = self.claim("apk_signing_certificate", sha256="00" * 32)
        self.assertEqual(result["verdict"], REFUTED)

    def test_unsigned_apk_absence(self):
        verifier = Verifier(synthetic_apk())
        digest = hashlib.sha256(cert_der()).hexdigest()
        claim = Claim.from_dict({"kind": "apk_signing_certificate",
                                 "params": {"sha256": digest}})
        self.assertEqual(verifier.verify(claim)["verdict"], REFUTED)
        claim = Claim.from_dict({"kind": "apk_signing_certificate",
                                 "params": {"sha256": digest, "present": False}})
        self.assertEqual(verifier.verify(claim)["verdict"], VERIFIED)

    def test_unparseable_dex_does_not_verify_absence(self):
        buffer = io.BytesIO()
        with zipfile.ZipFile(buffer, "w") as zf:
            zf.writestr("AndroidManifest.xml", synthetic_manifest_axml())
            zf.writestr("classes.dex", b"not a dex")
        verifier = Verifier(buffer.getvalue())
        claim = Claim.from_dict({"kind": "apk_class_present",
                                 "params": {"name": "com.example.Hello", "present": False}})
        self.assertEqual(verifier.verify(claim)["verdict"], INCONCLUSIVE)

    def test_non_apk_is_inconclusive(self):
        verifier = Verifier(b"MZ" + b"\x00" * 64)
        claim = Claim.from_dict({"kind": "apk_manifest",
                                 "params": {"field": "package", "expected": "x"}})
        self.assertEqual(verifier.verify(claim)["verdict"], INCONCLUSIVE)


if __name__ == "__main__":
    unittest.main()
