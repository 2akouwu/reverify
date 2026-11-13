"""Android APK awareness: ZIP container, binary AndroidManifest.xml, DEX and signing.

Everything here is pure standard library so ``pip install reverify`` without the
optional engines still identifies and inspects an APK.  The readers are
deliberately defensive: a malformed APK yields an ``error`` field instead of an
exception, because the verifier treats hostile input as normal input.
"""

from __future__ import annotations

import hashlib
import io
import re
import struct
import zipfile
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

ANDROID_NS = "http://schemas.android.com/apk/res/android"
APK_SIG_BLOCK_MAGIC = b"APK Sig Block 42"

# Bounds on decompressed entries: a ZIP bomb must not turn inspecting an APK
# into an unbounded allocation.  Real manifests are far below 16 MiB; a DEX is
# capped well above the largest practical multi-dex contribution.
_MAX_MANIFEST_BYTES = 16 * 1024 * 1024
_MAX_DEX_BYTES = 256 * 1024 * 1024
_MAX_SIGNATURE_BYTES = 64 * 1024 * 1024
_MAX_DECODED_STRINGS = 64 * 1024 * 1024
_MAX_DEX_STRINGS = 2 * 1024 * 1024
_MAX_PROTO_PARAMS = 4096
_MAX_METHOD_DESCRIPTOR = 64 * 1024
_MAX_METHOD_DESCRIPTORS = 16 * 1024 * 1024
_MAX_DEX_METHODS = 256 * 1024
_MAX_DEX_FIELDS = 256 * 1024

# Chunk types from frameworks/base/libs/androidfw/include/androidfw/ResourceTypes.h
_RES_STRING_POOL_TYPE = 0x0001
_RES_XML_TYPE = 0x0003
_RES_XML_START_ELEMENT_TYPE = 0x0102
_RES_XML_END_ELEMENT_TYPE = 0x0103

# APK Signature Scheme v2 / v3 block IDs.
_APK_SIG_SCHEME_V2_ID = 0x7109871A
_APK_SIG_SCHEME_V3_ID = 0xF05368C0
_APK_SIG_SCHEME_V31_ID = 0x1B93AD61


class ApkError(ValueError):
    """Raised when a structure inside an APK cannot be decoded."""


def _int_at(data: bytes, off: int, size: int, signed: bool = False) -> int:
    if off < 0 or off + size > len(data):
        raise ApkError("truncated structure")
    return int.from_bytes(data[off : off + size], "little", signed=signed)


def _u16(data: bytes, off: int) -> int:
    return _int_at(data, off, 2)


def _u32(data: bytes, off: int) -> int:
    return _int_at(data, off, 4)


def _u64(data: bytes, off: int) -> int:
    return _int_at(data, off, 8)


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _read_entry(zf: zipfile.ZipFile, name: str, limit: int) -> bytes:
    info = zf.getinfo(name)
    if info.file_size > limit:
        raise ApkError("entry %s is %d bytes (limit %d)" % (name, info.file_size, limit))
    # Do not trust the size stored in the central directory: read one byte past
    # the budget and fail if the stream really produces more.
    with zf.open(name) as handle:
        data = handle.read(limit + 1)
    if len(data) > limit:
        raise ApkError("entry %s exceeds %d bytes when decompressed" % (name, limit))
    return data


# -- AXML ------------------------------------------------------------------


def _decode_len8(data: bytes, off: int) -> Tuple[int, int]:
    if off >= len(data):
        raise ApkError("truncated string length")
    value = data[off]
    off += 1
    if value & 0x80:
        if off >= len(data):
            raise ApkError("truncated string length")
        value = ((value & 0x7F) << 8) | data[off]
        off += 1
    return value, off


def _decode_len16(data: bytes, off: int) -> Tuple[int, int]:
    value = _u16(data, off)
    off += 2
    if value & 0x8000:
        value = ((value & 0x7FFF) << 16) | _u16(data, off)
        off += 2
    return value, off


def _parse_string_pool(data: bytes, off: int = 0) -> List[str]:
    if _u16(data, off) != _RES_STRING_POOL_TYPE:
        raise ApkError("not a string pool chunk")
    header_size = _u16(data, off + 2)
    chunk_size = _u32(data, off + 4)
    if header_size < 28 or chunk_size < header_size:
        raise ApkError("short string pool header")
    end = min(off + chunk_size, len(data))
    count = _u32(data, off + 8)
    flags = _u32(data, off + 16)
    strings_start = _u32(data, off + 20)
    utf8 = bool(flags & 0x100)
    offsets_at = off + header_size
    strings_at = off + strings_start
    if strings_at > end or offsets_at + count * 4 > end:
        raise ApkError("string pool offsets out of range")

    strings: List[str] = []
    decoded_bytes = 0
    for i in range(count):
        rel = _u32(data, offsets_at + i * 4)
        p = strings_at + rel
        if p >= end:
            raise ApkError("string pool entry points past the chunk")
        if utf8:
            _, p = _decode_len8(data, p)  # UTF-16 length, unused
            byte_len, p = _decode_len8(data, p)
            if p + byte_len > end:
                raise ApkError("string pool entry runs past the chunk")
            raw = data[p : p + byte_len]
            decoded_bytes += byte_len
            if decoded_bytes > _MAX_DECODED_STRINGS:
                raise ApkError("decoded string pool exceeds budget")
            strings.append(raw.decode("utf-8", errors="replace"))
        else:
            char_len, p = _decode_len16(data, p)
            if p + char_len * 2 > end:
                raise ApkError("string pool entry runs past the chunk")
            raw = data[p : p + char_len * 2]
            decoded_bytes += len(raw)
            if decoded_bytes > _MAX_DECODED_STRINGS:
                raise ApkError("decoded string pool exceeds budget")
            strings.append(raw.decode("utf-16le", errors="replace"))
    return strings


@dataclass
class _Attr:
    name: str
    namespace: Optional[str]
    raw: Optional[str]
    data_type: int
    data: int
    value: Any


@dataclass
class _Element:
    name: str
    namespace: Optional[str]
    attributes: List[_Attr] = field(default_factory=list)
    children: List["_Element"] = field(default_factory=list)


def _pool_string(strings: List[str], index: int) -> Optional[str]:
    if index == 0xFFFFFFFF or index < 0 or index >= len(strings):
        return None
    return strings[index]


def _typed_value(data_type: int, data: int, strings: List[str]) -> Any:
    if data_type == 0x03:  # TYPE_STRING
        value = _pool_string(strings, data)
        return value if value is not None else ""
    if data_type == 0x10:  # TYPE_INT_DEC
        return data - 0x100000000 if data & 0x80000000 else data
    if data_type == 0x11:  # TYPE_INT_HEX
        return data
    if data_type == 0x12:  # TYPE_INT_BOOLEAN
        return bool(data)
    if data_type == 0x04:  # TYPE_FLOAT
        return struct.unpack("<f", struct.pack("<I", data & 0xFFFFFFFF))[0]
    if data_type == 0x01:  # TYPE_REFERENCE
        return "@0x%08x" % data
    return data


def _parse_axml(data: bytes) -> Tuple[List[str], List[_Element]]:
    if len(data) < 8 or _u16(data, 0) != _RES_XML_TYPE:
        raise ApkError("not a binary XML document")
    total = _u32(data, 4)
    if total < 8 or total > len(data):
        raise ApkError("truncated binary XML document")
    end = total
    off = 8
    strings: List[str] = []
    roots: List[_Element] = []
    stack: List[_Element] = []

    while off + 8 <= end:
        chunk_type = _u16(data, off)
        header_size = _u16(data, off + 2)
        chunk_size = _u32(data, off + 4)
        if chunk_size < 8 or off + chunk_size > end:
            raise ApkError("truncated AXML chunk")
        chunk = data[off : off + chunk_size]

        if chunk_type == _RES_STRING_POOL_TYPE:
            strings = _parse_string_pool(chunk)
        elif chunk_type == _RES_XML_START_ELEMENT_TYPE:
            if header_size < 16:
                raise ApkError("short XML start-element header")
            name = _pool_string(strings, _u32(chunk, 20)) or ""
            ns = _pool_string(strings, _u32(chunk, 16))
            attribute_start = _u16(chunk, 24)
            attribute_size = _u16(chunk, 26)
            attribute_count = _u16(chunk, 28)
            # ``attributeStart`` is relative to the attrExt structure, which
            # begins after the 16-byte node header (chunk header + line +
            # comment), not after the chunk header alone.
            attrs_at = header_size + attribute_start
            if attribute_size < 20:
                raise ApkError("short XML attribute record")
            attributes: List[_Attr] = []
            for i in range(attribute_count):
                a = attrs_at + i * attribute_size
                if a + 20 > len(chunk):
                    raise ApkError("truncated XML attribute")
                attr_ns = _pool_string(strings, _u32(chunk, a))
                attr_name = _pool_string(strings, _u32(chunk, a + 4)) or ""
                raw_index = _u32(chunk, a + 8)
                raw = _pool_string(strings, raw_index)
                data_type = chunk[a + 15]
                attr_data = _u32(chunk, a + 16)
                value = raw if raw is not None else _typed_value(data_type, attr_data, strings)
                attributes.append(_Attr(attr_name, attr_ns, raw, data_type, attr_data, value))
            element = _Element(name, ns, attributes)
            if stack:
                stack[-1].children.append(element)
            else:
                roots.append(element)
            stack.append(element)
        elif chunk_type == _RES_XML_END_ELEMENT_TYPE:
            if not stack:
                raise ApkError("unexpected XML end element")
            stack.pop()

        off += chunk_size

    if off < end and any(data[off:end]):
        raise ApkError("trailing bytes after the last AXML chunk")
    if stack:
        raise ApkError("unclosed XML element")
    return strings, roots


def _attr(element: _Element, name: str, namespace: Optional[str] = ANDROID_NS) -> Optional[_Attr]:
    for attribute in element.attributes:
        if attribute.name == name and attribute.namespace == namespace:
            return attribute
    return None


def _attr_value(element: _Element, name: str, default: Any = None,
                namespace: Optional[str] = ANDROID_NS) -> Any:
    attribute = _attr(element, name, namespace=namespace)
    return default if attribute is None else attribute.value


def _bool_value(value: Any) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        return value.strip().lower() == "true"
    return bool(value)


def _children(element: _Element, name: str) -> List[_Element]:
    return [child for child in element.children if child.name == name]


def _resolve_component_name(name: Optional[str], package: Optional[str]) -> Optional[str]:
    if not name:
        return None
    if not package:
        return name
    if name.startswith("."):
        return package + name
    if "." not in name:
        return package + "." + name
    return name


def _manifest_summary(roots: List[_Element]) -> Dict[str, Any]:
    if not roots:
        raise ApkError("binary XML has no root element")
    manifest = roots[0]
    if manifest.name != "manifest":
        # The manifest is always the root; accepting another root would let a
        # caller mistake an arbitrary AXML for an APK manifest.
        raise ApkError("root element is %r, not 'manifest'" % manifest.name)

    package = _attr_value(manifest, "package", namespace=None)
    if package is not None:
        package = str(package)
    version_code = _attr_value(manifest, "versionCode")
    version_name = _attr_value(manifest, "versionName")
    if version_name is not None:
        version_name = str(version_name)

    min_sdk = target_sdk = None
    compile_sdk = _attr_value(manifest, "compileSdkVersion")
    uses_sdk = _children(manifest, "uses-sdk")
    if uses_sdk:
        min_sdk = _attr_value(uses_sdk[0], "minSdkVersion", _attr_value(uses_sdk[0], "minSdk"))
        target_sdk = _attr_value(uses_sdk[0], "targetSdkVersion", _attr_value(uses_sdk[0], "targetSdk"))

    permissions: List[str] = []
    for child in manifest.children:
        if child.name in ("uses-permission", "uses-permission-sdk-23"):
            name = _attr_value(child, "name")
            if name and str(name) not in permissions:
                permissions.append(str(name))

    activities: List[Dict[str, Any]] = []
    for child in manifest.children:
        if child.name in ("activity", "activity-alias"):
            candidates = [child]
        else:
            candidates = _children(child, "activity") + _children(child, "activity-alias")
        for activity in candidates:
            name = _attr_value(activity, "name")
            filters: List[Dict[str, Any]] = []
            for intent_filter in _children(activity, "intent-filter"):
                actions = [str(_attr_value(a, "name")) for a in _children(intent_filter, "action")
                           if _attr_value(a, "name") is not None]
                categories = [str(_attr_value(c, "name")) for c in _children(intent_filter, "category")
                              if _attr_value(c, "name") is not None]
                data: List[Dict[str, Any]] = []
                for item in _children(intent_filter, "data"):
                    attributes = {}
                    for a in item.attributes:
                        if a.value is not None and a.namespace in (ANDROID_NS, None):
                            attributes[a.name] = a.value
                    if attributes:
                        data.append(attributes)
                filters.append({"actions": actions, "categories": categories, "data": data})
            exported = _attr_value(activity, "exported")
            entry: Dict[str, Any] = {
                "name": str(name) if name is not None else None,
                "resolved_name": _resolve_component_name(str(name) if name is not None else None, package),
                "kind": activity.name,
                "intent_filters": filters,
            }
            if exported is not None:
                entry["exported"] = _bool_value(exported)
            activities.append(entry)

    return {
        "package": package,
        "version_code": version_code,
        "version_name": version_name,
        "min_sdk": min_sdk,
        "target_sdk": target_sdk,
        "compile_sdk": compile_sdk,
        "permissions": permissions,
        "activities": activities,
    }


def decode_axml(data: bytes) -> Dict[str, Any]:
    """Decode the binary ``AndroidManifest.xml`` payload (AXML) of an APK."""
    _, roots = _parse_axml(data)
    if len(roots) != 1:
        raise ApkError("binary XML has %d root elements, not 1" % len(roots))
    return _manifest_summary(roots)


# -- DEX -------------------------------------------------------------------


def _uleb128(data: bytes, off: int) -> Tuple[int, int]:
    result = 0
    shift = 0
    while True:
        if off >= len(data):
            raise ApkError("truncated uleb128")
        byte = data[off]
        off += 1
        result |= (byte & 0x7F) << shift
        if not byte & 0x80:
            return result, off
        shift += 7
        if shift > 35:
            raise ApkError("uleb128 too long")


def _mutf8(raw: bytes) -> str:
    # MUTF-8 encodes U+0000 as C0 80 and supplementary characters as a pair of
    # 3-byte surrogate sequences.  ``surrogatepass`` keeps those sequences
    # intact during the UTF-8 pass; a UTF-16 round-trip then combines them.
    raw = raw.replace(b"\xc0\x80", b"\x00")
    try:
        text = raw.decode("utf-8", errors="surrogatepass")
        if any("\ud800" <= ch <= "\udfff" for ch in text):
            text = text.encode("utf-16", errors="surrogatepass").decode("utf-16")
        return text
    except (UnicodeDecodeError, UnicodeEncodeError):
        return raw.decode("utf-8", errors="replace")


def _dex_table(data: bytes, off: int, count: int, width: int, label: str) -> None:
    """Reject an index table that cannot fit in the file before iterating it."""
    if off > len(data) or count > (len(data) - off) // width:
        raise ApkError("DEX %s table is out of range" % label)


def _dex_strings(data: bytes, string_ids_off: int, count: int) -> List[str]:
    strings: List[str] = []
    decoded_bytes = 0
    for i in range(count):
        string_off = _u32(data, string_ids_off + i * 4)
        if string_off >= len(data):
            raise ApkError("DEX string offset out of range")
        _, p = _uleb128(data, string_off)
        end = data.find(b"\x00", p)
        if end < 0:
            raise ApkError("unterminated DEX string")
        decoded_bytes += end - p
        if decoded_bytes > _MAX_DECODED_STRINGS:
            raise ApkError("decoded DEX strings exceed budget")
        strings.append(_mutf8(data[p:end]))
    return strings


def _descriptor_to_name(descriptor: str) -> str:
    if len(descriptor) >= 2 and descriptor[0] == "L" and descriptor.endswith(";"):
        return descriptor[1:-1].replace("/", ".")
    return descriptor


def _type_descriptor(types: List[str], type_idx: int) -> str:
    if 0 <= type_idx < len(types):
        return types[type_idx]
    raise ApkError("DEX type index out of range")


def _proto_descriptor(data: bytes, types: List[str], proto_ids_off: int, proto_count: int,
                      proto_idx: int) -> str:
    if not 0 <= proto_idx < proto_count:
        raise ApkError("DEX prototype index out of range")
    base = proto_ids_off + proto_idx * 12
    return_type_idx = _u32(data, base + 4)
    params_off = _u32(data, base + 8)
    params: List[str] = []
    if params_off:
        size = _u32(data, params_off)
        if size > _MAX_PROTO_PARAMS:
            raise ApkError("DEX prototype has too many parameters")
        if params_off + 4 + size * 2 > len(data):
            raise ApkError("DEX prototype out of range")
        for i in range(size):
            params.append(_type_descriptor(types, _u16(data, params_off + 4 + i * 2)))
    return_type = _type_descriptor(types, return_type_idx)
    length = 2 + sum(len(p) for p in params) + len(return_type)
    if length > _MAX_METHOD_DESCRIPTOR:
        raise ApkError("DEX method descriptor exceeds budget")
    return "(" + "".join(params) + ")" + return_type


def _class_methods(data: bytes, class_data_off: int, method_ids: List[Tuple[int, int, str]],
                   types: List[str], proto_ids_off: int, proto_count: int,
                   descriptor_budget: List[int], method_budget: List[int],
                   field_budget: List[int]) -> List[Dict[str, Any]]:
    if class_data_off == 0:
        return []  # the valid "class has no data" encoding
    if class_data_off >= len(data):
        raise ApkError("DEX class_data offset out of range")
    p = class_data_off
    static_fields, p = _uleb128(data, p)
    instance_fields, p = _uleb128(data, p)
    direct_methods, p = _uleb128(data, p)
    virtual_methods, p = _uleb128(data, p)
    if static_fields + instance_fields > 0x10000 or direct_methods + virtual_methods > 0x10000:
        raise ApkError("DEX class_data member count out of range")
    field_budget[0] -= static_fields + instance_fields
    if field_budget[0] < 0:
        raise ApkError("DEX field declarations exceed budget")
    for _ in range(static_fields + instance_fields):
        _, p = _uleb128(data, p)
        _, p = _uleb128(data, p)

    methods: List[Dict[str, Any]] = []
    for count in (direct_methods, virtual_methods):
        method_idx = 0
        for _ in range(count):
            diff, p = _uleb128(data, p)
            method_idx += diff
            access_flags, p = _uleb128(data, p)
            _, p = _uleb128(data, p)  # code_off
            if not 0 <= method_idx < len(method_ids):
                raise ApkError("DEX method index out of range")
            method_budget[0] -= 1
            if method_budget[0] < 0:
                raise ApkError("DEX method declarations exceed budget")
            _, proto_idx, name = method_ids[method_idx]
            descriptor = _proto_descriptor(data, types, proto_ids_off, proto_count, proto_idx)
            descriptor_budget[0] -= len(descriptor)
            if descriptor_budget[0] < 0:
                raise ApkError("DEX method descriptors exceed budget")
            methods.append({
                "name": name,
                "descriptor": descriptor,
                "access_flags": access_flags,
            })
    return methods


def parse_dex(data: bytes, name: str = "classes.dex") -> Dict[str, Any]:
    """Parse one DEX file into class and method lists."""
    if len(data) < 0x70 or data[:4] != b"dex\n":
        raise ApkError("not a DEX file")
    version = data[4:7].decode("ascii", errors="replace")
    if _u32(data, 40) != 0x12345678:
        raise ApkError("unsupported DEX endianness")

    string_count = _u32(data, 56)
    string_off = _u32(data, 60)
    type_count = _u32(data, 64)
    type_off = _u32(data, 68)
    proto_count = _u32(data, 72)
    proto_off = _u32(data, 76)
    method_count = _u32(data, 88)
    method_off = _u32(data, 92)
    class_count = _u32(data, 96)
    class_off = _u32(data, 100)
    if (type_count > 0x10000 or proto_count > 0x10000
            or method_count > 0x10000 or class_count > 0x10000):
        raise ApkError("DEX index table exceeds 16-bit indices")
    if string_count > _MAX_DEX_STRINGS:
        raise ApkError("DEX string count exceeds budget")
    _dex_table(data, string_off, string_count, 4, "string_ids")
    _dex_table(data, type_off, type_count, 4, "type_ids")
    _dex_table(data, proto_off, proto_count, 12, "proto_ids")
    _dex_table(data, method_off, method_count, 8, "method_ids")
    _dex_table(data, class_off, class_count, 32, "class_defs")

    strings = _dex_strings(data, string_off, string_count)
    types = []
    for i in range(type_count):
        descriptor_idx = _u32(data, type_off + i * 4)
        if descriptor_idx >= len(strings):
            raise ApkError("DEX type descriptor index out of range")
        types.append(strings[descriptor_idx])

    method_ids: List[Tuple[int, int, str]] = []
    for i in range(method_count):
        base = method_off + i * 8
        class_idx = _u16(data, base)
        proto_idx = _u16(data, base + 2)
        name_idx = _u32(data, base + 4)
        if class_idx >= len(types) or proto_idx >= proto_count:
            raise ApkError("DEX method reference out of range")
        if name_idx >= len(strings):
            raise ApkError("DEX method name index out of range")
        method_ids.append((class_idx, proto_idx, strings[name_idx]))

    classes: List[Dict[str, Any]] = []
    total_methods = 0
    descriptor_budget = [_MAX_METHOD_DESCRIPTORS]
    method_budget = [_MAX_DEX_METHODS]
    field_budget = [_MAX_DEX_FIELDS]
    for i in range(class_count):
        base = class_off + i * 32
        class_idx = _u32(data, base)
        access_flags = _u32(data, base + 4)
        superclass_idx = _u32(data, base + 8)
        class_data_off = _u32(data, base + 24)
        descriptor = _type_descriptor(types, class_idx)
        methods = _class_methods(data, class_data_off, method_ids, types, proto_off,
                                 proto_count, descriptor_budget, method_budget, field_budget)
        total_methods += len(methods)
        superclass = None
        if superclass_idx != 0xFFFFFFFF:
            superclass = _descriptor_to_name(_type_descriptor(types, superclass_idx))
        classes.append({
            "name": _descriptor_to_name(descriptor),
            "descriptor": descriptor,
            "access_flags": access_flags,
            "superclass": superclass,
            "methods": methods,
        })

    return {
        "name": name,
        "size": len(data),
        "version": version,
        "class_count": len(classes),
        "method_count": total_methods,
        "classes": classes,
    }


# -- signing ---------------------------------------------------------------


def _find_eocd(data: bytes) -> Optional[int]:
    start = max(0, len(data) - 0xFFFF - 22)
    index = data.rfind(b"PK\x05\x06", start)
    while index >= 0:
        if index + 22 <= len(data):
            comment_len = _u16(data, index + 20)
            if index + 22 + comment_len <= len(data):
                return index
        index = data.rfind(b"PK\x05\x06", start, index)
    return None


def _read_lp(buf: bytes, off: int) -> Tuple[bytes, int]:
    length = _u32(buf, off)
    off += 4
    if off + length > len(buf):
        raise ApkError("length-prefixed field out of range")
    return buf[off : off + length], off + length


def _parse_certs(blob: bytes) -> List[Dict[str, Any]]:
    certs: List[Dict[str, Any]] = []
    off = 0
    while off < len(blob):
        cert, off = _read_lp(blob, off)
        if cert:
            certs.append({"sha256": _sha256(cert), "der_size": len(cert), "der": cert})
    return certs


def _public_cert(cert: Dict[str, Any]) -> Dict[str, Any]:
    return {"sha256": cert["sha256"], "der_size": cert["der_size"]}


def _signer_certs(blob: bytes) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
    """Return (signer certificates, chain certificates) for one signer.

    APK Signature Scheme v2/v3 list the signer's certificate first; the rest
    are its chain.  Only the first is the identity a claim should match.
    """
    certs = _parse_certs(blob)
    if not certs:
        raise ApkError("signer has no certificates")
    return [_public_cert(certs[0])], [_public_cert(c) for c in certs[1:]]


def _parse_signer_v2(signer: bytes) -> Dict[str, Any]:
    signed_data, off = _read_lp(signer, 0)
    _, off = _read_lp(signer, off)  # signatures
    public_key, off = _read_lp(signer, off)
    _, p = _read_lp(signed_data, 0)  # digests
    certs_blob, p = _read_lp(signed_data, p)
    signer_certs, chain_certs = _signer_certs(certs_blob)
    return {
        "certificates": signer_certs,
        "chain_certificates": chain_certs,
        "public_key_sha256": _sha256(public_key) if public_key else None,
    }


def _parse_signer_v3(signer: bytes) -> Dict[str, Any]:
    signed_data, off = _read_lp(signer, 0)
    _, p = _read_lp(signed_data, 0)  # digests
    certs_blob, p = _read_lp(signed_data, p)
    signer_certs, chain_certs = _signer_certs(certs_blob)
    result: Dict[str, Any] = {
        "certificates": signer_certs,
        "chain_certificates": chain_certs,
    }
    try:
        result["min_sdk"] = _u32(signer, off)
        result["max_sdk"] = _u32(signer, off + 4)
        off += 8
        _, off = _read_lp(signer, off)  # signatures
        public_key, off = _read_lp(signer, off)
        result["public_key_sha256"] = _sha256(public_key) if public_key else None
    except ApkError:
        # v3.1 keeps the certificate layout but may add fields the v3 reader
        # does not know; the digest already read above is still evidence.
        result.setdefault("min_sdk", None)
        result.setdefault("max_sdk", None)
        result.setdefault("public_key_sha256", None)
    return result


def _parse_signers(blob: bytes, parser) -> List[Dict[str, Any]]:
    signers: List[Dict[str, Any]] = []
    off = 0
    while off < len(blob):
        signer, off = _read_lp(blob, off)
        signers.append(parser(signer))
    return signers


def _apk_signing_pairs(data: bytes) -> Dict[int, List[bytes]]:
    eocd = _find_eocd(data)
    if eocd is None:
        return {}
    central_dir_off = _u32(data, eocd + 16)
    if central_dir_off == 0xFFFFFFFF:
        # ZIP64 puts the real offset in a separate record; reporting "no
        # signature" from the sentinel would turn an unknown into an absence.
        raise ApkError("ZIP64 APK signing block is not supported")
    if central_dir_off < 24 or central_dir_off > len(data):
        raise ApkError("APK central directory offset is out of range")
    if data[central_dir_off - 16 : central_dir_off] != APK_SIG_BLOCK_MAGIC:
        return {}  # no signing block at all
    size = _u64(data, central_dir_off - 24)
    if size < 24 or size > central_dir_off - 8:
        raise ApkError("malformed APK signing block size")
    block_start = central_dir_off - 8 - size
    if block_start < 0 or _u64(data, block_start) != size:
        raise ApkError("APK signing block size fields disagree")
    pairs: Dict[int, List[bytes]] = {}
    p = block_start + 8
    end = central_dir_off - 24
    while p < end:
        if p + 12 > end:
            raise ApkError("truncated APK signing block pair header")
        pair_len = _u64(data, p)
        p += 8
        if pair_len < 4 or p + pair_len > end:
            raise ApkError("malformed APK signing block pair length")
        pair_id = _u32(data, p)
        value = data[p + 4 : p + pair_len]
        p += pair_len
        pairs.setdefault(pair_id, []).append(value)
    return pairs


def _der_tlv(buf: bytes, off: int) -> Tuple[int, bytes, int, int]:
    start = off
    if off + 2 > len(buf):
        raise ApkError("truncated DER")
    tag = buf[off]
    off += 1
    length = buf[off]
    off += 1
    if length & 0x80:
        count = length & 0x7F
        if count == 0 or count > 4 or off + count > len(buf):
            raise ApkError("unsupported DER length")
        length = int.from_bytes(buf[off : off + count], "big")
        off += count
    if off + length > len(buf):
        raise ApkError("truncated DER value")
    return tag, buf[off : off + length], off + length, start


def _x509_issuer_serial(der: bytes) -> Tuple[bytes, bytes]:
    """Return ``(issuer Name DER, serialNumber INTEGER content)`` for a certificate."""
    tag, cert_content, _, _ = _der_tlv(der, 0)
    if tag != 0x30:
        raise ApkError("certificate is not a sequence")
    tag, tbs, _, _ = _der_tlv(cert_content, 0)
    if tag != 0x30:
        raise ApkError("tbsCertificate is not a sequence")

    p = 0
    tag, value, next_off, _ = _der_tlv(tbs, p)
    if tag == 0xA0:  # optional [0] EXPLICIT version
        p = next_off
        tag, value, next_off, _ = _der_tlv(tbs, p)
    if tag != 0x02:
        raise ApkError("serialNumber is not an INTEGER")
    serial = value
    p = next_off
    tag, _, next_off, _ = _der_tlv(tbs, p)  # signatureAlgorithm
    if tag != 0x30:
        raise ApkError("signatureAlgorithm is not a sequence")
    p = next_off
    tag, _, next_off, issuer_start = _der_tlv(tbs, p)  # issuer Name
    if tag != 0x30:
        raise ApkError("issuer is not a sequence")
    return tbs[issuer_start:next_off], serial


def _signer_ids(signer_infos: bytes) -> List[Tuple[bytes, bytes]]:
    """Return the IssuerAndSerialNumber identifiers of PKCS#7 SignerInfos."""
    ids: List[Tuple[bytes, bytes]] = []
    p = 0
    while p < len(signer_infos):
        tag, signer_info, p, _ = _der_tlv(signer_infos, p)
        if tag != 0x30:
            continue
        q = 0
        tag, _, q, _ = _der_tlv(signer_info, q)  # version
        if tag != 0x02:
            continue
        tag, sid, q, _ = _der_tlv(signer_info, q)
        if tag != 0x30:  # subjectKeyIdentifier form: cannot map without extensions
            continue
        r = 0
        tag, _, r, issuer_start = _der_tlv(sid, r)
        if tag != 0x30:
            continue
        issuer = sid[issuer_start:r]
        tag, serial, r, _ = _der_tlv(sid, r)
        if tag != 0x02:
            continue
        ids.append((issuer, serial))
    return ids


def _pkcs7_parts(blob: bytes) -> Tuple[List[bytes], List[Tuple[bytes, bytes]]]:
    tag, content, _, _ = _der_tlv(blob, 0)
    if tag != 0x30:
        raise ApkError("PKCS#7 ContentInfo is not a sequence")
    _, _, off, _ = _der_tlv(content, 0)  # contentType OID
    tag, explicit, _, _ = _der_tlv(content, off)
    if tag != 0xA0:
        raise ApkError("PKCS#7 ContentInfo has no content")
    tag, signed_data, _, _ = _der_tlv(explicit, 0)
    if tag != 0x30:
        raise ApkError("PKCS#7 SignedData is not a sequence")

    bag: List[bytes] = []
    sets: List[bytes] = []
    off = 0
    while off < len(signed_data):
        tag, value, next_off, _ = _der_tlv(signed_data, off)
        off = next_off
        if tag == 0xA0:  # [0] IMPLICIT CertificateSet
            c_off = 0
            while c_off < len(value):
                c_tag, _, c_next, c_start = _der_tlv(value, c_off)
                if c_tag == 0x30:
                    bag.append(value[c_start:c_next])
                c_off = c_next
        elif tag == 0x31:  # SET: digestAlgorithms, then signerInfos last
            sets.append(value)
    signer_ids = _signer_ids(sets[-1]) if sets else []
    return bag, signer_ids


def _v1_certificates(blob: bytes) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
    bag, signer_ids = _pkcs7_parts(blob)
    if not bag:
        raise ApkError("PKCS#7 has no certificates")
    if not signer_ids:
        raise ApkError("PKCS#7 has no SignerInfo")
    signer: List[Dict[str, Any]] = []
    chain: List[Dict[str, Any]] = []
    matched_ids = set()
    for der in bag:
        try:
            issuer_serial = _x509_issuer_serial(der)
        except ApkError:
            chain.append({"sha256": _sha256(der), "der_size": len(der)})
            continue
        entry = {"sha256": _sha256(der), "der_size": len(der)}
        if issuer_serial in signer_ids:
            matched_ids.add(issuer_serial)
            signer.append(entry)
        else:
            chain.append(entry)
    if not signer:
        raise ApkError("no certificate matches a SignerInfo")
    if set(signer_ids) - matched_ids:
        raise ApkError("a SignerInfo has no matching certificate")
    return signer, chain


def _v1_report(zf: zipfile.ZipFile, names: List[str]) -> Dict[str, Any]:
    sf_files = sorted(n for n in names if n.upper().startswith("META-INF/") and n.upper().endswith(".SF"))
    block_files = sorted(
        n for n in names
        if n.upper().startswith("META-INF/") and n.upper().endswith((".RSA", ".DSA", ".EC"))
    )
    def stem(name: str) -> str:
        return name.rsplit("/", 1)[-1].rsplit(".", 1)[0].lower()

    sf_stems = {stem(name) for name in sf_files}
    matched_blocks = [name for name in block_files if stem(name) in sf_stems]
    present = bool(matched_blocks)
    certs: List[Dict[str, Any]] = []
    chain: List[Dict[str, Any]] = []
    errors: List[str] = []
    if present:
        for name in matched_blocks:
            try:
                signer, extra = _v1_certificates(_read_entry(zf, name, _MAX_SIGNATURE_BYTES))
                certs.extend(signer)
                chain.extend(extra)
            except Exception as exc:
                errors.append("%s: %s" % (name, exc))
    return {
        "scheme": "v1",
        "present": present,
        "manifest_files": sf_files,
        "signature_files": block_files,
        "certificates": certs,
        "chain_certificates": chain,
        **({"errors": errors} if errors else {}),
    }


def signing_report(data: bytes, zf: zipfile.ZipFile, names: List[str]) -> Dict[str, Any]:
    """Report v1/v2/v3 (and v3.1 when present) and signer certificate SHA-256 digests."""
    pairs = _apk_signing_pairs(data)
    v2 = {"present": bool(pairs.get(_APK_SIG_SCHEME_V2_ID)), "scheme": "v2", "signers": []}
    v3 = {"present": bool(pairs.get(_APK_SIG_SCHEME_V3_ID)), "scheme": "v3", "signers": []}
    v31 = {"present": bool(pairs.get(_APK_SIG_SCHEME_V31_ID)), "scheme": "v3.1", "signers": []}

    for scheme_id, label, target in (
        (_APK_SIG_SCHEME_V2_ID, "v2", v2),
        (_APK_SIG_SCHEME_V3_ID, "v3", v3),
        (_APK_SIG_SCHEME_V31_ID, "v3.1", v31),
    ):
        parser = _parse_signer_v2 if label == "v2" else _parse_signer_v3
        for value in pairs.get(scheme_id, []):
            try:
                signers_blob, _ = _read_lp(value, 0)
                target["signers"].extend(_parse_signers(signers_blob, parser))
            except Exception as exc:
                target.setdefault("errors", []).append(str(exc))

    v1 = _v1_report(zf, names)
    entries = {"v1": v1, "v2": v2, "v3": v3, "v3.1": v31}
    schemes = [name for name, entry in entries.items() if entry["present"]]

    cert_sources: Dict[str, set] = {}
    chain_sources: Dict[str, set] = {}
    for scheme, entry in entries.items():
        for signer in entry.get("signers", []):
            for cert in signer.get("certificates", []):
                cert_sources.setdefault(cert["sha256"], set()).add(scheme)
            for cert in signer.get("chain_certificates", []):
                chain_sources.setdefault(cert["sha256"], set()).add(scheme)
        for cert in entry.get("certificates", []):
            cert_sources.setdefault(cert["sha256"], set()).add(scheme)
        for cert in entry.get("chain_certificates", []):
            chain_sources.setdefault(cert["sha256"], set()).add(scheme)

    return {
        "schemes": schemes,
        "certificates": [
            {"sha256": digest, "schemes": sorted(sources)}
            for digest, sources in sorted(cert_sources.items())
        ],
        "chain_certificates": [
            {"sha256": digest, "schemes": sorted(sources)}
            for digest, sources in sorted(chain_sources.items())
        ],
        "v1": v1,
        "v2": v2,
        "v3": v3,
        "v3.1": v31,
    }


# -- APK -------------------------------------------------------------------


def _dex_sort_key(name: str) -> Optional[int]:
    match = re.fullmatch(r"classes(\d*)\.dex", name)
    if not match:
        return None
    digits = match.group(1)
    if not digits:
        return 1
    # Converted digit strings above the interpreter's int-conversion limit
    # raise ValueError; an absurd name is not a DEX we should try to read.
    if len(digits) > 9:
        return None
    try:
        return int(digits)
    except ValueError:
        return None


def _dex_names(names: List[str]) -> List[str]:
    found = []
    for name in names:
        num = _dex_sort_key(name)
        if num is not None:
            found.append((num, name))
    return [name for _, name in sorted(found)]


def is_apk(data: bytes) -> bool:
    """True when ``data`` is a ZIP with AndroidManifest.xml and classes*.dex."""
    try:
        with zipfile.ZipFile(io.BytesIO(data)) as zf:
            names = zf.namelist()
    except Exception:
        return False
    return "AndroidManifest.xml" in names and bool(_dex_names(names))


def inspect_apk(data: bytes) -> Dict[str, Any]:
    """Inspect an APK: manifest fields, DEX class/method lists and signing.

    A failure in one reader is recorded in an ``*_error`` field; the remaining
    readers still run, which is what makes this usable on hostile input.
    """
    report: Dict[str, Any] = {"format": "APK", "size": len(data), "is_apk": False}
    try:
        zf = zipfile.ZipFile(io.BytesIO(data))
    except Exception as exc:
        report["error"] = "%s: %s" % (type(exc).__name__, exc)
        return report

    with zf:
        names = zf.namelist()
        dex_names = _dex_names(names)
        report["is_apk"] = "AndroidManifest.xml" in names and bool(dex_names)
        report["entries"] = len(names)
        report["dex_names"] = dex_names

        if "AndroidManifest.xml" in names:
            try:
                report["manifest"] = decode_axml(_read_entry(zf, "AndroidManifest.xml", _MAX_MANIFEST_BYTES))
            except Exception as exc:
                report["manifest_error"] = "%s: %s" % (type(exc).__name__, exc)

        dexes: List[Dict[str, Any]] = []
        for name in dex_names:
            try:
                dexes.append(parse_dex(_read_entry(zf, name, _MAX_DEX_BYTES), name=name))
            except Exception as exc:
                dexes.append({"name": name, "error": "%s: %s" % (type(exc).__name__, exc)})
        report["dex"] = dexes

        try:
            report["signing"] = signing_report(data, zf, names)
        except Exception as exc:
            report["signing"] = {"schemes": [], "certificates": [],
                                 "error": "%s: %s" % (type(exc).__name__, exc)}

    return report
