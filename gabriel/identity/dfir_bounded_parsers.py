"""Strict, bounded parsers for small forensic exports.

The parsers inspect supplied bytes only.  They do not execute content, extract
archives, follow links, open databases, or attempt to interpret complex binary
forensic formats.
"""

from __future__ import annotations

from email import policy
from email.parser import BytesHeaderParser
from hashlib import sha256
from io import BytesIO
import json
import re
from xml.etree import ElementTree
from zipfile import BadZipFile, ZipFile


MAX_TEXT_BYTES = 1_048_576
MAX_HEADER_BYTES = 65_536
MAX_ARCHIVE_BYTES = 8_388_608
MAX_RECORDS = 256
MAX_FIELD_CHARS = 4_096
MAX_ARCHIVE_EXPANDED_BYTES = 1_073_741_824
COMPLEX_BINARY_KINDS = frozenset({
    "amcache", "disk_image", "memory_dump", "malware_binary", "prefetch",
    "shimcache", "container_layer",
})


class ArtifactParseError(ValueError):
    """Raised when supplied bytes cannot be inspected within the safe subset."""


def _bytes(payload: bytes, limit: int) -> bytes:
    if type(payload) is not bytes or not payload or len(payload) > limit:
        raise ArtifactParseError("invalid_or_oversized_artifact")
    return payload


def _text(payload: bytes, *, encodings=("utf-8",), limit=MAX_TEXT_BYTES) -> str:
    raw = _bytes(payload, limit)
    for encoding in encodings:
        try:
            value = raw.decode(encoding, errors="strict")
        except UnicodeDecodeError:
            continue
        if "\x00" in value:
            raise ArtifactParseError("embedded_nul")
        return value
    raise ArtifactParseError("unsupported_text_encoding")


def _field(value) -> str:
    text = str(value)
    if len(text) > MAX_FIELD_CHARS or any(ord(char) < 32 and char not in "\t\n\r" for char in text):
        raise ArtifactParseError("invalid_field_value")
    return text


def parse_json_lines(payload: bytes) -> list[dict]:
    rows = []
    for line in _text(payload).splitlines():
        if not line.strip():
            continue
        if len(rows) >= MAX_RECORDS:
            raise ArtifactParseError("record_limit_exceeded")
        try:
            row = json.loads(line)
        except (json.JSONDecodeError, RecursionError) as error:
            raise ArtifactParseError("invalid_json_line") from error
        if type(row) is not dict or len(row) > 64:
            raise ArtifactParseError("invalid_json_record")
        normalized = {}
        for key, value in row.items():
            if type(key) is not str or type(value) not in {str, int, float, bool, type(None)}:
                raise ArtifactParseError("unsupported_json_value")
            normalized[_field(key)] = value if value is None or type(value) is not str else _field(value)
        rows.append(normalized)
    return rows


def parse_windows_event_xml(payload: bytes) -> list[dict]:
    raw = _bytes(payload, MAX_TEXT_BYTES)
    upper = raw.upper()
    if b"<!DOCTYPE" in upper or b"<!ENTITY" in upper:
        raise ArtifactParseError("xml_entities_not_allowed")
    try:
        root = ElementTree.fromstring(raw)
    except ElementTree.ParseError as error:
        raise ArtifactParseError("invalid_event_xml") from error
    events = [root] if root.tag.rsplit("}", 1)[-1] == "Event" else [
        node for node in root.iter() if node.tag.rsplit("}", 1)[-1] == "Event"
    ]
    if not events or len(events) > MAX_RECORDS:
        raise ArtifactParseError("invalid_event_count")
    rows = []
    for event in events:
        row = {"event_id": None, "provider": None, "computer": None,
               "system_time": None, "data": {}}
        for node in event.iter():
            tag = node.tag.rsplit("}", 1)[-1]
            if tag == "EventID" and node.text is not None:
                row["event_id"] = _field(node.text.strip())
            elif tag == "Provider":
                row["provider"] = _field(node.attrib.get("Name", ""))
            elif tag == "Computer" and node.text is not None:
                row["computer"] = _field(node.text.strip())
            elif tag == "TimeCreated":
                row["system_time"] = _field(node.attrib.get("SystemTime", ""))
            elif tag == "Data" and node.text is not None and len(row["data"]) < 64:
                key = _field(node.attrib.get("Name", str(len(row["data"]))))
                row["data"][key] = _field(node.text.strip())
        rows.append(row)
    return rows


def parse_email_headers(payload: bytes) -> list[dict]:
    raw = _bytes(payload, MAX_HEADER_BYTES)
    boundary = raw.find(b"\r\n\r\n")
    if boundary < 0:
        boundary = raw.find(b"\n\n")
    header_bytes = raw if boundary < 0 else raw[:boundary]
    try:
        message = BytesHeaderParser(policy=policy.default).parsebytes(header_bytes + b"\r\n\r\n")
    except (ValueError, UnicodeError) as error:
        raise ArtifactParseError("invalid_email_headers") from error
    if message.defects or len(message.keys()) > 128:
        raise ArtifactParseError("invalid_email_headers")
    return [{"name": _field(name.lower()), "value": _field(str(value))}
            for name, value in message.raw_items()]


def parse_zip_metadata(payload: bytes) -> list[dict]:
    raw = _bytes(payload, MAX_ARCHIVE_BYTES)
    try:
        with ZipFile(BytesIO(raw)) as archive:
            infos = archive.infolist()
    except (BadZipFile, OSError, ValueError) as error:
        raise ArtifactParseError("invalid_zip_archive") from error
    if len(infos) > MAX_RECORDS or sum(info.file_size for info in infos) > MAX_ARCHIVE_EXPANDED_BYTES:
        raise ArtifactParseError("archive_limit_exceeded")
    return [{
        "name": _field(info.filename),
        "compressed_size": info.compress_size,
        "uncompressed_size": info.file_size,
        "crc32": f"{info.CRC:08x}",
        "encrypted": bool(info.flag_bits & 1),
        "unsafe_path": info.filename.startswith(("/", "\\")) or ".." in re.split(r"[/\\]+", info.filename),
    } for info in infos]


def parse_registry_export(payload: bytes) -> list[dict]:
    text = _text(payload, encodings=("utf-16", "utf-8-sig", "utf-8"))
    lines = text.splitlines()
    if not lines or lines[0].strip() != "Windows Registry Editor Version 5.00":
        raise ArtifactParseError("invalid_registry_export")
    current = None
    rows = []
    for raw in lines[1:]:
        line = raw.strip()
        if not line or line.startswith(";"):
            continue
        if line.startswith("[") and line.endswith("]"):
            current = _field(line[1:-1])
            continue
        if current is None or "=" not in line or len(rows) >= MAX_RECORDS:
            raise ArtifactParseError("invalid_registry_record")
        name, value = line.split("=", 1)
        rows.append({"key": current, "name": _field(name), "value": _field(value)})
    return rows


def parse_powershell_history(payload: bytes) -> list[dict]:
    lines = _text(payload).splitlines()
    if len(lines) > MAX_RECORDS:
        raise ArtifactParseError("record_limit_exceeded")
    rows = []
    for number, line in enumerate(lines, 1):
        if not line.strip():
            continue
        encoded = _field(line).encode("utf-8")
        rows.append({"line": number, "command_digest": sha256(encoded).hexdigest(), "byte_length": len(encoded)})
    return rows


def parse_artifact(kind: str, payload: bytes):
    parsers = {
        "jsonl": parse_json_lines,
        "windows_event_xml": parse_windows_event_xml,
        "email_headers": parse_email_headers,
        "zip_metadata": parse_zip_metadata,
        "registry_export": parse_registry_export,
        "powershell_history": parse_powershell_history,
    }
    if kind in COMPLEX_BINARY_KINDS:
        raise ArtifactParseError("complex_binary_requires_admitted_external_tool")
    if kind not in parsers:
        raise ArtifactParseError("unsupported_artifact_kind")
    return parsers[kind](payload)
