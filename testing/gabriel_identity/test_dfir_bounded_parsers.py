"""Hermetic tests for bounded, non-executing forensic parsers."""

from io import BytesIO
import json
import unittest
from zipfile import ZipFile

from gabriel.identity.dfir_bounded_parsers import ArtifactParseError, parse_artifact


class DfirBoundedParserTests(unittest.TestCase):
    def test_json_lines_accepts_only_flat_objects(self):
        rows = parse_artifact("jsonl", b'{"event":"login","count":2}\n')
        self.assertEqual([{"event": "login", "count": 2}], rows)
        with self.assertRaisesRegex(ArtifactParseError, "unsupported_json_value"):
            parse_artifact("jsonl", json.dumps({"nested": {"x": 1}}).encode() + b"\n")

    def test_windows_xml_rejects_entities_and_extracts_bounded_fields(self):
        xml = (b'<Events><Event><System><Provider Name="Example"/><EventID>4624</EventID>'
               b'<TimeCreated SystemTime="2026-11-16T10:00:00Z"/><Computer>host</Computer>'
               b'</System><EventData><Data Name="User">analyst</Data></EventData></Event></Events>')
        rows = parse_artifact("windows_event_xml", xml)
        self.assertEqual("4624", rows[0]["event_id"])
        self.assertEqual("analyst", rows[0]["data"]["User"])
        with self.assertRaisesRegex(ArtifactParseError, "xml_entities_not_allowed"):
            parse_artifact("windows_event_xml", b'<!DOCTYPE x [<!ENTITY a "b">]><Event/>')

    def test_email_parser_never_returns_body(self):
        rows = parse_artifact("email_headers", b"From: a@example.test\r\nSubject: review\r\n\r\nsecret body")
        self.assertEqual(["from", "subject"], [row["name"] for row in rows])
        self.assertNotIn("secret body", str(rows))

    def test_zip_parser_reads_metadata_without_extracting(self):
        stream = BytesIO()
        with ZipFile(stream, "w") as archive:
            archive.writestr("../unsafe.txt", "evidence")
        rows = parse_artifact("zip_metadata", stream.getvalue())
        self.assertTrue(rows[0]["unsafe_path"])
        self.assertEqual(8, rows[0]["uncompressed_size"])

    def test_registry_and_powershell_parsers_are_read_only(self):
        registry = "Windows Registry Editor Version 5.00\r\n\r\n[HKEY_TEST] \r\n\"Value\"=\"Data\"\r\n".encode("utf-16")
        self.assertEqual("HKEY_TEST", parse_artifact("registry_export", registry)[0]["key"])
        history = parse_artifact("powershell_history", b"Get-Process\n")
        self.assertEqual(64, len(history[0]["command_digest"]))
        self.assertNotIn("Get-Process", str(history))

    def test_complex_binary_formats_fail_closed(self):
        for kind in ("memory_dump", "disk_image", "malware_binary", "prefetch", "amcache"):
            with self.subTest(kind=kind), self.assertRaisesRegex(
                    ArtifactParseError, "complex_binary_requires_admitted_external_tool"):
                parse_artifact(kind, b"not interpreted")


if __name__ == "__main__":
    unittest.main()
