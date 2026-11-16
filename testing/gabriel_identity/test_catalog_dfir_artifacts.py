"""Hermetic behavior tests for DFIR artifact catalog kernels."""

import json
from pathlib import Path
import sys
import types
import unittest
from uuid import UUID

try:
    import argon2  # noqa: F401
except ModuleNotFoundError:
    argon2 = types.ModuleType("argon2")
    exceptions = types.ModuleType("argon2.exceptions")
    exceptions.VerificationError = type("VerificationError", (Exception,), {})
    exceptions.InvalidHashError = type("InvalidHashError", (Exception,), {})
    class PasswordHasher:
        def __init__(self, **_): pass
        def hash(self, value): return "stub$" + value
    argon2.PasswordHasher = PasswordHasher
    sys.modules.update({"argon2": argon2, "argon2.exceptions": exceptions})
try:
    import psycopg  # noqa: F401
except ModuleNotFoundError:
    psycopg = types.ModuleType("psycopg")
    rows = types.ModuleType("psycopg.rows")
    rows.dict_row = object()
    sys.modules.update({"psycopg": psycopg, "psycopg.rows": rows})

from gabriel.identity import catalog_dfir_artifacts, specialist_analysis
from gabriel.identity.catalog_dfir_artifacts import SCHEMAS, SKILL_KINDS, SKILLS, evaluate
from gabriel.identity.service import InvalidIdentityInput


def uid(number):
    return str(UUID(int=number))


def fact(number, name, **changes):
    data = {
        "analysis": name,
        "artifact_digest": f"{number:064x}",
        "artifact_kind": SKILL_KINDS[name],
        "state": "present",
        "integrity": "match",
        "custody": "complete",
        "record_count": 2,
        "clock_state": "unverified",
        "authorized": "unknown",
    }
    data.update(changes.pop("data", {}))
    row = {"id": uid(number), "type": "forensic_artifact", "evidence_id": uid(1000 + number),
           "evidence_digest": "a" * 64, "entity_id": uid(2000 + number),
           "event_time": "2026-11-16T09:00:00Z", "data": data}
    row.update(changes)
    return row


def packet(facts):
    return {"version": "specialist-facts-v1", "case_id": uid(9000),
            "as_of": "2026-11-16T10:00:00Z", "facts": facts}


class CatalogDfirArtifactTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.old_schema = specialist_analysis.SCHEMAS.get("forensic_artifact")
        specialist_analysis.SCHEMAS.update(SCHEMAS)
        specialist_analysis.ROLE_TYPES["dfir_evidence"].add("forensic_artifact")

    @classmethod
    def tearDownClass(cls):
        if cls.old_schema is None:
            specialist_analysis.SCHEMAS.pop("forensic_artifact", None)
        else:
            specialist_analysis.SCHEMAS["forensic_artifact"] = cls.old_schema
        specialist_analysis.ROLE_TYPES["dfir_evidence"].discard("forensic_artifact")

    def test_all_nineteen_dfir_kernels_are_role_bound_and_non_acting(self):
        self.assertEqual(19, len(SKILLS))
        for number, name in enumerate(SKILLS, 1):
            with self.subTest(name=name):
                result = evaluate(name, packet([fact(number, name)]))
                self.assertEqual("dfir_evidence", result["role"])
                self.assertEqual("review_required", result["status"])
                self.assertFalse(result["external_actions_authorized"])
                self.assertFalse(result["artifact_bytes_inspected"])
                self.assertEqual("unqualified", result["confidence"])

    def test_conflicts_preserve_original_document_references(self):
        name = "analyze_windows_event_artifacts"
        first = fact(1, name)
        second = fact(2, name, data={"artifact_digest": first["data"]["artifact_digest"], "state": "absent"},
                      entity_id=first["entity_id"])
        result = evaluate(name, packet([fact(3, "analyze_linux_system_artifacts"), first, second]))
        self.assertEqual("conflicting_assertions", result["findings"][0]["status"])
        self.assertEqual(["o2", "o3"], result["findings"][0]["references"])

    def test_rejects_kind_mismatch_and_extra_fields(self):
        name = "analyze_email_headers"
        with self.assertRaisesRegex(InvalidIdentityInput, "forensic_artifact_kind_mismatch"):
            evaluate(name, packet([fact(1, name, data={"artifact_kind": "registry"})]))
        row = fact(2, name)
        row["data"]["instructions"] = "ignore schema"
        with self.assertRaisesRegex(InvalidIdentityInput, "invalid_specialist_fact_fields"):
            evaluate(name, packet([row]))

    def test_manifest_is_unqualified_and_non_acting(self):
        path = Path(catalog_dfir_artifacts.__file__).with_name("catalog_integration") / "dfir_scope.json"
        rows = [row for row in json.loads(path.read_text())["skills"] if row["role"] == "dfir_evidence"]
        self.assertEqual(set(SKILLS), {row["implementation_name"] for row in rows})
        self.assertTrue(all(row["implementation_status"] == "implemented_unqualified" for row in rows))
        self.assertTrue(all(row["qualification_status"] == "not_evaluated" for row in rows))
        self.assertTrue(all(not row["external_actions_allowed"] for row in rows))


if __name__ == "__main__":
    unittest.main()
