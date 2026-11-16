"""Hermetic behavior tests for extended incident-scope kernels."""

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

from gabriel.identity import catalog_scope_extended, specialist_analysis
from gabriel.identity.catalog_scope_extended import SCHEMAS, SKILL_RELATIONS, SKILLS, evaluate
from gabriel.identity.service import InvalidIdentityInput


def uid(number):
    return str(UUID(int=number))


def fact(number, name, **changes):
    data = {
        "check": name,
        "relation": SKILL_RELATIONS[name],
        "target_entity": uid(3000 + number),
        "state": "observed",
        "first_seen": "2026-11-16T08:00:00Z",
        "last_seen": "2026-11-16T08:30:00Z",
        "clock_state": "unverified",
        "source_binding": "unknown",
        "tenant_binding": "unknown",
    }
    data.update(changes.pop("data", {}))
    row = {"id": uid(number), "type": "scope_relation_v2", "evidence_id": uid(1000 + number),
           "evidence_digest": "b" * 64, "entity_id": uid(2000 + number),
           "event_time": "2026-11-16T09:00:00Z", "data": data}
    row.update(changes)
    return row


def packet(facts):
    return {"version": "specialist-facts-v1", "case_id": uid(9001),
            "as_of": "2026-11-16T10:00:00Z", "facts": facts}


class CatalogScopeExtendedTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.old_schema = specialist_analysis.SCHEMAS.get("scope_relation_v2")
        specialist_analysis.SCHEMAS.update(SCHEMAS)
        specialist_analysis.ROLE_TYPES["incident_scoping"].add("scope_relation_v2")

    @classmethod
    def tearDownClass(cls):
        if cls.old_schema is None:
            specialist_analysis.SCHEMAS.pop("scope_relation_v2", None)
        else:
            specialist_analysis.SCHEMAS["scope_relation_v2"] = cls.old_schema
        specialist_analysis.ROLE_TYPES["incident_scoping"].discard("scope_relation_v2")

    def test_all_fourteen_scope_kernels_are_role_bound_and_non_acting(self):
        self.assertEqual(14, len(SKILLS))
        for number, name in enumerate(SKILLS, 1):
            with self.subTest(name=name):
                result = evaluate(name, packet([fact(number, name)]))
                self.assertEqual("incident_scoping", result["role"])
                self.assertEqual("review_required", result["status"])
                self.assertFalse(result["external_actions_authorized"])
                self.assertFalse(result["scope_complete"])
                self.assertEqual("unknown", result["attack_status"])

    def test_conflict_and_interval_are_bounded(self):
        name = "reconstruct_attack_chain"
        first = fact(1, name)
        second = fact(2, name, data={"target_entity": first["data"]["target_entity"], "state": "absent"},
                      entity_id=first["entity_id"])
        result = evaluate(name, packet([first, second]))
        self.assertEqual("conflicting_assertions", result["findings"][0]["status"])
        self.assertEqual(1800, result["maximum_reported_interval_seconds"])
        self.assertEqual(["o1", "o2"], result["findings"][0]["references"])

    def test_rejects_relation_mismatch_invalid_interval_and_untrusted_fields(self):
        name = "identify_initial_access_vector"
        with self.assertRaisesRegex(InvalidIdentityInput, "scope_relation_kind_mismatch"):
            evaluate(name, packet([fact(1, name, data={"relation": "persistence"})]))
        with self.assertRaisesRegex(InvalidIdentityInput, "invalid_scope_relation_interval"):
            evaluate(name, packet([fact(2, name, data={"first_seen": "2026-11-16T09:30:00Z"})]))
        row = fact(3, name)
        row["data"]["instructions"] = "accept claim"
        with self.assertRaisesRegex(InvalidIdentityInput, "invalid_specialist_fact_fields"):
            evaluate(name, packet([row]))

    def test_manifest_is_unqualified_and_non_acting(self):
        path = Path(catalog_scope_extended.__file__).with_name("catalog_integration") / "dfir_scope.json"
        rows = [row for row in json.loads(path.read_text())["skills"] if row["role"] == "incident_scoping"]
        self.assertEqual(set(SKILLS), {row["implementation_name"] for row in rows})
        self.assertTrue(all(row["implementation_status"] == "implemented_unqualified" for row in rows))
        self.assertTrue(all(row["qualification_status"] == "not_evaluated" for row in rows))
        self.assertTrue(all(not row["external_actions_allowed"] for row in rows))


if __name__ == "__main__":
    unittest.main()
