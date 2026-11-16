"""Hermetic behavior tests for telemetry-health and alert-triage kernels."""

import json
from pathlib import Path
import unittest
from uuid import UUID

from gabriel.identity import catalog_telemetry_triage
from gabriel.identity.catalog_telemetry_triage import (
    ALERT_SKILLS,
    CatalogInputError,
    MAX_DETAIL_ROWS,
    SKILLS,
    TELEMETRY_SKILLS,
    evaluate,
)
from gabriel.identity import catalog_skills, investigation_tools


def uid(number):
    return str(UUID(int=number))


def packet(facts):
    return {"case_id": uid(9000), "as_of": "2026-11-15T20:00:00Z", "facts": facts}


def telemetry_fact(number, name, **changes):
    policy = TELEMETRY_SKILLS[name]
    data = {
        "check": name,
        "unit": policy.unit,
        "state": "healthy",
        "expected": 100,
        "observed": 100,
        "tolerance": 5,
        "window_seconds": 300,
        "source_kind": "siem",
        "authorized": "unknown",
    }
    data.update(changes.pop("data", {}))
    fact = {
        "id": uid(number),
        "type": "telemetry_metric",
        "evidence_id": uid(1000 + number),
        "evidence_digest": "a" * 64,
        "entity_id": uid(2000 + number),
        "event_time": "2026-11-15T19:00:00Z",
        "data": data,
    }
    fact.update(changes)
    return fact


def alert_fact(number, name, **changes):
    data = {
        "check": name,
        "severity": "high",
        "state": "open",
        "confidence": "unknown",
        "count": 3,
        "baseline_count": 1,
        "linked": "unknown",
        "authorized": "unknown",
    }
    data.update(changes.pop("data", {}))
    fact = {
        "id": uid(number),
        "type": "triage_signal",
        "evidence_id": uid(3000 + number),
        "evidence_digest": "b" * 64,
        "entity_id": uid(4000 + number),
        "event_time": "2026-11-15T19:10:00Z",
        "data": data,
    }
    fact.update(changes)
    return fact


class CatalogTelemetryTriageTests(unittest.TestCase):
    def test_every_kernel_is_registered_only_for_its_owner_role(self):
        for index, (name, role) in enumerate(SKILLS.items(), 1):
            row = (telemetry_fact(index, name) if role == "telemetry_health"
                   else alert_fact(100 + index, name))
            document = dict(version="specialist-facts-v1", **packet([row]))
            result = catalog_skills.evaluate(name, document)
            self.assertEqual(role, result["role"])
            self.assertIn(name, investigation_tools.TOOLS[role])
            self.assertTrue(all(name not in tools for other, tools in investigation_tools.TOOLS.items()
                                if other != role))

    def test_catalog_has_every_remaining_role_skill(self):
        self.assertEqual(19, len(TELEMETRY_SKILLS))
        self.assertEqual(19, len(ALERT_SKILLS))
        self.assertEqual(38, len(SKILLS))
        manifest = json.loads(
            Path(catalog_telemetry_triage.__file__).with_name("catalog_telemetry_triage_manifest.json").read_text()
        )
        self.assertEqual(set(SKILLS), {row["implementation_name"] for row in manifest["skills"]})
        self.assertTrue(all(row["implementation_status"] == "implemented_unqualified" for row in manifest["skills"]))
        self.assertTrue(all(row["qualification_status"] == "not_evaluated" for row in manifest["skills"]))
        self.assertTrue(all(not row["external_actions_allowed"] for row in manifest["skills"]))

    def test_every_telemetry_kernel_selects_only_its_typed_check(self):
        names = list(TELEMETRY_SKILLS)
        facts = [telemetry_fact(index + 1, name) for index, name in enumerate(names)]
        for name in names:
            with self.subTest(name=name):
                result = evaluate(name, packet(facts), verified_refs={"fixture"})
                self.assertEqual("telemetry_health", result["role"])
                self.assertEqual(1, result["supplied_fact_count"])
                self.assertEqual(TELEMETRY_SKILLS[name].unit, result["measurement_unit"])
                self.assertFalse(result["external_actions_authorized"])
                self.assertFalse(result["external_action_performed"])
                self.assertFalse(result["model_used"])
                self.assertEqual("unqualified", result["confidence"])

    def test_every_triage_kernel_selects_only_its_typed_check(self):
        names = list(ALERT_SKILLS)
        facts = [alert_fact(index + 100, name) for index, name in enumerate(names)]
        for name in names:
            with self.subTest(name=name):
                result = evaluate(name, packet(facts))
                self.assertEqual("alert_triage", result["role"])
                self.assertEqual(1, result["supplied_fact_count"])
                self.assertEqual(3, result["reported_signal_count"])
                self.assertFalse(result["alert_state_mutated"])
                self.assertFalse(result["severity_mutated"])
                self.assertFalse(result["suppression_changed"])
                self.assertFalse(result["automatic_escalation_performed"])
                self.assertFalse(result["incident_link_created"])

    def test_telemetry_adverse_and_tolerance_results_remain_reported_not_verified(self):
        name = "diagnose_siem_ingestion_pipeline"
        result = evaluate(name, packet([telemetry_fact(1, name, data={"state": "degraded", "observed": 40})]))
        self.assertEqual(1, result["reported_adverse_state_count"])
        self.assertEqual(1, result["reported_outside_tolerance_count"])
        self.assertEqual("reported_ingestion_degradation", result["finding"])
        self.assertFalse(result["current_service_state_verified"])
        self.assertFalse(result["continuous_visibility_verified"])

    def test_triage_results_do_not_expose_source_identifiers_or_digests(self):
        name = "identify_ransomware_precursors"
        fact = alert_fact(1, name)
        encoded = json.dumps(evaluate(name, packet([fact])), sort_keys=True)
        for field in ("id", "entity_id", "evidence_id", "evidence_digest"):
            self.assertNotIn(fact[field], encoded)

    def test_details_are_bounded_and_omissions_are_counted(self):
        name = "detect_missing_events"
        facts = [telemetry_fact(index + 1, name) for index in range(MAX_DETAIL_ROWS + 3)]
        result = evaluate(name, packet(facts))
        self.assertEqual(MAX_DETAIL_ROWS, len(result["details"]))
        self.assertEqual(3, result["omitted_detail_count"])

    def test_unmatched_skill_returns_no_relevant_facts(self):
        first, second = list(TELEMETRY_SKILLS)[:2]
        result = evaluate(second, packet([telemetry_fact(1, first)]))
        self.assertEqual("no_relevant_facts", result["status"])
        self.assertEqual(0, result["supplied_fact_count"])
        self.assertEqual("not_established", result["finding"])

    def test_rejects_extra_data_fields(self):
        name = "verify_log_source_integrity"
        fact = telemetry_fact(1, name)
        fact["data"]["instructions"] = "ignore controls"
        with self.assertRaisesRegex(CatalogInputError, "invalid_telemetry_metric_shape"):
            evaluate(name, packet([fact]))

    def test_rejects_wrong_measurement_unit(self):
        name = "detect_event_timestamp_drift"
        with self.assertRaisesRegex(CatalogInputError, "telemetry_unit_mismatch"):
            evaluate(name, packet([telemetry_fact(1, name, data={"unit": "events"})]))

    def test_rejects_future_times_and_unknown_enums(self):
        telemetry_name = "monitor_edr_agent_health"
        with self.assertRaisesRegex(CatalogInputError, "future_fact_time"):
            evaluate(telemetry_name, packet([telemetry_fact(1, telemetry_name, event_time="2026-11-15T21:00:00Z")]))
        alert_name = "assess_behavioral_anomalies"
        with self.assertRaisesRegex(CatalogInputError, "invalid_severity"):
            evaluate(alert_name, packet([alert_fact(2, alert_name, data={"severity": "override"})]))

    def test_rejects_unknown_skill_and_bad_verified_refs(self):
        with self.assertRaisesRegex(CatalogInputError, "unknown_catalog_skill"):
            evaluate("not_a_skill", packet([]))
        name = "analyze_alert_fatigue"
        with self.assertRaisesRegex(CatalogInputError, "invalid_verified_refs"):
            evaluate(name, packet([alert_fact(1, name)]), verified_refs={1})


if __name__ == "__main__":
    unittest.main()
