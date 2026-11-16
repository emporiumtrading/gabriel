"""Bounded telemetry-health and alert-triage catalog kernels.

The kernels consume only a closed, case-local fact packet.  They never query a
SIEM, mutate an alert, suppress a detection, or authorize an escalation.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
import re
from uuid import UUID


VERSION = "gabriel-telemetry-triage-catalog-v1"
MAX_FACTS = 128
MAX_DETAIL_ROWS = 5
HEX64 = re.compile(r"[0-9a-f]{64}")
AUTHORITY = {"yes", "no", "unknown"}
TELEMETRY_STATES = {"healthy", "degraded", "unavailable", "unknown"}
ALERT_STATES = {"open", "resolved", "benign", "suppressed", "unknown"}
SEVERITIES = {"critical", "high", "medium", "low", "informational", "unknown"}
CONFIDENCE = {"high", "medium", "low", "unknown"}
LINKAGE = {"yes", "no", "unknown"}
SOURCE_KINDS = {
    "application", "authentication", "cloud", "connector", "endpoint",
    "identity", "network", "security_control", "siem", "other", "unknown",
}


class CatalogInputError(ValueError):
    """Raised when an untrusted catalog packet violates its closed schema."""


@dataclass(frozen=True)
class TelemetryPolicy:
    unit: str
    adverse_label: str


TELEMETRY_SKILLS = {
    "verify_log_source_integrity": TelemetryPolicy("integrity_checks", "reported_integrity_exception"),
    "diagnose_siem_ingestion_pipeline": TelemetryPolicy("events", "reported_ingestion_degradation"),
    "validate_log_parsing_normalization": TelemetryPolicy("records", "reported_parse_or_normalization_exception"),
    "detect_missing_events": TelemetryPolicy("events", "reported_missing_event_window"),
    "detect_event_timestamp_drift": TelemetryPolicy("seconds", "reported_timestamp_drift"),
    "monitor_log_retention_expiration": TelemetryPolicy("seconds", "reported_retention_exception"),
    "monitor_endpoint_heartbeat_anomalies": TelemetryPolicy("seconds", "reported_heartbeat_exception"),
    "analyze_network_sensor_health": TelemetryPolicy("packets", "reported_sensor_degradation"),
    "monitor_edr_agent_health": TelemetryPolicy("agents", "reported_agent_health_exception"),
    "monitor_security_connector_authentication": TelemetryPolicy("attempts", "reported_connector_authentication_exception"),
    "detect_telemetry_volume_anomalies": TelemetryPolicy("events", "reported_volume_exception"),
    "detect_log_tampering_deletion": TelemetryPolicy("records", "reported_tampering_or_deletion_signal"),
    "identify_duplicate_events": TelemetryPolicy("events", "reported_duplicate_event_exception"),
    "assess_event_correlation_quality": TelemetryPolicy("links", "reported_correlation_quality_exception"),
    "discover_monitoring_blind_spots": TelemetryPolicy("sources", "reported_monitoring_blind_spot"),
    "verify_cloud_audit_logging_coverage": TelemetryPolicy("services", "reported_cloud_audit_coverage_exception"),
    "reconcile_security_control_status": TelemetryPolicy("controls", "reported_control_status_conflict"),
    "assess_telemetry_outage_impact": TelemetryPolicy("seconds", "reported_telemetry_outage_impact"),
    "report_monitoring_service_levels": TelemetryPolicy("basis_points", "reported_service_level_exception"),
}


ALERT_SKILLS = {
    "deduplicate_alert_clusters": "reported_duplicate_cluster",
    "correlate_multiple_alerts": "reported_multi_alert_relationship",
    "recalibrate_alert_severity": "reported_severity_review_candidate",
    "assess_behavioral_anomalies": "reported_behavioral_anomaly",
    "score_contextual_risk": "reported_contextual_risk",
    "recognize_known_good_activity": "reported_known_good_candidate",
    "analyze_alert_fatigue": "reported_alert_fatigue_condition",
    "correlate_attack_chain_alerts": "reported_attack_chain_relationship",
    "identify_multi_stage_incidents": "reported_multi_stage_candidate",
    "assess_business_asset_criticality": "reported_asset_criticality_context",
    "analyze_user_behavior_deviation": "reported_user_behavior_deviation",
    "assess_geolocation_anomalies": "reported_geolocation_anomaly",
    "triage_suspicious_administrative_activity": "reported_administrative_activity_candidate",
    "correlate_malware_alerts": "reported_malware_alert_relationship",
    "investigate_phishing_alerts": "reported_phishing_candidate",
    "identify_ransomware_precursors": "reported_ransomware_precursor",
    "review_alert_suppression_effectiveness": "reported_suppression_exception",
    "match_historical_incident_similarity": "reported_historical_similarity",
    "calibrate_alert_confidence": "reported_confidence_calibration_candidate",
}


SKILLS = {
    **{name: "telemetry_health" for name in TELEMETRY_SKILLS},
    **{name: "alert_triage" for name in ALERT_SKILLS},
}

SCHEMAS = {
    "telemetry_metric": {
        "check": frozenset(TELEMETRY_SKILLS),
        "unit": frozenset(policy.unit for policy in TELEMETRY_SKILLS.values()),
        "state": TELEMETRY_STATES,
        "expected": "zero_to_billion",
        "observed": "zero_to_billion",
        "tolerance": "zero_to_billion",
        "window_seconds": "positive_week_seconds",
        "source_kind": SOURCE_KINDS,
        "authorized": AUTHORITY,
    },
    "triage_signal": {
        "check": frozenset(ALERT_SKILLS),
        "severity": SEVERITIES,
        "state": ALERT_STATES,
        "confidence": CONFIDENCE,
        "count": "zero_to_billion",
        "baseline_count": "zero_to_billion",
        "linked": LINKAGE,
        "authorized": AUTHORITY,
    },
}
ROLE_TYPES = {
    "telemetry_health": {"telemetry_metric"},
    "alert_triage": {"triage_signal"},
}


def _require(condition: bool, code: str) -> None:
    if not condition:
        raise CatalogInputError(code)


def _exact_dict(value, keys: set[str], code: str) -> None:
    _require(type(value) is dict and set(value) == keys, code)


def _time(value: str) -> datetime:
    _require(type(value) is str and value.endswith("Z"), "invalid_utc_time")
    try:
        parsed = datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError as error:
        raise CatalogInputError("invalid_utc_time") from error
    _require(parsed.tzinfo is not None and parsed.utcoffset().total_seconds() == 0, "invalid_utc_time")
    return parsed


def _uuid(value, code: str, *, optional: bool = False) -> None:
    if optional and value is None:
        return
    _require(type(value) is str, code)
    try:
        parsed = UUID(value)
    except (ValueError, AttributeError) as error:
        raise CatalogInputError(code) from error
    _require(str(parsed) == value and parsed.int != 0, code)


def _bounded_int(value, code: str, maximum: int = 1_000_000_000) -> None:
    _require(type(value) is int and 0 <= value <= maximum, code)


def _validate_common(document: dict) -> tuple[datetime, list[dict]]:
    keys = set(document) if type(document) is dict else set()
    specialist_packet = keys == {"version", "case_id", "as_of", "facts"}
    _require(specialist_packet or keys == {"case_id", "as_of", "facts"}, "invalid_document_shape")
    if specialist_packet:
        _require(document["version"] == "specialist-facts-v1", "invalid_document_version")
        from gabriel.identity.specialist_analysis import validate_document as validate_specialist_document
        validate_specialist_document(document, document["case_id"])
    _uuid(document["case_id"], "invalid_case_id")
    as_of = _time(document["as_of"])
    facts = document["facts"]
    _require(type(facts) is list and len(facts) <= MAX_FACTS, "invalid_fact_collection")
    seen = set()
    for fact in facts:
        _exact_dict(
            fact,
            {"id", "type", "evidence_id", "evidence_digest", "entity_id", "event_time", "data"},
            "invalid_fact_shape",
        )
        _uuid(fact["id"], "invalid_fact_id")
        _require(fact["id"] not in seen, "duplicate_fact_id")
        seen.add(fact["id"])
        _uuid(fact["evidence_id"], "invalid_evidence_id")
        _uuid(fact["entity_id"], "invalid_entity_id", optional=True)
        _require(type(fact["evidence_digest"]) is str and HEX64.fullmatch(fact["evidence_digest"]) is not None,
                 "invalid_evidence_digest")
        if not specialist_packet:
            _require(fact["type"] in {"telemetry_metric", "triage_signal"}, "invalid_fact_type")
        _require(_time(fact["event_time"]) <= as_of, "future_fact_time")
    return as_of, facts


def _validate_telemetry(fact: dict) -> None:
    data = fact["data"]
    _exact_dict(
        data,
        {"check", "unit", "state", "expected", "observed", "tolerance", "window_seconds", "source_kind", "authorized"},
        "invalid_telemetry_metric_shape",
    )
    _require(data["check"] in TELEMETRY_SKILLS, "invalid_telemetry_check")
    _require(data["unit"] == TELEMETRY_SKILLS[data["check"]].unit, "telemetry_unit_mismatch")
    _require(data["state"] in TELEMETRY_STATES, "invalid_telemetry_state")
    _bounded_int(data["expected"], "invalid_expected")
    _bounded_int(data["observed"], "invalid_observed")
    _bounded_int(data["tolerance"], "invalid_tolerance")
    _bounded_int(data["window_seconds"], "invalid_window", 604_800)
    _require(data["window_seconds"] > 0, "invalid_window")
    _require(data["source_kind"] in SOURCE_KINDS, "invalid_source_kind")
    _require(data["authorized"] in AUTHORITY, "invalid_authority")


def _validate_alert(fact: dict) -> None:
    data = fact["data"]
    _exact_dict(
        data,
        {"check", "severity", "state", "confidence", "count", "baseline_count", "linked", "authorized"},
        "invalid_triage_signal_shape",
    )
    _require(data["check"] in ALERT_SKILLS, "invalid_triage_check")
    _require(data["severity"] in SEVERITIES, "invalid_severity")
    _require(data["state"] in ALERT_STATES, "invalid_alert_state")
    _require(data["confidence"] in CONFIDENCE, "invalid_confidence")
    _bounded_int(data["count"], "invalid_alert_count")
    _bounded_int(data["baseline_count"], "invalid_baseline_count")
    _require(data["linked"] in LINKAGE, "invalid_linkage")
    _require(data["authorized"] in AUTHORITY, "invalid_authority")


def validate_document(document: dict) -> None:
    """Validate a closed packet without accepting instructions or free text."""
    _, facts = _validate_common(document)
    for fact in facts:
        if fact["type"] == "telemetry_metric":
            _validate_telemetry(fact)
        elif fact["type"] == "triage_signal":
            _validate_alert(fact)


def validate_fact(fact: dict) -> None:
    """Apply cross-field rules after the shared specialist schema check."""
    from gabriel.identity.specialist_analysis import require
    require(fact["entity_id"] is not None, "catalog_entity_alias_required")
    if fact["type"] == "telemetry_metric":
        data = fact["data"]
        require(data["unit"] == TELEMETRY_SKILLS[data["check"]].unit, "telemetry_unit_mismatch")


def _base(name: str, role: str, supplied: int) -> dict:
    return {
        "version": VERSION,
        "skill": name,
        "role": role,
        "status": "review_required" if supplied else "no_relevant_facts",
        "supplied_fact_count": supplied,
        "source_authenticity": "unverified",
        "source_clocks_verified": False,
        "coverage_complete": False,
        "confidence": "unqualified",
        "external_actions_authorized": False,
        "external_action_performed": False,
        "model_used": False,
        "requires_analyst_review": True,
    }


def _telemetry_result(name: str, document: dict) -> dict:
    rows = [fact for fact in document["facts"]
            if fact["type"] == "telemetry_metric" and fact["data"]["check"] == name]
    adverse = [fact for fact in rows if fact["data"]["state"] in {"degraded", "unavailable"}]
    breached = [fact for fact in rows
                if abs(fact["data"]["observed"] - fact["data"]["expected"]) > fact["data"]["tolerance"]]
    evidence = sorted({fact["evidence_id"] for fact in rows})
    source_kinds = sorted({fact["data"]["source_kind"] for fact in rows})
    details = []
    for fact in sorted(rows, key=lambda item: (item["event_time"], item["id"]))[:MAX_DETAIL_ROWS]:
        data = fact["data"]
        details.append({
            "observation": f"o{document['facts'].index(fact) + 1}",
            "state": data["state"],
            "difference": data["observed"] - data["expected"],
            "outside_tolerance": abs(data["observed"] - data["expected"]) > data["tolerance"],
            "source_kind": data["source_kind"],
        })
    result = _base(name, "telemetry_health", len(rows))
    result.update({
        "measurement_unit": TELEMETRY_SKILLS[name].unit,
        "represented_evidence_source_count": len(evidence),
        "represented_source_kinds": source_kinds,
        "reported_adverse_state_count": len(adverse),
        "reported_outside_tolerance_count": len(breached),
        "reported_unknown_state_count": sum(fact["data"]["state"] == "unknown" for fact in rows),
        "unknown_authority_count": sum(fact["data"]["authorized"] == "unknown" for fact in rows),
        "finding": TELEMETRY_SKILLS[name].adverse_label if adverse or breached else "not_established",
        "details": details,
        "omitted_detail_count": max(0, len(rows) - MAX_DETAIL_ROWS),
        "continuous_visibility_verified": False,
        "current_service_state_verified": False,
    })
    return result


def _alert_result(name: str, document: dict) -> dict:
    rows = [fact for fact in document["facts"]
            if fact["type"] == "triage_signal" and fact["data"]["check"] == name]
    unresolved = [fact for fact in rows if fact["data"]["state"] in {"open", "unknown"}]
    evidence = {fact["evidence_id"] for fact in rows}
    severe = [fact for fact in unresolved if fact["data"]["severity"] in {"critical", "high"}]
    details = []
    for fact in sorted(rows, key=lambda item: (item["event_time"], item["id"]))[:MAX_DETAIL_ROWS]:
        data = fact["data"]
        details.append({
            "observation": f"o{document['facts'].index(fact) + 1}",
            "severity": data["severity"],
            "state": data["state"],
            "confidence": data["confidence"],
            "reported_count_delta": data["count"] - data["baseline_count"],
            "linked": data["linked"],
        })
    result = _base(name, "alert_triage", len(rows))
    result.update({
        "represented_evidence_source_count": len(evidence),
        "reported_signal_count": sum(fact["data"]["count"] for fact in rows),
        "reported_unresolved_fact_count": len(unresolved),
        "reported_unresolved_high_or_critical_count": len(severe),
        "unknown_confidence_count": sum(fact["data"]["confidence"] == "unknown" for fact in rows),
        "unknown_linkage_count": sum(fact["data"]["linked"] == "unknown" for fact in rows),
        "unknown_authority_count": sum(fact["data"]["authorized"] == "unknown" for fact in rows),
        "finding": ALERT_SKILLS[name] if rows else "not_established",
        "details": details,
        "omitted_detail_count": max(0, len(rows) - MAX_DETAIL_ROWS),
        "alert_state_mutated": False,
        "severity_mutated": False,
        "suppression_changed": False,
        "automatic_escalation_performed": False,
        "incident_link_created": False,
    })
    return result


def evaluate(name: str, document: dict, *, verified_refs=None) -> dict:
    """Execute one role-bound kernel over validated supplied facts."""
    _require(name in SKILLS, "unknown_catalog_skill")
    validate_document(document)
    if verified_refs is not None:
        _require(type(verified_refs) in {set, frozenset, tuple, list}, "invalid_verified_refs")
        _require(all(type(item) is str for item in verified_refs), "invalid_verified_refs")
    if name in TELEMETRY_SKILLS:
        return _telemetry_result(name, document)
    return _alert_result(name, document)
