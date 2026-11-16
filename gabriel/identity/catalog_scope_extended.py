"""Bounded relationship reviews for the remaining incident-scope catalog."""

from __future__ import annotations

from collections import Counter, defaultdict
from datetime import datetime


VERSION = "gabriel-scope-extended-catalog-v1"
MAX_FINDINGS = 4
YES_NO = {"yes", "no", "unknown"}
SKILL_RELATIONS = {
    "reconstruct_attack_chain": "attack_chain",
    "reconcile_hostname_ip_history": "hostname_ip",
    "map_compromised_account_relationships": "account_relationship",
    "identify_initial_access_vector": "initial_access",
    "analyze_incident_entry_point": "entry_point",
    "determine_data_exposure_scope": "data_exposure",
    "identify_affected_business_services": "business_service",
    "map_network_segment_impact": "network_segment",
    "map_cloud_resource_impact": "cloud_resource",
    "assess_third_party_access_impact": "third_party",
    "identify_persistence_footprint": "persistence",
    "estimate_attacker_dwell_time": "dwell_time",
    "determine_incident_boundary": "incident_boundary",
    "analyze_multi_tenant_isolation": "tenant_isolation",
}
SKILLS = {name: "incident_scoping" for name in SKILL_RELATIONS}
SCHEMAS = {
    "scope_relation_v2": {
        "check": frozenset(SKILLS),
        "relation": frozenset(SKILL_RELATIONS.values()),
        "target_entity": "uuid",
        "state": {"observed", "absent", "unknown"},
        "first_seen": "time",
        "last_seen": "time",
        "clock_state": {"verified", "unverified", "conflicting", "unknown"},
        "source_binding": YES_NO,
        "tenant_binding": YES_NO,
    },
}
ROLE_TYPES = {"incident_scoping": {"scope_relation_v2"}}


def _at(value):
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def validate_fact(fact):
    from gabriel.identity.specialist_analysis import require
    data = fact["data"]
    require(fact["entity_id"] is not None, "scope_relation_source_required")
    require(data["relation"] == SKILL_RELATIONS[data["check"]], "scope_relation_kind_mismatch")
    require(_at(data["first_seen"]) <= _at(data["last_seen"]) <= _at(fact["event_time"]),
            "invalid_scope_relation_interval")


def evaluate(name, document, *, verified_refs=None):
    from gabriel.identity.specialist_analysis import validate_document
    if name not in SKILLS:
        raise ValueError("unknown_scope_extended_skill")
    validate_document(document, document.get("case_id") if type(document) is dict else None)
    for fact in document["facts"]:
        if fact["type"] == "scope_relation_v2":
            validate_fact(fact)
    rows = [(fact, f"o{index}") for index, fact in enumerate(document["facts"], 1)
            if fact["type"] == "scope_relation_v2" and fact["data"]["check"] == name]
    grouped = defaultdict(list)
    for fact, ref in rows:
        grouped[(fact["entity_id"], fact["data"]["target_entity"])].append((fact, ref))
    findings = []
    for reports in grouped.values():
        states = {fact["data"]["state"] for fact, _ in reports}
        if "observed" in states and "absent" in states:
            status = "conflicting_assertions"
        elif states == {"absent"}:
            status = "reported_absent_unverified"
        elif "observed" in states:
            status = "reported_relationship_unverified"
        else:
            status = "unknown_relationship_state"
        findings.append({"status": status, "references": [ref for _, ref in reports[:3]]})
    findings.sort(key=lambda row: (row["status"] == "reported_relationship_unverified", row["references"]))
    counts = Counter(row["status"] for row in findings)
    intervals = [(_at(fact["data"]["last_seen"]) - _at(fact["data"]["first_seen"])).total_seconds()
                 for fact, _ in rows if fact["data"]["state"] == "observed"]
    return {
        "version": VERSION,
        "skill": name,
        "role": "incident_scoping",
        "status": "review_required" if rows else "no_applicable_role_facts",
        "supplied_fact_count": len(rows),
        "reported_relationship_count": len(grouped),
        "status_counts": dict(sorted(counts.items())),
        "maximum_reported_interval_seconds": int(max(intervals)) if intervals else 0,
        "unverified_clock_count": sum(fact["data"]["clock_state"] != "verified" for fact, _ in rows),
        "unbound_source_count": sum(fact["data"]["source_binding"] != "yes" for fact, _ in rows),
        "unbound_tenant_count": sum(fact["data"]["tenant_binding"] != "yes" for fact, _ in rows),
        "findings": findings[:MAX_FINDINGS],
        "omitted_finding_count": max(0, len(findings) - MAX_FINDINGS),
        "source_authenticity": "unverified",
        "entity_identity_verified": False,
        "source_clocks_verified": False,
        "scope_complete": False,
        "attack_status": "unknown",
        "confidence": "unqualified",
        "external_actions_authorized": False,
        "external_action_performed": False,
        "model_used": False,
        "requires_analyst_review": True,
    }
