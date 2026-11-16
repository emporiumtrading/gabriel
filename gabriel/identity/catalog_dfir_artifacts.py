"""Evidence-bounded reviews for supplied forensic-artifact assertions."""

from __future__ import annotations

from collections import Counter, defaultdict


VERSION = "gabriel-dfir-artifact-catalog-v1"
MAX_FINDINGS = 4
YES_NO = {"yes", "no", "unknown"}
ARTIFACT_KINDS = {
    "windows_event", "linux_system", "macos_system", "browser_history",
    "email_header", "file_metadata", "deleted_file", "memory_dump",
    "disk_image", "malware", "registry", "prefetch", "amcache_shimcache",
    "powershell_history", "authentication", "cloud_audit", "container",
    "forensic_timeline", "legal_hold",
}

SKILL_KINDS = {
    "analyze_windows_event_artifacts": "windows_event",
    "analyze_linux_system_artifacts": "linux_system",
    "analyze_macos_forensic_artifacts": "macos_system",
    "examine_browser_history_artifacts": "browser_history",
    "analyze_email_headers": "email_header",
    "examine_file_metadata": "file_metadata",
    "assess_deleted_file_recovery": "deleted_file",
    "coordinate_memory_dump_analysis": "memory_dump",
    "verify_disk_image_integrity": "disk_image",
    "examine_malware_artifacts": "malware",
    "examine_registry_artifacts": "registry",
    "analyze_prefetch_execution_artifacts": "prefetch",
    "analyze_amcache_shimcache": "amcache_shimcache",
    "examine_powershell_history": "powershell_history",
    "reconstruct_authentication_artifacts": "authentication",
    "analyze_cloud_audit_trails": "cloud_audit",
    "review_container_forensic_collection": "container",
    "cross_validate_forensic_timeline": "forensic_timeline",
    "track_legal_hold_preservation": "legal_hold",
}
SKILLS = {name: "dfir_evidence" for name in SKILL_KINDS}
SCHEMAS = {
    "forensic_artifact": {
        "analysis": frozenset(SKILLS),
        "artifact_digest": "digest",
        "artifact_kind": ARTIFACT_KINDS,
        "state": {"present", "absent", "partial", "unknown"},
        "integrity": {"match", "mismatch", "unknown"},
        "custody": {"complete", "gap", "unknown"},
        "record_count": "zero_to_billion",
        "clock_state": {"verified", "unverified", "conflicting", "unknown"},
        "authorized": YES_NO,
    },
}
ROLE_TYPES = {"dfir_evidence": {"forensic_artifact"}}


def validate_fact(fact):
    from gabriel.identity.specialist_analysis import require
    require(fact["entity_id"] is not None, "forensic_artifact_entity_alias_required")
    data = fact["data"]
    require(data["artifact_kind"] == SKILL_KINDS[data["analysis"]], "forensic_artifact_kind_mismatch")


def _rows(name, document):
    return [(fact, f"o{index}") for index, fact in enumerate(document["facts"], 1)
            if fact["type"] == "forensic_artifact" and fact["data"]["analysis"] == name]


def evaluate(name, document, *, verified_refs=None):
    from gabriel.identity.specialist_analysis import validate_document
    if name not in SKILLS:
        raise ValueError("unknown_dfir_artifact_skill")
    validate_document(document, document.get("case_id") if type(document) is dict else None)
    for fact in document["facts"]:
        if fact["type"] == "forensic_artifact":
            validate_fact(fact)
    rows = _rows(name, document)
    grouped = defaultdict(list)
    for fact, ref in rows:
        grouped[(fact["entity_id"], fact["data"]["artifact_digest"])].append((fact, ref))
    findings = []
    for reports in grouped.values():
        assertions = {(fact["data"]["state"], fact["data"]["integrity"], fact["data"]["custody"])
                      for fact, _ in reports}
        states = {fact["data"]["state"] for fact, _ in reports}
        if len(assertions) > 1 and ("present" in states and "absent" in states):
            status = "conflicting_assertions"
        elif any(fact["data"]["integrity"] == "mismatch" for fact, _ in reports):
            status = "reported_integrity_mismatch"
        elif any(fact["data"]["custody"] == "gap" for fact, _ in reports):
            status = "reported_custody_gap"
        elif any(fact["data"]["state"] in {"partial", "unknown"} for fact, _ in reports):
            status = "incomplete_artifact_assertion"
        else:
            status = "reported_artifact_available_unverified"
        findings.append({"status": status, "references": [ref for _, ref in reports[:3]]})
    findings.sort(key=lambda row: (row["status"] == "reported_artifact_available_unverified", row["references"]))
    status_counts = Counter(row["status"] for row in findings)
    return {
        "version": VERSION,
        "skill": name,
        "role": "dfir_evidence",
        "status": "review_required" if rows else "no_applicable_role_facts",
        "supplied_fact_count": len(rows),
        "reported_artifact_count": len(grouped),
        "reported_record_count": sum(fact["data"]["record_count"] for fact, _ in rows),
        "status_counts": dict(sorted(status_counts.items())),
        "findings": findings[:MAX_FINDINGS],
        "omitted_finding_count": max(0, len(findings) - MAX_FINDINGS),
        "source_authenticity": "unverified",
        "artifact_identity_verified": False,
        "artifact_bytes_inspected": False,
        "source_clocks_verified": False,
        "coverage_complete": False,
        "incident_status": "unknown",
        "confidence": "unqualified",
        "external_actions_authorized": False,
        "external_action_performed": False,
        "model_used": False,
        "requires_analyst_review": True,
    }
