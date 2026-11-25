"""Deterministic cross-specialist synthesis for one completed Gabriel investigation.

This module combines bounded specialist metadata and preserves disagreement. It
does not call a model, infer source truth, authorize response, or replace the
individual specialist evidence records.
"""
from collections import Counter

from gabriel.identity.specialist_contracts import ROLES

VERSION = 'specialist-collaboration-v1'

# These are investigative handoffs, not permissions. They make the detective
# workflow explicit while allowing every role to contribute to one case.
HANDOFFS = {
    'telemetry_health': ('alert_triage', 'incident_scoping', 'threat_hunting', 'detection_engineering'),
    'alert_triage': ('incident_scoping', 'threat_hunting', 'dfir_evidence', 'response_remediation'),
    'incident_scoping': ('dfir_evidence', 'identity_access', 'cloud_supply_chain', 'response_remediation'),
    'threat_intelligence': ('threat_hunting', 'detection_engineering', 'exposure_vulnerability'),
    'threat_hunting': ('detection_engineering', 'dfir_evidence', 'identity_access', 'response_remediation'),
    'dfir_evidence': ('incident_scoping', 'detection_engineering', 'recovery_learning'),
    'detection_engineering': ('threat_hunting', 'exposure_vulnerability', 'response_remediation'),
    'exposure_vulnerability': ('cloud_supply_chain', 'detection_engineering', 'response_remediation'),
    'identity_access': ('incident_scoping', 'threat_hunting', 'response_remediation'),
    'cloud_supply_chain': ('exposure_vulnerability', 'dfir_evidence', 'recovery_learning'),
    'response_remediation': ('recovery_learning', 'incident_scoping'),
    'recovery_learning': ('response_remediation', 'detection_engineering'),
}

HANDOFF_REASONS = {
    'telemetry_health': 'coverage quality determines which later conclusions can be trusted',
    'alert_triage': 'reported urgency and benign alternatives guide scope and evidence review',
    'incident_scoping': 'affected entities and time bounds constrain specialist searches',
    'threat_intelligence': 'indicator validity informs hunting and detection priorities',
    'threat_hunting': 'behavior hypotheses require artifact, identity and response review',
    'dfir_evidence': 'artifact and custody limits constrain detection and recovery claims',
    'detection_engineering': 'rule gaps and false positives guide hunts and remediation',
    'exposure_vulnerability': 'reachability and exploitability context informs cloud and response review',
    'identity_access': 'authorization and session context constrain movement and response claims',
    'cloud_supply_chain': 'workload and component provenance informs exposure and recovery',
    'response_remediation': 'dependency and rollback checks inform recovery and scope decisions',
    'recovery_learning': 'restore and control evidence feeds response closure and future detections',
}


def _require(condition, message):
    if not condition:
        raise ValueError(message)


def _summary(role, result):
    _require(type(result) is dict, 'invalid_specialist_result')
    observations = result.get('observations', [])
    hypotheses = result.get('hypotheses', [])
    alternatives = result.get('alternatives', [])
    contradictions = result.get('contradictions', [])
    uncertainty = result.get('uncertainty', [])
    next_steps = result.get('next_steps', [])
    for value in (observations, hypotheses, alternatives, contradictions, uncertainty, next_steps):
        _require(type(value) is list, 'invalid_specialist_result_shape')
    urgency = result.get('urgency', 'review')
    incident_assessment = result.get('incident_assessment', 'abstained')
    attack_status = result.get('attack_status', 'unknown')
    confidence = result.get('confidence', 'unqualified')
    _require(urgency in {'review', 'urgent_review', 'visibility_gap'}, 'invalid_specialist_urgency')
    _require(incident_assessment in {'bounded_rule_review', 'abstained', 'not_performed'}, 'invalid_specialist_assessment')
    _require(attack_status == 'unknown', 'specialist_attack_authority_not_allowed')
    _require(confidence == 'unqualified', 'specialist_quality_claim_not_allowed')
    return dict(
        role=role,
        observation_count=len(observations),
        hypothesis_count=len(hypotheses),
        alternative_count=len(alternatives),
        contradiction_count=len(contradictions),
        uncertainty_count=len(uncertainty),
        next_step_count=len(next_steps),
        urgency=urgency,
        incident_assessment=incident_assessment,
        attack_status=attack_status,
        confidence=confidence,
    )


def synthesize(records):
    """Create a bounded case-level collaboration receipt from twelve role results."""
    _require(type(records) is list and 1 <= len(records) <= len(ROLES), 'invalid_specialist_records')
    by_role = {}
    for record in records:
        _require(type(record) is dict and set(record) == {'role', 'result'}, 'invalid_specialist_record')
        role, result = record['role'], record['result']
        _require(role in ROLES and role not in by_role, 'invalid_specialist_role_set')
        by_role[role] = _summary(role, result)
    missing = [role for role in ROLES if role not in by_role]
    summaries = [by_role[role] for role in ROLES if role in by_role]
    urgency_counts = Counter(row['urgency'] for row in summaries)
    assessment_counts = Counter(row['incident_assessment'] for row in summaries)
    attention = [row['role'] for row in summaries if row['urgency'] in {'urgent_review', 'visibility_gap'}]
    disagreements = []
    if len(assessment_counts) > 1:
        disagreements.append(dict(dimension='incident_assessment', values=dict(sorted(assessment_counts.items())),
                                  interpretation='Specialists received different bounded evidence or reached different local rule states; reconcile the cited records.'))
    if len(urgency_counts) > 1:
        disagreements.append(dict(dimension='urgency', values=dict(sorted(urgency_counts.items())),
                                  interpretation='Urgency differs by role; do not collapse the highest or lowest state without analyst review.'))
    handoffs = [
        dict(source=role, targets=list(HANDOFFS[role]), reason=HANDOFF_REASONS[role])
        for role in ROLES if role in by_role
    ]
    return dict(
        version=VERSION,
        status='complete' if not missing else 'partial',
        expected_role_count=len(ROLES),
        completed_role_count=len(summaries),
        missing_roles=missing,
        roles=summaries,
        attention_order=attention,
        urgency_counts=dict(sorted(urgency_counts.items())),
        assessment_counts=dict(sorted(assessment_counts.items())),
        disagreements=disagreements,
        handoffs=handoffs,
        source_authenticity='unverified',
        coverage='partial',
        confidence='unqualified',
        attack_status='unknown',
        model_used=False,
        external_actions_authorized=False,
        decision_made=False,
        limitations=[
            'This receipt summarizes bounded specialist outputs; it does not merge or rewrite their evidence.',
            'Disagreement is preserved and requires analyst reconciliation.',
            'A complete twelve-role receipt does not establish complete telemetry or source truth.',
            'No specialist can prove attacker absence, compromise, exploitability or a zero-day from this receipt.',
        ],
    )
