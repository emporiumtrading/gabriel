"""Bounded response-planning and recovery-learning reviews.

The kernels consume only case-bound assertions.  They never execute a response,
change access, restore a system, accept risk, close an incident, or imply that a
reported approval is sufficient authority for a current action.
"""
from collections import Counter, defaultdict
from datetime import datetime


RESPONSE_TARGET_SKILLS = {
    'recommend_endpoint_isolation': 'endpoint_isolate',
    'plan_account_suspension': 'account_suspend',
    'coordinate_credential_rotation': 'credential_rotate',
    'recommend_domain_blocking': 'domain_block',
    'recommend_firewall_containment': 'firewall_rule',
    'recommend_network_segmentation': 'segment_network',
    'coordinate_malware_quarantine': 'malware_quarantine',
    'plan_vulnerability_remediation': 'vulnerability_remediate',
    'prioritize_patch_deployment': 'patch_deploy',
}
RECOVERY_VALIDATION_SKILLS = {
    'verify_system_restoration': 'restore',
    'revalidate_endpoint_security': 'endpoint_security',
    'revalidate_identity_after_compromise': 'identity',
    'verify_persistence_removal': 'persistence',
    'reassess_post_recovery_vulnerabilities': 'vulnerability',
    'verify_business_service_availability': 'service_availability',
}
LEARNING_SKILLS = {
    'analyze_incident_lessons': 'lesson',
    'analyze_root_cause': 'root_cause',
    'identify_recurring_incident_patterns': 'recurring_pattern',
    'reassess_security_control_effectiveness': 'control',
    'recommend_detection_rule_improvements': 'detection',
    'improve_threat_hunting_playbook': 'hunt',
}
SKILLS = {
    'plan_incident_response': 'response_remediation',
    **{name: 'response_remediation' for name in RESPONSE_TARGET_SKILLS},
    'assess_emergency_change_impact': 'response_remediation',
    'assess_business_continuity_impact': 'response_remediation',
    'validate_response_authorization': 'response_remediation',
    'coordinate_incident_escalation': 'response_remediation',
    'assess_disaster_recovery_readiness': 'recovery_learning',
    'verify_backup_integrity': 'recovery_learning',
    'assess_backup_immutability': 'recovery_learning',
    **{name: 'recovery_learning' for name in RECOVERY_VALIDATION_SKILLS},
    **{name: 'recovery_learning' for name in LEARNING_SKILLS},
    'map_recovery_dependencies': 'recovery_learning',
    'track_residual_risk_acceptance': 'recovery_learning',
}

YES_NO = {'yes', 'no', 'unknown'}
IMPACT = {'none', 'low', 'medium', 'high', 'critical', 'unknown'}
SCHEMAS = {
    'response_plan': {
        'plan_id': 'uuid', 'scenario': {'ransomware', 'credential_misuse', 'phishing', 'cloud_change', 'other'},
        'phase': {'containment', 'eradication', 'recovery', 'combined'},
        'owner': {'assigned', 'unassigned', 'unknown'}, 'dependencies': {'ready', 'not_ready', 'unknown'},
        'rollback': {'ready', 'not_ready', 'not_applicable', 'unknown'}, 'valid_until': 'time',
    },
    'response_target': {
        'action': set(RESPONSE_TARGET_SKILLS.values()), 'authority': YES_NO, 'business_impact': IMPACT,
        'dependencies': {'ready', 'not_ready', 'unknown'},
        'rollback': {'ready', 'not_ready', 'not_applicable', 'unknown'}, 'valid_until': 'time',
    },
    'change_impact': {
        'change_id': 'uuid', 'availability': IMPACT, 'data_integrity': IMPACT, 'recovery': IMPACT,
        'assessed': YES_NO, 'valid_until': 'time',
    },
    'service_continuity': {
        'service_id': 'uuid', 'criticality': {'low', 'medium', 'high', 'critical', 'unknown'},
        'state': {'available', 'degraded', 'unavailable', 'unknown'},
        'dependencies': {'ready', 'not_ready', 'unknown'}, 'valid_until': 'time',
    },
    'response_authorization': {
        'action_id': 'uuid', 'decision': {'approved', 'denied', 'revoked', 'unknown'},
        'approver': {'incident_commander', 'service_owner', 'security_engineer', 'change_manager', 'unknown'},
        'scope_digest': 'digest', 'valid_until': 'time',
    },
    'response_escalation': {
        'escalation_id': 'uuid', 'severity': {'low', 'medium', 'high', 'critical', 'unknown'},
        'recipient': {'incident_commander', 'service_owner', 'legal', 'executive', 'unknown'},
        'state': {'queued', 'acknowledged', 'rejected', 'unknown'}, 'due_at': 'time',
    },
    'recovery_readiness': {
        'plan_digest': 'digest',
        'check': {'owner', 'runbook', 'dependency', 'restore_test', 'communications'},
        'result': {'pass', 'fail', 'unknown'}, 'baseline': {'current', 'stale', 'unknown'},
        'valid_until': 'time',
    },
    'backup_assurance': {
        'backup_id': 'uuid', 'check': {'integrity', 'immutability', 'restore_test'},
        'result': {'pass', 'fail', 'unknown'}, 'generated_at': 'time', 'valid_until': 'time',
    },
    'recovery_validation': {
        'recovery_id': 'uuid', 'check': set(RECOVERY_VALIDATION_SKILLS.values()),
        'result': {'pass', 'fail', 'unknown'}, 'baseline': {'current', 'stale', 'unknown'},
        'valid_until': 'time',
    },
    'learning_finding': {
        'finding_id': 'uuid', 'category': set(LEARNING_SKILLS.values()),
        'support': {'supported', 'unsupported', 'conflicting', 'unknown'},
        'source_count': int, 'valid_until': 'time',
    },
    'recovery_dependency': {
        'dependency_id': 'uuid', 'kind': {'identity', 'network', 'data', 'application', 'security_control'},
        'state': {'available', 'unavailable', 'degraded', 'unknown'}, 'tested': YES_NO,
        'valid_until': 'time',
    },
    'residual_risk': {
        'risk_id': 'uuid', 'severity': {'low', 'medium', 'high', 'critical', 'unknown'},
        'decision': {'accepted', 'rejected', 'expired', 'unknown'},
        'owner': {'assigned', 'unassigned', 'unknown'}, 'valid_until': 'time',
    },
}
ROLE_TYPES = {
    'response_remediation': {
        'response_plan', 'response_target', 'change_impact', 'service_continuity',
        'response_authorization', 'response_escalation',
    },
    'recovery_learning': {
        'recovery_readiness', 'backup_assurance', 'recovery_validation', 'learning_finding',
        'recovery_dependency', 'residual_risk',
    },
}


def _at(value):
    return datetime.fromisoformat(value.replace('Z', '+00:00'))


def validate_fact(fact):
    """Enforce chronology that is specific to response and recovery assertions."""
    from gabriel.identity.specialist_analysis import require

    require(fact['entity_id'] is not None, 'response_recovery_entity_alias_required')
    data = fact['data']
    observed = _at(fact['event_time'])
    if 'generated_at' in data:
        require(_at(data['generated_at']) <= observed, 'backup_generated_after_observation')
    if 'valid_until' in data:
        require(observed < _at(data['valid_until']), 'expired_at_response_recovery_observation')


def _selected(document, role):
    admitted = ROLE_TYPES[role]
    return [(fact, 'o' + str(index)) for index, fact in enumerate(document['facts'], 1)
            if fact['type'] in admitted]


def _latest_groups(rows, kind, key):
    grouped = defaultdict(list)
    for fact, ref in rows:
        if fact['type'] == kind:
            grouped[(fact['entity_id'], fact['data'][key])].append((fact, ref))
    for reports in grouped.values():
        instant = max(_at(fact['event_time']) for fact, _ in reports)
        yield [(fact, ref) for fact, ref in reports if _at(fact['event_time']) == instant]


def _groups(rows, kind, key):
    grouped = defaultdict(list)
    for fact, ref in rows:
        if fact['type'] == kind:
            grouped[(fact['entity_id'], fact['data'][key])].append((fact, ref))
    yield from grouped.values()


def _latest(reports):
    instant = max(_at(fact['event_time']) for fact, _ in reports)
    return [(fact, ref) for fact, ref in reports if _at(fact['event_time']) == instant]


def _finding(status, reports, **values):
    return dict(status=status, refs=[ref for _, ref in reports[:3]], **values)


def _response_plan(rows, now):
    findings = []
    for reports in _latest_groups(rows, 'response_plan', 'plan_id'):
        values = {tuple(sorted(fact['data'].items())) for fact, _ in reports}
        data = reports[0][0]['data']
        if len(values) > 1:
            status = 'conflicting_plan_assertions'
        elif _at(data['valid_until']) <= now:
            status = 'stale_plan'
        elif data['owner'] != 'assigned':
            status = 'owner_not_confirmed'
        elif data['dependencies'] != 'ready' or data['rollback'] in {'not_ready', 'unknown'}:
            status = 'plan_prerequisites_incomplete'
        else:
            status = 'reported_plan_ready_for_engineer_review'
        findings.append(_finding(status, reports, scenario=data['scenario'], phase=data['phase']))
    return findings


def _target(rows, now, action):
    findings = []
    for reports in _latest_groups(rows, 'response_target', 'action'):
        data = reports[0][0]['data']
        if data['action'] != action:
            continue
        assertions = {tuple(sorted(fact['data'].items())) for fact, _ in reports}
        if len(assertions) > 1:
            status = 'conflicting_target_assertions'
        elif _at(data['valid_until']) <= now:
            status = 'stale_target_assessment'
        elif data['authority'] != 'yes':
            status = 'authority_not_confirmed'
        elif data['dependencies'] != 'ready':
            status = 'dependencies_not_ready'
        elif data['rollback'] in {'not_ready', 'unknown'}:
            status = 'rollback_not_ready'
        elif data['business_impact'] in {'high', 'critical', 'unknown'}:
            status = 'impact_requires_explicit_review'
        else:
            status = 'candidate_for_engineer_review'
        findings.append(_finding(status, reports, action=action, business_impact=data['business_impact']))
    return findings


def _change_impact(rows, now):
    findings = []
    for reports in _latest_groups(rows, 'change_impact', 'change_id'):
        data = reports[0][0]['data']
        assertions = {tuple(sorted(fact['data'].items())) for fact, _ in reports}
        impacts = [data['availability'], data['data_integrity'], data['recovery']]
        if len(assertions) > 1:
            status = 'conflicting_impact_assertions'
        elif _at(data['valid_until']) <= now:
            status = 'stale_impact_assessment'
        elif data['assessed'] != 'yes' or 'unknown' in impacts:
            status = 'impact_assessment_incomplete'
        elif any(value in {'high', 'critical'} for value in impacts):
            status = 'reported_material_impact'
        else:
            status = 'reported_limited_impact_unverified'
        order = {'none': 0, 'low': 1, 'medium': 2, 'high': 3, 'critical': 4, 'unknown': 5}
        findings.append(_finding(status, reports,
                                 maximum_reported_impact=max(impacts, key=order.__getitem__)))
    return findings


def _continuity(rows, now):
    findings = []
    for reports in _latest_groups(rows, 'service_continuity', 'service_id'):
        data = reports[0][0]['data']
        assertions = {tuple(sorted(fact['data'].items())) for fact, _ in reports}
        if len(assertions) > 1:
            status = 'conflicting_service_assertions'
        elif _at(data['valid_until']) <= now:
            status = 'stale_service_assessment'
        elif data['state'] in {'unavailable', 'degraded'} and data['criticality'] in {'high', 'critical'}:
            status = 'reported_material_continuity_impact'
        elif data['state'] == 'unknown' or data['dependencies'] != 'ready':
            status = 'continuity_evidence_incomplete'
        else:
            status = 'reported_service_available_unverified'
        findings.append(_finding(status, reports, criticality=data['criticality'], reported_state=data['state']))
    return findings


def _authorization(rows, now):
    findings = []
    for reports in _latest_groups(rows, 'response_authorization', 'action_id'):
        data = reports[0][0]['data']
        assertions = {tuple(sorted(fact['data'].items())) for fact, _ in reports}
        if len(assertions) > 1:
            status = 'conflicting_authorization_assertions'
        elif _at(data['valid_until']) <= now:
            status = 'expired_authorization_assertion'
        elif data['decision'] == 'approved' and data['approver'] != 'unknown':
            status = 'reported_approval_requires_current_scope_review'
        else:
            status = 'reported_' + data['decision']
        findings.append(_finding(status, reports, decision=data['decision'], approver=data['approver']))
    return findings


def _escalation(rows, now):
    findings = []
    for reports in _latest_groups(rows, 'response_escalation', 'escalation_id'):
        data = reports[0][0]['data']
        assertions = {tuple(sorted(fact['data'].items())) for fact, _ in reports}
        if len(assertions) > 1:
            status = 'conflicting_escalation_assertions'
        elif data['state'] == 'queued' and _at(data['due_at']) < now:
            status = 'reported_escalation_overdue'
        elif data['state'] == 'acknowledged':
            status = 'reported_acknowledged_unverified'
        else:
            status = 'reported_' + data['state']
        findings.append(_finding(status, reports, severity=data['severity'], recipient=data['recipient']))
    return findings


def _readiness(rows, now):
    required = {'owner', 'runbook', 'dependency', 'restore_test', 'communications'}
    findings = []
    for reports in _groups(rows, 'recovery_readiness', 'plan_digest'):
        by_check = defaultdict(list)
        for fact, ref in reports:
            by_check[fact['data']['check']].append((fact, ref))
        current = [row for values in by_check.values() for row in _latest(values)]
        checks = defaultdict(set)
        for fact, _ in current:
            data = fact['data']
            checks[data['check']].add((data['result'], data['baseline']))
        missing = sorted(required - checks.keys())
        if any(len(values) > 1 for values in checks.values()):
            status = 'conflicting_readiness_assertions'
        elif any(result == 'fail' for values in checks.values() for result, _ in values):
            status = 'reported_readiness_failure'
        elif missing or any(result == 'unknown' or baseline != 'current'
                            for values in checks.values() for result, baseline in values):
            status = 'readiness_evidence_incomplete'
        elif any(_at(fact['data']['valid_until']) <= now for fact, _ in current):
            status = 'stale_readiness_evidence'
        else:
            status = 'reported_ready_unverified'
        findings.append(_finding(status, current, missing_checks=missing))
    return findings


def _backup(rows, now, check):
    findings = []
    for reports in _groups(rows, 'backup_assurance', 'backup_id'):
        selected = [(fact, ref) for fact, ref in reports if fact['data']['check'] == check]
        if not selected:
            continue
        selected = _latest(selected)
        values = {fact['data']['result'] for fact, _ in selected}
        data = selected[0][0]['data']
        if len(values) > 1:
            status = 'conflicting_backup_assertions'
        elif _at(data['valid_until']) <= now:
            status = 'stale_backup_evidence'
        elif values == {'pass'}:
            status = 'reported_check_passed_unverified'
        elif values == {'fail'}:
            status = 'reported_check_failed'
        else:
            status = 'backup_check_unknown'
        findings.append(_finding(status, selected, check=check))
    return findings


def _recovery_validation(rows, now, check):
    findings = []
    for reports in _groups(rows, 'recovery_validation', 'recovery_id'):
        selected = [(fact, ref) for fact, ref in reports if fact['data']['check'] == check]
        if not selected:
            continue
        selected = _latest(selected)
        states = {(fact['data']['result'], fact['data']['baseline']) for fact, _ in selected}
        data = selected[0][0]['data']
        if len(states) > 1:
            status = 'conflicting_validation_assertions'
        elif _at(data['valid_until']) <= now:
            status = 'stale_validation_evidence'
        elif states == {('pass', 'current')}:
            status = 'reported_validation_passed_unverified'
        elif any(result == 'fail' for result, _ in states):
            status = 'reported_validation_failed'
        else:
            status = 'validation_evidence_incomplete'
        findings.append(_finding(status, selected, check=check))
    return findings


def _learning(rows, now, category):
    findings = []
    for reports in _groups(rows, 'learning_finding', 'finding_id'):
        selected = [(fact, ref) for fact, ref in reports if fact['data']['category'] == category]
        if not selected:
            continue
        selected = _latest(selected)
        states = {fact['data']['support'] for fact, _ in selected}
        data = selected[0][0]['data']
        if len(states) > 1:
            status = 'conflicting_learning_assertions'
        elif _at(data['valid_until']) <= now:
            status = 'stale_learning_evidence'
        elif states == {'supported'} and data['source_count'] >= 2:
            status = 'reported_supported_requires_analyst_review'
        elif states == {'supported'}:
            status = 'single_source_support_only'
        else:
            status = 'reported_' + next(iter(states))
        findings.append(_finding(status, selected, category=category, reported_source_count=data['source_count']))
    return findings


def _dependencies(rows, now):
    findings = []
    for reports in _latest_groups(rows, 'recovery_dependency', 'dependency_id'):
        data = reports[0][0]['data']
        assertions = {tuple(sorted(fact['data'].items())) for fact, _ in reports}
        if len(assertions) > 1:
            status = 'conflicting_dependency_assertions'
        elif _at(data['valid_until']) <= now:
            status = 'stale_dependency_evidence'
        elif data['state'] in {'unavailable', 'degraded'}:
            status = 'reported_dependency_' + data['state']
        elif data['tested'] != 'yes' or data['state'] == 'unknown':
            status = 'dependency_not_verified'
        else:
            status = 'reported_dependency_available_unverified'
        findings.append(_finding(status, reports, kind=data['kind'], reported_state=data['state']))
    return findings


def _risk(rows, now):
    findings = []
    for reports in _latest_groups(rows, 'residual_risk', 'risk_id'):
        data = reports[0][0]['data']
        assertions = {tuple(sorted(fact['data'].items())) for fact, _ in reports}
        if len(assertions) > 1:
            status = 'conflicting_risk_assertions'
        elif _at(data['valid_until']) <= now or data['decision'] == 'expired':
            status = 'expired_risk_decision'
        elif data['decision'] == 'accepted' and data['owner'] == 'assigned':
            status = 'reported_acceptance_requires_current_authority_review'
        elif data['decision'] == 'accepted':
            status = 'acceptance_owner_not_confirmed'
        else:
            status = 'reported_' + data['decision']
        findings.append(_finding(status, reports, severity=data['severity'], decision=data['decision']))
    return findings


def _result(name, findings):
    counts = Counter(finding['status'] for finding in findings)
    findings.sort(key=lambda finding: (finding['status'], finding['refs']))
    return {
        'version': 'gabriel-response-recovery-v1', 'skill': name, 'role': SKILLS[name],
        'status': 'review_required' if findings else 'no_applicable_role_facts',
        'reported_item_count': len(findings), 'status_counts': dict(sorted(counts.items())),
        'findings': findings[:4], 'omitted_finding_count': max(0, len(findings) - 4),
        'source_authenticity': 'unverified', 'confidence': 'unqualified',
        'incident_status': 'unknown', 'external_actions_authorized': False, 'model_used': False,
        'requires_analyst_review': True, 'execution_performed': False,
        'incident_closure_authorized': False,
        'limitations': ['supplied_assertions_only', 'no_live_verification', 'current_authority_not_established'],
    }


def evaluate(name, document, *, verified_refs=None):
    """Evaluate a registered skill against an already case-bound fact packet."""
    from gabriel.identity.specialist_analysis import validate_document

    if name not in SKILLS:
        raise ValueError('unknown_response_recovery_skill')
    validate_document(document, document.get('case_id') if type(document) is dict else None)
    for fact in document['facts']:
        if fact['type'] in SCHEMAS:
            validate_fact(fact)
    rows = _selected(document, SKILLS[name])
    now = _at(document['as_of'])
    if name == 'plan_incident_response':
        findings = _response_plan(rows, now)
    elif name in RESPONSE_TARGET_SKILLS:
        findings = _target(rows, now, RESPONSE_TARGET_SKILLS[name])
    elif name == 'assess_emergency_change_impact':
        findings = _change_impact(rows, now)
    elif name == 'assess_business_continuity_impact':
        findings = _continuity(rows, now)
    elif name == 'validate_response_authorization':
        findings = _authorization(rows, now)
    elif name == 'coordinate_incident_escalation':
        findings = _escalation(rows, now)
    elif name == 'assess_disaster_recovery_readiness':
        findings = _readiness(rows, now)
    elif name == 'verify_backup_integrity':
        findings = _backup(rows, now, 'integrity')
    elif name == 'assess_backup_immutability':
        findings = _backup(rows, now, 'immutability')
    elif name in RECOVERY_VALIDATION_SKILLS:
        findings = _recovery_validation(rows, now, RECOVERY_VALIDATION_SKILLS[name])
    elif name in LEARNING_SKILLS:
        findings = _learning(rows, now, LEARNING_SKILLS[name])
    elif name == 'map_recovery_dependencies':
        findings = _dependencies(rows, now)
    else:
        findings = _risk(rows, now)
    return _result(name, findings)
