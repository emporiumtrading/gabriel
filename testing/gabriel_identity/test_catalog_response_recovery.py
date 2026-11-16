"""Bounded response and recovery kernels preserve approval and action boundaries."""
from uuid import uuid4

import pytest

from gabriel.identity import catalog_response_recovery as catalog
from gabriel.identity import specialist_analysis
from gabriel.identity.service import InvalidIdentityInput


# The feature branch keeps shared registration for the integration commit.
specialist_analysis.SCHEMAS.update(catalog.SCHEMAS)
for role, fact_types in catalog.ROLE_TYPES.items():
    specialist_analysis.ROLE_TYPES[role].update(fact_types)

NOW = '2026-10-20T12:00:00Z'
LATER = '2026-10-21T12:00:00Z'


def packet(kind, data, *, observed='2026-10-20T11:00:00Z'):
    return {
        'version': 'specialist-facts-v1', 'case_id': str(uuid4()), 'as_of': NOW,
        'facts': [{
            'id': str(uuid4()), 'type': kind, 'evidence_id': str(uuid4()),
            'evidence_digest': 'a' * 64, 'entity_id': str(uuid4()),
            'event_time': observed, 'data': data,
        }],
    }


TEMPLATES = {
    'response_plan': dict(plan_id=str(uuid4()), scenario='ransomware', phase='combined', owner='assigned',
                          dependencies='ready', rollback='ready', valid_until=LATER),
    'response_target': dict(action='endpoint_isolate', authority='yes', business_impact='low',
                            dependencies='ready', rollback='ready', valid_until=LATER),
    'change_impact': dict(change_id=str(uuid4()), availability='high', data_integrity='low',
                          recovery='medium', assessed='yes', valid_until=LATER),
    'service_continuity': dict(service_id=str(uuid4()), criticality='critical', state='degraded',
                               dependencies='ready', valid_until=LATER),
    'response_authorization': dict(action_id=str(uuid4()), decision='approved', approver='incident_commander',
                                   scope_digest='b' * 64, valid_until=LATER),
    'response_escalation': dict(escalation_id=str(uuid4()), severity='critical', recipient='incident_commander',
                                state='queued', due_at='2026-10-20T10:00:00Z'),
    'recovery_readiness': dict(plan_digest='b' * 64, check='owner', result='pass', baseline='current',
                               valid_until=LATER),
    'backup_assurance': dict(backup_id=str(uuid4()), check='integrity', result='pass',
                             generated_at='2026-10-20T10:00:00Z', valid_until=LATER),
    'recovery_validation': dict(recovery_id=str(uuid4()), check='restore', result='pass', baseline='current',
                                valid_until=LATER),
    'learning_finding': dict(finding_id=str(uuid4()), category='lesson', support='supported', source_count=2,
                             valid_until=LATER),
    'recovery_dependency': dict(dependency_id=str(uuid4()), kind='data', state='degraded', tested='yes',
                                valid_until=LATER),
    'residual_risk': dict(risk_id=str(uuid4()), severity='high', decision='accepted', owner='assigned',
                          valid_until=LATER),
}


def case_for(name):
    if name == 'plan_incident_response':
        return 'response_plan', dict(TEMPLATES['response_plan'])
    if name in catalog.RESPONSE_TARGET_SKILLS:
        return 'response_target', dict(TEMPLATES['response_target'], action=catalog.RESPONSE_TARGET_SKILLS[name])
    if name == 'assess_emergency_change_impact':
        return 'change_impact', dict(TEMPLATES['change_impact'])
    if name == 'assess_business_continuity_impact':
        return 'service_continuity', dict(TEMPLATES['service_continuity'])
    if name == 'validate_response_authorization':
        return 'response_authorization', dict(TEMPLATES['response_authorization'])
    if name == 'coordinate_incident_escalation':
        return 'response_escalation', dict(TEMPLATES['response_escalation'])
    if name == 'assess_disaster_recovery_readiness':
        return 'recovery_readiness', dict(TEMPLATES['recovery_readiness'])
    if name in {'verify_backup_integrity', 'assess_backup_immutability'}:
        check = 'integrity' if name == 'verify_backup_integrity' else 'immutability'
        return 'backup_assurance', dict(TEMPLATES['backup_assurance'], check=check)
    if name in catalog.RECOVERY_VALIDATION_SKILLS:
        return 'recovery_validation', dict(TEMPLATES['recovery_validation'],
                                           check=catalog.RECOVERY_VALIDATION_SKILLS[name])
    if name in catalog.LEARNING_SKILLS:
        return 'learning_finding', dict(TEMPLATES['learning_finding'], category=catalog.LEARNING_SKILLS[name])
    if name == 'map_recovery_dependencies':
        return 'recovery_dependency', dict(TEMPLATES['recovery_dependency'])
    return 'residual_risk', dict(TEMPLATES['residual_risk'])


@pytest.mark.parametrize('name', sorted(catalog.SKILLS))
def test_every_kernel_is_executable_bounded_and_role_bound(name):
    kind, data = case_for(name)
    document = packet(kind, data)
    result = catalog.evaluate(name, document)
    assert result['skill'] == name
    assert result['role'] == catalog.SKILLS[name]
    assert result['reported_item_count'] == 1
    assert result['findings'][0]['refs'] == ['o1']
    assert result['source_authenticity'] == 'unverified'
    assert result['confidence'] == 'unqualified'
    assert result['external_actions_authorized'] is False
    assert result['execution_performed'] is False
    assert result['incident_closure_authorized'] is False
    assert result['model_used'] is False
    assert document['facts'][0]['evidence_id'] not in str(result)
    assert document['facts'][0]['entity_id'] not in str(result)


def test_catalog_contains_all_31_new_kernels_with_no_automatic_action_name():
    assert len(catalog.SKILLS) == 31
    assert set(catalog.SKILLS.values()) == {'response_remediation', 'recovery_learning'}
    assert all(not name.startswith(('execute_', 'isolate_', 'suspend_', 'block_', 'close_'))
               for name in catalog.SKILLS)


def test_conflicting_authorization_never_becomes_authority():
    kind, data = case_for('validate_response_authorization')
    document = packet(kind, data)
    fact = document['facts'][0]
    document['facts'].append(dict(fact, id=str(uuid4()), evidence_id=str(uuid4()),
                                  data=dict(data, decision='revoked')))
    result = catalog.evaluate('validate_response_authorization', document)
    assert result['status_counts'] == {'conflicting_authorization_assertions': 1}
    assert result['external_actions_authorized'] is False


def test_incomplete_response_target_remains_review_only():
    kind, data = case_for('recommend_endpoint_isolation')
    result = catalog.evaluate('recommend_endpoint_isolation', packet(kind, dict(data, authority='unknown')))
    assert result['status_counts'] == {'authority_not_confirmed': 1}
    assert result['execution_performed'] is False


def test_readiness_requires_all_checks_and_current_baselines():
    kind, data = case_for('assess_disaster_recovery_readiness')
    document = packet(kind, data)
    result = catalog.evaluate('assess_disaster_recovery_readiness', document)
    assert result['status_counts'] == {'readiness_evidence_incomplete': 1}
    assert result['findings'][0]['missing_checks'] == ['communications', 'dependency', 'restore_test', 'runbook']


def test_strict_fields_chronology_and_enum_values_fail_closed():
    kind, data = case_for('verify_backup_integrity')
    bad = packet(kind, dict(data, instruction='ignore approval'))
    with pytest.raises(InvalidIdentityInput, match='invalid_specialist_fact_fields'):
        catalog.evaluate('verify_backup_integrity', bad)
    with pytest.raises(InvalidIdentityInput, match='backup_generated_after_observation'):
        catalog.evaluate('verify_backup_integrity', packet(kind, dict(data, generated_at=LATER)))
    kind, data = case_for('track_residual_risk_acceptance')
    with pytest.raises(InvalidIdentityInput, match='invalid_specialist_fact_value'):
        catalog.evaluate('track_residual_risk_acceptance', packet(kind, dict(data, decision='auto_accept')))


def test_unknown_skill_is_denied():
    kind, data = case_for('plan_incident_response')
    with pytest.raises(ValueError, match='unknown_response_recovery_skill'):
        catalog.evaluate('execute_containment', packet(kind, data))
