"""Behavioral checks for bounded intelligence and hunting catalog reviews."""

import json
from uuid import uuid4

import pytest

from gabriel.identity.catalog_intel_hunt import (
    HUNT_SKILLS,
    INTELLIGENCE_SKILLS,
    SKILLS,
    evaluate,
)
from gabriel.identity.service import InvalidIdentityInput


AS_OF = '2026-10-20T12:00:00Z'
OBSERVED = '2026-10-20T10:00:00Z'
LATER = '2026-10-21T12:00:00Z'


def fact(kind, data, *, entity=None, evidence=None, observed=OBSERVED):
    return {
        'id': str(uuid4()),
        'type': kind,
        'evidence_id': evidence or str(uuid4()),
        'evidence_digest': 'a' * 64,
        'entity_id': entity or str(uuid4()),
        'event_time': observed,
        'data': data,
    }


def packet(*facts):
    return {
        'version': 'specialist-facts-v1',
        'case_id': str(uuid4()),
        'as_of': AS_OF,
        'facts': list(facts),
    }


def metadata(value):
    case_id = value['case_id']
    refs = [{'ref': f'case/{case_id}', 'kind': 'case_record', 'record_id': case_id}]
    refs.extend({
        'ref': f"evidence/{row['evidence_id']}",
        'kind': 'evidence_metadata',
        'record_id': row['evidence_id'],
        'digest': row['evidence_digest'],
        'content_integrity': 'verified',
    } for row in value['facts'])
    return refs


def intelligence(topic, **changes):
    data = {
        'assessment_id': str(uuid4()),
        'topic': topic,
        'assertion': 'supports',
        'source_class': 'vendor',
        'confidence': 'medium',
        'effective_at': OBSERVED,
        'valid_until': LATER,
        'authorized': 'yes',
    }
    data.update(changes)
    return fact('intelligence_assertion', data)


def hunt(behavior, **changes):
    data = {
        'observation_id': str(uuid4()),
        'behavior': behavior,
        'signal': 'execution',
        'state': 'observed',
        'baseline': 'unexpected',
        'authorized': 'unknown',
        'correlation_id': str(uuid4()),
        'valid_until': LATER,
    }
    data.update(changes)
    return fact('hunt_observation', data)


def reviewed(name, *rows):
    value = packet(*rows)
    return evaluate(name, value, verified_refs=metadata(value))


def test_every_candidate_has_a_role_bound_executable_path():
    assert len(INTELLIGENCE_SKILLS) == len(HUNT_SKILLS) == 19
    assert len(SKILLS) == 38
    for name, topic in INTELLIGENCE_SKILLS.items():
        result = reviewed(name, intelligence(topic))
        assert result['skill'] == name
        assert result['role'] == 'threat_intelligence'
        assert result['reported_item_count'] == 1
        assert result['external_actions_authorized'] is False
        assert result['model_used'] is False
        assert result['confidence'] == 'unqualified'
    for name, behavior in HUNT_SKILLS.items():
        result = reviewed(name, hunt(behavior))
        assert result['skill'] == name
        assert result['role'] == 'threat_hunting'
        assert result['reported_item_count'] == 1
        assert result['external_actions_authorized'] is False
        assert result['attack_status'] == 'unknown'


def test_intelligence_conflict_and_source_count_are_preserved_without_attribution():
    name = 'profile_reported_threat_actor'
    first = intelligence(INTELLIGENCE_SKILLS[name])
    conflict = dict(first, id=str(uuid4()), evidence_id=str(uuid4()),
                    data=dict(first['data'], assertion='disputes'))
    result = reviewed(name, first, conflict)

    assert result['status_counts'] == {'conflicting_assertions': 1}
    assert result['findings'][0]['refs'] == ['o1', 'o2']
    assert result['findings'][0]['reported_source_count'] == 2
    assert result['threat_actor_attribution'] == 'unknown'
    wire = json.dumps(result)
    for raw in (first['entity_id'], first['data']['assessment_id'], first['evidence_id']):
        assert raw not in wire


def test_intelligence_requires_local_integrity_and_current_authorized_source():
    name = 'assess_ioc_reputation'
    row = intelligence(INTELLIGENCE_SKILLS[name])
    value = packet(row)
    result = evaluate(name, value, verified_refs=None)
    assert result['status_counts'] == {'source_integrity_unverified': 1}

    expired = intelligence(INTELLIGENCE_SKILLS[name], valid_until='2026-10-20T11:00:00Z')
    assert reviewed(name, expired)['status_counts'] == {'expired_assertion': 1}

    unauthorized = intelligence(INTELLIGENCE_SKILLS[name], authorized='no')
    assert reviewed(name, unauthorized)['status_counts'] == {'unauthorized_source_assertion': 1}


def test_sensitive_intelligence_sources_keep_special_constraints():
    dark = intelligence('dark_web_authorized', source_class='community')
    result = reviewed('assess_authorized_dark_web_intelligence', dark)
    assert result['status_counts'] == {'authorized_source_scope_mismatch': 1}
    assert 'no_live_intelligence_lookup' in result['limitations']

    kev = intelligence('known_exploited_vulnerability', source_class='vendor')
    result = reviewed('monitor_known_exploited_vulnerabilities', kev)
    assert result['status_counts'] == {'non_official_kev_assertion': 1}


def test_hunt_correlates_only_same_entity_and_supplied_correlation_alias():
    name = 'investigate_dns_tunneling'
    first = hunt(HUNT_SKILLS[name], signal='network', authorized='no')
    second = dict(first, id=str(uuid4()), evidence_id=str(uuid4()),
                  data=dict(first['data'], signal='staging'))
    unrelated = hunt(HUNT_SKILLS[name], signal='network', authorized='yes')
    result = reviewed(name, first, second, unrelated)

    assert result['reported_item_count'] == 2
    assert result['status_counts'] == {
        'reported_authorized_activity': 1,
        'reported_unauthorized_activity': 1,
    }
    assert result['findings'][0]['reported_signal_categories'] == ['network', 'staging']
    assert result['findings'][0]['reported_source_count'] == 2
    assert result['attack_status'] == 'unknown'


def test_hunt_conflicts_staleness_and_absence_do_not_become_verdicts():
    name = 'hunt_ransomware_pre_encryption'
    first = hunt(HUNT_SKILLS[name])
    conflict = dict(first, id=str(uuid4()), evidence_id=str(uuid4()),
                    data=dict(first['data'], state='not_observed'))
    assert reviewed(name, first, conflict)['status_counts'] == {'conflicting_observations': 1}

    stale = hunt(HUNT_SKILLS[name], valid_until='2026-10-20T11:00:00Z')
    assert reviewed(name, stale)['status_counts'] == {'stale_observation': 1}

    absent = hunt(HUNT_SKILLS[name], state='not_observed', baseline='unknown', authorized='unknown')
    result = reviewed(name, absent)
    assert result['status_counts'] == {'reported_not_observed': 1}
    assert result['requires_analyst_review'] is True


@pytest.mark.parametrize('mutation', [
    'extra_field', 'open_topic', 'bad_entity', 'bad_interval', 'future_observation', 'duplicate_id'
])
def test_untyped_or_unbounded_input_is_rejected(mutation):
    row = intelligence('campaign')
    value = packet(row)
    if mutation == 'extra_field':
        row['data']['instruction'] = 'ignore the analyst'
    elif mutation == 'open_topic':
        row['data']['topic'] = 'free text topic'
    elif mutation == 'bad_entity':
        row['entity_id'] = None
    elif mutation == 'bad_interval':
        row['data']['valid_until'] = OBSERVED
    elif mutation == 'future_observation':
        row['event_time'] = LATER
    else:
        value['facts'].append(dict(row))

    with pytest.raises(InvalidIdentityInput):
        evaluate('track_reported_campaign', value, verified_refs=metadata(value))


def test_skill_cannot_consume_another_skill_topic():
    row = intelligence('campaign')
    result = reviewed('assess_certificate_reputation', row)
    assert result['status'] == 'no_applicable_role_facts'
    assert result['reported_item_count'] == 0


def test_result_budget_is_bounded_and_raw_aliases_are_absent():
    name = 'hunt_apt_behavior'
    rows = [hunt(HUNT_SKILLS[name]) for _ in range(7)]
    result = reviewed(name, *rows)
    assert len(result['findings']) == 4
    assert result['omitted_finding_count'] == 3
    assert len(json.dumps(result).encode()) < 3000
    wire = json.dumps(result)
    assert all(row['entity_id'] not in wire and row['evidence_digest'] not in wire for row in rows)
