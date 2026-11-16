"""Bounded intelligence and hunting reviews over case-bound typed facts."""

from collections import Counter, defaultdict
from datetime import datetime
import json
import re
from uuid import UUID


INTELLIGENCE_SKILLS = {
    'enrich_attack_techniques': 'attack_technique',
    'profile_reported_threat_actor': 'threat_actor',
    'track_reported_campaign': 'campaign',
    'review_malware_family_intelligence': 'malware_family',
    'review_ransomware_group_intelligence': 'ransomware_group',
    'assess_ioc_reputation': 'ioc_reputation',
    'analyze_domain_dns_reputation': 'domain_dns_reputation',
    'analyze_ip_infrastructure_relationships': 'ip_infrastructure',
    'assess_certificate_reputation': 'certificate_reputation',
    'score_intelligence_feed_quality': 'feed_quality',
    'score_intelligence_source_reliability': 'source_reliability',
    'review_cve_exploitation_intelligence': 'cve_exploitation',
    'monitor_known_exploited_vulnerabilities': 'known_exploited_vulnerability',
    'cluster_reported_adversary_infrastructure': 'adversary_infrastructure',
    'reconstruct_threat_campaign_timeline': 'campaign_timeline',
    'profile_industry_threats': 'industry_threat',
    'assess_geopolitical_threat_context': 'geopolitical_context',
    'assess_authorized_dark_web_intelligence': 'dark_web_authorized',
    'map_intelligence_to_detection': 'intelligence_detection_mapping',
}
HUNT_SKILLS = {
    'detect_living_off_land_activity': 'living_off_land',
    'investigate_linux_command_anomalies': 'linux_command',
    'investigate_macos_persistence': 'macos_persistence',
    'detect_unauthorized_scheduled_tasks': 'scheduled_task',
    'investigate_service_creation': 'service_creation',
    'investigate_registry_persistence': 'registry_persistence',
    'detect_unusual_process_parentage': 'process_parentage',
    'investigate_credential_dumping_indicators': 'credential_dumping',
    'investigate_kerberos_anomalies': 'kerberos',
    'investigate_pass_the_hash_ticket_indicators': 'pass_hash_ticket',
    'detect_remote_desktop_misuse': 'remote_desktop',
    'investigate_smb_lateral_movement': 'smb_lateral_movement',
    'investigate_dns_tunneling': 'dns_tunneling',
    'analyze_command_control_beaconing': 'command_control_beaconing',
    'investigate_data_staging_exfiltration': 'data_staging_exfiltration',
    'discover_shadow_it': 'shadow_it',
    'investigate_unauthorized_remote_access': 'remote_access',
    'hunt_ransomware_pre_encryption': 'ransomware_pre_encryption',
    'hunt_apt_behavior': 'apt_behavior',
}
SKILLS = {
    **{name: 'threat_intelligence' for name in INTELLIGENCE_SKILLS},
    **{name: 'threat_hunting' for name in HUNT_SKILLS},
}

SCHEMAS = {
    'intelligence_assertion': {
        'assessment_id': 'uuid',
        'topic': set(INTELLIGENCE_SKILLS.values()),
        'assertion': {'supports', 'disputes', 'observed', 'exploited', 'matched', 'not_observed', 'unknown'},
        'source_class': {'official', 'vendor', 'community', 'internal', 'dark_web_authorized', 'unknown'},
        'confidence': {'high', 'medium', 'low', 'unknown'},
        'effective_at': 'time',
        'valid_until': 'time',
        'authorized': {'yes', 'no', 'unknown'},
    },
    'hunt_observation': {
        'observation_id': 'uuid',
        'behavior': set(HUNT_SKILLS.values()),
        'signal': {'execution', 'persistence', 'authentication', 'network', 'access', 'staging', 'discovery', 'impact'},
        'state': {'observed', 'not_observed', 'unknown'},
        'baseline': {'expected', 'unexpected', 'unknown'},
        'authorized': {'yes', 'no', 'unknown'},
        'correlation_id': 'uuid',
        'valid_until': 'time',
    },
}
ROLE_TYPES = {
    'threat_intelligence': {'intelligence_assertion'},
    'threat_hunting': {'hunt_observation'},
}
MAX_FINDINGS = 4


def _require(condition, message):
    if not condition:
        from gabriel.identity.service import InvalidIdentityInput
        raise InvalidIdentityInput(message)


def _at(value):
    try:
        _require(type(value) is str and value.endswith('Z'), 'invalid_catalog_fact_time')
        parsed = datetime.fromisoformat(value[:-1] + '+00:00')
        _require(1970 <= parsed.year <= 2100 and parsed.utcoffset().total_seconds() == 0,
                 'invalid_catalog_fact_time')
        return parsed
    except (ValueError, TypeError, AttributeError):
        from gabriel.identity.service import InvalidIdentityInput
        raise InvalidIdentityInput('invalid_catalog_fact_time') from None


def _uid(value):
    try:
        _require(type(value) is str and str(UUID(value)) == value, 'invalid_catalog_fact_uuid')
        return value
    except (ValueError, TypeError, AttributeError):
        from gabriel.identity.service import InvalidIdentityInput
        raise InvalidIdentityInput('invalid_catalog_fact_uuid') from None


def validate_fact(fact):
    """Reject open text, unbound entities and invalid review intervals."""
    kind = fact['type']
    _require(kind in SCHEMAS, 'unknown_intel_hunt_fact_type')
    _require(fact['entity_id'] is not None, 'intel_hunt_entity_alias_required')
    schema, data = SCHEMAS[kind], fact['data']
    _require(type(data) is dict and set(data) == set(schema), 'invalid_intel_hunt_fact_fields')
    for key, allowed in schema.items():
        value = data[key]
        if allowed == 'uuid':
            _uid(value)
        elif allowed == 'time':
            _at(value)
        else:
            _require(type(value) is str and value in allowed, 'invalid_intel_hunt_fact_value')
    observed = _at(fact['event_time'])
    if kind == 'intelligence_assertion':
        _require(_at(data['effective_at']) <= observed < _at(data['valid_until']),
                 'invalid_intelligence_assertion_interval')
    else:
        _require(observed < _at(data['valid_until']), 'invalid_hunt_observation_interval')


def _validate_document(document):
    _require(type(document) is dict and set(document) == {'version', 'case_id', 'as_of', 'facts'}
             and document['version'] == 'specialist-facts-v1', 'invalid_specialist_facts')
    _uid(document['case_id'])
    as_of = _at(document['as_of'])
    facts = document['facts']
    _require(type(facts) is list and 1 <= len(facts) <= 128, 'specialist_fact_limit')
    encoded = json.dumps(document, sort_keys=True, separators=(',', ':'), ensure_ascii=False).encode()
    _require(len(encoded) <= 65536, 'specialist_fact_limit')
    seen, other = set(), []
    for fact in facts:
        _require(type(fact) is dict and set(fact) == {
            'id', 'type', 'evidence_id', 'evidence_digest', 'entity_id', 'event_time', 'data'
        }, 'invalid_specialist_fact')
        identifier = _uid(fact['id'])
        _require(identifier not in seen, 'duplicate_specialist_fact')
        seen.add(identifier)
        _uid(fact['evidence_id'])
        if fact['entity_id'] is not None:
            _uid(fact['entity_id'])
        digest = fact['evidence_digest']
        _require(type(digest) is str and re.fullmatch(r'[a-f0-9]{64}', digest) is not None,
                 'invalid_specialist_fact_digest')
        _require(_at(fact['event_time']) <= as_of, 'specialist_fact_after_snapshot')
        if fact['type'] in SCHEMAS:
            validate_fact(fact)
        else:
            other.append(fact)
    _require(len({fact['evidence_id'] for fact in facts}) <= 32, 'specialist_fact_source_limit')
    if other:
        from gabriel.identity.specialist_analysis import validate_document
        validate_document(dict(document, facts=other), document['case_id'])
    return document


def _verified_digests(case_id, refs):
    cases, candidates = [], defaultdict(list)
    for ref in refs or ():
        if type(ref) is not dict:
            continue
        if ref.get('kind') == 'case_record':
            cases.append(ref)
        if ref.get('kind') == 'evidence_metadata' and type(ref.get('record_id')) is str:
            candidates[ref['record_id']].append(ref)
    if len(cases) != 1 or cases[0].get('record_id') != case_id or cases[0].get('ref') != f'case/{case_id}':
        return {}
    return {
        evidence_id: entries[0].get('digest')
        for evidence_id, entries in candidates.items()
        if len(entries) == 1
        and entries[0].get('ref') == f'evidence/{evidence_id}'
        and entries[0].get('content_integrity') == 'verified'
    }


def _base(name, findings, total, limitations):
    counts = Counter(row['status'] for row in findings)
    findings.sort(key=lambda row: (row['priority'], row['refs'][0] if row['refs'] else ''))
    for row in findings:
        row.pop('priority', None)
    return {
        'version': 'gabriel-intel-hunt-catalog-v1',
        'skill': name,
        'role': SKILLS[name],
        'status': 'review_required' if findings else 'no_applicable_role_facts',
        'reported_item_count': total,
        'status_counts': dict(sorted(counts.items())),
        'findings': findings[:MAX_FINDINGS],
        'omitted_finding_count': max(0, len(findings) - MAX_FINDINGS),
        'limitations': limitations,
        'source_authenticity': 'unverified',
        'source_independence': 'unestablished',
        'attack_status': 'unknown',
        'threat_actor_attribution': 'unknown',
        'confidence': 'unqualified',
        'external_actions_authorized': False,
        'model_used': False,
        'requires_analyst_review': True,
    }


def _intelligence(name, document, verified):
    topic = INTELLIGENCE_SKILLS[name]
    grouped = defaultdict(list)
    for index, fact in enumerate(document['facts'], 1):
        if fact['type'] == 'intelligence_assertion' and fact['data']['topic'] == topic:
            grouped[(fact['entity_id'], fact['data']['assessment_id'])].append((fact, f'o{index}'))
    now, findings = _at(document['as_of']), []
    for reports in grouped.values():
        instant = max(_at(fact['data']['effective_at']) for fact, _ in reports)
        latest = [(fact, ref) for fact, ref in reports if _at(fact['data']['effective_at']) == instant]
        assertions = {fact['data']['assertion'] for fact, _ in latest}
        source_classes = {fact['data']['source_class'] for fact, _ in latest}
        authorizations = {fact['data']['authorized'] for fact, _ in latest}
        confidences = {fact['data']['confidence'] for fact, _ in latest}
        refs = [ref for _, ref in latest[:4]]
        verified_count = sum(verified.get(fact['evidence_id']) == fact['evidence_digest'] for fact, _ in latest)
        source_count = len({fact['evidence_id'] for fact, _ in latest})
        if verified_count != len(latest):
            status, priority = 'source_integrity_unverified', 0
        elif len(assertions) > 1 or len(authorizations) > 1:
            status, priority = 'conflicting_assertions', 1
        elif all(_at(fact['data']['valid_until']) <= now for fact, _ in latest):
            status, priority = 'expired_assertion', 2
        elif 'no' in authorizations:
            status, priority = 'unauthorized_source_assertion', 3
        elif 'unknown' in authorizations:
            status, priority = 'source_authorization_unknown', 4
        elif topic == 'dark_web_authorized' and source_classes != {'dark_web_authorized'}:
            status, priority = 'authorized_source_scope_mismatch', 5
        elif topic == 'known_exploited_vulnerability' and 'official' not in source_classes:
            status, priority = 'non_official_kev_assertion', 6
        elif assertions == {'unknown'} or confidences == {'unknown'}:
            status, priority = 'unknown_assertion', 7
        elif confidences == {'low'}:
            status, priority = 'low_confidence_assertion', 8
        elif source_count < 2:
            status, priority = 'single_source_report', 9
        else:
            status, priority = 'multi_source_report_unverified', 10
        findings.append({
            'status': status,
            'refs': refs,
            'reported_source_count': source_count,
            'locally_integrity_verified_count': verified_count,
            'reported_assertions': sorted(assertions),
            'priority': priority,
        })
    return _base(name, findings, len(grouped), [
        'supplied_assertions_only', 'source_identity_not_authenticated',
        'source_independence_not_established', 'no_live_intelligence_lookup',
    ])


def _hunt(name, document, verified):
    behavior = HUNT_SKILLS[name]
    grouped = defaultdict(list)
    for index, fact in enumerate(document['facts'], 1):
        if fact['type'] == 'hunt_observation' and fact['data']['behavior'] == behavior:
            key = (fact['entity_id'], fact['data']['correlation_id'])
            grouped[key].append((fact, f'o{index}'))
    now, findings = _at(document['as_of']), []
    for reports in grouped.values():
        instant = max(_at(fact['event_time']) for fact, _ in reports)
        latest = [(fact, ref) for fact, ref in reports if _at(fact['event_time']) == instant]
        states = {fact['data']['state'] for fact, _ in latest}
        baselines = {fact['data']['baseline'] for fact, _ in latest}
        authorizations = {fact['data']['authorized'] for fact, _ in latest}
        signals = {fact['data']['signal'] for fact, _ in reports}
        refs = [ref for _, ref in latest[:4]]
        verified_count = sum(verified.get(fact['evidence_id']) == fact['evidence_digest'] for fact, _ in latest)
        source_count = len({fact['evidence_id'] for fact, _ in reports})
        if verified_count != len(latest):
            status, priority = 'source_integrity_unverified', 0
        elif len(states) > 1 or len(authorizations) > 1 or len(baselines) > 1:
            status, priority = 'conflicting_observations', 1
        elif all(_at(fact['data']['valid_until']) <= now for fact, _ in latest):
            status, priority = 'stale_observation', 2
        elif states == {'unknown'}:
            status, priority = 'unknown_observation', 3
        elif states == {'not_observed'}:
            status, priority = 'reported_not_observed', 7
        elif authorizations == {'no'}:
            status, priority = 'reported_unauthorized_activity', 4
        elif authorizations == {'unknown'}:
            status, priority = 'reported_activity_authority_unknown', 5
        elif baselines == {'unexpected'}:
            status, priority = 'reported_unexpected_authorized_activity', 6
        else:
            status, priority = 'reported_authorized_activity', 8
        findings.append({
            'status': status,
            'refs': refs,
            'reported_signal_categories': sorted(signals),
            'reported_source_count': source_count,
            'locally_integrity_verified_count': verified_count,
            'priority': priority,
        })
    return _base(name, findings, len(grouped), [
        'supplied_observations_only', 'entity_binding_not_independently_verified',
        'baseline_and_authority_not_independently_verified', 'no_live_system_query',
    ])


def evaluate(name, document, *, verified_refs=None):
    if name not in SKILLS:
        raise ValueError('unknown_intel_hunt_skill')
    _validate_document(document)
    verified = _verified_digests(document['case_id'], verified_refs)
    if name in INTELLIGENCE_SKILLS:
        return _intelligence(name, document, verified)
    return _hunt(name, document, verified)
