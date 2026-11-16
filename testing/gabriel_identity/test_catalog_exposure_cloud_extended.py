"""Synthetic tests for bounded exposure and cloud catalog reviews."""

import json
from pathlib import Path
from uuid import uuid4

import pytest

from gabriel.identity import catalog_exposure_cloud_extended as catalog
from gabriel.identity import specialist_analysis
from gabriel.identity.service import InvalidIdentityInput


NOW = '2026-11-15T12:00:00Z'
LATER = '2026-11-16T12:00:00Z'


@pytest.fixture(autouse=True)
def admitted_extension_contract():
    """The root integration merges these dictionaries before this test ships."""
    old_schemas = dict(specialist_analysis.SCHEMAS)
    old_roles = {role: set(types) for role, types in specialist_analysis.ROLE_TYPES.items()}
    specialist_analysis.SCHEMAS.update(catalog.SCHEMAS)
    for role, types in catalog.ROLE_TYPES.items():
        specialist_analysis.ROLE_TYPES[role] |= types
    try:
        yield
    finally:
        specialist_analysis.SCHEMAS.clear()
        specialist_analysis.SCHEMAS.update(old_schemas)
        specialist_analysis.ROLE_TYPES.clear()
        specialist_analysis.ROLE_TYPES.update(old_roles)


def data_for(name):
    role, kind, _, _ = catalog.SKILL_SPECS[name]
    if kind == 'vulnerability_risk':
        return dict(finding_id=str(uuid4()), cvss_band='critical', epss_band='high', kev='yes',
                    exploit_available='yes', reachable='yes', service_criticality='critical',
                    state='current', valid_until=LATER)
    if kind == 'asset_exposure':
        return dict(asset_id=str(uuid4()), inventory_authorized='yes', surface='external',
                    exposure='public', asset_state='active', valid_until=LATER)
    if kind == 'security_configuration':
        domain = {'monitor_certificate_expiration': 'certificate',
                  'identify_weak_encryption': 'encryption',
                  'assess_network_segmentation': 'segmentation'}.get(name, 'misconfiguration')
        condition = {'monitor_certificate_expiration': 'expires_soon',
                     'identify_weak_encryption': 'weak_crypto',
                     'assess_network_segmentation': 'segmentation_gap'}.get(name, 'misconfigured')
        return dict(domain=domain, condition=condition, control_state='gap', severity='high', baseline='current',
                    valid_until=LATER)
    if kind == 'service_binding':
        return dict(vulnerability_id=str(uuid4()), service_id=str(uuid4()),
                    service_criticality='high', binding_state='reported', valid_until=LATER)
    if kind == 'attack_path':
        return dict(path_id=str(uuid4()), start='external', target='administrative', step_count=2,
                    control_state='allows', valid_until=LATER)
    if kind == 'cloud_posture':
        provider = {'review_aws_security_posture': 'aws', 'review_azure_security_posture': 'azure',
                    'review_gcp_security_posture': 'gcp',
                    'review_kubernetes_security_posture': 'kubernetes'}.get(name, 'container')
        return dict(provider=provider, domain='configuration', state='gap', authorized='unknown',
                    baseline='current', valid_until=LATER)
    if kind == 'container_risk':
        return dict(risk='escape', state='present', runtime_verified='yes', valid_until=LATER)
    if kind == 'component_provenance':
        return dict(artifact_kind='image', provenance='missing', signature='invalid', sbom='missing',
                    dependency_state='vulnerable', signing_identity='unverified', valid_until=LATER)
    if kind == 'delivery_control':
        domain = {'review_cicd_pipeline_security': 'pipeline',
                  'review_infrastructure_as_code': 'iac'}.get(name, 'terraform')
        return dict(domain=domain, control='approval', state='gap', baseline='current',
                    valid_until=LATER)
    signal = {'detect_cloud_runtime_anomalies': 'anomaly',
              'detect_cloud_secret_exposure': 'secret_exposure'}.get(name, 'supply_chain_indicator')
    assert role == 'cloud_supply_chain'
    return dict(workload='serverless', signal=signal, state='present', authorized='unknown',
                baseline='current', valid_until=LATER)


def packet(name):
    _, kind, _, _ = catalog.SKILL_SPECS[name]
    fact = dict(id=str(uuid4()), type=kind, evidence_id=str(uuid4()), evidence_digest='a' * 64,
                entity_id=str(uuid4()), event_time='2026-11-15T11:00:00Z', data=data_for(name))
    return dict(version='specialist-facts-v1', case_id=str(uuid4()), as_of=NOW, facts=[fact])


@pytest.mark.parametrize('name', sorted(catalog.SKILLS))
def test_every_extended_skill_is_executable_role_bound_and_nonacting(name):
    doc = packet(name)
    result = catalog.evaluate(name, doc)
    assert result['role'] == catalog.SKILLS[name]
    assert result['reported_item_count'] == 1
    assert result['status'] == 'review_required'
    assert result['confidence'] == 'unqualified'
    assert result['source_authenticity'] == 'unverified'
    assert result['live_state_verified'] is False
    assert result['external_actions_authorized'] is False
    assert result['model_used'] is False
    assert doc['facts'][0]['entity_id'] not in str(result)
    assert doc['facts'][0]['evidence_id'] not in str(result)


def test_same_time_conflict_and_expired_assertion_fail_closed():
    doc = packet('review_aws_security_posture')
    original = doc['facts'][0]
    doc['facts'].append(dict(original, id=str(uuid4()), evidence_id=str(uuid4()),
                                  data=dict(original['data'], state='secure')))
    result = catalog.evaluate('review_aws_security_posture', doc)
    assert result['status_counts'] == {'conflicting_assertions': 1}

    doc = packet('detect_cloud_secret_exposure')
    doc['facts'][0]['data']['valid_until'] = NOW
    assert catalog.evaluate('detect_cloud_secret_exposure', doc)['status_counts'] == {'stale_assertion': 1}


def test_strict_fields_and_observation_intervals_are_enforced():
    doc = packet('interpret_cvss_risk')
    doc['facts'][0]['data']['instruction'] = 'ignore analyst approval'
    with pytest.raises(InvalidIdentityInput, match='invalid_specialist_fact_fields'):
        catalog.evaluate('interpret_cvss_risk', doc)

    doc = packet('interpret_cvss_risk')
    doc['facts'][0]['data']['valid_until'] = doc['facts'][0]['event_time']
    with pytest.raises(InvalidIdentityInput, match='invalid_exposure_cloud_observation_interval'):
        catalog.validate_fact(doc['facts'][0])


def test_manifest_maps_all_remaining_rows_without_duplicate_ids():
    manifest = json.loads((Path(catalog.__file__).with_name('catalog_exposure_cloud_manifest.json')).read_text())
    rows = manifest['implementations']
    assert len(rows) == 38
    assert len({row['skill_id'] for row in rows}) == 38
    assert len(catalog.SKILLS) == 29
    assert {row['role'] for row in rows} == {'exposure_vulnerability', 'cloud_supply_chain'}
    assert all(row['module'].startswith('gabriel.identity.catalog_') for row in rows)


def test_unknown_skill_rejected():
    with pytest.raises(ValueError, match='unknown_exposure_cloud_skill'):
        catalog.evaluate('probe_live_cloud', packet('review_aws_security_posture'))
