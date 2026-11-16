"""All expanded identity reviews execute only on strict case-bound facts."""
from uuid import uuid4

import pytest

from gabriel.identity.catalog_identity import SKILLS, evaluate
from gabriel.identity.investigation_tools import TOOLS
from gabriel.identity.service import InvalidIdentityInput


def uid():
    return str(uuid4())


def fact(kind, data, *, entity=None, event_time='2026-11-13T10:00:00Z'):
    return dict(id=uid(), type=kind, evidence_id=uid(), evidence_digest='a' * 64,
                entity_id=entity or uid(), event_time=event_time, data=data)


def packet():
    account = uid()
    session = uid()
    rows = [
        fact('identity_account', dict(kind='human', enabled=True,
             last_used='2026-01-01T00:00:00Z', owner='inactive', mfa='bypassed', privileged=True), entity=account),
        fact('identity_group_change', dict(change='grant', approved='no', privileged=True,
             membership_state='present'), entity=account),
        fact('identity_location', dict(latitude_millidegrees=41881, longitude_millidegrees=-87623,
             login='success'), entity=account, event_time='2026-11-13T09:00:00Z'),
        fact('identity_location', dict(latitude_millidegrees=51507, longitude_millidegrees=-127,
             login='success'), entity=account, event_time='2026-11-13T10:00:00Z'),
        fact('directory_control', dict(platform='active_directory', control='ldap_signing',
             state='gap', baseline='current')),
        fact('directory_control', dict(platform='entra_id', control='conditional_access',
             state='gap', baseline='current')),
        fact('identity_workload', dict(kind='service', enabled=True, owner='unknown',
             last_rotated='2026-01-01T00:00:00Z', interactive_login=True, workload_bound=False)),
        fact('identity_policy', dict(mode='enforced', scope='privileged', requires_mfa='no',
             requires_healthy_device='no', exception='yes')),
        fact('identity_edge', dict(target_id=uid(), grant='can_assume', privileged_target=True,
             active=True), entity=account),
        fact('identity_permission', dict(level='admin', needed='no', active=True), entity=account),
        fact('identity_oauth', dict(scope='manage', consent='no', publisher_verified='no',
             resource_scope='all', state='active'), entity=account),
        fact('identity_token', dict(token_id=uid(), state='revoked', audience='unexpected',
             outcome='success'), entity=account),
        fact('identity_session', dict(session_id=session, device='known', mfa='yes', outcome='success'),
             entity=account, event_time='2026-11-13T09:00:00Z'),
        fact('identity_session', dict(session_id=session, device='new', mfa='no', outcome='success'),
             entity=account, event_time='2026-11-13T10:00:00Z'),
        fact('identity_lifecycle', dict(event='leave', approved='yes', state='inactive'), entity=account),
        fact('identity_federation', dict(mode='active', metadata_signed='no', certificate='expired',
             endpoint_verified='no')),
    ]
    return dict(version='specialist-facts-v1', case_id=uid(),
                as_of='2026-11-13T11:00:00Z', facts=rows)


@pytest.mark.parametrize('name', sorted(SKILLS))
def test_every_identity_catalog_skill_is_bounded_and_role_bound(name):
    result = evaluate(name, packet())
    assert result['role'] == 'identity_access'
    assert result['source_authenticity'] == 'unverified'
    assert result['confidence'] == 'unqualified'
    assert result['external_actions_authorized'] is False
    assert result['model_used'] is False
    assert result['requires_analyst_review'] is True
    assert name in TOOLS['identity_access']
    assert all(name not in tools for role, tools in TOOLS.items() if role != 'identity_access')


def test_identity_catalog_rejects_untyped_fields_and_future_events():
    doc = packet()
    doc['facts'][0]['data']['instruction'] = 'disable the account'
    with pytest.raises(InvalidIdentityInput, match='invalid_specialist_fact_fields'):
        evaluate('identify_dormant_accounts', doc)
    doc = packet()
    doc['facts'][0]['event_time'] = '2026-11-13T12:00:00Z'
    with pytest.raises(InvalidIdentityInput, match='specialist_fact_after_snapshot'):
        evaluate('identify_dormant_accounts', doc)


def test_catalog_contains_exactly_the_remaining_nineteen_identity_skills():
    assert len(SKILLS) == 19
    assert 'review_privileged_access_changes' not in SKILLS

