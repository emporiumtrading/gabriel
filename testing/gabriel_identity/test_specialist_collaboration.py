"""Pure cross-specialist synthesis checks."""
import pytest

from gabriel.identity.specialist_collaboration import VERSION, synthesize
from gabriel.identity.specialist_contracts import ROLES


def result(*, urgency='review', assessment='abstained'):
    return dict(
        observations=[{'statement': 'bounded observation'}],
        hypotheses=[],
        alternatives=['approved activity remains possible'],
        contradictions=[],
        uncertainty=['source authenticity is unknown'],
        next_steps=[],
        urgency=urgency,
        incident_assessment=assessment,
        attack_status='unknown',
        confidence='unqualified',
    )


def test_all_twelve_roles_are_combined_with_handoffs_and_attention_order():
    records=[dict(role=role,result=result(urgency='urgent_review' if role=='threat_hunting' else 'review'))
             for role in ROLES]
    value=synthesize(records)
    assert value['version']==VERSION
    assert value['status']=='complete'
    assert value['completed_role_count']==12
    assert value['missing_roles']==[]
    assert value['attention_order']==['threat_hunting']
    assert len(value['handoffs'])==12
    assert value['external_actions_authorized'] is False
    assert value['decision_made'] is False
    assert value['confidence']=='unqualified'


def test_disagreement_is_preserved_instead_of_collapsed():
    records=[dict(role=role,result=result(assessment='bounded_rule_review' if role=='alert_triage' else 'abstained'))
             for role in ROLES]
    value=synthesize(records)
    assert any(item['dimension']=='incident_assessment' for item in value['disagreements'])
    assert value['attack_status']=='unknown'


def test_partial_suite_identifies_missing_roles():
    records=[dict(role=ROLES[0],result=result())]
    value=synthesize(records)
    assert value['status']=='partial'
    assert value['completed_role_count']==1
    assert value['missing_roles']==list(ROLES[1:])


@pytest.mark.parametrize('records', [
    [dict(role=ROLES[0],result=result()), dict(role=ROLES[0],result=result())],
    [dict(role='unknown_role',result=result())],
])
def test_duplicate_or_unknown_roles_are_rejected(records):
    with pytest.raises(ValueError):
        synthesize(records)
