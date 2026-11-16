"""Safety invariants for the restored identity catalog kernels."""
import unittest
from uuid import uuid4

from gabriel.identity.catalog_identity import evaluate


def fact(kind, data):
    return dict(id=str(uuid4()), type=kind, evidence_id=str(uuid4()),
                evidence_digest='a'*64, entity_id=str(uuid4()),
                event_time='2026-10-20T11:00:00Z', data=data)


def packet(row):
    return dict(version='specialist-facts-v1', case_id=str(uuid4()),
                as_of='2026-10-20T12:00:00Z', facts=[row])


class IdentityCatalogSafety(unittest.TestCase):
    def assert_safe_review(self, result):
        self.assertEqual(result['source_authenticity'], 'unverified')
        self.assertEqual(result['incident_status'], 'unknown')
        self.assertFalse(result['source_clocks_verified'])
        self.assertFalse(result['external_actions_authorized'])
        self.assertFalse(result['model_used'])
        self.assertTrue(result['requires_analyst_review'])

    def test_account_review_never_changes_an_account(self):
        row=fact('identity_account',dict(kind='human',enabled=True,
            last_used='2026-01-01T00:00:00Z',owner='active',mfa='enforced',privileged=False))
        result=evaluate('identify_dormant_accounts',packet(row))
        self.assert_safe_review(result)
        self.assertFalse(result['account_change_performed'])

    def test_directory_review_never_changes_access(self):
        row=fact('directory_control',dict(platform='active_directory',control='ldap_signing',
            state='gap',baseline='current'))
        result=evaluate('review_active_directory_posture',packet(row))
        self.assert_safe_review(result)
        self.assertFalse(result['access_changes_performed'])


if __name__ == '__main__':
    unittest.main()
