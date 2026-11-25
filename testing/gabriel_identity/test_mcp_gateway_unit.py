import pytest

from gabriel.identity.mcp_gateway import minimize_result, normalize_endpoint, safe_manifest
from gabriel.identity.service import InvalidIdentityInput


def test_mcp_endpoint_is_https_and_has_no_ambient_authority():
    assert normalize_endpoint('https://example.test/mcp') == 'https://example.test/mcp'
    for value in ('http://example.test/mcp', 'https://user@example.test/mcp',
                  'https://example.test/mcp?redirect=https://evil.test', 'https://example.test'):
        with pytest.raises(InvalidIdentityInput):
            normalize_endpoint(value)


def test_mcp_manifest_admits_only_explicit_read_only_tools():
    manifest = safe_manifest([
        {'name': 'search_alerts', 'description': 'Read alert metadata',
         'annotations': {'readOnlyHint': True, 'destructiveHint': False}},
        {'name': 'delete_alert', 'description': 'Delete an alert',
         'annotations': {'readOnlyHint': True, 'destructiveHint': False}},
        {'name': 'unknown_tool', 'description': 'Unclassified', 'annotations': {}},
    ])
    assert [item['name'] for item in manifest] == ['search_alerts']


def test_mcp_results_are_minimized_and_bounded():
    result = minimize_result({'token': 'do-not-export', 'alert': {'id': 'a1'}, 'items': list(range(3))})
    assert result['raw_result_exported'] is False
    assert result['result']['token'] == '[hidden]'
