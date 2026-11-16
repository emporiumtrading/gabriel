"""Bounded exposure and cloud reviews over case-linked typed assertions."""

from collections import Counter, defaultdict
from datetime import datetime


YES_NO = {'yes', 'no', 'unknown'}
SCHEMAS = {
    'vulnerability_risk': {
        'finding_id': 'uuid', 'cvss_band': {'low', 'medium', 'high', 'critical', 'unknown'},
        'epss_band': {'low', 'medium', 'high', 'unknown'}, 'kev': YES_NO,
        'exploit_available': YES_NO, 'reachable': YES_NO,
        'service_criticality': {'low', 'medium', 'high', 'critical', 'unknown'},
        'state': {'current', 'stale', 'unknown'}, 'valid_until': 'time',
    },
    'asset_exposure': {
        'asset_id': 'uuid', 'inventory_authorized': YES_NO,
        'surface': {'external', 'internal', 'unknown'},
        'exposure': {'public', 'restricted', 'unknown'},
        'asset_state': {'active', 'retired', 'unknown'}, 'valid_until': 'time',
    },
    'security_configuration': {
        'domain': {'misconfiguration', 'certificate', 'encryption', 'segmentation'},
        'condition': {'misconfigured', 'expires_soon', 'expired', 'weak_crypto',
                      'segmentation_gap', 'none', 'unknown'},
        'control_state': {'secure', 'gap', 'unknown'},
        'severity': {'low', 'medium', 'high', 'critical', 'unknown'},
        'baseline': {'current', 'stale', 'unknown'}, 'valid_until': 'time',
    },
    'service_binding': {
        'vulnerability_id': 'uuid', 'service_id': 'uuid',
        'service_criticality': {'low', 'medium', 'high', 'critical', 'unknown'},
        'binding_state': {'confirmed', 'reported', 'unknown'}, 'valid_until': 'time',
    },
    'attack_path': {
        'path_id': 'uuid', 'start': {'external', 'internal', 'unknown'},
        'target': {'service', 'administrative', 'data', 'unknown'}, 'step_count': int,
        'control_state': {'blocks', 'allows', 'unknown'}, 'valid_until': 'time',
    },
    'cloud_posture': {
        'provider': {'aws', 'azure', 'gcp', 'kubernetes', 'container'},
        'domain': {'identity', 'network', 'storage', 'logging', 'runtime', 'configuration'},
        'state': {'secure', 'gap', 'unknown'}, 'authorized': YES_NO,
        'baseline': {'current', 'stale', 'unknown'}, 'valid_until': 'time',
    },
    'container_risk': {
        'risk': {'escape', 'privileged_mount', 'host_namespace', 'root_runtime'},
        'state': {'present', 'absent', 'unknown'}, 'runtime_verified': YES_NO,
        'valid_until': 'time',
    },
    'component_provenance': {
        'artifact_kind': {'image', 'package', 'release'},
        'provenance': {'verified', 'missing', 'unknown'},
        'signature': {'valid', 'invalid', 'missing', 'unknown'},
        'sbom': {'current', 'stale', 'missing', 'unknown'},
        'dependency_state': {'clear', 'vulnerable', 'unknown'},
        'signing_identity': {'verified', 'unverified', 'unknown'}, 'valid_until': 'time',
    },
    'delivery_control': {
        'domain': {'pipeline', 'iac', 'terraform'},
        'control': {'approval', 'branch_protection', 'secrets', 'review', 'plan', 'state_backend'},
        'state': {'enforced', 'gap', 'unknown'},
        'baseline': {'current', 'stale', 'unknown'}, 'valid_until': 'time',
    },
    'cloud_runtime_signal': {
        'workload': {'serverless', 'container', 'vm', 'other'},
        'signal': {'anomaly', 'secret_exposure', 'supply_chain_indicator'},
        'state': {'present', 'absent', 'unknown'}, 'authorized': YES_NO,
        'baseline': {'current', 'stale', 'unknown'}, 'valid_until': 'time',
    },
}
ROLE_TYPES = {
    'exposure_vulnerability': {'vulnerability_risk', 'asset_exposure', 'security_configuration',
                               'service_binding', 'attack_path'},
    'cloud_supply_chain': {'cloud_posture', 'container_risk', 'component_provenance',
                           'delivery_control', 'cloud_runtime_signal'},
}


SKILL_SPECS = {
    'interpret_cvss_risk': ('exposure_vulnerability', 'vulnerability_risk', 'cvss_band', {'high', 'critical'}),
    'assess_epss_probability': ('exposure_vulnerability', 'vulnerability_risk', 'epss_band', {'high'}),
    'correlate_kev_entries': ('exposure_vulnerability', 'vulnerability_risk', 'kev', {'yes'}),
    'review_external_attack_surface': ('exposure_vulnerability', 'asset_exposure', 'surface', {'external'}),
    'discover_inventory_exposed_assets': ('exposure_vulnerability', 'asset_exposure', 'exposure', {'public'}),
    'assess_misconfiguration_risk': ('exposure_vulnerability', 'security_configuration', 'condition', {'misconfigured'}),
    'monitor_certificate_expiration': ('exposure_vulnerability', 'security_configuration', 'condition', {'expires_soon', 'expired'}),
    'identify_weak_encryption': ('exposure_vulnerability', 'security_configuration', 'condition', {'weak_crypto'}),
    'assess_network_segmentation': ('exposure_vulnerability', 'security_configuration', 'condition', {'segmentation_gap'}),
    'map_vulnerabilities_to_services': ('exposure_vulnerability', 'service_binding', 'binding_state', {'confirmed', 'reported'}),
    'analyze_exploitability_context': ('exposure_vulnerability', 'vulnerability_risk', 'exploit_available', {'yes'}),
    'prioritize_attack_path_exposure': ('exposure_vulnerability', 'attack_path', 'control_state', {'allows'}),
    'report_vulnerability_risk': ('exposure_vulnerability', 'vulnerability_risk', 'service_criticality', {'high', 'critical'}),
    'review_aws_security_posture': ('cloud_supply_chain', 'cloud_posture', 'provider', {'aws'}),
    'review_azure_security_posture': ('cloud_supply_chain', 'cloud_posture', 'provider', {'azure'}),
    'review_gcp_security_posture': ('cloud_supply_chain', 'cloud_posture', 'provider', {'gcp'}),
    'review_kubernetes_security_posture': ('cloud_supply_chain', 'cloud_posture', 'provider', {'kubernetes'}),
    'review_container_security': ('cloud_supply_chain', 'cloud_posture', 'provider', {'container'}),
    'identify_container_escape_risk': ('cloud_supply_chain', 'container_risk', 'risk', {'escape'}),
    'verify_image_provenance': ('cloud_supply_chain', 'component_provenance', 'provenance', {'missing', 'unknown'}),
    'analyze_sbom': ('cloud_supply_chain', 'component_provenance', 'sbom', {'stale', 'missing', 'unknown'}),
    'correlate_dependency_vulnerabilities': ('cloud_supply_chain', 'component_provenance', 'dependency_state', {'vulnerable'}),
    'verify_software_signing': ('cloud_supply_chain', 'component_provenance', 'signature', {'invalid', 'missing', 'unknown'}),
    'review_cicd_pipeline_security': ('cloud_supply_chain', 'delivery_control', 'domain', {'pipeline'}),
    'review_infrastructure_as_code': ('cloud_supply_chain', 'delivery_control', 'domain', {'iac'}),
    'analyze_terraform_configuration': ('cloud_supply_chain', 'delivery_control', 'domain', {'terraform'}),
    'detect_cloud_runtime_anomalies': ('cloud_supply_chain', 'cloud_runtime_signal', 'signal', {'anomaly'}),
    'detect_cloud_secret_exposure': ('cloud_supply_chain', 'cloud_runtime_signal', 'signal', {'secret_exposure'}),
    'investigate_supply_chain_compromise': ('cloud_supply_chain', 'cloud_runtime_signal', 'signal', {'supply_chain_indicator'}),
}
SKILLS = {name: spec[0] for name, spec in SKILL_SPECS.items()}


def _at(value):
    return datetime.fromisoformat(value.replace('Z', '+00:00'))


def validate_fact(fact):
    """Require aliased resources and a finite assertion interval."""
    from gabriel.identity.specialist_analysis import require

    require(fact['entity_id'] is not None, 'exposure_cloud_entity_alias_required')
    require(_at(fact['event_time']) < _at(fact['data']['valid_until']),
            'invalid_exposure_cloud_observation_interval')
    if fact['type'] == 'security_configuration':
        conditions = {
            'misconfiguration': {'misconfigured', 'none', 'unknown'},
            'certificate': {'expires_soon', 'expired', 'none', 'unknown'},
            'encryption': {'weak_crypto', 'none', 'unknown'},
            'segmentation': {'segmentation_gap', 'none', 'unknown'},
        }
        require(fact['data']['condition'] in conditions[fact['data']['domain']],
                'invalid_security_configuration_condition')


def _risk_status(kind, data, field, selected):
    if data[field] not in selected:
        return 'reported_no_selected_condition'
    if kind == 'vulnerability_risk':
        if data['state'] != 'current':
            return 'incomplete_or_stale_context'
        return 'reported_risk_candidate'
    if kind == 'asset_exposure':
        if data['inventory_authorized'] != 'yes' or data['asset_state'] != 'active':
            return 'incomplete_or_stale_context'
        return 'reported_exposure_candidate'
    if kind == 'security_configuration':
        if data['baseline'] != 'current' or data['control_state'] == 'unknown':
            return 'incomplete_or_stale_context'
        return 'reported_control_gap' if data['control_state'] == 'gap' else 'reported_control_state'
    if kind == 'service_binding':
        return 'reported_service_binding_unverified'
    if kind == 'attack_path':
        return 'reported_attack_path_candidate'
    if kind == 'cloud_posture':
        if data['baseline'] != 'current' or data['state'] == 'unknown':
            return 'incomplete_or_stale_context'
        return 'reported_posture_gap' if data['state'] == 'gap' else 'reported_posture_state'
    if kind == 'container_risk':
        if data['runtime_verified'] != 'yes':
            return 'incomplete_or_stale_context'
        return 'reported_container_risk' if data['state'] == 'present' else 'reported_no_selected_condition'
    if kind == 'component_provenance':
        return 'reported_component_review_candidate'
    if kind == 'delivery_control':
        if data['baseline'] != 'current':
            return 'incomplete_or_stale_context'
        return 'reported_control_gap' if data['state'] == 'gap' else 'reported_control_state'
    if data['baseline'] != 'current' or data['state'] == 'unknown':
        return 'incomplete_or_stale_context'
    return 'reported_runtime_signal' if data['state'] == 'present' else 'reported_no_selected_condition'


def evaluate(name, document, *, verified_refs=None):
    """Review supplied assertions without probing assets, clouds, or registries."""
    from gabriel.identity.specialist_analysis import validate_document

    if name not in SKILL_SPECS:
        raise ValueError('unknown_exposure_cloud_skill')
    validate_document(document, document.get('case_id') if type(document) is dict else None)
    role, kind, field, selected = SKILL_SPECS[name]
    as_of = _at(document['as_of'])
    grouped = defaultdict(list)
    for index, fact in enumerate(document['facts'], 1):
        if fact['type'] in ROLE_TYPES[role] and fact['type'] == kind and (name != 'verify_image_provenance'
                                     or fact['data']['artifact_kind'] == 'image'):
            grouped[fact['entity_id']].append((fact, f'o{index}'))

    findings = []
    for reports in grouped.values():
        latest_time = max(_at(fact['event_time']) for fact, _ in reports)
        latest = [(fact, ref) for fact, ref in reports if _at(fact['event_time']) == latest_time]
        values = {tuple(sorted(fact['data'].items())) for fact, _ in latest}
        if len(values) > 1:
            status = 'conflicting_assertions'
        elif any(_at(fact['data']['valid_until']) <= as_of for fact, _ in latest):
            status = 'stale_assertion'
        else:
            status = _risk_status(kind, latest[0][0]['data'], field, selected)
        findings.append({'status': status, 'refs': [ref for _, ref in latest[:2]]})

    priority = {'conflicting_assertions': 0, 'stale_assertion': 1,
                'reported_risk_candidate': 2, 'reported_exposure_candidate': 2,
                'reported_control_gap': 2, 'reported_posture_gap': 2,
                'reported_container_risk': 2, 'reported_runtime_signal': 2}
    findings.sort(key=lambda row: (priority.get(row['status'], 5), row['refs'][0]))
    counts = Counter(row['status'] for row in findings)
    return {
        'version': 'gabriel-exposure-cloud-catalog-v1', 'skill': name, 'role': role,
        'status': 'review_required' if findings else 'no_applicable_role_facts',
        'reported_item_count': len(findings), 'status_counts': dict(sorted(counts.items())),
        'findings': findings[:4], 'omitted_finding_count': max(0, len(findings) - 4),
        'scope': 'supplied_assertions_only', 'source_authenticity': 'unverified',
        'source_clocks_verified': False, 'confidence': 'unqualified',
        'live_state_verified': False, 'external_actions_authorized': False,
        'model_used': False, 'requires_analyst_review': True,
    }
