"""Fail-closed, read-only MCP gateway for role-scoped specialist context.

The gateway is deliberately narrower than a general MCP client: HTTPS only,
no redirects, bearer credentials stay encrypted, only explicitly read-only
tools are admitted, and results cross the boundary as bounded typed summaries.
"""
import http.client
from hashlib import sha256
import json
import os
import re
import ssl
from urllib.parse import urlsplit
from uuid import uuid4

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from gabriel.identity.evidence_store import canonical
from gabriel.identity.model_protocol import ProbeError, decode
from gabriel.identity.service import AccessDenied, InvalidIdentityInput, _audit, connection
from gabriel.identity.specialist_contracts import ROLES, role_name
from gabriel.identity.vault import ProviderCredential, ProviderVault, SecretUnavailable, _secret

VERSION = 'gabriel-mcp-gateway-v1'
PROTOCOL_VERSION = '2025-06-18'
MAX_MANIFEST_TOOLS = 128
MAX_RESULT_BYTES = 16384
MAX_ARGUMENT_BYTES = 4096
NAME = re.compile(r'[a-z][a-z0-9_.-]{2,63}')
DENY_WORDS = re.compile(r'(?:write|delete|destroy|remove|create|update|modify|execute|run|send|close|disable|enable|rotate|reset|install|uninstall|publish|revoke)', re.I)
SENSITIVE_KEY = re.compile(r'(?:password|passwd|secret|token|cookie|authorization|credential|private[_-]?key|api[_-]?key)', re.I)


def normalize_endpoint(value):
    if not isinstance(value, str) or len(value) > 512 or any(ord(c) < 33 or ord(c) > 126 for c in value):
        raise InvalidIdentityInput('invalid_mcp_endpoint')
    parsed = urlsplit(value)
    if (parsed.scheme != 'https' or not parsed.hostname or parsed.username is not None
            or parsed.password is not None or parsed.query or parsed.fragment
            or parsed.netloc != parsed.netloc.lower() or '\\' in value or '%' in value
            or not parsed.path or not parsed.path.startswith('/') or parsed.path == '//'):
        raise InvalidIdentityInput('invalid_mcp_endpoint')
    try:
        port = parsed.port
    except ValueError:
        raise InvalidIdentityInput('invalid_mcp_endpoint') from None
    if port is not None and not 1 <= port <= 65535:
        raise InvalidIdentityInput('invalid_mcp_endpoint')
    return 'https://' + parsed.netloc + parsed.path


def _roles(value):
    if isinstance(value, str):
        value = [v for v in value.split(',') if v]
    if not isinstance(value, (list, tuple, set)) or not 1 <= len(value) <= len(ROLES):
        raise InvalidIdentityInput('invalid_mcp_roles')
    result = sorted(set(value))
    if len(result) != len(value) or any(v not in ROLES for v in result):
        raise InvalidIdentityInput('invalid_mcp_roles')
    return result


def _name(value):
    if not isinstance(value, str) or not NAME.fullmatch(value):
        raise InvalidIdentityInput('invalid_mcp_name')
    return value


def _aad(row, key_id):
    return canonical([VERSION, str(row['organization_id']), str(row['id']), row['revision'], key_id])


def _credential(value):
    secret = value.reveal() if isinstance(value, ProviderCredential) else value
    if not isinstance(secret, str) or not 1 <= len(secret.encode('utf-8')) <= 8192:
        raise InvalidIdentityInput('invalid_mcp_credential')
    if any(ord(c) < 32 or ord(c) == 127 for c in secret):
        raise InvalidIdentityInput('invalid_mcp_credential')
    return secret


def _safe_tool(row):
    if not isinstance(row, dict) or not isinstance(row.get('name'), str) or not NAME.fullmatch(row['name']):
        return None
    description = row.get('description', '')
    if not isinstance(description, str) or len(description) > 512 or any(ord(c) < 32 and c not in '\t\n' for c in description):
        return None
    annotations = row.get('annotations') if isinstance(row.get('annotations'), dict) else {}
    # Annotation values are untrusted, but absence is not safe enough for an
    # external agent.  Only an explicit read-only declaration is admitted.
    if annotations.get('readOnlyHint') is not True or annotations.get('destructiveHint') is True:
        return None
    if DENY_WORDS.search(row['name']) or DENY_WORDS.search(description):
        return None
    return dict(name=row['name'], description=description[:512], annotations=dict(readOnlyHint=True, destructiveHint=False))


def safe_manifest(tools):
    if not isinstance(tools, list) or len(tools) > MAX_MANIFEST_TOOLS:
        raise ProbeError('mcp_manifest_invalid')
    result = []
    seen = set()
    for tool in tools:
        safe = _safe_tool(tool)
        if safe and safe['name'] not in seen:
            seen.add(safe['name'])
            result.append(safe)
    return sorted(result, key=lambda row: row['name'])


def _minimize(value, *, key=''):
    if SENSITIVE_KEY.search(key):
        return '[hidden]'
    if isinstance(value, dict):
        return {str(k)[:64]: _minimize(v, key=str(k)) for k, v in list(value.items())[:64]
                if isinstance(k, str) and len(k) <= 128}
    if isinstance(value, list):
        return [_minimize(v, key=key) for v in value[:64]]
    if isinstance(value, (str, int, float, bool)) or value is None:
        if isinstance(value, str):
            return value[:512]
        return value
    return None


def minimize_result(value):
    minimized = _minimize(value)
    encoded = canonical(minimized)
    if len(encoded) > MAX_RESULT_BYTES:
        return dict(status='result_too_large', result_digest=sha256(encoded).hexdigest(), raw_result_exported=False)
    return dict(status='read_only_result', result=minimized, result_digest=sha256(encoded).hexdigest(), raw_result_exported=False)


class McpTransport:
    def __init__(self, target, credential=None):
        self.target = normalize_endpoint(target)
        self.credential = _credential(credential) if credential is not None else None
        parsed = urlsplit(self.target)
        self.host = parsed.hostname
        self.port = parsed.port or 443
        self.path = parsed.path
        self.session_id = None
        self._request_id = 0

    def request(self, method, params=None):
        self._request_id += 1
        payload = dict(jsonrpc='2.0', id=self._request_id, method=method)
        if params is not None:
            payload['params'] = params
        body = canonical(payload)
        if len(body) > 8192:
            raise ProbeError('mcp_request_limit')
        headers = {'Content-Type': 'application/json', 'Accept': 'application/json, text/event-stream'}
        if self.credential:
            headers['Authorization'] = 'Bearer ' + self.credential
        if self.session_id:
            headers['Mcp-Session-Id'] = self.session_id
        client = http.client.HTTPSConnection(self.host, self.port, timeout=15, context=ssl.create_default_context())
        try:
            client.request('POST', self.path, body=body, headers=headers)
            response = client.getresponse()
            if response.status not in {200, 202}:
                raise ProbeError('mcp_http_' + str(response.status))
            self.session_id = response.getheader('Mcp-Session-Id') or self.session_id
            raw = response.read(MAX_RESULT_BYTES + 1)
            if len(raw) > MAX_RESULT_BYTES:
                raise ProbeError('mcp_response_limit')
            content_type = response.getheader('Content-Type', '').lower()
            if 'text/event-stream' in content_type:
                data = next((line[5:].strip() for line in raw.decode('utf-8').splitlines() if line.startswith('data:')), '')
                if not data:
                    raise ProbeError('mcp_event_missing')
                return decode(data.encode('utf-8'))
            if 'application/json' not in content_type:
                raise ProbeError('mcp_content_type_invalid')
            return decode(raw)
        except ProbeError:
            raise
        except (OSError, http.client.HTTPException, UnicodeError, ValueError, RecursionError):
            raise ProbeError('mcp_transport_unresolved') from None
        finally:
            client.close()

    def manifest(self):
        initialize = self.request('initialize', dict(protocolVersion=PROTOCOL_VERSION, capabilities={},
            clientInfo=dict(name='Gabriel', version=VERSION)))
        if not isinstance(initialize, dict) or not isinstance(initialize.get('result'), dict):
            raise ProbeError('mcp_initialize_invalid')
        listing = self.request('tools/list', dict(cursor=None))
        if not isinstance(listing, dict) or not isinstance(listing.get('result'), dict):
            raise ProbeError('mcp_tools_invalid')
        return safe_manifest(listing['result'].get('tools'))

    def call(self, tool, arguments):
        if not isinstance(arguments, dict) or len(canonical(arguments)) > MAX_ARGUMENT_BYTES:
            raise ProbeError('mcp_argument_limit')
        reply = self.request('tools/call', dict(name=tool, arguments=arguments))
        if not isinstance(reply, dict) or not isinstance(reply.get('result'), dict):
            raise ProbeError('mcp_tool_result_invalid')
        return minimize_result(reply['result'])


class McpGateway:
    def __init__(self, vault):
        if not isinstance(vault, ProviderVault):
            raise ValueError('provider_vault_required')
        self.vault = vault

    def _secret(self, conn, row):
        secret = conn.execute('''SELECT * FROM gabriel_identity.mcp_connection_secrets
            WHERE organization_id=%s AND connection_id=%s AND revoked_at IS NULL''',
            (row['organization_id'], row['id'])).fetchone()
        if not secret:
            return None
        try:
            self.vault._register_key(conn, secret['key_id'])
            return AESGCM(self.vault._ring._key(secret['key_id'])).decrypt(
                bytes(secret['nonce']), bytes(secret['ciphertext']), _aad(secret, secret['key_id'])).decode('utf-8')
        except (InvalidTag, UnicodeError, ValueError, TypeError):
            raise SecretUnavailable('mcp_secret_integrity_failed') from None

    def register(self, token, name, target, roles, *, bearer_token=None):
        name, target, roles = _name(name), normalize_endpoint(target), _roles(roles)
        if bearer_token is not None:
            bearer_token = _credential(bearer_token)
        with connection(self.vault._dsn) as conn:
            principal = self.vault._admin(conn, token)
            self.vault._active(conn, principal)
            if conn.execute('SELECT 1 FROM gabriel_identity.mcp_connections WHERE organization_id=%s AND name=%s', (principal.organization_id, name)).fetchone():
                raise AccessDenied('mcp_name_already_registered')
            connection_id = uuid4()
            row = conn.execute('''INSERT INTO gabriel_identity.mcp_connections
                (organization_id,id,name,endpoint,roles,auth_mode,tool_manifest,created_by)
                VALUES (%s,%s,%s,%s,%s,%s,%s,%s) RETURNING *''',
                (principal.organization_id, connection_id, name, target, roles,
                 'bearer' if bearer_token else 'none', json.dumps([]), principal.user_id)).fetchone()
            if bearer_token:
                key_id, nonce = self.vault._ring.active, os.urandom(12)
                self.vault._register_key(conn, key_id)
                ciphertext = AESGCM(self.vault._ring._key(key_id)).encrypt(nonce, bearer_token.encode('utf-8'), _aad(dict(row, revision=1), key_id))
                conn.execute('''INSERT INTO gabriel_identity.mcp_connection_secrets
                    (organization_id,connection_id,revision,key_id,nonce,ciphertext,updated_by)
                    VALUES (%s,%s,1,%s,%s,%s,%s)''',
                    (principal.organization_id, connection_id, key_id, nonce, ciphertext, principal.user_id))
            _audit(conn, 'mcp.connection_registered', principal, connection_id)
        return dict(id=str(connection_id), name=name, endpoint=target, roles=roles, status='registered')

    def list(self, token):
        with connection(self.vault._dsn) as conn:
            principal = self.vault._human(conn, token)
            rows = conn.execute('''SELECT id,name,endpoint,roles,auth_mode,status,tool_manifest,tool_manifest_digest,
                    checked_at,created_at,revoked_at FROM gabriel_identity.mcp_connections
                WHERE organization_id=%s ORDER BY name LIMIT 64''', (principal.organization_id,)).fetchall()
            return [dict(id=str(row['id']), name=row['name'], endpoint=row['endpoint'], roles=list(row['roles']),
                auth_mode=row['auth_mode'], status=row['status'], tool_count=len(row['tool_manifest'] or []),
                tool_manifest_digest=row['tool_manifest_digest'], checked_at=row['checked_at'].isoformat() if row['checked_at'] else None,
                revoked=bool(row['revoked_at'])) for row in rows]

    def refresh(self, token, connection_id):
        connection_id = str(connection_id)
        with connection(self.vault._dsn) as conn:
            principal = self.vault._admin(conn, token)
            row = conn.execute('''SELECT * FROM gabriel_identity.mcp_connections
                WHERE organization_id=%s AND id=%s AND revoked_at IS NULL FOR UPDATE''',
                (principal.organization_id, connection_id)).fetchone()
            if not row:
                raise AccessDenied('mcp_connection_not_accessible')
            secret = self._secret(conn, row)
        try:
            manifest = McpTransport(row['endpoint'], secret).manifest()
            status, error = ('ready' if manifest else 'degraded'), None
        except ProbeError as exc:
            manifest, status, error = [], 'degraded', exc.code
        with connection(self.vault._dsn) as conn:
            principal = self.vault._admin(conn, token)
            digest = sha256(canonical(manifest)).hexdigest()
            conn.execute('''UPDATE gabriel_identity.mcp_connections SET tool_manifest=%s,tool_manifest_digest=%s,
                    status=%s,last_error=%s,checked_at=clock_timestamp(),updated_at=clock_timestamp(),updated_by=%s
                WHERE organization_id=%s AND id=%s AND revoked_at IS NULL''',
                (json.dumps(manifest), digest, status, error, principal.user_id, principal.organization_id, connection_id))
            _audit(conn, 'mcp.manifest_refreshed', principal, connection_id)
        return dict(id=connection_id, status=status, tool_count=len(manifest), tool_manifest_digest=digest, error=error)

    def revoke(self, token, connection_id):
        with connection(self.vault._dsn) as conn:
            principal = self.vault._admin(conn, token)
            row = conn.execute('''UPDATE gabriel_identity.mcp_connections SET status='revoked',revoked_at=clock_timestamp(),
                    updated_at=clock_timestamp(),updated_by=%s WHERE organization_id=%s AND id=%s AND revoked_at IS NULL RETURNING id''',
                (principal.user_id, principal.organization_id, str(connection_id))).fetchone()
            if not row:
                raise AccessDenied('mcp_connection_not_accessible')
            conn.execute('UPDATE gabriel_identity.mcp_connection_secrets SET revoked_at=clock_timestamp() WHERE organization_id=%s AND connection_id=%s', (principal.organization_id, row['id']))
            _audit(conn, 'mcp.connection_revoked', principal, row['id'])

    def read(self, token, connection_id, role, tool, arguments):
        role_name(role)
        with connection(self.vault._dsn) as conn:
            principal = self.vault._human(conn, token, write=True, content=True)
            row = conn.execute('''SELECT * FROM gabriel_identity.mcp_connections
                WHERE organization_id=%s AND id=%s AND revoked_at IS NULL''',
                (principal.organization_id, str(connection_id))).fetchone()
            if not row or role not in row['roles'] or row['status'] != 'ready':
                raise AccessDenied('mcp_connection_scope_denied')
            admitted = next((t for t in row['tool_manifest'] if t.get('name') == tool), None)
            if not admitted or not admitted.get('annotations', {}).get('readOnlyHint'):
                raise AccessDenied('mcp_tool_not_admitted')
            secret = self._secret(conn, row)
        result = McpTransport(row['endpoint'], secret).call(tool, arguments)
        with connection(self.vault._dsn) as conn:
            principal = self.vault._human(conn, token, write=True, content=True)
            _audit(conn, 'mcp.read_completed', principal, row['id'])
        return dict(connection_id=str(row['id']), connection_name=row['name'], role=role, tool=tool, **result)
