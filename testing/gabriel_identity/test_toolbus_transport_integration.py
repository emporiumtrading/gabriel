"""Tool-bus services require certificate-verified TLS and the installation token."""
import http.client
import os
from pathlib import Path
import socket
import ssl

import pytest

pytestmark=pytest.mark.integration


def services():
    rows=[]
    if os.environ.get('GABRIEL_REQUIRE_TOOLBOX')=='1': rows.append(('investigation-tools',8450))
    if os.environ.get('GABRIEL_REQUIRE_HERMES')=='1': rows.append(('hermes',8451))
    return rows


@pytest.mark.parametrize('host,port',services())
def test_plaintext_and_unauthenticated_requests_are_denied(host,port):
    with socket.create_connection((host,port),timeout=3) as client:
        client.sendall(b'GET /health HTTP/1.1\r\nHost: '+host.encode()+b'\r\nConnection: close\r\n\r\n')
        try: raw=client.recv(128)
        except ConnectionResetError: raw=b''
    assert not raw.startswith(b'HTTP/1.1 200')

    context=ssl.create_default_context(cafile=os.environ['GABRIEL_TOOLBUS_CA_FILE'])
    client=http.client.HTTPSConnection(host,port,context=context,timeout=3)
    try:
        client.request('GET','/health',headers={'Authorization':'Bearer invalid'})
        response=client.getresponse();response.read()
        assert response.status==403
    finally: client.close()

    token=Path(os.environ['GABRIEL_TOOLBUS_TOKEN_FILE']).read_text().strip()
    client=http.client.HTTPSConnection(host,port,context=context,timeout=3)
    try:
        client.request('GET','/health',headers={'Authorization':'Bearer '+token})
        response=client.getresponse();response.read()
        assert response.status==200
    finally: client.close()
