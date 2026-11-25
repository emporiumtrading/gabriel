"""Private bounded gateway; no credentials, database, evidence mounts or egress."""
from hashlib import sha256
import hmac
import http.client
from http.server import BaseHTTPRequestHandler,HTTPServer
import json
import os
from pathlib import Path
import subprocess
import tempfile
import ssl

from runtime import VERSION,UPSTREAM


def secret(name):
    return Path(os.environ[name]).read_text().strip()


def fingerprint():
    return sha256(b''.join((Path('/opt/gabriel-hermes')/name).read_bytes() for name in ('runtime.py','server.py','prepare_runtime.py','Dockerfile','requirements.lock'))).hexdigest()


class Handler(BaseHTTPRequestHandler):
    def setup(self):
        super().setup()
        self.connection.settimeout(5)

    def log_message(self,*args):pass

    def reply(self,status,body):
        data=json.dumps(body,separators=(',',':')).encode()
        self.send_response(status);self.send_header('Content-Type','application/json')
        self.send_header('Content-Length',str(len(data)));self.end_headers();self.wfile.write(data)

    def authenticated(self):
        return hmac.compare_digest(self.headers.get('Authorization',''),'Bearer '+secret('GABRIEL_TOOLBUS_TOKEN_FILE'))

    def do_GET(self):
        if not self.authenticated(): return self.reply(403,{'error':'denied'})
        if self.path!='/health':return self.reply(404,{'error':'not_found'})
        try:
            p=json.loads(Path('/etc/hermes/image-provenance.json').read_text())
            if p.get('revision')!=UPSTREAM or json.loads(Path('/opt/hermes/install-stamp.json').read_text()).get('commit')!=UPSTREAM:raise ValueError
            self.reply(200,dict(version=VERSION,upstream=UPSTREAM,runtime_digest=fingerprint()))
        except Exception:self.reply(503,{'error':'hermes_source_unavailable'})

    def do_POST(self):
        if not self.authenticated(): return self.reply(403,{'error':'denied'})
        if self.path!='/turn':return self.reply(404,{'error':'not_found'})
        try:
            n=int(self.headers.get('Content-Length','0'))
            if not 0<n<=32768 or self.headers.get('Content-Type')!='application/json':raise ValueError
            raw=self.rfile.read(n)
            if len(raw)!=n:raise ValueError
            # Each turn gets an empty home. Upstream skills, sessions and memory
            # cannot leak from one analyst's investigation into another's.
            with tempfile.TemporaryDirectory(prefix='hermes-') as home:
                env=dict(PATH='/opt/hermes/.venv/bin:/usr/bin:/bin',HOME=home,HERMES_HOME=home,
                    PYTHONDONTWRITEBYTECODE='1',PYTHONUNBUFFERED='1',HERMES_DISABLE_LAZY_INSTALLS='1')
                result=subprocess.run(['/opt/hermes/.venv/bin/python','/opt/gabriel-hermes/runtime.py'],input=raw,
                    stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,env=env,cwd=home,timeout=35,close_fds=True)
            if len(result.stdout)>32768:raise ValueError
            body=json.loads(result.stdout)
            if result.returncode:
                return self.reply(503,{k:body[k] for k in ('error','stage','error_type','code','frames','native_calls','stream','request_metadata') if k in body})
            if body.get('version')!=VERSION:raise ValueError
            self.reply(200,body)
        except Exception:self.reply(503,{'error':'hermes_turn_unavailable'})


if __name__=='__main__':
    if len(__import__('sys').argv)==2 and __import__('sys').argv[1]=='health':
        context=ssl.create_default_context(cafile=os.environ['GABRIEL_TOOLBUS_CA_FILE'])
        client=http.client.HTTPSConnection('127.0.0.1',8451,context=context,timeout=2)
        try:
            client.request('GET','/health',headers={'Authorization':'Bearer '+secret('GABRIEL_TOOLBUS_TOKEN_FILE')})
            response=client.getresponse();response.read()
            raise SystemExit(0 if response.status==200 else 1)
        finally: client.close()
    server=HTTPServer(('0.0.0.0',8451),Handler)
    server.timeout=40
    context=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER);context.minimum_version=ssl.TLSVersion.TLSv1_2
    context.load_cert_chain(os.environ['GABRIEL_TOOLBUS_CERT_FILE'],os.environ['GABRIEL_TOOLBUS_KEY_FILE'])
    server.socket=context.wrap_socket(server.socket,server_side=True)
    server.serve_forever()
