"""Private-network toolbox: bounded stdin, fixed subprocess, no secrets or mounts."""
import base64
from hashlib import sha256
import hmac
import http.client
from http.server import BaseHTTPRequestHandler,HTTPServer
from importlib.metadata import version
import json
import os
from pathlib import Path
import ssl
import subprocess
import sys

MAX_WIRE=1500000
TOOLS={'scan_artifacts','inspect_packets','inspect_logs'}
ENGINE=Path(__file__).with_name('engine.py')


def secret(name):
    return Path(os.environ[name]).read_text().strip()


class Handler(BaseHTTPRequestHandler):
    def log_message(self,*args):pass

    def reply(self,status,body):
        raw=json.dumps(body,sort_keys=True).encode()
        self.send_response(status);self.send_header('Content-Type','application/json')
        self.send_header('Content-Length',str(len(raw)));self.end_headers();self.wfile.write(raw)

    def authenticated(self):
        return hmac.compare_digest(self.headers.get('Authorization',''),'Bearer '+secret('GABRIEL_TOOLBUS_TOKEN_FILE'))

    def do_GET(self):
        if not self.authenticated(): return self.reply(403,dict(status='denied'))
        if self.path!='/health':return self.reply(404,dict(status='not_found'))
        return self.reply(200,dict(status='ready',packages={p:version(p) for p in ('yara-python','dpkt')},
            tools=sorted(TOOLS),engine_sha256=sha256(ENGINE.read_bytes()).hexdigest(),credential_access=False,network_actions=False))

    def do_POST(self):
        try:
            if not self.authenticated(): return self.reply(403,dict(status='denied'))
            self.connection.settimeout(5)
            size=int(self.headers.get('Content-Length','0'))
            if self.path!='/analyze' or not 1<=size<=MAX_WIRE:raise ValueError
            if self.headers.get('Transfer-Encoding') or self.headers.get('Content-Type')!='application/json':raise ValueError
            doc=json.loads(self.rfile.read(size))
            if type(doc) is not dict or set(doc)!={'tool','data'} or doc['tool'] not in TOOLS:raise ValueError
            data=base64.b64decode(doc['data'],validate=True)
            if not 1<=len(data)<=1048576:raise ValueError
            completed=subprocess.run([sys.executable,'-I',str(ENGINE),doc['tool']],input=data,
                capture_output=True,timeout=5,check=False,close_fds=True,
                env={'PYTHONDONTWRITEBYTECODE':'1'},cwd='/tmp')
            if len(completed.stdout)>8192 or completed.returncode not in {0,2}:raise ValueError
            result=json.loads(completed.stdout)
            self.reply(200,result)
        except Exception:self.reply(422,dict(status='analysis_failed'))


class BoundedServer(HTTPServer):
    def get_request(self):
        sock,address=super().get_request()
        sock.settimeout(5)
        return sock,address


def main():
    if len(sys.argv)==2 and sys.argv[1]=='health':
        context=ssl.create_default_context(cafile=os.environ['GABRIEL_TOOLBUS_CA_FILE'])
        client=http.client.HTTPSConnection('127.0.0.1',8450,context=context,timeout=2)
        try:
            client.request('GET','/health',headers={'Authorization':'Bearer '+secret('GABRIEL_TOOLBUS_TOKEN_FILE')})
            response=client.getresponse();response.read()
            raise SystemExit(0 if response.status==200 else 1)
        finally: client.close()
    server=BoundedServer(('0.0.0.0',8450),Handler)
    context=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER);context.minimum_version=ssl.TLSVersion.TLSv1_2
    context.load_cert_chain(os.environ['GABRIEL_TOOLBUS_CERT_FILE'],os.environ['GABRIEL_TOOLBUS_KEY_FILE'])
    server.socket=context.wrap_socket(server.socket,server_side=True)
    server.serve_forever()


if __name__=='__main__':main()
