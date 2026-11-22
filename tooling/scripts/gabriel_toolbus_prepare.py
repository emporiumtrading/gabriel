#!/usr/bin/env python3
"""Generate a private CA, server identity and bearer token for Gabriel's tool bus."""
import argparse
import os
from pathlib import Path
import secrets
import stat
import subprocess


def run(*args):
    subprocess.run(args,check=True,stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,env={'PATH':os.environ.get('PATH','/usr/bin:/bin')})


def prepare(directory):
    directory=directory.resolve()
    repo=Path(__file__).resolve().parents[2]
    if directory==repo or repo in directory.parents or directory.exists():
        raise ValueError('new external toolbus directory required')
    directory.mkdir(mode=0o700)
    ca_key=directory/'ca.key';ca=directory/'ca.pem';key=directory/'server.key'
    request=directory/'server.csr';certificate=directory/'server.pem';extensions=directory/'extensions.cnf'
    extensions.write_text('subjectAltName=DNS:hermes,DNS:investigation-tools,DNS:localhost,IP:127.0.0.1\n'
        'extendedKeyUsage=serverAuth\nkeyUsage=critical,digitalSignature,keyEncipherment\n')
    run('openssl','req','-x509','-newkey','rsa:3072','-nodes','-days','31','-sha256',
        '-subj','/CN=Gabriel private tool bus CA','-keyout',str(ca_key),'-out',str(ca))
    run('openssl','req','-new','-newkey','rsa:3072','-nodes','-sha256','-subj','/CN=Gabriel tool bus',
        '-keyout',str(key),'-out',str(request))
    run('openssl','x509','-req','-in',str(request),'-CA',str(ca),'-CAkey',str(ca_key),'-CAcreateserial',
        '-days','30','-sha256','-extfile',str(extensions),'-out',str(certificate))
    (directory/'token').write_text(secrets.token_hex(32)+'\n')
    for path in directory.iterdir():
        if path.name not in {'ca.pem','server.pem','server.key','token'}: path.unlink()
    for path in directory.iterdir(): path.chmod(stat.S_IRUSR|stat.S_IRGRP|stat.S_IROTH)
    return directory


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('directory',type=Path)
    args=parser.parse_args()
    try: prepare(args.directory)
    except (ValueError,OSError,subprocess.SubprocessError) as exc: parser.exit(2,str(exc)+'\n')
    print('Prepared private tool-bus transport material; no credentials printed.')


if __name__=='__main__': main()
