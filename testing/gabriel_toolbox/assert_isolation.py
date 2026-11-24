"""Read Docker metadata; never print environment values or secret material."""
import json
from pathlib import Path
import sys

row=json.loads(Path(sys.argv[1]).read_text())[0]
assert row['Config']['User']=='10001:10001'
assert row['HostConfig']['ReadonlyRootfs']
assert row['HostConfig']['CapDrop']==['ALL']
assert 'no-new-privileges:true' in row['HostConfig']['SecurityOpt']
assert not row['HostConfig']['PortBindings']
mounts={(m['Type'],m['Destination']):m for m in row['Mounts']}
expected={('bind','/run/secrets/toolbus_ca'),('bind','/run/secrets/toolbus_certificate'),
    ('bind','/run/secrets/toolbus_key'),('bind','/run/secrets/toolbus_token')}
assert set(mounts)==expected
tmpfs=row['HostConfig']['Tmpfs']
assert set(tmpfs)=={'/tmp'} and {'rw','noexec','nosuid','nodev'}<=set(tmpfs['/tmp'].split(','))
assert all(not mounts[key]['RW'] for key in expected)
assert list(row['NetworkSettings']['Networks'])==['gabriel-tool-check_toolbus']
allowed={'GABRIEL_TOOLBUS_CA_FILE','GABRIEL_TOOLBUS_CERT_FILE','GABRIEL_TOOLBUS_KEY_FILE','GABRIEL_TOOLBUS_TOKEN_FILE'}
assert not any(e.split('=',1)[0].startswith(('GABRIEL_','OPENROUTER_','OPENAI_','ANTHROPIC_','DATABASE_')) and e.split('=',1)[0] not in allowed for e in row['Config']['Env'])
print('Toolbox isolation verified: authenticated TLS identity only; no application credentials, host ports, persistent mounts or database network.')
