"""Verify actual Docker isolation without printing environment values."""
import json
from pathlib import Path
import sys

row=json.loads(Path(sys.argv[1]).read_text())[0]
assert row['Config']['User']=='10001:10001'
assert row['HostConfig']['ReadonlyRootfs'] and row['HostConfig']['CapDrop']==['ALL']
assert 'no-new-privileges:true' in row['HostConfig']['SecurityOpt']
assert not row['HostConfig']['PortBindings']
assert all(m['Type']=='tmpfs' and m['Destination']=='/tmp' for m in row['Mounts'])
assert list(row['NetworkSettings']['Networks'])==['gabriel-hermes-check_toolbus']
allowed={'GABRIEL_TOOLBUS_CA_FILE','GABRIEL_TOOLBUS_CERT_FILE','GABRIEL_TOOLBUS_KEY_FILE','GABRIEL_TOOLBUS_TOKEN_FILE'}
assert not any(e.split('=',1)[0].startswith(('GABRIEL_','OPENROUTER_','OPENAI_API_KEY','ANTHROPIC_API_KEY','DATABASE_')) and e.split('=',1)[0] not in allowed for e in row['Config']['Env'])
print('Required Hermes isolation verified: authenticated TLS identity only; no application credentials, host ports, persistent mounts or database network.')
