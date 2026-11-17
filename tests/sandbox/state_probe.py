"""Run through the production entrypoint in an isolated network namespace."""
import os
from pathlib import Path
import subprocess
import sys

state = Path('/var/lib/nftguard')
uid = int(os.environ['EXPECTED_UID'])
gid = int(os.environ['EXPECTED_GID'])
assert (os.getuid(), os.getgid()) == (uid, gid)
assert (state.stat().st_uid, state.stat().st_gid) == (uid, gid)
assert sys.argv[1:] == ['probe-argument']
fields = {}
for line in Path('/proc/self/status').read_text().splitlines():
    if line.startswith(('CapEff:', 'CapPrm:', 'CapBnd:', 'CapAmb:')):
        key, value = line.split(':', 1)
        fields[key] = int(value.strip(), 16)
assert fields['CapEff'] == 1 << 12, fields
assert fields['CapPrm'] == 1 << 12, fields
assert fields['CapBnd'] == 1 << 12, fields
if uid:
    assert fields['CapAmb'] == 1 << 12, fields
(state / 'state.tmp').write_text('ok')
(state / 'state.tmp').replace(state / 'status.json')
assert (state / 'status.json').stat().st_uid == uid
subprocess.run(['nft', 'add', 'table', 'inet', 'probe'], check=True)
print(f'Entrypoint UID={uid} GID={gid}, only NET_ADMIN retained; state write and nft succeeded')
