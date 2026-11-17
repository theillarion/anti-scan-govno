"""Verify nftguard can write state without changing its owner's UID or GID."""
import subprocess
import uuid

volume = f'nftguard-state-test-{uuid.uuid4().hex}'
image = 'nftguard-sandbox-test'


def run(*args, check=True):
    return subprocess.run(['docker', *args], check=check, capture_output=True, text=True)


run('volume', 'create', volume)
try:
    mount = f'{volume}:/state'
    run('run', '--rm', '--network', 'none', '-v', mount, image, 'sh', '-c',
        'chown 1001:27 /state && chmod 755 /state && '
        'echo old > /state/status.json && chown 1001:27 /state/status.json')
    script = '''
import os
from pathlib import Path
import nftguard
state = Path('/state')
assert (state.stat().st_uid, state.stat().st_gid) == (1001, 27)
nftguard.atomic_write(state / 'status.json', 'updated')
nftguard.atomic_write(state / 'new.nft', 'rules')
assert (state / 'status.json').read_text() == 'updated'
assert (state.stat().st_uid, state.stat().st_gid) == (1001, 27)
'''
    args = ('run', '--rm', '--network', 'none', '--read-only', '--cap-drop', 'ALL',
            '--cap-add', 'NET_ADMIN', '-v', mount, image, 'python', '-c', script)
    blocked = run(*args, check=False)
    assert blocked.returncode != 0 and 'PermissionError' in blocked.stderr, blocked.stderr
    run('run', '--rm', '--network', 'none', '--read-only', '--cap-drop', 'ALL',
        '--cap-add', 'NET_ADMIN', '--cap-add', 'DAC_OVERRIDE', '-v', mount,
        image, 'python', '-c', script)
    print('State directory: user ownership preserved, container can write with DAC_OVERRIDE')
finally:
    run('volume', 'rm', volume)
