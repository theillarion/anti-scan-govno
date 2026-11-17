"""Exercise the production image entrypoint with user- and root-owned state."""
from pathlib import Path
import subprocess
import uuid

volume = f'nftguard-state-test-{uuid.uuid4().hex}'
image = 'nftguard-product-test'
probe = Path('tests/sandbox/state_probe.py').resolve()


def run(*args):
    return subprocess.run(['docker', *args], check=True, capture_output=True, text=True)


run('volume', 'create', volume)
try:
    mount = f'{volume}:/var/lib/nftguard'
    for uid, gid in [(1001, 27), (0, 0)]:
        run('run', '--rm', '--network', 'none', '--entrypoint', 'sh',
            '-v', mount, image, '-c', f'chown {uid}:{gid} /var/lib/nftguard && chmod 755 /var/lib/nftguard && rm -f /var/lib/nftguard/status.json')
        result = run('run', '--rm', '--network', 'none', '--read-only', '--cap-drop', 'ALL',
                     '--cap-add', 'NET_ADMIN', '--cap-add', 'SETUID', '--cap-add', 'SETGID',
                     '--cap-add', 'SETPCAP', '--security-opt', 'no-new-privileges:true',
                     '-e', f'EXPECTED_UID={uid}', '-e', f'EXPECTED_GID={gid}',
                     '-v', mount, '-v', f'{probe}:/usr/local/bin/nftguard:ro', image, 'probe-argument')
        print(result.stdout.strip())
finally:
    run('volume', 'rm', volume)
