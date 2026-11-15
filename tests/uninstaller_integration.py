"""Exercise removal in a Debian container with its own nftables namespace."""
import os
from pathlib import Path
import pty
import select
import subprocess
import tempfile


def run_installer(dest, confirmation):
    pid, master = pty.fork()
    if pid == 0:
        os.execv('/bin/bash', ['bash', '/work/uninstall.sh'])
    transcript = b''
    for prompt, answer in [(b']:', str(dest)), (b'confirm:', confirmation)]:
        while prompt not in transcript:
            ready, _, _ = select.select([master], [], [], 10)
            if not ready:
                raise RuntimeError(f'prompt timeout: {transcript!r}')
            transcript += os.read(master, 8192)
        transcript = b''
        os.write(master, (answer + '\n').encode())
    _, status = os.waitpid(pid, 0)
    os.close(master)
    assert os.waitstatus_to_exitcode(status) == 0


with tempfile.TemporaryDirectory() as tmp:
    root = Path(tmp)
    bins = root / 'bin'
    bins.mkdir()
    docker = bins / 'docker'
    docker.write_text('#!/bin/sh\necho "$*" >> "$DOCKER_LOG"\n')
    docker.chmod(0o755)
    os.environ['PATH'] = str(bins) + ':' + os.environ['PATH']
    os.environ['DOCKER_LOG'] = str(root / 'docker.log')
    dest = root / 'installed'
    dest.mkdir()
    for filename in ['compose.yaml', 'nftguard.py', 'Dockerfile']:
        (dest / filename).touch()
    subprocess.run(['nft', 'add', 'table', 'inet', 'nftguard'], check=True)
    subprocess.run(['nft', 'add', 'table', 'inet', 'unrelated'], check=True)
    run_installer(dest, 'no')
    assert dest.exists()
    assert subprocess.run(['nft', 'list', 'table', 'inet', 'nftguard'], capture_output=True).returncode == 0
    run_installer(dest, 'DELETE')
    assert not dest.exists()
    assert subprocess.run(['nft', 'list', 'table', 'inet', 'nftguard'], capture_output=True).returncode != 0
    assert subprocess.run(['nft', 'list', 'table', 'inet', 'unrelated'], capture_output=True).returncode == 0
    commands = (root / 'docker.log').read_text()
    assert 'compose stop nftguard' in commands
    assert 'compose down --rmi local' in commands
    print('Uninstaller: cancellation, stop, nft table removal, unrelated table and directory removal passed')
