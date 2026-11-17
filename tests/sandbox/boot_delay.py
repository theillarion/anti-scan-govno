"""Exercise boot-delay handling with the real host uptime and nftables."""
import datetime as dt
import json
import math
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time

import nftguard as guard


def exists():
    return subprocess.run(['nft', 'list', 'table', 'inet', 'nftguard'], capture_output=True).returncode == 0


def wait_until_applied(process, timeout):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if exists():
            return
        if process.poll() is not None:
            raise AssertionError(f'daemon exited early: {process.returncode}')
        time.sleep(.1)
    raise AssertionError('rules were not restored before the deadline')


def stop(process):
    process.terminate()
    process.wait(timeout=5)


with tempfile.TemporaryDirectory() as state:
    delay = math.ceil(float(Path('/proc/uptime').read_text().split()[0])) + 4
    env = dict(os.environ, STATE_DIR=state, BOOT_DELAY_SECONDS=str(delay), DRY_RUN='false', TZ='UTC')
    cfg = guard.config()
    status = {'last_success': dt.datetime.now(dt.timezone.utc).isoformat(),
              'config_hash': guard.config_hash(cfg), 'dry_run': False}
    Path(state, 'status.json').write_text(json.dumps(status))
    sets = {'src_v4': set(), 'src_v6': set()}
    Path(state, 'current.nft').write_text(guard.render(sets, cfg))
    process = subprocess.Popen([sys.executable, '/work/nftguard.py'], env=env)
    try:
        time.sleep(.5)
        assert not exists(), 'rules applied during the boot delay'
        wait_until_applied(process, 12)
    finally:
        stop(process)
    subprocess.run(['nft', 'delete', 'table', 'inet', 'nftguard'], check=True)
    process = subprocess.Popen([sys.executable, '/work/nftguard.py'], env=env)
    try:
        wait_until_applied(process, 2)
    finally:
        stop(process)
print('Sandbox boot delay: waits for host uptime, container restart does not restart delay')
