"""Run in an isolated Docker network namespace with CAP_NET_ADMIN."""
import os
from pathlib import Path
import subprocess
import tempfile
from unittest import mock

import nftguard as g

with tempfile.TemporaryDirectory() as state:
    g.STATE = Path(state)
    os.environ.update(TZ='UTC', RETRIES='0', ENABLE_VK_OUTPUT='true', ALLOW_CIDRS='195.209.120.1')
    cfg = g.config()
    subprocess.run(['nft', 'add', 'table', 'inet', 'unrelated'], check=True)
    assert g.update(cfg)
    first = g.nft('list', 'table', 'inet', 'nftguard').stdout
    assert 'vk_v4' in first and 'vk_v6' in first and 'src_v6' in first
    assert '195.209.120.1' in first
    assert g.health(cfg)
    assert g.update(cfg)
    assert g.nft('list', 'table', 'inet', 'unrelated').returncode == 0
    with mock.patch.object(g, 'fetch', return_value='invalid'):
        assert not g.update(cfg)
    assert g.nft('list', 'table', 'inet', 'nftguard').returncode == 0
    cfg['vk'] = False
    assert not g.health(cfg)
    assert g.update(cfg)
    assert 'vk_v4' not in g.nft('list', 'table', 'inet', 'nftguard').stdout
    saved = (g.STATE / 'current.nft').read_text()
    g.nft('delete', 'table', 'inet', 'nftguard')
    g.apply(saved)
    assert g.health(cfg)
    print('Integration: repeated update, foreign table, failure, VK toggle, restore, health passed')
