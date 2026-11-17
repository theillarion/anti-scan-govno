import datetime as dt
import io
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest import mock

import nftguard as guard


class ExtendedTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.state = Path(self.temp.name)
        self.stack = mock.patch.object(guard, 'STATE', self.state)
        self.stack.start()
        self.addCleanup(self.stack.stop)
        self.env = mock.patch.dict(os.environ, {'TZ': 'UTC', 'RETRIES': '0'}, clear=True)
        self.env.start()
        self.addCleanup(self.env.stop)
        self.cfg = guard.config()

    def test_invalid_configuration(self):
        for name, value in [('DRY_RUN', 'maybe'), ('ALLOW_CIDRS', 'bad'),
                            ('UPDATE_AT', '24:00'), ('HTTP_TIMEOUT', 'abc'),
                            ('HTTP_TIMEOUT', '0'), ('RETRIES', '21'), ('LOG_LEVEL', 'bad'),
                            ('BOOT_DELAY_SECONDS', '-1'), ('BOOT_DELAY_SECONDS', '1.5')]:
            with self.subTest(name=name, value=value), mock.patch.dict(os.environ, {name: value}):
                with self.assertRaises(ValueError):
                    guard.config()

    def test_fetch_retry_and_failures(self):
        self.cfg['retries'] = 1
        with mock.patch.object(guard.urllib.request, 'urlopen', side_effect=[OSError('offline'), io.BytesIO(b'ok')]), \
             mock.patch.object(guard.time, 'sleep') as sleep:
            self.assertEqual(guard.fetch('anti', self.cfg), 'ok')
            sleep.assert_called_once_with(1)
        for payload in [b'\xff', b'x' * 20_000_001]:
            with self.subTest(size=len(payload)), mock.patch.object(guard.urllib.request, 'urlopen', return_value=io.BytesIO(payload)), \
                 mock.patch.object(guard.time, 'sleep'):
                with self.assertRaises(RuntimeError):
                    guard.fetch('anti', self.cfg)

    def test_render_limit(self):
        with mock.patch.object(guard, 'LIMIT', 0):
            with self.assertRaises(ValueError):
                guard.render({'src_v4': guard.networks('192.0.2.1')}, self.cfg)

    def test_nft_invocation(self):
        with mock.patch.object(guard.subprocess, 'run') as run:
            guard.nft('list', 'tables', check=False)
            run.assert_called_once_with(['nft', 'list', 'tables'], capture_output=True, text=True, check=False)

    def test_apply_rollback(self):
        (self.state / 'current.nft').write_text('table inet nftguard {}\n')
        failure = subprocess.CalledProcessError(1, ['nft'])
        replies = [mock.Mock(returncode=1), mock.Mock(), mock.Mock(), failure, mock.Mock(returncode=0), mock.Mock()]
        with mock.patch.object(guard, 'nft', side_effect=replies):
            with self.assertRaises(subprocess.CalledProcessError):
                guard.apply('table inet nftguard { }\n')
        self.assertTrue((self.state / 'rollback.nft').read_text().startswith('delete table inet nftguard\n'))

    def test_update_applies_vk_and_records_failure(self):
        self.cfg['vk'] = True
        sources = {'c24_v4': '\n'.join(f'10.0.{i}.0/24' for i in range(100)),
                   'c24_v6': '2001:db8::/32', 'anti': '\n'.join(f'10.1.{i}.0/24' for i in range(100)),
                   'vk': '\n'.join(f'192.0.2.{i}' for i in range(10))}
        with mock.patch.object(guard, 'fetch', side_effect=lambda name, cfg: sources[name]), \
             mock.patch.object(guard, 'apply') as apply:
            self.assertTrue(guard.update(self.cfg))
            self.assertTrue((self.state / 'current.nft').exists())
            self.assertIn('vk_v4', guard.status_read()['counts'])
            apply.assert_called_once()
        failure = subprocess.CalledProcessError(1, ['nft'], stderr='bad rules')
        with mock.patch.object(guard, 'fetch', side_effect=lambda name, cfg: sources[name]), \
             mock.patch.object(guard, 'apply', side_effect=failure):
            self.assertFalse(guard.update(self.cfg))
        self.assertEqual(guard.status_read()['last_error'], 'bad rules')

    def test_health_states(self):
        self.assertFalse(guard.fresh({}))
        self.assertFalse(guard.fresh({'last_success': 'invalid'}))
        self.assertFalse(guard.health(self.cfg))
        status = {'last_success': dt.datetime.now(dt.timezone.utc).isoformat(),
                  'config_hash': guard.config_hash(self.cfg), 'dry_run': False}
        guard.atomic_write(self.state / 'status.json', json.dumps(status))
        with mock.patch.object(guard, 'nft', return_value=mock.Mock(returncode=0)):
            self.assertTrue(guard.health(self.cfg))
        status['dry_run'] = True
        guard.atomic_write(self.state / 'status.json', json.dumps(status))
        self.assertFalse(guard.health(self.cfg))

    def test_main_commands(self):
        with mock.patch.object(guard.sys, 'argv', ['nftguard.py', 'healthcheck']):
            self.assertEqual(guard.main(), 1)
        with mock.patch.object(guard.sys, 'argv', ['nftguard.py', 'update']), \
             mock.patch.object(guard, 'wait_for_boot') as wait, \
             mock.patch.object(guard, 'update', return_value=True):
            self.assertEqual(guard.main(), 0)
            wait.assert_called_once_with(120)
        with mock.patch.object(guard.sys, 'argv', ['nftguard.py', 'unknown']):
            with self.assertRaises(ValueError):
                guard.main()

    def test_daemon_restore_and_schedule(self):
        status = {'last_success': dt.datetime.now(dt.timezone.utc).isoformat(),
                  'config_hash': guard.config_hash(self.cfg), 'dry_run': False}
        guard.atomic_write(self.state / 'status.json', json.dumps(status))
        (self.state / 'current.nft').write_text('saved')
        with mock.patch.object(guard.sys, 'argv', ['nftguard.py']), \
             mock.patch.object(guard, 'wait_for_boot'), \
             mock.patch.object(guard, 'apply', side_effect=OSError('failed')) as apply, \
             mock.patch.object(guard, 'update') as update, \
             mock.patch.object(guard.time, 'sleep', side_effect=InterruptedError):
            with self.assertRaises(InterruptedError):
                guard.main()
            apply.assert_called_once_with('saved')
            update.assert_called_once()
        (self.state / 'current.nft').unlink()
        with mock.patch.object(guard.sys, 'argv', ['nftguard.py']), \
             mock.patch.object(guard, 'wait_for_boot'), \
             mock.patch.object(guard, 'update') as update, \
             mock.patch.object(guard.time, 'sleep', side_effect=InterruptedError):
            with self.assertRaises(InterruptedError):
                guard.main()
            update.assert_called_once()

    def test_boot_delay_uses_system_uptime(self):
        for uptime, delay, expected in [(30, 120, 90), (120, 120, None),
                                        (500, 120, None), (30, 0, None)]:
            with self.subTest(uptime=uptime, delay=delay), \
                 mock.patch.object(Path, 'read_text', return_value=f'{uptime} 0') as read, \
                 mock.patch.object(guard.time, 'sleep') as sleep:
                guard.wait_for_boot(delay)
                if expected is None:
                    sleep.assert_not_called()
                else:
                    sleep.assert_called_once_with(expected)
                if delay:
                    read.assert_called_once()

    def test_boot_delay_blocks_update_and_restore_until_wait_finishes(self):
        with mock.patch.object(guard.sys, 'argv', ['nftguard.py', 'update']), \
             mock.patch.object(guard, 'wait_for_boot', side_effect=InterruptedError), \
             mock.patch.object(guard, 'update') as update:
            with self.assertRaises(InterruptedError):
                guard.main()
            update.assert_not_called()
        with mock.patch.object(guard.sys, 'argv', ['nftguard.py']), \
             mock.patch.object(guard, 'wait_for_boot', side_effect=InterruptedError), \
             mock.patch.object(guard, 'apply') as apply, mock.patch.object(guard, 'update') as update:
            with self.assertRaises(InterruptedError):
                guard.main()
            apply.assert_not_called()
            update.assert_not_called()

    def test_dry_run_does_not_wait_for_boot(self):
        with mock.patch.dict(os.environ, {'DRY_RUN': 'true'}), \
             mock.patch.object(guard.sys, 'argv', ['nftguard.py', 'update']), \
             mock.patch.object(guard, 'wait_for_boot') as wait, \
             mock.patch.object(guard, 'update', return_value=True):
            self.assertEqual(guard.main(), 0)
            wait.assert_not_called()
