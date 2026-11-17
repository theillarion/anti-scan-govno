import datetime as dt
import os
from pathlib import Path
import tempfile
import unittest
from unittest import mock

import nftguard as guard


class GuardTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.state = mock.patch.object(guard, 'STATE', Path(self.temp.name))
        self.state.start()
        self.addCleanup(self.state.stop)
        self.env = mock.patch.dict(os.environ, {'TZ': 'UTC', 'RETRIES': '0'}, clear=True)
        self.env.start()
        self.addCleanup(self.env.stop)
        self.cfg = guard.config()

    def test_parsing_and_allowlist_validation(self):
        result = guard.networks('192.0.2.7/24 # comment\n2001:db8::1\nbad')
        self.assertEqual({str(x) for x in result}, {'192.0.2.0/24', '2001:db8::1/128'})
        with mock.patch.dict(os.environ, {'ALLOW_CIDRS': '2001:db8::1/128'}):
            with self.assertRaises(ValueError):
                guard.config()

    def test_render_exceptions_before_drops_and_optional_output(self):
        self.cfg['allow4'] = guard.networks('192.0.2.1')
        sets = {'src_v4': guard.networks('192.0.2.0/24'), 'src_v6': set()}
        rules = guard.render(sets, self.cfg)
        self.assertLess(rules.index('192.0.2.1/32'), rules.index('@src_v4 drop'))
        self.assertNotIn('chain output', rules)
        self.cfg['vk'] = True
        sets.update(vk_v4=set(), vk_v6=set())
        self.assertIn('chain output', guard.render(sets, self.cfg))

    def test_invalid_required_source_keeps_current(self):
        current = guard.STATE / 'current.nft'
        current.write_text('old')
        with mock.patch.object(guard, 'fetch', return_value='192.0.2.0/24'), mock.patch.object(guard, 'apply') as apply:
            self.assertFalse(guard.update(self.cfg))
            apply.assert_not_called()
        self.assertEqual(current.read_text(), 'old')
        self.assertTrue(guard.status_read()['last_error'])

    def test_optional_failure_and_dry_run(self):
        self.cfg['dry'] = True
        sources = {'c24_v4': '\n'.join(f'10.0.{i}.0/24' for i in range(100)),
                   'c24_v6': '2001:db8::/32'}
        def fetch(name, cfg):
            if name == 'anti':
                raise RuntimeError('unavailable')
            return sources[name]
        with mock.patch.object(guard, 'fetch', side_effect=fetch), mock.patch.object(guard, 'apply') as apply:
            self.assertTrue(guard.update(self.cfg))
            apply.assert_not_called()
        self.assertEqual(guard.status_read()['sources'], ['c24_v4', 'c24_v6'])
        self.assertFalse((guard.STATE / 'current.nft').exists())
        self.assertTrue(guard.health(self.cfg))

    def test_empty_ipv6_source_applies_other_lists_and_reports_warning(self):
        sources = {'c24_v4': '\n'.join(f'10.0.{i}.0/24' for i in range(100)),
                   'c24_v6': '',
                   'anti': '\n'.join(f'10.1.{i}.0/24' for i in range(100)) + '\n2001:db8::/32'}
        with mock.patch.object(guard, 'fetch', side_effect=lambda name, cfg: sources[name]), \
             mock.patch.object(guard, 'apply') as apply, \
             self.assertLogs('nftguard', level='WARNING') as logs:
            self.assertTrue(guard.update(self.cfg))
        self.assertIn('source=c24_v6 reason=empty_list', logs.output[0])
        self.assertIn('2001:db8::/32', apply.call_args.args[0])
        self.assertEqual(guard.status_read()['empty_sources'], ['c24_v6'])
        self.assertIsNone(guard.status_read()['last_error'])

    def test_invalid_nonempty_ipv6_source_does_not_apply(self):
        sources = {'c24_v4': '\n'.join(f'10.0.{i}.0/24' for i in range(100)),
                   'c24_v6': 'not an IPv6 list'}
        with mock.patch.object(guard, 'fetch', side_effect=lambda name, cfg: sources[name]), \
             mock.patch.object(guard, 'apply') as apply:
            self.assertFalse(guard.update(self.cfg))
        apply.assert_not_called()
        self.assertIn('c24_v6 count 0', guard.status_read()['last_error'])

    def test_stale_and_changed_config_health(self):
        self.assertFalse(guard.fresh({'last_success': (dt.datetime.now(dt.timezone.utc) - dt.timedelta(hours=27)).isoformat()}))
        old = guard.config_hash(self.cfg)
        self.cfg['vk'] = True
        self.assertNotEqual(old, guard.config_hash(self.cfg))

    def test_batch_replaces_existing_atomically(self):
        replies = [mock.Mock(returncode=0), mock.Mock(), mock.Mock(), mock.Mock()]
        with mock.patch.object(guard, 'nft', side_effect=replies) as nft:
            guard.apply('table inet nftguard {}\n')
        self.assertTrue((guard.STATE / 'new.nft').read_text().startswith('delete table inet nftguard\n'))
        self.assertEqual(nft.call_args_list[1].args[:2], ('-c', '-f'))


if __name__ == '__main__':
    unittest.main()
