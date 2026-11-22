import os
from pathlib import Path
import tempfile
import unittest
from unittest import mock

import nftguard as guard


class CustomListTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.custom = self.root / 'custom'
        self.custom.mkdir()
        self.state = self.root / 'state'
        self.state.mkdir()
        patches = [mock.patch.object(guard, 'CUSTOM_DIR', self.custom),
                   mock.patch.object(guard, 'STATE', self.state),
                   mock.patch.dict(os.environ, {'TZ': 'UTC', 'RETRIES': '0'}, clear=True)]
        for patch in patches:
            patch.start()
            self.addCleanup(patch.stop)
        self.cfg = guard.config()
        self.sources = {'c24_v4': '\n'.join(f'10.0.{i}.0/24' for i in range(100)),
                        'c24_v6': '2001:db8::/32', 'anti': ''}

    def test_missing_empty_comments_and_normalization(self):
        (self.custom / 'input-v4.txt').write_text('# header\n192.0.2.5/24 # example\n\n')
        (self.custom / 'input-v6.txt').write_text('2001:db8::1\n')
        lists = guard.custom_lists()
        self.assertEqual({str(net) for net in lists['input-v4.txt']}, {'192.0.2.0/24'})
        self.assertEqual({str(net) for net in lists['input-v6.txt']}, {'2001:db8::1/128'})
        self.assertFalse(lists['output-v4.txt'])
        self.assertFalse(lists['output-v6.txt'])

    def test_invalid_files_preserve_existing_rules(self):
        current = self.state / 'current.nft'
        current.write_text('previous rules')
        for filename, value, message in [('input-v4.txt', 'invalid', 'invalid IP'),
                                         ('input-v6.txt', '192.0.2.1', 'wrong address family'),
                                         ('output-v4.txt', '2001:db8::1', 'wrong address family')]:
            with self.subTest(filename=filename):
                path = self.custom / filename
                path.write_text(value)
                with mock.patch.object(guard, 'apply') as apply:
                    self.assertFalse(guard.update(self.cfg))
                apply.assert_not_called()
                self.assertEqual(current.read_text(), 'previous rules')
                self.assertIn(message, guard.status_read()['last_error'])
                path.unlink()

    def test_user_input_merged_and_file_changes_health(self):
        (self.custom / 'input-v4.txt').write_text('192.0.2.3\n')
        (self.custom / 'input-v6.txt').write_text('2001:db8:ffff::/48\n')
        self.cfg['dry'] = True
        with mock.patch.object(guard, 'fetch', side_effect=lambda name, cfg: self.sources[name]):
            self.assertTrue(guard.update(self.cfg))
        self.assertEqual(guard.status_read()['custom_counts']['input-v4.txt'], 1)
        self.assertTrue(guard.health(self.cfg))
        (self.custom / 'input-v4.txt').write_text('192.0.2.4\n')
        self.assertFalse(guard.health(self.cfg))
        (self.custom / 'input-v4.txt').write_text('invalid')
        self.assertFalse(guard.health(self.cfg))

    def test_size_and_count_limits(self):
        path = self.custom / 'input-v4.txt'
        path.write_text('192.0.2.1\n')
        with mock.patch.object(guard, 'LIMIT', 0):
            with self.assertRaisesRegex(ValueError, 'element limit'):
                guard.custom_lists()

    def test_output_lists_apply_without_vk_and_with_vk(self):
        (self.custom / 'output-v4.txt').write_text('192.0.2.2')
        (self.custom / 'output-v6.txt').write_text('2001:db8:ffff::1')
        for vk_enabled in (False, True):
            with self.subTest(vk_enabled=vk_enabled):
                self.cfg['vk'] = vk_enabled
                self.sources['vk'] = '\n'.join(f'192.0.2.{i}' for i in range(10))
                with mock.patch.object(guard, 'fetch', side_effect=lambda name, cfg: self.sources[name]), \
                     mock.patch.object(guard, 'apply') as apply:
                    self.assertTrue(guard.update(self.cfg))
                rules = apply.call_args.args[0]
                self.assertIn('ip daddr @custom_out_v4 drop', rules)
                self.assertIn('ip6 daddr @custom_out_v6 drop', rules)
                self.assertEqual('ip daddr @external_out_v4 drop' in rules, vk_enabled)
        with mock.patch.object(Path, 'open', mock.mock_open(read_data='x' * 20_000_001)):
            with self.assertRaisesRegex(ValueError, 'size limit'):
                guard.custom_lists()
