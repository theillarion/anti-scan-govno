import copy
import os
from pathlib import Path
import tempfile
import unittest
from unittest import mock

import yaml
import nftguard as guard


class SourceTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.config_file = self.root / 'sources.yaml'
        self.state = self.root / 'state'
        self.state.mkdir()
        self.sources = [
            {'name': 'text', 'url': 'https://example.test/list.txt', 'format': 'txt',
             'direction': 'input', 'required': True},
            {'name': 'nft', 'url': 'https://example.test/list.nft', 'format': 'nftables',
             'direction': 'output', 'required': True, 'enabled_when': 'EXTRA_OUTPUT'},
        ]
        self.write_sources()
        for patch in [mock.patch.object(guard, 'SOURCES_FILE', self.config_file),
                      mock.patch.object(guard, 'CUSTOM_DIR', self.root / 'custom'),
                      mock.patch.object(guard, 'STATE', self.state),
                      mock.patch.dict(os.environ, {'TZ': 'UTC', 'RETRIES': '0', 'EXTRA_OUTPUT': 'true'}, clear=True)]:
            patch.start()
            self.addCleanup(patch.stop)

    def write_sources(self):
        self.config_file.write_text(yaml.safe_dump({'sources': self.sources}))

    def test_default_sources_use_text_for_vk(self):
        with mock.patch.object(guard, 'SOURCES_FILE', Path(__file__).resolve().parents[1] / 'config' / 'sources.yaml'):
            sources = guard.load_sources()
        self.assertEqual([source['name'] for source in sources], ['c24_v4', 'c24_v6', 'anti', 'vk'])
        self.assertEqual(sources[-1]['format'], 'txt')
        self.assertTrue(sources[-1]['url'].endswith('blacklist-vk.txt'))
        self.assertFalse(sources[-1]['_enabled'])

    def test_txt_and_nftables_sources_can_be_added(self):
        cfg = guard.config()
        data = {'text': '192.0.2.1\n2001:db8::/32\n',
                'nft': 'set bad { elements = { 198.51.100.0/24, 2001:db8:1::/48 } }'}
        with mock.patch.object(guard, 'fetch', side_effect=lambda name, cfg: data[name]), \
             mock.patch.object(guard, 'apply') as apply:
            self.assertTrue(guard.update(cfg))
        rules = apply.call_args.args[0]
        self.assertIn('192.0.2.1/32', rules)
        self.assertIn('2001:db8::/32', rules)
        self.assertIn('198.51.100.0/24', rules)
        self.assertIn('2001:db8:1::/48', rules)
        self.assertIn('ip daddr @external_out_v4 drop', rules)
        self.assertEqual(guard.status_read()['sources'], ['text', 'nft'])

    def test_nftables_ranges_cover_every_address(self):
        data = 'elements = { 198.51.100.1-198.51.100.6, 2001:db8::1 - 2001:db8::3 }'
        entries = guard.networks(data, tokens=True)
        self.assertEqual(sum(net.num_addresses for net in entries if net.version == 4), 6)
        self.assertEqual(sum(net.num_addresses for net in entries if net.version == 6), 3)
        self.assertEqual(sum(net.num_addresses for net in guard.networks(data, 4, tokens=True)), 6)

    def test_optional_failure_and_required_failure(self):
        self.sources[1]['required'] = False
        self.write_sources()
        cfg = guard.config()
        def fetch(name, cfg):
            if name == 'nft':
                raise RuntimeError('offline')
            return '192.0.2.1'
        with mock.patch.object(guard, 'fetch', side_effect=fetch), mock.patch.object(guard, 'apply') as apply:
            self.assertTrue(guard.update(cfg))
            apply.assert_called_once()
        self.assertEqual(guard.status_read()['sources'], ['text'])
        previous = (self.state / 'current.nft').read_text()
        cfg['sources'][0]['required'] = True
        with mock.patch.object(guard, 'fetch', side_effect=RuntimeError('offline')), mock.patch.object(guard, 'apply') as apply:
            self.assertFalse(guard.update(cfg))
            apply.assert_not_called()
        self.assertEqual((self.state / 'current.nft').read_text(), previous)

    def test_switches_empty_and_thresholds(self):
        self.sources[0].update(allow_empty=True, min_entries=1, ip_version=6)
        self.sources[1].update(min_ipv4=2, max_ipv4=5)
        self.write_sources()
        cfg = guard.config()
        with mock.patch.object(guard, 'fetch', side_effect=lambda name, cfg: '' if name == 'text' else '198.51.100.1'), \
             mock.patch.object(guard, 'apply') as apply:
            self.assertFalse(guard.update(cfg))
            apply.assert_not_called()
        self.assertIn('nft_v4 count 1', guard.status_read()['last_error'])
        with mock.patch.dict(os.environ, {'EXTRA_OUTPUT': 'false'}):
            cfg = guard.config()
        with mock.patch.object(guard, 'fetch', return_value=''), mock.patch.object(guard, 'apply') as apply:
            self.assertTrue(guard.update(cfg))
            self.assertNotIn('chain output', apply.call_args.args[0])
        self.assertEqual(guard.status_read()['empty_sources'], ['text'])

    def test_config_hash_changes_with_sources(self):
        first = guard.config_hash(guard.config())
        self.sources[0]['url'] = 'https://example.test/changed.txt'
        self.write_sources()
        self.assertNotEqual(first, guard.config_hash(guard.config()))

    def test_rejects_invalid_configuration(self):
        cases = [
            ('missing URL', lambda item: item.pop('url')),
            ('invalid URL', lambda item: item.update(url='file:///etc/passwd')),
            ('format', lambda item: item.update(format='other')),
            ('direction', lambda item: item.update(direction='forward')),
            ('ip version', lambda item: item.update(ip_version=True)),
            ('required', lambda item: item.update(required='yes')),
            ('empty', lambda item: item.update(allow_empty='yes')),
            ('negative', lambda item: item.update(min_entries=-1)),
            ('thresholds', lambda item: item.update(min_ipv4=2, max_ipv4=1)),
            ('flag', lambda item: item.update(enabled_when='bad flag')),
            ('unknown', lambda item: item.update(typo=True)),
            ('name', lambda item: item.update(name='bad name')),
        ]
        for label, mutate in cases:
            with self.subTest(label=label):
                original = self.sources
                self.sources = copy.deepcopy(original)
                mutate(self.sources[0])
                self.write_sources()
                with self.assertRaises(ValueError):
                    guard.load_sources()
                self.sources = original
        self.sources[1]['name'] = self.sources[0]['name']
        self.write_sources()
        with self.assertRaises(ValueError):
            guard.load_sources()
        for text in ['[', 'sources: {}', '!!python/object/apply:os.system [echo unsafe]']:
            with self.subTest(text=text):
                self.config_file.write_text(text)
                with self.assertRaises(ValueError):
                    guard.load_sources()
