#!/usr/bin/env python3
"""Download blocklists and atomically manage the isolated nftguard table."""
import datetime as dt
import hashlib
import ipaddress
import json
import logging
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

import yaml

STATE = Path(os.environ.get('STATE_DIR', '/var/lib/nftguard'))
CUSTOM_DIR = Path(os.environ.get('CUSTOM_DIR', '/etc/nftguard/custom'))
CUSTOM_FILES = {'input-v4.txt': 4, 'input-v6.txt': 6, 'output-v4.txt': 4, 'output-v6.txt': 6}
SOURCES_FILE = Path(os.environ.get('SOURCES_FILE', Path(__file__).with_name('config') / 'sources.yaml'))
LIMIT = 1_000_000
LOG = logging.getLogger('nftguard')


def boolean(name):
    value = os.environ.get(name, 'false').lower()
    if value not in ('true', 'false'):
        raise ValueError(f'{name} must be true or false')
    return value == 'true'


def load_sources():
    try:
        document = yaml.safe_load(SOURCES_FILE.read_text(encoding='utf-8'))
    except (yaml.YAMLError, UnicodeError) as exc:
        raise ValueError(f'invalid sources file: {exc}') from exc
    if not isinstance(document, dict) or set(document) != {'sources'} or not isinstance(document['sources'], list):
        raise ValueError('sources file must contain a sources list')
    allowed_keys = {'name', 'url', 'format', 'direction', 'ip_version', 'required', 'allow_empty',
                    'enabled_when', 'min_entries', 'max_entries', 'min_ipv4', 'max_ipv4', 'min_ipv6', 'max_ipv6'}
    names = set()
    result = []
    for item in document['sources']:
        if not isinstance(item, dict) or set(item) - allowed_keys:
            raise ValueError('invalid source fields')
        name = item.get('name')
        if not isinstance(name, str) or not re.fullmatch(r'[A-Za-z][A-Za-z0-9_-]*', name) or name in names:
            raise ValueError('source names must be unique identifiers')
        names.add(name)
        url = item.get('url')
        if not isinstance(url, str) or urllib.parse.urlsplit(url).scheme not in ('http', 'https') or not urllib.parse.urlsplit(url).netloc:
            raise ValueError(f'{name}: invalid URL')
        if item.get('format') not in ('txt', 'nftables') or item.get('direction') not in ('input', 'output'):
            raise ValueError(f'{name}: invalid format or direction')
        if 'ip_version' in item and (type(item['ip_version']) is not int or item['ip_version'] not in (4, 6)):
            raise ValueError(f'{name}: ip_version must be 4 or 6')
        for key in ('required', 'allow_empty'):
            if key in item and type(item[key]) is not bool:
                raise ValueError(f'{name}: {key} must be boolean')
        for key in ('min_entries', 'max_entries', 'min_ipv4', 'max_ipv4', 'min_ipv6', 'max_ipv6'):
            if key in item and (type(item[key]) is not int or not 0 <= item[key] <= LIMIT):
                raise ValueError(f'{name}: invalid {key}')
        for low, high in [('min_entries', 'max_entries'), ('min_ipv4', 'max_ipv4'), ('min_ipv6', 'max_ipv6')]:
            if item.get(low, 0) > item.get(high, LIMIT):
                raise ValueError(f'{name}: {low} exceeds {high}')
        flag = item.get('enabled_when')
        if flag is not None and (not isinstance(flag, str) or not re.fullmatch(r'[A-Z][A-Z0-9_]*', flag)):
            raise ValueError(f'{name}: invalid enabled_when')
        result.append({**item, '_enabled': boolean(flag) if flag else True})
    return result


def networks(text, version=None, tokens=False):
    result = set()
    for line in text.splitlines():
        line = line.split('#', 1)[0].strip()
        candidates = re.findall(r'[0-9A-Fa-f:.]+(?:/\d+)?(?:\s*-\s*[0-9A-Fa-f:.]+(?:/\d+)?)?', line) if tokens else [line]
        for candidate in candidates:
            try:
                if tokens and '-' in candidate:
                    first, last = re.split(r'\s*-\s*', candidate, maxsplit=1)
                    start = ipaddress.ip_address(first)
                    end = ipaddress.ip_address(last)
                    ranges = ipaddress.summarize_address_range(start, end)
                else:
                    ranges = [ipaddress.ip_network(candidate, strict=False)]
                result.update(network for network in ranges if version is None or network.version == version)
            except (ValueError, TypeError):
                continue
    return result


def allowed(name, version):
    result = set()
    for item in re.split(r'[\s,]+', os.environ.get(name, '').strip()):
        if not item:
            continue
        try:
            network = ipaddress.ip_network(item, strict=False)
        except ValueError as exc:
            raise ValueError(f'invalid {name}: {item}') from exc
        if network.version != version:
            raise ValueError(f'wrong address family in {name}: {item}')
        result.add(network)
    return result


def custom_lists():
    result = {}
    for filename, version in CUSTOM_FILES.items():
        path = CUSTOM_DIR / filename
        try:
            with path.open(encoding='utf-8') as source:
                text = source.read(20_000_001)
        except FileNotFoundError:
            result[filename] = set()
            continue
        if len(text) > 20_000_000:
            raise ValueError(f'{filename} exceeds size limit')
        entries = set()
        for number, line in enumerate(text.splitlines(), 1):
            value = line.split('#', 1)[0].strip()
            if not value:
                continue
            try:
                network = ipaddress.ip_network(value, strict=False)
            except ValueError as exc:
                raise ValueError(f'{filename}:{number}: invalid IP address or CIDR') from exc
            if network.version != version:
                raise ValueError(f'{filename}:{number}: wrong address family')
            entries.add(network)
            if len(entries) > LIMIT:
                raise ValueError(f'{filename} exceeds element limit')
        result[filename] = entries
    return result


def config():
    delay_text = os.environ.get('BOOT_DELAY_SECONDS', '120')
    if not re.fullmatch(r'[0-9]+', delay_text):
        raise ValueError('BOOT_DELAY_SECONDS must be a non-negative integer')
    boot_delay = int(delay_text)
    clock = os.environ.get('UPDATE_AT', '03:00')
    if not re.fullmatch(r'(?:[01]\d|2[0-3]):[0-5]\d', clock):
        raise ValueError('UPDATE_AT must be HH:MM')
    zone = ZoneInfo(os.environ.get('TZ', 'Europe/Moscow'))
    timeout_text = os.environ.get('HTTP_TIMEOUT', '30s')
    match = re.fullmatch(r'(\d+(?:\.\d+)?)(ms|s|m)?', timeout_text)
    if not match:
        raise ValueError('invalid HTTP_TIMEOUT')
    timeout = float(match[1]) * {'ms': .001, 's': 1, 'm': 60, None: 1}[match[2]]
    retries = int(os.environ.get('RETRIES', '3'))
    if timeout <= 0 or retries < 0 or retries > 20:
        raise ValueError('HTTP_TIMEOUT must be positive and RETRIES must be 0..20')
    level = os.environ.get('LOG_LEVEL', 'info').upper()
    if level not in ('DEBUG', 'INFO', 'WARN', 'ERROR'):
        raise ValueError('invalid LOG_LEVEL')
    logging.basicConfig(level=level, format='%(asctime)s %(levelname)s %(message)s', stream=sys.stdout)
    return {'vk': boolean('ENABLE_VK_OUTPUT'), 'dry': boolean('DRY_RUN'), 'clock': clock, 'boot_delay': boot_delay,
            'zone': zone, 'timeout': timeout, 'retries': retries,
            'allow4': allowed('ALLOW_CIDRS', 4), 'allow6': allowed('ALLOW_CIDRS6', 6), 'sources': load_sources()}


def fetch(name, cfg):
    url = next(source['url'] for source in cfg['sources'] if source['name'] == name)
    request = urllib.request.Request(url, headers={'User-Agent': 'nftguard/1.0'})
    for attempt in range(cfg['retries'] + 1):
        try:
            with urllib.request.urlopen(request, timeout=cfg['timeout']) as response:
                data = response.read(20_000_001)
            if len(data) > 20_000_000:
                raise ValueError(f'{name} response too large')
            return data.decode('utf-8')
        except (OSError, UnicodeError, ValueError) as exc:
            if attempt == cfg['retries']:
                raise RuntimeError(f'{name} download failed: {exc}') from exc
            time.sleep(min(2 ** attempt, 30))


def threshold(name, values, lower, upper):
    if not lower <= len(values) <= upper:
        raise ValueError(f'{name} count {len(values)} outside {lower}..{upper}')
    LOG.info('event=fetch source=%s count=%d', name, len(values))


def render(sets, cfg):
    lines = ['table inet nftguard {']
    for name, values in sets.items():
        if len(values) > LIMIT:
            raise ValueError(f'{name} exceeds element limit')
        family = 'ipv4_addr' if name.endswith('v4') else 'ipv6_addr'
        lines.append(f' set {name} {{ type {family}; flags interval; auto-merge;')
        if values:
            lines.append('  elements = { ' + ', '.join(map(str, sorted(values))) + ' }')
        lines.append(' }')
    lines.extend([' chain input {', '  type filter hook input priority -10; policy accept;',
                  '  ct state established,related accept', '  iif "lo" accept'])
    for key, family in [('allow4', 'ip'), ('allow6', 'ip6')]:
        if cfg[key]:
            lines.append(f'  {family} saddr {{ ' + ', '.join(map(str, sorted(cfg[key]))) + ' } accept')
    lines.extend(['  ip saddr @src_v4 drop', '  ip6 saddr @src_v6 drop', ' }'])
    if 'external_out_v4' in sets or 'custom_out_v4' in sets:
        lines.extend([' chain output {', '  type filter hook output priority -10; policy accept;',
                      '  ct state established,related accept'])
        if 'external_out_v4' in sets:
            lines.extend(['  ip daddr @external_out_v4 drop', '  ip6 daddr @external_out_v6 drop'])
        if 'custom_out_v4' in sets:
            lines.extend(['  ip daddr @custom_out_v4 drop', '  ip6 daddr @custom_out_v6 drop'])
        lines.append(' }')
    return '\n'.join(lines + ['}', ''])


def nft(*args, check=True):
    return subprocess.run(['nft', *args], capture_output=True, text=True, check=check)


def atomic_write(path, text):
    tmp = path.with_suffix(path.suffix + '.tmp')
    tmp.write_text(text, encoding='utf-8')
    os.replace(tmp, path)


def apply(rules):
    # Delete and recreate in one transaction: flush alone retains chains and sets.
    exists = nft('list', 'table', 'inet', 'nftguard', check=False).returncode == 0
    batch = ('delete table inet nftguard\n' if exists else '') + rules
    atomic_write(STATE / 'new.nft', batch)
    nft('-c', '-f', str(STATE / 'new.nft'))
    if (STATE / 'current.nft').exists():
        shutil.copyfile(STATE / 'current.nft', STATE / 'previous.nft')
    nft('-f', str(STATE / 'new.nft'))
    try:
        nft('list', 'table', 'inet', 'nftguard')
    except subprocess.SubprocessError:
        previous = STATE / 'previous.nft'
        if previous.exists():
            rollback = ('delete table inet nftguard\n' if nft('list', 'table', 'inet', 'nftguard', check=False).returncode == 0 else '') + previous.read_text()
            atomic_write(STATE / 'rollback.nft', rollback)
            nft('-f', str(STATE / 'rollback.nft'))
        raise


def status_read():
    try:
        return json.loads((STATE / 'status.json').read_text())
    except (OSError, ValueError):
        return {}


def update(cfg):
    started = time.monotonic()
    status = status_read()
    status['last_attempt'] = dt.datetime.now(dt.timezone.utc).isoformat()
    try:
        custom = custom_lists()
        empty_sources = []
        sources = []
        sets = {'src_v4': set(custom['input-v4.txt']), 'src_v6': set(custom['input-v6.txt'])}
        if custom['output-v4.txt'] or custom['output-v6.txt']:
            sets['custom_out_v4'] = custom['output-v4.txt']
            sets['custom_out_v6'] = custom['output-v6.txt']
        for source in cfg['sources']:
            enabled = cfg['vk'] if source.get('enabled_when') == 'ENABLE_VK_OUTPUT' else source['_enabled']
            if not enabled:
                continue
            name = source['name']
            try:
                text = fetch(name, cfg)
                entries = networks(text, source.get('ip_version'), tokens=source['format'] == 'nftables')
                if not text.strip() and source.get('allow_empty', False):
                    empty_sources.append(name)
                    LOG.warning('event=fetch source=%s reason=empty_list', name)
                else:
                    threshold(name, entries, source.get('min_entries', 1), source.get('max_entries', LIMIT))
                    for version in (4, 6):
                        lower, upper = f'min_ipv{version}', f'max_ipv{version}'
                        if lower in source or upper in source:
                            family = {entry for entry in entries if entry.version == version}
                            threshold(f'{name}_v{version}', family, source.get(lower, 0), source.get(upper, LIMIT))
            except (RuntimeError, ValueError, OSError, UnicodeError) as exc:
                if source.get('required', True):
                    raise RuntimeError(f'{name}: {exc}') from exc
                LOG.warning('event=fetch source=%s reason=%s', name, exc)
                continue
            sources.append(name)
            for version in (4, 6):
                key = f'src_v{version}' if source['direction'] == 'input' else f'external_out_v{version}'
                sets.setdefault(key, set()).update(entry for entry in entries if entry.version == version)
        rules = render(sets, cfg)
        if not cfg['dry']:
            apply(rules)
            atomic_write(STATE / 'current.nft', rules)
        status.update(last_success=dt.datetime.now(dt.timezone.utc).isoformat(), sources=sources,
                      counts={k: len(v) for k, v in sets.items()}, sha256=hashlib.sha256(rules.encode()).hexdigest(),
                      duration_ms=int((time.monotonic() - started) * 1000), last_error=None,
                      config_hash=config_hash(cfg, custom), dry_run=cfg['dry'], empty_sources=empty_sources,
                      custom_counts={name: len(values) for name, values in custom.items()})
        LOG.info('event=apply dry_run=%s counts=%s duration_ms=%s', cfg['dry'], status['counts'], status['duration_ms'])
    except (ValueError, RuntimeError, OSError, UnicodeError, subprocess.SubprocessError) as exc:
        detail = exc.stderr.strip() if isinstance(exc, subprocess.CalledProcessError) and exc.stderr else str(exc)
        status['last_error'] = detail
        LOG.error('event=error reason=%s', detail)
        atomic_write(STATE / 'status.json', json.dumps(status, indent=2) + '\n')
        return False
    atomic_write(STATE / 'status.json', json.dumps(status, indent=2) + '\n')
    return True


def config_hash(cfg, custom=None):
    if custom is None:
        custom = custom_lists()
    value = [cfg['vk'], cfg['sources'], sorted(map(str, cfg['allow4'])), sorted(map(str, cfg['allow6'])),
             {name: sorted(map(str, entries)) for name, entries in custom.items()}]
    return hashlib.sha256(json.dumps(value).encode()).hexdigest()


def fresh(status):
    try:
        age = dt.datetime.now(dt.timezone.utc) - dt.datetime.fromisoformat(status['last_success'])
        return dt.timedelta(0) <= age < dt.timedelta(hours=26)
    except (KeyError, ValueError, TypeError):
        return False


def health(cfg):
    status = status_read()
    try:
        current_hash = config_hash(cfg)
    except (ValueError, OSError, UnicodeError):
        return False
    if not fresh(status) or status.get('config_hash') != current_hash:
        return False
    if cfg['dry']:
        return True
    return not status.get('dry_run') and nft('list', 'table', 'inet', 'nftguard', check=False).returncode == 0


def wait_for_boot(delay):
    if not delay:
        return
    uptime = float(Path('/proc/uptime').read_text().split()[0])
    remaining = max(0, delay - uptime)
    if remaining:
        LOG.info('event=boot_delay remaining_seconds=%.1f', remaining)
        time.sleep(remaining)


def main():
    cfg = config()
    STATE.mkdir(parents=True, exist_ok=True)
    if sys.argv[1:] == ['healthcheck']:
        return 0 if health(cfg) else 1
    if sys.argv[1:] not in ([], ['update']):
        raise ValueError('usage: nftguard.py [update|healthcheck]')
    if not cfg['dry']:
        wait_for_boot(cfg['boot_delay'])
    if sys.argv[1:] == ['update']:
        return 0 if update(cfg) else 1
    status = status_read()
    current = STATE / 'current.nft'
    if not cfg['dry'] and current.exists() and fresh(status) and not status.get('dry_run') and status.get('config_hash') == config_hash(cfg):
        try:
            apply(current.read_text())
        except (OSError, subprocess.SubprocessError) as exc:
            LOG.error('event=restore reason=%s', exc)
            update(cfg)
    else:
        update(cfg)
    while True:
        now = dt.datetime.now(cfg['zone'])
        hour, minute = map(int, cfg['clock'].split(':'))
        target = now.replace(hour=hour, minute=minute, second=0, microsecond=0)
        if target <= now:
            target = (now + dt.timedelta(days=1)).replace(hour=hour, minute=minute, second=0, microsecond=0)
        time.sleep(max(1, target.timestamp() - now.timestamp()))
        update(cfg)


if __name__ == '__main__':
    try:
        sys.exit(main())
    except (ValueError, OSError, ZoneInfoNotFoundError) as error:
        print(f'event=error reason={error}', file=sys.stderr)
        sys.exit(1)
