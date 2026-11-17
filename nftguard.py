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
import urllib.request
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

STATE = Path(os.environ.get('STATE_DIR', '/var/lib/nftguard'))
URLS = {
    'c24_v4': 'https://raw.githubusercontent.com/C24Be/AS_Network_List/main/blacklists/blacklist-v4.txt',
    'c24_v6': 'https://raw.githubusercontent.com/C24Be/AS_Network_List/main/blacklists/blacklist-v6.txt',
    'anti': 'https://gist.githubusercontent.com/sngvy/07cee7ac810c9d222fbebddff8c1d1b8/raw/blacklist.txt',
    'vk': 'https://raw.githubusercontent.com/C24Be/AS_Network_List/main/blacklists_nftables/blacklist-vk.nft',
}
LIMIT = 1_000_000
LOG = logging.getLogger('nftguard')


def boolean(name):
    value = os.environ.get(name, 'false').lower()
    if value not in ('true', 'false'):
        raise ValueError(f'{name} must be true or false')
    return value == 'true'


def networks(text, version=None, tokens=False):
    result = set()
    for line in text.splitlines():
        line = line.split('#', 1)[0].strip()
        candidates = re.findall(r'[0-9A-Fa-f:.]+(?:/\d+)?', line) if tokens else [line]
        for candidate in candidates:
            try:
                network = ipaddress.ip_network(candidate, strict=False)
                if version is None or network.version == version:
                    result.add(network)
            except ValueError:
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
            'allow4': allowed('ALLOW_CIDRS', 4), 'allow6': allowed('ALLOW_CIDRS6', 6)}


def fetch(name, cfg):
    request = urllib.request.Request(URLS[name], headers={'User-Agent': 'nftguard/1.0'})
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
    if cfg['vk']:
        lines.extend([' chain output {', '  type filter hook output priority -10; policy accept;',
                      '  ct state established,related accept', '  ip daddr @vk_v4 drop',
                      '  ip6 daddr @vk_v6 drop', ' }'])
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
        c4 = networks(fetch('c24_v4', cfg), 4)
        c6 = networks(fetch('c24_v6', cfg), 6)
        threshold('c24_v4', c4, 100, 10000)
        threshold('c24_v6', c6, 1, 1000)
        sources = ['c24_v4', 'c24_v6']
        try:
            anti = networks(fetch('anti', cfg))
            threshold('anti', anti, 100, 50000)
            sources.append('anti')
        except (RuntimeError, ValueError) as exc:
            LOG.warning('event=fetch source=anti reason=%s', exc)
            anti = set()
        sets = {'src_v4': c4 | {n for n in anti if n.version == 4},
                'src_v6': c6 | {n for n in anti if n.version == 6}}
        if cfg['vk']:
            vk = networks(fetch('vk', cfg), tokens=True)
            sets['vk_v4'] = {n for n in vk if n.version == 4}
            sets['vk_v6'] = {n for n in vk if n.version == 6}
            threshold('vk_v4', sets['vk_v4'], 10, 500)
            threshold('vk_v6', sets['vk_v6'], 0, 100)
            sources.append('vk')
        rules = render(sets, cfg)
        if not cfg['dry']:
            apply(rules)
            atomic_write(STATE / 'current.nft', rules)
        status.update(last_success=dt.datetime.now(dt.timezone.utc).isoformat(), sources=sources,
                      counts={k: len(v) for k, v in sets.items()}, sha256=hashlib.sha256(rules.encode()).hexdigest(),
                      duration_ms=int((time.monotonic() - started) * 1000), last_error=None,
                      config_hash=config_hash(cfg), dry_run=cfg['dry'])
        LOG.info('event=apply dry_run=%s counts=%s duration_ms=%s', cfg['dry'], status['counts'], status['duration_ms'])
    except (ValueError, RuntimeError, OSError, subprocess.SubprocessError) as exc:
        detail = exc.stderr.strip() if isinstance(exc, subprocess.CalledProcessError) and exc.stderr else str(exc)
        status['last_error'] = detail
        LOG.error('event=error reason=%s', detail)
        atomic_write(STATE / 'status.json', json.dumps(status, indent=2) + '\n')
        return False
    atomic_write(STATE / 'status.json', json.dumps(status, indent=2) + '\n')
    return True


def config_hash(cfg):
    value = [cfg['vk'], sorted(map(str, cfg['allow4'])), sorted(map(str, cfg['allow6']))]
    return hashlib.sha256(json.dumps(value).encode()).hexdigest()


def fresh(status):
    try:
        age = dt.datetime.now(dt.timezone.utc) - dt.datetime.fromisoformat(status['last_success'])
        return dt.timedelta(0) <= age < dt.timedelta(hours=26)
    except (KeyError, ValueError, TypeError):
        return False


def health(cfg):
    status = status_read()
    if not fresh(status) or status.get('config_hash') != config_hash(cfg):
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
