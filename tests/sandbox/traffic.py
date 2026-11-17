"""Test real TCP packets against nftguard in an isolated Docker network."""
import json
import socket
import tempfile
import threading
import time
from pathlib import Path
from unittest import mock

import nftguard as guard


def echo_server(family):
    with socket.socket(family, socket.SOCK_STREAM) as server:
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        if family == socket.AF_INET6:
            server.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
        server.bind(('::' if family == socket.AF_INET6 else '0.0.0.0', 8000))
        server.listen()
        while True:
            conn, _ = server.accept()
            with conn:
                conn.sendall(conn.recv(16))


def outgoing(address):
    family = socket.AF_INET6 if ':' in address else socket.AF_INET
    try:
        with socket.socket(family, socket.SOCK_STREAM) as conn:
            conn.settimeout(1)
            conn.connect((address, 8000))
            conn.sendall(b'ok')
            return conn.recv(2) == b'ok'
    except OSError:
        return False


for family in (socket.AF_INET, socket.AF_INET6):
    threading.Thread(target=echo_server, args=(family,), daemon=True).start()

for attempt in range(50):
    try:
        control = socket.create_connection(('172.29.241.2', 9000), timeout=1)
        control.settimeout(5)
        break
    except OSError:
        time.sleep(.1)
else:
    raise RuntimeError('sandbox peer did not start')

with tempfile.TemporaryDirectory() as state, control, control.makefile('rwb') as stream:
    guard.STATE = Path(state)
    cfg = guard.config()
    cfg['allow4'] = guard.networks('172.29.241.11')
    cfg['allow6'] = guard.networks('fd42:6e66:7467::11')
    sets = {'src_v4': guard.networks('172.29.241.10 172.29.241.11'.replace(' ', '\n')),
            'src_v6': guard.networks('fd42:6e66:7467::10\nfd42:6e66:7467::11'),
            'vk_v4': guard.networks('172.29.241.12'),
            'vk_v6': guard.networks('fd42:6e66:7467::12')}

    def incoming(source, destination):
        stream.write(json.dumps({'source': source, 'destination': destination}).encode() + b'\n')
        stream.flush()
        return json.loads(stream.readline())

    cfg['vk'] = False
    guard.apply(guard.render(sets, cfg))
    for blocked, allowed, normal, target, output in [
        ('172.29.241.10', '172.29.241.11', '172.29.241.2', '172.29.241.3', '172.29.241.12'),
        ('fd42:6e66:7467::10', 'fd42:6e66:7467::11', 'fd42:6e66:7467::2', 'fd42:6e66:7467::3', 'fd42:6e66:7467::12'),
    ]:
        assert not incoming(blocked, target), f'blocked source passed: {blocked}'
        assert incoming(allowed, target), f'allowlist source blocked: {allowed}'
        assert incoming(normal, target), f'normal source blocked: {normal}'
        assert outgoing(output), f'output blocked with VK disabled: {output}'
    cfg['vk'] = True
    guard.apply(guard.render(sets, cfg))
    for blocked, normal in [('172.29.241.12', '172.29.241.2'), ('fd42:6e66:7467::12', 'fd42:6e66:7467::2')]:
        assert not outgoing(blocked), f'VK output passed: {blocked}'
        assert outgoing(normal), f'normal output blocked: {normal}'
    cfg['vk'] = False
    sources = {'c24_v4': '\n'.join(f'10.0.{i}.0/24' for i in range(100)) + '\n172.29.241.10',
               'c24_v6': '',
               'anti': '\n'.join(f'10.1.{i}.0/24' for i in range(100)) + '\nfd42:6e66:7467::10'}
    with mock.patch.object(guard, 'fetch', side_effect=lambda name, cfg: sources[name]):
        assert guard.update(cfg), 'empty C24Be IPv6 file prevented update'
    assert guard.status_read()['empty_sources'] == ['c24_v6']
    assert not incoming('172.29.241.10', '172.29.241.3'), 'C24Be IPv4 source passed'
    assert not incoming('fd42:6e66:7467::10', 'fd42:6e66:7467::3'), 'AntiScanner IPv6 source passed'
    assert incoming('172.29.241.2', '172.29.241.3'), 'normal source blocked after update'
print('Sandbox traffic: IPv4/IPv6 input, allowlist and optional output passed')
