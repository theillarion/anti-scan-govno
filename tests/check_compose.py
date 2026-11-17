"""Ensure source and GHCR deployments retain identical service settings."""
import json
import os
import subprocess


def config(filename):
    env = dict(os.environ, NFTGUARD_IMAGE_TAG='test-version')
    result = subprocess.run(
        ['docker', 'compose', '-f', filename, 'config', '--format', 'json'],
        check=True, capture_output=True, text=True, env=env,
    )
    return json.loads(result.stdout)['services']['nftguard']


source = config('compose.yaml')
registry = config('compose.ghcr.yaml')
assert source.pop('build'), 'source deployment must build the image'
assert registry.pop('image') == 'ghcr.io/theillarion/anti-scan-govno:test-version'
assert source == registry, 'source and registry service settings differ'
assert set(source['cap_add']) == {'NET_ADMIN', 'SETUID', 'SETGID', 'SETPCAP'}
print('Compose configurations: identical service settings, correct GHCR image tag')
