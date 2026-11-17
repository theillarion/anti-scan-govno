"""Exercise interactive installer with stubbed Docker and a local source in Debian."""
import os
from pathlib import Path
import pty
import select
import tempfile

with tempfile.TemporaryDirectory() as tmp:
    root = Path(tmp)
    binaries = root / 'bin'
    binaries.mkdir()
    (binaries / 'docker').write_text('''#!/bin/sh
echo "$*" >> "$DOCKER_LOG"
case "$*" in
  "compose config --images nftguard") echo "${TEST_IMAGE:-ghcr.io/theillarion/anti-scan-govno:latest}" ;;
  "compose ps --all --quiet nftguard") echo "${TEST_CONTAINER:-container-id}" ;;
  "compose pull nftguard") [ "${TEST_PULL_FAIL:-0}" = 0 ] || exit 1 ;;
  "inspect --format {{.Image}} container-id") echo "${TEST_OLD_ID:-old-image}" ;;
  "image inspect --format {{.Id}} "*) echo "${TEST_NEW_ID:-new-image}" ;;
esac
''')
    # Implement the downloader without depending on shell argument ordering.
    (binaries / 'curl').write_text('''#!/bin/sh
while [ "$#" -gt 0 ]; do
  case "$1" in */compose.ghcr.yaml|*/uninstall.sh) source=${1##*/};; -o) shift; output=$1;; esac
  shift
done
cp "/work/$source" "$output"
''')
    for path in binaries.iterdir():
        path.chmod(0o755)
    pid, master = pty.fork()
    if pid == 0:
        os.environ['PATH'] = str(binaries) + ':' + os.environ['PATH']
        os.environ['DOCKER_LOG'] = str(root / 'docker.log')
        os.execv('/bin/sh', ['sh', '/work/install.sh'])
    answers = [str(root / 'installed'), 'y', '192.0.2.1/32', '2001:db8::1/128', '', 'y']
    transcript = b''
    for prompt, answer in zip([b']:', b'[y/N]:', b'): ', b'): ', b'[Y/n]:', b'[y/N]:'], answers):
        while prompt not in transcript:
            ready, _, _ = select.select([master], [], [], 10)
            if not ready:
                raise RuntimeError(f'installer prompt timeout: {transcript!r}')
            transcript += os.read(master, 8192)
        transcript = b''
        os.write(master, (answer + '\n').encode())
    _, status = os.waitpid(pid, 0)
    assert os.waitstatus_to_exitcode(status) == 0
    config = (root / 'installed' / '.env').read_text()
    assert 'ENABLE_VK_OUTPUT=true' in config and 'DRY_RUN=true' in config
    assert 'BOOT_DELAY_SECONDS=120' in config
    assert 'ALLOW_CIDRS=192.0.2.1/32' in config and 'ALLOW_CIDRS6=2001:db8::1/128' in config
    assert (root / 'installed' / 'compose.yaml').read_text() == Path('/work/compose.ghcr.yaml').read_text()
    assert (root / 'installed' / 'uninstall.sh').exists()
    assert not (root / 'installed' / 'Dockerfile').exists()
    assert 'compose up -d\n' in (root / 'docker.log').read_text()
    assert '--build' not in (root / 'docker.log').read_text()
    print('Interactive installer: answers, downloaded files and configuration passed')

    state_file = root / 'installed' / 'state' / 'keep'
    state_file.write_text('keep state')
    compose_file = root / 'installed' / 'compose.yaml'
    original_compose = compose_file.read_text()
    original_config = (root / 'installed' / '.env').read_text()

    def repeat_install(env, confirm=None, expected_exit=0):
        (root / 'docker.log').write_text('')
        pid, master = pty.fork()
        if pid == 0:
            os.environ.update(env)
            os.environ['PATH'] = str(binaries) + ':' + os.environ['PATH']
            os.environ['DOCKER_LOG'] = str(root / 'docker.log')
            os.execv('/bin/sh', ['sh', '/work/install.sh'])
        transcript = b''
        prompts = [(b']:', str(root / 'installed'))]
        if confirm is not None:
            prompts.append((b'[y/N]:', confirm))
        for prompt, answer in prompts:
            while prompt not in transcript:
                ready, _, _ = select.select([master], [], [], 10)
                if not ready:
                    raise RuntimeError(f'installer prompt timeout: {transcript!r}')
                transcript += os.read(master, 8192)
            transcript = b''
            os.write(master, (answer + '\n').encode())
        _, status = os.waitpid(pid, 0)
        os.close(master)
        assert os.waitstatus_to_exitcode(status) == expected_exit
        assert compose_file.read_text() == original_compose
        assert (root / 'installed' / '.env').read_text() == original_config
        assert state_file.read_text() == 'keep state'
        return (root / 'docker.log').read_text()

    log = repeat_install({'TEST_OLD_ID': 'same', 'TEST_NEW_ID': 'same'})
    assert 'compose pull nftguard' in log and 'compose up' not in log
    log = repeat_install({}, confirm='n')
    assert 'compose pull nftguard' in log and 'compose up' not in log
    log = repeat_install({}, confirm='y')
    assert 'compose up -d --no-deps nftguard' in log
    log = repeat_install({'TEST_PULL_FAIL': '1'}, expected_exit=1)
    assert 'compose up' not in log
    log = repeat_install({'TEST_IMAGE': 'custom/source-build'}, expected_exit=1)
    assert 'compose pull' not in log and 'compose up' not in log
    print('Installer update: unchanged, cancelled, confirmed, pull failure and non-GHCR installation passed')
