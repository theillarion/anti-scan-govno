#!/bin/sh
set -eu

state=${STATE_DIR:-/var/lib/nftguard}
uid=$(stat -c '%u' "$state")
gid=$(stat -c '%g' "$state")

if [ "$uid" -eq 0 ]; then
    exec capsh --drop=cap_setuid,cap_setgid,cap_setpcap -- -c \
        'exec python3 /usr/local/bin/nftguard "$@"' -- "$@"
fi
exec capsh --drop=cap_setuid,cap_setgid,cap_setpcap --inh=cap_net_admin \
    --keep=1 --groups="$gid" --gid="$gid" --uid="$uid" --addamb=cap_net_admin -- -c \
    'exec python3 /usr/local/bin/nftguard "$@"' -- "$@"
