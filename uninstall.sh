#!/bin/bash
set -euo pipefail

if ! { : </dev/tty; } 2>/dev/null; then
    echo 'A terminal is required to confirm removal.' >&2
    exit 1
fi
exec 3</dev/tty
if [[ $(id -u) -ne 0 ]]; then
    echo 'Run this script with sudo.' >&2
    exit 1
fi
command -v docker >/dev/null 2>&1 || { echo 'Docker was not found.' >&2; exit 1; }
docker compose version >/dev/null 2>&1 || { echo 'Docker Compose was not found.' >&2; exit 1; }

printf 'Install folder [/opt/nftguard]: ' >&2
IFS= read -r dest <&3 || exit 1
dest=${dest:-/opt/nftguard}
if [[ $dest != /* || -L $dest || ! -d $dest ]]; then
    echo 'Enter the absolute path to the install folder (not a symlink).' >&2
    exit 1
fi
dest=$(cd -- "$dest" && pwd -P)
if [[ $dest == / || $dest == /opt || ! -f $dest/compose.yaml || ! -f $dest/nftguard.py || ! -f $dest/Dockerfile ]]; then
    echo 'This folder does not look like an nftguard install. Removal stopped.' >&2
    exit 1
fi
printf 'This will delete the service, its local image, the inet nftguard table, and all files in %s.\n' "$dest" >&2
printf 'Type DELETE to confirm: ' >&2
IFS= read -r answer <&3 || exit 1
if [[ $answer != DELETE ]]; then
    echo 'Removal cancelled.'
    exit 0
fi
cd -- "$dest"
# Stop first, so the daemon cannot recreate the table while it is removed.
docker compose stop nftguard
if command -v nft >/dev/null 2>&1; then
    nft_command=(nft)
else
    # Use the installed service image when nft is not installed on the host.
    nft_command=(docker compose run --rm --no-deps --entrypoint nft nftguard)
fi
if ! tables=$("${nft_command[@]}" list tables); then
    echo 'Could not read nftables tables. The folder was kept. Check permissions and try again.' >&2
    exit 1
fi
if printf '%s\n' "$tables" | grep -Eq '^table inet nftguard[[:space:]]*$'; then
    "${nft_command[@]}" delete table inet nftguard
fi
docker compose down --rmi local
cd /
rm -rf -- "$dest"
echo 'nftguard removed.'
