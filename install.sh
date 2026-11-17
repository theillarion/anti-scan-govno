#!/bin/sh
set -eu

# Read answers from the terminal even when this script is supplied via curl.
if ! ( : </dev/tty ) 2>/dev/null; then
    echo 'A terminal is required. For automatic setup, use Docker Compose.' >&2
    exit 1
fi
exec 3</dev/tty
[ "$(id -u)" -eq 0 ] || { echo 'Run this script with sudo.' >&2; exit 1; }
command -v docker >/dev/null 2>&1 || { echo 'Install Docker and Docker Compose first.' >&2; exit 1; }
docker compose version >/dev/null 2>&1 || { echo 'Docker Compose was not found.' >&2; exit 1; }
command -v curl >/dev/null 2>&1 || { echo 'Install curl first.' >&2; exit 1; }

ask() {
    printf '%s' "$1" >&2
    IFS= read -r answer <&3 || exit 1
}
ask 'Install folder [/opt/nftguard]: '
dest=${answer:-/opt/nftguard}
case "$dest" in /*) ;; *) echo 'Enter an absolute path.' >&2; exit 1;; esac
if [ -e "$dest/.env" ] || [ -e "$dest/compose.yaml" ]; then
    echo 'Config or compose.yaml already exists in this folder. Setup stopped.' >&2
    exit 1
fi
printf '%s\n' 'Incoming IPs from RKN, FSB, MVD, GRChTs and scanners (Censys, Shodan, etc.) are blocked.'
printf '%s\n' 'You can also block outgoing connections to VK, MAX and OK IPs.'
ask 'Block outgoing connections to VK, MAX and OK on this server? [y/N]: '
case "$answer" in y|Y|yes|YES) vk=true;; *) vk=false;; esac
ask 'IPv4 addresses/CIDRs to allow (comma-separated, Enter for none): '
allow4=$answer
ask 'IPv6 addresses/CIDRs to allow (comma-separated, Enter for none): '
allow6=$answer
# Compose env values must stay on one line and not contain interpolation syntax.
case "$allow4$allow6" in *[!0-9a-fA-F:.,/\ ]*) echo 'Invalid characters in the allowlist.' >&2; exit 1;; esac
ask 'Start in dry-run mode (do not apply rules)? [Y/n]: '
case "$answer" in n|N|no|NO) dry=false;; *) dry=true;; esac
ask 'Create config and start the service? [y/N]: '
case "$answer" in y|Y|yes|YES) ;; *) echo 'Setup cancelled.'; exit 0;; esac
mkdir -p "$dest/state"
base=${NFTGUARD_SOURCE_URL:-https://raw.githubusercontent.com/theillarion/anti-scan-govno/master}
for file in compose.ghcr.yaml uninstall.sh; do
    target=$file
    [ "$file" != compose.ghcr.yaml ] || target=compose.yaml
    curl -fsSL --retry 3 "$base/$file" -o "$dest/$target.tmp"
    mv "$dest/$target.tmp" "$dest/$target"
done
chmod +x "$dest/uninstall.sh"
umask 077
cat > "$dest/.env" <<CONFIG
ENABLE_VK_OUTPUT=$vk
ALLOW_CIDRS=$allow4
ALLOW_CIDRS6=$allow6
DRY_RUN=$dry
BOOT_DELAY_SECONDS=120
TZ=Europe/Moscow
UPDATE_AT=03:00
CONFIG
cd "$dest"
docker compose up -d
printf '\nDone. Check logs: cd %s && docker compose logs -f\n' "$dest"
if [ "$dry" = true ]; then
    echo 'After checking logs, set DRY_RUN=false in .env and run docker compose up -d.'
fi
