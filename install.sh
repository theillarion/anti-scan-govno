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
if [ -f "$dest/compose.yaml" ]; then
    cd "$dest"
    image=$(docker compose config --images nftguard) || exit 1
    case "$image" in
        ghcr.io/theillarion/anti-scan-govno:*) ;;
        *) echo 'Existing nftguard service does not use the GHCR image. Update it using its existing deployment method.' >&2; exit 1;;
    esac
    echo 'Existing nftguard installation found. Checking for an updated image.'
    container=$(docker compose ps --all --quiet nftguard)
    case "$container" in
        *'
'*) echo 'Multiple nftguard containers found. Update them manually.' >&2; exit 1;;
    esac
    current_image=
    if [ -n "$container" ]; then
        current_image=$(docker inspect --format '{{.Image}}' "$container")
    fi
    docker compose pull nftguard
    new_image=$(docker image inspect --format '{{.Id}}' "$image")
    if [ -n "$current_image" ] && [ "$current_image" = "$new_image" ]; then
        echo 'The installed image is up to date. Nothing to do.'
        exit 0
    fi
    if [ -n "$container" ]; then
        ask 'An updated image is available. Stop and update nftguard? Configuration and data will be kept. [y/N]: '
    else
        ask 'No nftguard container found. Start it using the downloaded image? Configuration and data will be kept. [y/N]: '
    fi
    case "$answer" in y|Y|yes|YES) ;; *) echo 'Update cancelled.'; exit 0;; esac
    docker compose up -d --no-deps nftguard
    echo 'Update complete. Check logs: docker compose logs -f nftguard'
    exit 0
fi
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
owner=
if [ -n "${SUDO_UID:-}" ] && [ -n "${SUDO_GID:-}" ]; then
    case "$SUDO_UID:$SUDO_GID" in
        *[!0-9:]*) echo 'Invalid sudo user or group ID.' >&2; exit 1;;
    esac
    owner=$SUDO_UID:$SUDO_GID
fi
if [ ! -e "$dest" ]; then
    mkdir -p "$dest"
    [ -z "$owner" ] || chown "$owner" "$dest"
fi
if [ ! -e "$dest/state" ]; then
    mkdir -p "$dest/state"
    [ -z "$owner" ] || chown "$owner" "$dest/state"
fi
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
if [ -n "$owner" ]; then
    chown "$owner" "$dest/compose.yaml" "$dest/uninstall.sh" "$dest/.env"
fi
cd "$dest"
docker compose up -d
printf '\nDone. Check logs: cd %s && docker compose logs -f\n' "$dest"
if [ "$dry" = true ]; then
    echo 'After checking logs, set DRY_RUN=false in .env and run docker compose up -d.'
fi
