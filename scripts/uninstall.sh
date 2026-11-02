#!/bin/bash
set -euo pipefail
SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd -P)
# shellcheck source=install-common.sh
. "$SCRIPT_DIR/install-common.sh"
PURGE=0
case "${1:-}" in
    '') ;;
    --purge-account) [ "$#" = 1 ] || fail 'unexpected argument'; PURGE=1 ;;
    --help) printf 'Usage: sudo bash scripts/uninstall.sh [--purge-account]\n'; exit 0 ;;
    *) fail 'expected --purge-account or no arguments' ;;
esac
if [ ! -e "$STATE" ] && [ ! -L "$STATE" ]; then
    printf 'No tracked installation. Nothing removed.\n'
    exit 0
fi
load_state
secure_dir "$PREFIX"
secure_dir "$PREFIX/bin"
secure_dir "$(dirname "$SERVICE")"
check_runtime
for path in "$SERVICE" "$CONFIG/daemon.env" "$PREFIX/bin/ssh-brokerd" "$PREFIX/bin/broker-ssh" "$PREFIX/bin/brokerctl"; do
    if [ -e "$path" ] || [ -L "$path" ]; then secure_file "$path"; fi
done
if [ "$PURGE" = 1 ]; then
    # Refuse to delete a group adopted by any unrelated user since installation.
    for group in "$BROKER" "$EXEC_GROUP" "$ADMIN_GROUP"; do
        gid=$(group_id "$group")
        if [ "$OS" = Linux ]; then
            members=$(getent group "$group" | cut -d: -f4 | tr ',' ' ')
            primaries=$(getent passwd | awk -F: -v gid="$gid" '$4 == gid { print $1 }')
        else
            members=$(dscl . -read "/Groups/$group" GroupMembership 2>/dev/null | cut -d' ' -f2- || true)
            primaries=$(dscl . -search /Users PrimaryGroupID "$gid" 2>/dev/null | awk '{print $1}')
        fi
        for member in $members $primaries; do
            case "$group:$member" in
                "$BROKER:"|"$EXEC_GROUP:"|"$ADMIN_GROUP:") ;;
                "$BROKER:$BROKER"|"$EXEC_GROUP:$BROKER"|"$EXEC_GROUP:$HARNESS"|"$ADMIN_GROUP:$BROKER"|"$ADMIN_GROUP:$OPERATOR") ;;
                "$BROKER:$BROKER_UID"|"$BROKER:$BROKER_GID") ;;
                *) fail "group $group has an unrelated member ($member); refusing account purge" ;;
            esac
        done
    done
fi
stop_service
rm -f "$SERVICE" "$CONFIG/daemon.env" "$PREFIX/bin/ssh-brokerd" "$PREFIX/bin/broker-ssh" "$PREFIX/bin/brokerctl"
if [ "$OS" = Linux ]; then systemctl daemon-reload; fi
if [ -d "$RUNTIME" ]; then
    # Unlink only the daemon's two socket paths. Never recursively delete a directory.
    for socket in "$RUNTIME/exec.sock" "$RUNTIME/admin.sock"; do
        if [ -e "$socket" ] || [ -L "$socket" ]; then
            [ -S "$socket" ] && [ ! -L "$socket" ] && [ "$(owner "$socket")" = "$BROKER_UID" ] || fail 'unexpected runtime resource; refusing deletion'
            rm -f "$socket"
        fi
    done
    rmdir "$RUNTIME" || fail 'runtime contains an unrecognized resource; left intact'
fi
if [ "$PURGE" = 1 ]; then
    remove_member "$HARNESS" "$EXEC_GROUP"
    remove_member "$OPERATOR" "$ADMIN_GROUP"
    if [ "$OS" = Linux ]; then
        userdel "$BROKER"
        for group in "$EXEC_GROUP" "$ADMIN_GROUP" "$BROKER"; do
            if getent group "$group" >/dev/null; then groupdel "$group"; fi
        done
    else
        dscl . -delete "/Users/$BROKER"
        for group in "$EXEC_GROUP" "$ADMIN_GROUP" "$BROKER"; do dscl . -delete "/Groups/$group"; done
    fi
    rm -f "$STATE"
    rmdir "$CONFIG" || printf 'Preserved nonempty configuration directory.\n'
    # These directories are removed only if empty; unrelated files are preserved.
    rmdir "$PREFIX/bin" "$PREFIX" 2>/dev/null || true
    if [ "$OS" = Darwin ]; then rmdir /private/var/db/ssh-credential-broker 2>/dev/null || true; fi
    printf 'Removed tracked service, binaries, broker account, and dedicated groups.\n'
else
    printf 'Removed service and binaries. Account, groups, and installer record retained.\nUse --purge-account to explicitly remove the tracked broker identity.\n'
fi
