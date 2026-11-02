#!/bin/bash
# Sourced by the root-only installer and uninstaller. No credentials live here.
set -euo pipefail
PATH=/usr/sbin:/usr/bin:/sbin:/bin
export PATH
umask 077
fail() { printf 'ssh-credential-broker: %s\n' "$*" >&2; exit 1; }
[ "$(id -u)" = 0 ] || fail 'run as root'
OS=$(uname -s)
case "$OS" in
    Linux) ROOT_GROUP=root; CONFIG=/etc/ssh-credential-broker; RUNTIME=/run/ssh-credential-broker; SERVICE=/etc/systemd/system/ssh-brokerd.service ;;
    Darwin) ROOT_GROUP=wheel; CONFIG=/private/etc/ssh-credential-broker; RUNTIME=/private/var/db/ssh-credential-broker/run; SERVICE=/Library/LaunchDaemons/com.ssh-credential-broker.daemon.plist ;;
    *) fail 'only Linux with systemd and macOS with launchd are supported' ;;
esac
PREFIX=/opt/ssh-credential-broker
STATE=$CONFIG/install-state
BROKER=sshbroker
EXEC_GROUP=sshbroker-exec
ADMIN_GROUP=sshbroker-admin
owner() { if [ "$OS" = Linux ]; then stat -c %u "$1"; else stat -f %u "$1"; fi; }
mode() { if [ "$OS" = Linux ]; then stat -c %a "$1"; else stat -f %Lp "$1"; fi; }
group_id() { if [ "$OS" = Linux ]; then getent group "$1" | cut -d: -f3; else dscl . -read "/Groups/$1" PrimaryGroupID 2>/dev/null | cut -d' ' -f2; fi; }
check_acl() {
    if [ "$OS" = Darwin ] && /bin/ls -lde "$1" | grep -Eq ' allow .*(write|append|add_file|add_subdirectory|delete|chown)'; then
        fail "write-granting ACL on protected path: $1"
    fi
}
# Resolve platform-owned aliases such as /etc, then check every physical ancestor.
secure_dir() {
    local path="$1" physical bits
    [ -d "$path" ] && [ ! -L "$path" ] || fail "not a real directory: $path"
    physical=$(cd "$path" && pwd -P)
    while :; do
        [ "$(owner "$physical")" = 0 ] || fail "directory is not root-owned: $physical"
        bits=$(mode "$physical")
        if [ $((8#$bits & 0022)) != 0 ]; then
            if [ "$physical" = /opt ] || [ "$physical" = /tmp ]; then
                chmod 0755 "$physical"
            else
                fail "directory is group/world writable: $physical"
            fi
        fi
        check_acl "$physical"
        [ "$physical" != / ] || break
        physical=${physical%/*}; [ -n "$physical" ] || physical=/
    done
}
make_secure_dir() {
    local path="$1"
    secure_dir "$(dirname "$path")"
    if [ ! -e "$path" ] && [ ! -L "$path" ]; then mkdir "$path"; chmod 0755 "$path"; fi
    secure_dir "$path"
}
secure_file() {
    local path="$1" bits
    secure_dir "$(dirname "$path")"
    [ -f "$path" ] && [ ! -L "$path" ] || fail "not a regular file: $path"
    [ "$(owner "$path")" = 0 ] || fail "file is not root-owned: $path"
    bits=$(mode "$path")
    [ $((8#$bits & 0022)) = 0 ] || fail "file is group/world writable: $path"
    check_acl "$path"
}
check_destination() {
    secure_dir "$(dirname "$1")"
    if [ -e "$1" ] || [ -L "$1" ]; then secure_file "$1"; fi
}
add_member() {
    if [ "$OS" = Linux ]; then usermod -a -G "$2" "$1"; else dseditgroup -o edit -a "$1" -t user "$2"; fi
}
remove_member() {
    if id -Gn "$1" | tr ' ' '\n' | grep -Fxq "$2"; then
        if [ "$OS" = Linux ]; then gpasswd -d "$1" "$2" >/dev/null; else dseditgroup -o edit -d "$1" -t user "$2"; fi
    fi
}
load_state() {
    secure_file "$STATE"
    VERSION=; OPERATOR=; HARNESS=; OPERATOR_UID=; HARNESS_UID=; BROKER_UID=; BROKER_GID=; EXEC_GID=; ADMIN_GID=
    local key value
    while IFS='=' read -r key value; do
        case "$key" in
            VERSION|OPERATOR_UID|HARNESS_UID|BROKER_UID|BROKER_GID|EXEC_GID|ADMIN_GID)
                case "$value" in ''|*[!0-9]*) fail 'invalid installation state' ;; esac ;;
            OPERATOR|HARNESS) case "$value" in ''|*[!a-zA-Z0-9_.-]*) fail 'invalid installation identity' ;; esac ;;
            *) fail 'unknown installation state key' ;;
        esac
        printf -v "$key" '%s' "$value"
    done < "$STATE"
    [ "$VERSION" = 1 ] && [ -n "$OPERATOR" ] && [ -n "$HARNESS" ] || fail 'incomplete installation state'
    [ -n "$BROKER_GID" ] && [ -n "$EXEC_GID" ] && [ -n "$ADMIN_GID" ] || fail 'incomplete group state'
    [ "$(id -u "$BROKER")" = "$BROKER_UID" ] && [ "$BROKER_UID" != 0 ] || fail 'broker identity changed'
    [ "$(id -g "$BROKER")" = "$BROKER_GID" ] || fail 'broker primary group changed'
    [ "$(group_id "$BROKER")" = "$BROKER_GID" ] || fail 'broker group changed'
    [ "$(group_id "$EXEC_GROUP")" = "$EXEC_GID" ] || fail 'execution group changed'
    [ "$(group_id "$ADMIN_GROUP")" = "$ADMIN_GID" ] || fail 'administration group changed'
    [ "$(id -u "$OPERATOR")" = "$OPERATOR_UID" ] && [ "$(id -u "$HARNESS")" = "$HARNESS_UID" ] || fail 'operator or harness identity changed'
    [ "$HARNESS_UID" != 0 ] && [ "$HARNESS_UID" != "$OPERATOR_UID" ] && [ "$HARNESS_UID" != "$BROKER_UID" ] && [ "$OPERATOR_UID" != "$BROKER_UID" ] || fail 'identities are not isolated'
}
stop_service() {
    if [ "$OS" = Linux ]; then
        if [ -f "$SERVICE" ]; then systemctl disable --now ssh-brokerd.service; fi
    elif launchctl print system/com.ssh-credential-broker.daemon >/dev/null 2>&1; then
        launchctl bootout system/com.ssh-credential-broker.daemon
    fi
}
check_runtime() {
    secure_dir "$(dirname "$RUNTIME")"
    if [ -e "$RUNTIME" ] || [ -L "$RUNTIME" ]; then
        [ -d "$RUNTIME" ] && [ ! -L "$RUNTIME" ] || fail 'unsafe runtime path'
        [ "$(owner "$RUNTIME")" = "$BROKER_UID" ] || fail 'runtime owner changed'
        [ "$(mode "$RUNTIME")" = 751 ] || fail 'runtime permissions changed'
        check_acl "$RUNTIME"
    fi
}
