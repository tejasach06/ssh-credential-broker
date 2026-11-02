#!/bin/bash
set -euo pipefail
SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd -P)
# shellcheck source=install-common.sh
. "$SCRIPT_DIR/install-common.sh"
usage() { printf 'Usage: sudo bash scripts/install.sh --bin-dir RELEASE_DIRECTORY --operator USER --harness USER\n'; }
BIN_DIR=; REQUEST_OPERATOR=; REQUEST_HARNESS=
while [ "$#" -gt 0 ]; do
    case "$1" in
        --bin-dir|--operator|--harness)
            [ "$#" -ge 2 ] || fail "missing value for $1"
            case "$1" in --bin-dir) BIN_DIR=$2 ;; --operator) REQUEST_OPERATOR=$2 ;; --harness) REQUEST_HARNESS=$2 ;; esac
            shift 2 ;;
        --help) usage; exit 0 ;;
        *) usage >&2; fail 'unknown option' ;;
    esac
done
[ -n "$BIN_DIR" ] && [ -n "$REQUEST_OPERATOR" ] && [ -n "$REQUEST_HARNESS" ] || { usage >&2; exit 1; }
for identity in "$REQUEST_OPERATOR" "$REQUEST_HARNESS"; do
    case "$identity" in *[!a-zA-Z0-9_.-]*|'') fail 'provide a local account name, not a numeric UID or option' ;; esac
    case "$identity" in [a-zA-Z_]*) ;; *) fail 'account names must start with a letter or underscore' ;; esac
    id "$identity" >/dev/null 2>&1 || fail "unknown identity: $identity"
done
REQUEST_OPERATOR_UID=$(id -u "$REQUEST_OPERATOR")
REQUEST_HARNESS_UID=$(id -u "$REQUEST_HARNESS")
[ "$REQUEST_HARNESS_UID" != 0 ] || fail 'the harness must not be root'
[ "$REQUEST_OPERATOR_UID" != "$REQUEST_HARNESS_UID" ] || fail 'operator and harness must have different UIDs'
[ "$REQUEST_OPERATOR" != "$BROKER" ] && [ "$REQUEST_HARNESS" != "$BROKER" ] || fail 'broker account must be separate'
# Known privileged memberships are rejected. Custom elevation rules still require an operator audit.
for group in $(id -Gn "$REQUEST_HARNESS"); do
    case "$group" in
        "$BROKER"|"$ADMIN_GROUP"|root|wheel|admin|sudo|docker|lxd|incus|libvirt)
            fail "harness belongs to a privileged or broker administration group: $group" ;;
    esac
done
for binary in ssh-brokerd broker-ssh brokerctl; do
    [ -f "$BIN_DIR/$binary" ] && [ -x "$BIN_DIR/$binary" ] && [ ! -L "$BIN_DIR/$binary" ] || fail "missing release binary: $binary"
done
if [ "$OS" = Linux ]; then
    command -v systemctl >/dev/null || fail 'systemd is required'
    [ -d /run/systemd/system ] || fail 'systemd must be the running service manager'
else
    command -v dscl >/dev/null || fail 'local Directory Services are required'
fi
make_secure_dir /opt
make_secure_dir "$PREFIX"
make_secure_dir "$PREFIX/bin"
make_secure_dir "$CONFIG"
secure_dir "$(dirname "$SERVICE")"
if [ -e "$STATE" ] || [ -L "$STATE" ]; then
    load_state
    [ "$REQUEST_OPERATOR_UID" = "$OPERATOR_UID" ] && [ "$REQUEST_HARNESS_UID" = "$HARNESS_UID" ] || fail 'identity change requires uninstall --purge-account and a new install'
else
    [ ! -e "$SERVICE" ] && [ ! -L "$SERVICE" ] || fail 'refusing to replace an untracked service'
    for path in "$CONFIG/daemon.env" "$PREFIX/bin/ssh-brokerd" "$PREFIX/bin/broker-ssh" "$PREFIX/bin/brokerctl"; do
        [ ! -e "$path" ] && [ ! -L "$path" ] || fail "refusing to replace an untracked file: $path"
    done
    ! id "$BROKER" >/dev/null 2>&1 || fail 'broker account already exists without installer ownership record'
    for group in "$BROKER" "$EXEC_GROUP" "$ADMIN_GROUP"; do
        [ -z "$(group_id "$group")" ] || fail "group already exists without installer ownership record: $group"
    done
    CREATED_GROUPS=; CREATED_USER=0
    rollback_accounts() {
        local result=$?
        if [ "$result" != 0 ]; then
            if [ "$CREATED_USER" = 1 ]; then
                if [ "$OS" = Linux ]; then userdel "$BROKER"; else dscl . -delete "/Users/$BROKER"; fi
            fi
            for group in $CREATED_GROUPS; do
                if [ "$OS" = Linux ]; then groupdel "$group"; else dscl . -delete "/Groups/$group"; fi
            done
        fi
    }
    trap rollback_accounts EXIT
    for group in "$BROKER" "$EXEC_GROUP" "$ADMIN_GROUP"; do
        if [ "$OS" = Linux ]; then
            candidate=450
            while getent group "$candidate" >/dev/null || [ -n "$(getent passwd | awk -F: -v gid="$candidate" '$4 == gid { print $1 }')" ]; do candidate=$((candidate + 1)); done
            groupadd --system --gid "$candidate" "$group"
            CREATED_GROUPS="$group $CREATED_GROUPS"
        else
            candidate=450
            while [ -n "$(dscl . -search /Groups PrimaryGroupID "$candidate")" ] || [ -n "$(dscl . -search /Users PrimaryGroupID "$candidate")" ]; do candidate=$((candidate + 1)); done
            dscl . -create "/Groups/$group"
            CREATED_GROUPS="$group $CREATED_GROUPS"
            dscl . -create "/Groups/$group" PrimaryGroupID "$candidate"
            dscl . -create "/Groups/$group" Password '*'
        fi
    done
    BROKER_GID=$(group_id "$BROKER")
    if [ "$OS" = Linux ]; then
        useradd --system --gid "$BROKER" --no-create-home --home-dir /nonexistent --shell /usr/sbin/nologin "$BROKER"
        CREATED_USER=1
    else
        candidate=450
        while [ -n "$(dscl . -search /Users UniqueID "$candidate")" ]; do candidate=$((candidate + 1)); done
        dscl . -create "/Users/$BROKER"
        CREATED_USER=1
        dscl . -create "/Users/$BROKER" UniqueID "$candidate"
        dscl . -create "/Users/$BROKER" PrimaryGroupID "$BROKER_GID"
        dscl . -create "/Users/$BROKER" UserShell /usr/bin/false
        dscl . -create "/Users/$BROKER" NFSHomeDirectory /var/empty
        dscl . -create "/Users/$BROKER" IsHidden 1
        dscl . -create "/Users/$BROKER" Password '*'
    fi
    OPERATOR=$REQUEST_OPERATOR; HARNESS=$REQUEST_HARNESS
    OPERATOR_UID=$REQUEST_OPERATOR_UID; HARNESS_UID=$REQUEST_HARNESS_UID
    BROKER_UID=$(id -u "$BROKER")
    EXEC_GID=$(group_id "$EXEC_GROUP"); ADMIN_GID=$(group_id "$ADMIN_GROUP")
    temporary=$(mktemp "$CONFIG/.state.XXXXXX")
    printf '%s\n' VERSION=1 "OPERATOR=$OPERATOR" "HARNESS=$HARNESS" "OPERATOR_UID=$OPERATOR_UID" "HARNESS_UID=$HARNESS_UID" "BROKER_UID=$BROKER_UID" "BROKER_GID=$BROKER_GID" "EXEC_GID=$EXEC_GID" "ADMIN_GID=$ADMIN_GID" > "$temporary"
    chmod 0600 "$temporary"
    mv "$temporary" "$STATE"
    trap - EXIT
fi
# Never replace the caller's unrelated supplementary memberships.
add_member "$BROKER" "$EXEC_GROUP"
add_member "$BROKER" "$ADMIN_GROUP"
add_member "$HARNESS" "$EXEC_GROUP"
add_member "$OPERATOR" "$ADMIN_GROUP"
! id -Gn "$HARNESS" | tr ' ' '\n' | grep -Fxq "$ADMIN_GROUP" || fail 'harness has administration group membership'
if [ "$OS" = Darwin ]; then make_secure_dir /private/var/db/ssh-credential-broker; fi
check_runtime
stop_service
# Updates revoke the old grant; the restarted daemon always starts locked.
for binary in ssh-brokerd broker-ssh brokerctl; do
    check_destination "$PREFIX/bin/$binary"
    temporary=$(mktemp "$PREFIX/bin/.binary.XXXXXX")
    install -o root -g "$ROOT_GROUP" -m 0755 "$BIN_DIR/$binary" "$temporary"
    mv -f "$temporary" "$PREFIX/bin/$binary"
done
check_destination "$SERVICE"
if [ "$OS" = Linux ]; then
    check_destination "$CONFIG/daemon.env"
    temporary=$(mktemp "$CONFIG/.env.XXXXXX")
    printf '%s\n' "OPERATOR_UID=$OPERATOR_UID" "HARNESS_UID=$HARNESS_UID" "EXEC_GID=$EXEC_GID" "ADMIN_GID=$ADMIN_GID" > "$temporary"
    chmod 0600 "$temporary"
    mv -f "$temporary" "$CONFIG/daemon.env"
    temporary=$(mktemp "$(dirname "$SERVICE")/.ssh-brokerd.XXXXXX")
    install -o root -g "$ROOT_GROUP" -m 0644 "$SCRIPT_DIR/../deploy/ssh-brokerd.service" "$temporary"
    mv -f "$temporary" "$SERVICE"
    systemctl daemon-reload
    systemctl enable --now ssh-brokerd.service
else
    if [ ! -d "$RUNTIME" ]; then mkdir "$RUNTIME"; chown "$BROKER:$BROKER" "$RUNTIME"; chmod 0751 "$RUNTIME"; fi
    temporary=$(mktemp "$(dirname "$SERVICE")/.ssh-brokerd.XXXXXX")
    while IFS= read -r line; do
        line=${line//@OPERATOR_UID@/$OPERATOR_UID}
        line=${line//@HARNESS_UID@/$HARNESS_UID}
        line=${line//@EXEC_GID@/$EXEC_GID}
        line=${line//@ADMIN_GID@/$ADMIN_GID}
        printf '%s\n' "$line"
    done < "$SCRIPT_DIR/../deploy/com.ssh-credential-broker.daemon.plist.in" > "$temporary"
    chmod 0644 "$temporary"
    chown root:wheel "$temporary"
    /usr/bin/plutil -lint "$temporary"
    mv -f "$temporary" "$SERVICE"
    launchctl enable system/com.ssh-credential-broker.daemon
    launchctl bootstrap system "$SERVICE"
fi
printf 'Installed. Daemon starts locked. Open a new harness login to refresh group membership.\nRuntime: %s\nBinaries: %s/bin\n' "$RUNTIME" "$PREFIX"
