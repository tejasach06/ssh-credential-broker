# SSH credential broker

A password-only SSH broker for an untrusted local automation harness. The trusted operator enters a credential pool into `ssh-brokerd`, approves each destination, and grants a bounded session. `broker-ssh` relays commands or an interactive shell without exporting the stored credentials. `brokerctl` administers the daemon.

The public requirements and acceptance scenarios are in [GitHub issue #1](https://github.com/tejasach06/ssh-credential-broker/issues/1). Read [SECURITY.md](SECURITY.md) before deployment. Full remote shell access exposes the remote username and can expose remote secrets or create persistent access. This is not a command sandbox.

Linux with systemd and macOS with launchd are the initial deployment targets. Windows service installation and execution are unsupported. Native CI is configured, but a workflow definition is not a successful platform test. See [Verification limits](#verification-limits).

## Install verified release binaries

Use an administrator-controlled terminal, not the harness session. The harness must have its own unprivileged local account, with no sudo, administrator, debugger, broker-account, or service-management access. The operator uses a different UID. A root operator is allowed. A root harness is rejected.

The installer rejects known privileged group memberships, including `root`, `sudo`, `wheel`, `admin`, `docker`, `lxd`, `incus`, `libvirt`, and the broker service and administration groups. This does not verify arbitrary sudoers rules or every privilege path. Audit the harness's effective sudo access, VM and container engine control, debugger rights, and service-management permissions before installation.

1. Obtain the three native release binaries, the matching `scripts/` directory, and `deploy/` directory from a trusted release. Verify the release provenance and published archive checksums independently. Do not run a downloaded installer before reviewing it.
2. Place `ssh-brokerd`, `broker-ssh`, and `brokerctl` together in a release directory. Do not run the installed daemon from a harness-writable checkout.
3. Supply the existing operator and harness account names. Replace `trusted-operator`, `automation`, and the release path below.

```sh
sudo bash scripts/install.sh --bin-dir /absolute/path/to/release \
	--operator trusted-operator --harness automation
```

The installer creates only its dedicated `sshbroker` account and the `sshbroker`, `sshbroker-exec`, and `sshbroker-admin` groups. Existing collisions without an installer ownership record are rejected. Repeating the command with the same identities updates binaries and restarts the service locked. Identity changes require explicit removal with `--purge-account`, then installation with the new identities. Open a new harness login after installation to obtain its new supplementary group.

Installed resources are:

| Resource | Linux | macOS |
| --- | --- | --- |
| Root-owned binaries | `/opt/ssh-credential-broker/bin/` | Same |
| Root-owned installation record | `/etc/ssh-credential-broker/install-state` | `/private/etc/ssh-credential-broker/install-state` |
| Root-owned service configuration | `/etc/ssh-credential-broker/daemon.env` and `/etc/systemd/system/ssh-brokerd.service` | `/Library/LaunchDaemons/com.ssh-credential-broker.daemon.plist` |
| Broker-owned runtime directory | `/run/ssh-credential-broker` | `/private/var/db/ssh-credential-broker/run` |

The runtime directory is mode `0751`. The daemon's primary group is `sshbroker`. Its supplementary groups include both socket groups, allowing it to assign socket groups without root privileges. `exec.sock` is mode `0660`, group `sshbroker-exec`, shared with the harness. `admin.sock` is mode `0660`, group `sshbroker-admin`, shared with the operator, never the harness. Peer UID checks also authorize requests. The macOS directory survives reboot so launchd can run the daemon unprivileged without a privileged startup helper. It contains sockets, not saved credentials.

The installer requires root-owned, non-group-writable, non-world-writable binary, configuration, service, and ancestor directories. It rejects unsafe paths rather than changing unrelated directory permissions. On macOS, write-granting ACLs are rejected too. It adds only the dedicated group memberships and does not replace existing memberships. It does not modify target SSH configuration or enable password authentication on any server.

Service control commands are:

```sh
# Linux
sudo systemctl status ssh-brokerd.service
sudo systemctl restart ssh-brokerd.service
# macOS
sudo launchctl print system/com.ssh-credential-broker.daemon
sudo launchctl kickstart -k system/com.ssh-credential-broker.daemon
```

Restart, reinstall, and upgrade revoke the current grant. Credentials and approvals must be entered again.

## Unlock from the trusted operator session

Use the installed binaries by absolute path, or add `/opt/ssh-credential-broker/bin` to your trusted shell's `PATH`. The examples below assume that directory is in `PATH`. Client default socket paths match the installed platform layout.

```sh
brokerctl unlock --harness-uid "$(id -u automation)" --credential-count 2 --ttl-seconds 1800
brokerctl status
```

`unlock` prompts through the operator's terminal with both username and password hidden. No literal credential flags or credential environment variables are supported. The default duration is 1,800 seconds. The allowed range is 60 through 28,800 seconds. An active grant cannot be replaced or extended by another unlock. Lock first, then provision the new fixed pool.

For trusted automation, `unlock --private-json-stdin` accepts a four-byte big-endian length followed by a UTF-8 JSON array of objects with `username` and `password` fields. The total frame is limited to 64 KiB and at most 64 entries. The input must be an explicitly private regular file, pipe, or socket owned by the effective operator UID, without group or other permission bits. The input producer and its environment are part of the trusted operator boundary. Do not save credentials to a harness-readable file, embed them in shell commands, use shell tracing, or pass them in the environment. This option conflicts with `--credential-count`.

Credentials, destination approvals, matches, budgets, and discovery state remain in memory for this grant only. There is no persistent vault, host inventory, or restart recovery.

## Request and approve a destination

From the harness account, request a numeric address or DNS name without a username:

```sh
broker-ssh server.example --port 22 -- 'uptime'
```

An unapproved target returns `APPROVAL_REQUIRED` and exits. No credentials are submitted. The pending request survives client exit, but approval does not execute that completed request.

From the trusted operator session:

```sh
brokerctl pending
```

Verify the displayed SSH host-key algorithm and SHA-256 fingerprint through an independent trusted source, such as the server console or an authenticated administrator. A fingerprint supplied only by the harness or the same untrusted network is not independent verification. The host key identifies the server. It is not a client login key, and this broker does not install client public keys.

Approve the verified fingerprint and the exact numeric destination, replacing both example values:

```sh
brokerctl approve server.example --port 22 --pinned-ip 192.0.2.10 \
	--fingerprint 'SHA256:REPLACE_WITH_INDEPENDENTLY_VERIFIED_FINGERPRINT' --attempt-budget 1
```

The daemon pins that numeric address, port, and host key for the grant. It does not perform an unconstrained DNS lookup for later connections. A changed server key fails closed and requires another operator decision. Retry the command from the harness only after approval.

The default budget is one password submission. Every login counts, including successful cached logins and possibly transmitted attempts that later time out or are cancelled. The cache does not provide free logins. Check the server's lockout policy before increasing a budget.

```sh
brokerctl budget server.example --port 22 --additional-attempts 1
brokerctl resume server.example --port 22 --additional-attempts 1
brokerctl deny server.example --port 22
```

`budget` adds attempts without resetting the discovery cursor. `resume` explicitly renews discovery after a cached credential is rejected. A cached rejection stops the request instead of silently scanning the remaining pool. Only rejected credentials advance discovery. Transport errors do not trigger a password scan. Alternate hostnames for the same approved numeric destination, port, and host key share the identity's budget.

## Execute commands and use a terminal

`broker-ssh` accepts one remote command string after `--`. The remote server interprets that string as shell syntax. No local shell executes it inside the broker.

```sh
broker-ssh server.example --port 22 -- 'printf hello; printf warning >&2; exit 7'
printf 'input\n' | broker-ssh server.example -- 'cat'
# Omit the command for an interactive shell with a PTY.
broker-ssh server.example
```

Command mode preserves binary stdin, stdout, and stderr. EOF closes the SSH input stream while output continues to drain. Interactive mode forwards terminal size changes and control input and restores local terminal state on exit. The remote account retains all of its normal privileges. The broker neither filters output nor supplies passwords to remote application or sudo prompts.

Use `--socket PATH` on `broker-ssh` or `--admin-socket PATH` on `brokerctl` to override the default socket. Client options are not OpenSSH options. SSH URLs, `user@host`, proxy commands, SSH configuration aliases, forwarding, agent forwarding, SCP, SFTP, and arbitrary SSH subsystems are unsupported.

A remote exit status becomes the shell exit code modulo 256. Local failures use exit code `125`. A remote process may also exit `125`, so automation must not classify outcomes from the exit code alone. `--outcome-fd FD` writes one JSON outcome to an already-open descriptor numbered at least 3, separate from remote output:

```sh
broker-ssh --outcome-fd 3 server.example -- 'exit 7' 3>outcome.json
```

The JSON outcome is `remote_exit` with `exit_status`, `remote_signal` with `code` and `signal`, or `client_error` with `code` and `message`. Without that descriptor, remote output remains untouched. Local errors and remote signals produce classified JSON on stderr. `brokerctl` writes JSON responses on stdout and classified failures on stderr.

## Lock or remove the broker

From the operator account, revoke the grant:

```sh
brokerctl lock
```

Lock and expiry invalidate authorization, disconnect active SSH channels, and clear the pool and all session state. A password already handed to the transport may already be in flight. Detached remote processes and changes made on the server may survive disconnect.

Remove the service and installed binaries:

```sh
sudo bash scripts/uninstall.sh
```

The default preserves the dedicated account, groups, memberships, and root-only installer record for reinstall or later removal. To explicitly delete the installer-created broker account and dedicated groups:

```sh
sudo bash scripts/uninstall.sh --purge-account
```

Removal uses tracked identities and numeric IDs. It refuses changed identities and group adoption by unrelated users during account purge. It removes only named files and empty directories, never a recursive tree or unrelated home directory. Unknown resources are preserved or cause a refusal. The operator and harness accounts are never removed.

## Diagnose classified outcomes

| Code | Meaning or action |
| --- | --- |
| `INPUT_ERROR` | Invalid target, option, field, or credential input. |
| `BROKER_LOCKED` | Provision a grant from the operator session. |
| `APPROVAL_REQUIRED` | Verify and approve the pending server identity, then retry. |
| `AUTHENTICATION_REJECTED` | The permitted credential was rejected or discovery has no remaining entry. |
| `BUDGET_EXHAUSTED` | Inspect lockout policy before adding attempts. |
| `RENEWAL_REQUIRED` | A cached credential failed. Operator `resume` is required. |
| `HOST_KEY_MISMATCH` | Stop and independently investigate the server key change. |
| `TRANSPORT_FAILURE` | Connection or IPC transport failed. No raw server error is exposed. |
| `BROKER_LOCK` | The operator revoked the active request. |
| `BROKER_EXPIRED` | The grant expired. |
| `PERMISSION_DENIED` | The caller or private input is not authorized. |
| `RESOURCE_LIMIT` | A bounded work or state limit was reached. |
| `UNSUPPORTED` | The requested capability or platform is unsupported. |
| `PROTOCOL_ERROR` | IPC version, framing, or message is invalid. |
| `ALREADY_UNLOCKED` | Lock before provisioning another grant. |
| `NOT_FOUND` | No matching pending or approved destination exists. |
| `CANCELLED` | The client cancelled the request. |
| `MISSING_REMOTE_STATUS` | The transport closed without a remote exit result. |
| `REMOTE_SIGNAL` | The remote process exited through a signal. |
| `LOCAL_IO` | Local terminal, input, output, or outcome descriptor failed. |
| `INTERNAL_ERROR` | The broker encountered an internal failure. |

Service metadata may include destination names, IPs, fingerprints, and timing. Treat it as potentially sensitive. Do not enable raw SSH packet logging or collect process memory as a diagnostic bundle.

## Verification limits

The native workflow runs formatting, clippy, unit and integration tests, release builds, and `sudo python3 scripts/smoke.py --bin-dir target/release` on Linux and macOS runners. The smoke uses a disposable loopback SSH server, generated fixture credentials, a root operator, and a distinct unprivileged harness. It refuses an existing tracked installation. Run it only on a disposable native host, not a workstation with a production broker.

The script reports the identities and behavior it actually observes. It is partial acceptance coverage, not a complete A01-A31 security audit. Configured tests do not establish a platform pass until the corresponding run completes. No Linux or macOS execution was performed while authoring these deployment files. Cross-compilation, mocked tests, and Linux containers do not establish macOS isolation. Release evidence must identify each native platform, service and harness identities, exercised scenarios, and observed results. Suspend behavior, race boundaries, resource exhaustion, and all remaining issue acceptance scenarios need their own evidence before a complete release claim.

The application attempts to limit and clear secret memory. It cannot guarantee absolute erasure of every copy held by allocators, SSH libraries, the kernel, swap, or crash infrastructure. Review [the security contract](SECURITY.md) for the trust assumptions and exclusions.
