# Security contract

The authoritative requirements and acceptance scenarios are in [GitHub issue #1](https://github.com/tejasach06/ssh-credential-broker/issues/1). This document describes the intended security boundary and deployment requirements. It is not a claim that every platform acceptance scenario has passed.

## Trusted and untrusted identities

The operating system, kernel, administrator, service manager, installed broker binaries, and trusted operator session are trusted. The harness and its child processes are untrusted. The harness must run as a separate unprivileged UID, without root, sudo, administrator, debugger, broker-account, or service-management privileges. A root operator is permitted. A root harness or shared operator and harness UID is not.

The daemon runs as the dedicated unprivileged `sshbroker` account, with a dedicated primary group. Only the broker and harness join `sshbroker-exec`. Only the broker and trusted operator join `sshbroker-admin`. Runtime traversal is mode `0751`, while each Unix socket is mode `0660` with its separate group. Protocol authorization uses peer credentials in addition to these filesystem controls.

The administrator must establish that the harness cannot elevate privilege through host-specific rules. Group membership checks alone do not prove this. Custom sudo rules, privileged container engines, writable root jobs, debugger entitlements, inherited descriptors, and shared trusted terminals can invalidate the boundary. Do not run the operator credential producer inside the harness environment.

The installer rejects harness membership in `root`, `sudo`, `wheel`, `admin`, `docker`, `lxd`, `incus`, `libvirt`, `sshbroker`, and `sshbroker-admin`. It does not claim to verify arbitrary sudoers configurations, all VM control channels, or every platform entitlement. The operator must audit effective privilege independently.

## Files and service execution

Binaries, configuration, service definitions, and their parent directories are root-owned and not writable by the harness. The installer refuses unsafe ownership, group/world write permissions, symlink destination files, and macOS write-granting ACLs instead of weakening unrelated paths. It copies native release binaries to `/opt/ssh-credential-broker/bin` and records only identities in a root-only installation record. Verify release provenance before running the root installer.

Linux uses systemd `User=sshbroker`, a dedicated primary group, both supplementary socket groups, an empty capability set, `NoNewPrivileges`, a read-only filesystem namespace except the runtime path, and `LimitCORE=0`. macOS uses launchd `UserName=sshbroker`, `GroupName=sshbroker`, initialized supplementary groups, and both hard and soft core limits of zero. macOS does not inherit Linux's systemd sandbox. The daemon's platform protections and native acceptance evidence remain necessary.

The broker needs outbound SSH network access. Service installation does not weaken SSH server configuration, install client keys, disable operating-system protections, or grant the harness administrator rights. Socket group assignment does not require root because the broker belongs to both dedicated socket groups.

## Native Windows boundary

The Service Control Manager runs the daemon as `NT SERVICE\ssh-brokerd`, separately from the configured operator and harness user SIDs. Administrator-controlled installation paths, service permissions, and process and token DACLs prevent harness service replacement, memory reads, debugger access, or token duplication. Limited identity-query access permits clients to authenticate the pipe server without granting those other rights. Administrators and SYSTEM remain trusted.

Execution and administration use separate local-only named pipes. Their protected DACLs admit the intended caller without granting pipe-instance creation. Each server authorizes the connected client's token user, and each client verifies the server process's service identity. The daemon requires its SCM identity and rejects privileged harness tokens. Credential input remains local to the trusted operator and is sent only after server authentication.

The Windows installer requires existing, distinct user accounts. It checks effective group membership, including nested and deny-only membership, plus local LSA privilege assignments. These checks do not audit arbitrary delegated ACLs, domain rules, third-party elevation mechanisms, or future policy changes. Installation refuses untracked service or directory collisions and existing application-specific crash-report settings. Uninstallation checks ownership records and preserves unrelated users, groups, service configuration, and crash policy.

Windows Error Reporting exclusions and a deny-write LocalDumps directory reduce application dump exposure. They are basename-scoped policy changes, not an absolute erasure guarantee. Paging, hibernation, kernel dumps, privileged external tools, and prior dumps remain outside that protection.

Before remote work starts, the Windows client validates an inherited outcome handle's object type and granted write access. A read-only file or non-I/O handle must fail without authentication or remote command execution.

## Credential and destination lifetime

The credential pool exists only in memory. Passwords and usernames are not accepted as command-line options or environment variables. The operator uses hidden terminal prompts or an explicitly private framed input stream. There is no persistent vault, keychain integration, credential file format, or restart recovery.

Each grant fixes its pool and authorized harness UID. Unlocking an active grant is rejected. Lock and expiry invalidate authorization before cancellation and clear credentials, approvals, budgets, cursors, and matches. Restart starts locked. Work that has not committed a password submission cannot submit after invalidation. An already committed submission may be in flight and remains charged. A completed authentication cannot create a channel after authorization is invalidated.

Revocation disconnects SSH before execution output drains. The daemon permits at most five seconds to flush queued output and the classified lock or expiry result. A consumer that does not drain promptly can receive a socket close without that diagnostic. The bounded drain does not renew the grant or permit another password submission or channel.

Before any username or password submission, the operator must approve the target's numeric destination, port, and SSH host-key fingerprint. Verify the fingerprint through an independent trusted source. Accepting a fingerprint supplied only by an untrusted harness or network does not establish server identity. Approvals last only for the grant. DNS aliases cannot bypass numeric pinning or create a separate budget for the same approved server identity. Changed host keys fail closed.

Every password submission consumes budget, including a successful cached login. A password possibly transmitted before cancellation or transport failure remains consumed. Rejected credentials are not automatically retried within the grant. Cached rejection requires explicit operator renewal rather than scanning the rest of the pool. Budget and delay settings cannot guarantee protection from arbitrary server lockout policies.

## Accepted limits

- An approved SSH server receives the password submitted to it. A compromised approved server can capture that password.
- Full remote shell access exposes the remote username through normal operating-system commands. It can reveal remote secrets, change passwords, create users, install access mechanisms, or recover reused credentials from server files. Local pool isolation does not prevent these actions.
- The broker does not redact remote output. Filtering would corrupt arbitrary binary streams and cannot make unrestricted shell access secret-safe.
- The broker cannot hide secrets from local root, the kernel, a compromised operator, a compromised broker binary, or an attacker with broker debugging privileges.
- Secret buffers are cleared where controlled, and core dumps are disabled for the service. Absolute erasure is not guaranteed. Allocators, SSH-library copies, kernel buffers, swap, hibernation images, and platform crash-report infrastructure can retain data. Host administrators must assess those mechanisms separately.
- Lock, expiry, cancellation, and daemon termination close broker-owned SSH transports. They do not guarantee remote process cleanup, undo remote changes, terminate detached processes, or remove access mechanisms created remotely.
- Disconnecting SSH cannot recall a password already delivered to a transport or remote server.

There is no forwarding, agent forwarding, X11 forwarding, SFTP, SCP, arbitrary subsystem access, public-key fallback, or keyboard-interactive fallback. Remote sudo and application password prompts receive no automatic broker assistance.

## Known dependency advisory

The locked `rsa` version `0.10.0-rc.18` is affected by [RUSTSEC-2023-0071](https://rustsec.org/advisories/RUSTSEC-2023-0071.html). Upstream reports no patched version. This advisory concerns timing leakage during private RSA operations.

The broker's current password-only client does not load or use a client private key. The enabled RSA feature supports verification of server host signatures. Static source review traced that path through Russh's client key exchange to `ssh-key` public-key verification and the RSA public exponent operation. The private-key signing and decryption paths implicated by the advisory are not reachable through the broker's exposed operations.

RSA support remains enabled for servers that offer only RSA host keys. This is a scoped reachability assessment, not a patched-dependency claim or a blanket advisory suppression. Reassess the advisory before adding private-key authentication, signing, decryption, agent signing, a server role, or changing these dependencies.

## Diagnostics and verification

Ordinary diagnostics must not contain pool usernames, passwords, credential identifiers, raw authentication prompts, server banners, remote commands, or terminal contents. Classified stable error codes cross the client boundary instead of raw library errors. Destination names, numeric addresses, host fingerprints, session identifiers, and timing are potentially sensitive metadata. There is no telemetry or raw SSH packet logging in the initial design.

The native smoke workflow uses generated credentials and disposable SSH server identities. Its structured report lists observed coverage and local identities. It does not prove all issue acceptance scenarios. Native Linux and macOS evidence, including debugger denial and service replacement denial, is required before claiming isolation on either platform. A cross-compiled Windows executable is not a supported Windows release.

Do not attach passwords, private input frames, process dumps, raw packets, terminal recordings, or production SSH logs to a public report. Report security concerns through the repository's private vulnerability reporting channel if available. If it is unavailable, contact the repository owner privately to arrange a secure channel before sharing sensitive evidence. Public issues can contain a credential-free description of the affected version and platform.
