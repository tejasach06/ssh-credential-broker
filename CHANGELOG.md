# Changelog

## Unreleased

- Upgrade `actions/upload-artifact` to v7, which uses Node.js 24 and removes the deprecated Node.js 20 action runtime.
- Add the memory-only password SSH broker, harness client, and trusted operator client described by [issue #1](https://github.com/tejasach06/ssh-credential-broker/issues/1).
- Add dedicated-user systemd and launchd deployment, separate execution and administration socket groups, root-owned installed binaries, and explicit account-purge removal.
- Retain Linux and macOS native SSH smoke scripts and historical run evidence. The current container-only CI does not run native service-isolation checks.
- Package release archives with the native `bin/` directory, installation scripts, service templates, and release documentation.
- Extend native SSH smoke coverage for outcome descriptor preflight and write failure, native custom-signal exit mapping, established stdin backpressure beyond 30 seconds, and complete revocation frames under real Unix-socket output backpressure.
- Add native hosts-file pinning and alias-budget checks, idle IPC and malformed-frame admission pressure with a live SSH channel, stalled-handshake pre-session streaming rejection, and hostile-banner diagnostic checks.
- Document operator approval, numeric address and host-key pinning, every-login authentication budgets, private credential entry, classified outcomes, accepted remote-shell risks, and verification limits.
- Add native x64 Windows clients, secured local named pipes, a dedicated virtual SCM service account, administrator-controlled installation and removal, protected console I/O, and inherited-handle preflight.
- Retain disposable native Windows SSH and ConPTY smoke scripts without claiming a native Windows pass.
- Move all CI jobs to the VM 101 rootless Podman runner for trusted repository pushes and manual runs, including feature branches. Remove GitHub-hosted workflows, pull request triggers, and the Windows workstation dispatch input.
- Use `--locked` for Cargo checks, tests, and release builds. Upload Linux and Windows GNU cross-compiled installation archives with their SHA-256 manifests. These artifacts do not establish native service-isolation or Windows runtime verification.
- Retain harness-writable Windows smoke scratch for disposable-host teardown instead of recursively deleting it with administrator privileges.
- No absolute memory-erasure or remote-process-cleanup guarantee is made.
