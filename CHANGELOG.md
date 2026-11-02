# Changelog

## Unreleased

- Add the memory-only password SSH broker, harness client, and trusted operator client described by [issue #1](https://github.com/tejasach06/ssh-credential-broker/issues/1).
- Add dedicated-user systemd and launchd deployment, separate execution and administration socket groups, root-owned installed binaries, and explicit account-purge removal.
- Add Linux and macOS native CI with real loopback SSH smoke scenarios and generated fixture credentials. Configured checks are not recorded platform passes.
- Document operator approval, numeric address and host-key pinning, every-login authentication budgets, private credential entry, classified outcomes, accepted remote-shell risks, and verification limits.
- Keep Windows service deployment unsupported. No absolute memory-erasure or remote-process-cleanup guarantee is made.
