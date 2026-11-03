---
name: ssh-broker
description: Use when an AI agent or automation harness needs to execute commands or open shells over SSH using ssh-credential-broker, handle destination approval handoffs, and interpret broker outcomes.
---

# SSH Credential Broker Harness Guide

The `ssh-credential-broker` allows an automated harness or AI agent to execute remote commands and interactive shells over SSH without accessing or managing stored passwords.

The broker isolates credentials in memory within the daemon (`ssh-brokerd`). The harness only provides the destination address and command; the daemon verifies server identity against operator approvals, tries credentials within an authorized attempt budget, and relays the SSH channel.

## Role boundary

The harness uses `broker-ssh`. It does not run `brokerctl`, enter credentials, approve host keys, or increase authentication budgets. Those operations belong to a human in the trusted operator session. If the agent is explicitly operating inside that trusted session, follow the operator commands below; otherwise report the required action and wait.

---

## 1. Quick Execution Reference

### Basic Non-Interactive Command

```bash
# Service mode (default platform socket / named pipe)
broker-ssh <target> -- <command>

# Standalone / portable mode
broker-ssh --standalone <target> -- <command>

# Custom endpoint (Unix socket or Windows named pipe)
broker-ssh --socket /path/to/exec.sock <target> -- <command>
broker-ssh --pipe "\\.\pipe\custom-exec" <target> -- <command>
```

- `<target>`: Bare hostname or IP address only (e.g. `192.0.2.10`, `db.internal`).
- **NEVER** pass `user@host`, `ssh://`, or login flags (`-l`, `-i`). The broker selects credentials from its authorized pool.
- Remote command follows `--` as one quoted shell-command string, for example `-- 'uname -a && id'`.
- Port defaults to `22`. Override with `--port <port>`.

### Interactive Shell

Omit `-- <command>` to request an interactive PTY shell:

```bash
broker-ssh <target>
broker-ssh --standalone <target>
```

---

## 2. Execution Outcomes & Exit Codes

`broker-ssh` maps results as follows:

| Exit Code | Meaning |
| :--- | :--- |
| `0` | Remote command succeeded (`0`). |
| `1`–`124`, `126`–`255` | Remote process exit status (modulo 256). |
| `125` | Local broker or client error (see JSON outcome on stderr or outcome descriptor). |
| `128 + N` | Remote process terminated by POSIX signal `N` (e.g. 143 for SIGTERM). |

### Structured Outcome Handling

To avoid ambiguity between remote exit code `125` and local client errors, consume structured JSON outcomes:

- **Linux / macOS**: Pass `--outcome-fd <fd>` (where `fd >= 3` is an inherited open writable descriptor).
- **Windows**: Pass `--outcome-handle <handle_int>` (an inherited open writable handle).

The broker writes one JSON object:
- Remote completion: `{"outcome":"remote_exit", "exit_status": 0}`
- Remote signal: `{"outcome":"remote_signal", "code":"REMOTE_SIGNAL", "signal":"TERM"}`
- Broker/client error: `{"outcome":"client_error", "code":"<ERROR_CODE>", "message":"<description>"}`

---

## 3. Destination Approval Workflow (`APPROVAL_REQUIRED`)

The broker operates with a strict server identity verification gate. It will **never** send credentials to an unapproved destination or host key.

When the harness contacts a target for the first time in a grant session:

1. `broker-ssh` fails immediately with exit code `125`:
   ```json
   {"outcome":"client_error","code":"APPROVAL_REQUIRED","message":"destination approval required"}
   ```
2. **Action required by harness**:
   - **DO NOT retry immediately in an automated loop.** Retrying before approval will repeatedly fail.
   - Stop and notify the human operator that the destination requires approval:
     > *"Target `<target>:<port>` requires operator approval in ssh-broker before credentials can be submitted."*
3. **Operator approval action** (executed by the human in their trusted operator terminal):
   ```bash
   # 1. View pending destinations and host key fingerprints
   brokerctl pending
   # (or: brokerctl --standalone pending)

   # 2. Verify the host key fingerprint independently, then approve:
   brokerctl approve <target> --port 22 --pinned-ip <resolved-ip> --fingerprint 'SHA256:<fingerprint>' --attempt-budget 1
   ```
4. **Resuming work**: Once the operator confirms approval, re-run the `broker-ssh` command.

---

## 4. Error Code Reference & Recovery Actions

When `broker-ssh` exits `125`, inspect the `code` field in the client error JSON:

### `BROKER_LOCKED`
- **Cause**: The broker is not unlocked, or the grant TTL expired.
- **Recovery**: Inform the operator. The operator unlocks the broker from the trusted session:
  ```bash
  # Linux/macOS service mode
  brokerctl unlock --harness-uid "$(id -u automation)" --credential-count <N> --ttl-seconds 1800

  # Portable mode on every platform
  brokerctl --standalone unlock --credential-count <N> --ttl-seconds 1800

  # Windows service mode
  brokerctl unlock --credential-count <N> --ttl-seconds 1800
  ```

### `BUDGET_EXHAUSTED`
- **Cause**: The attempt budget allocated for this server identity was exhausted (prevents account lockouts).
- **Recovery**: Inform the operator. The operator must check server lockout policy and grant additional attempts:
  ```bash
  brokerctl budget <target> --additional-attempts 1
  ```

### `RENEWAL_REQUIRED`
- **Cause**: A previously working cached credential was rejected by the server on a subsequent attempt. Discovery halted to prevent password spraying.
- **Recovery**: Inform the operator. The operator must renew discovery:
  ```bash
  brokerctl resume <target> --additional-attempts 1
  ```

### `AUTHENTICATION_REJECTED`
- **Cause**: The server rejected all attempted credentials in the pool, or no untried credentials remain.
- **Recovery**: Inform the operator that none of the pooled credentials succeeded. The operator must verify credentials on the target host.

### `HOST_KEY_MISMATCH`
- **Cause**: The server's SSH host key changed since approval, or DNS returned a different server identity.
- **Security Rule**: **CRITICAL SECURITY ALERT.** Do not attempt bypass. Notify operator of potential host spoofing or server re-installation.

### `TRANSPORT_FAILURE`
- **Cause**: Network unreachable, connection refused, or broker IPC pipe broken.
- **Recovery**: Check target IP/port accessibility or verify the broker daemon (`ssh-brokerd`) is running.

---

## 5. Deployment Modes

### Service Mode (Production)
- Daemon runs as dedicated service account (`sshbroker` or `NT SERVICE\ssh-brokerd`).
- Harness runs as a separate unprivileged OS user.
- Kernel enforces memory protection preventing the harness from attaching debuggers (`ptrace`, `OpenProcess`) or inspecting daemon memory.

### Standalone / Portable Mode (Dev / Single-User)
- Run `ssh-brokerd --standalone` in the foreground.
- Use `broker-ssh --standalone` and `brokerctl --standalone`.
- Allows zero-install execution from user-space without SCM, systemd, or root privileges.
- **Security Trade-off**: If harness and daemon run under the same OS user, OS-level memory isolation is not enforced. Stored passwords can be inspected by local user-space tools.
