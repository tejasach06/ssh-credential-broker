#!/usr/bin/env python3
"""Root-only disposable native smoke. Never use production credentials or hosts."""
import argparse
import fcntl
import grp
import json
import os
from pathlib import Path
import platform
import pty
import pwd
import re
import sys
import secrets
import select
import signal
import socket
import struct
import subprocess
import tempfile
import termios
import textwrap
import time

sys.dont_write_bytecode = True
from smoke_cases import AdmissionFlood, dns_pinning, hostile_and_pre_session

ROOT = Path(__file__).resolve().parent.parent
DARWIN = platform.system() == "Darwin"
RUNTIME = Path("/private/var/db/ssh-credential-broker/run" if DARWIN else "/run/ssh-credential-broker")
INSTALLED = Path("/opt/ssh-credential-broker/bin")


def run(args, **kwargs):
    try:
        return subprocess.run([str(arg) for arg in args], check=True, capture_output=True, timeout=45, **kwargs)
    except subprocess.CalledProcessError as exc:
        if exc.stdout or exc.stderr:
            print(f"FAILED: {' '.join(str(a) for a in args)}\nstdout: {exc.stdout.decode(errors='replace')}\nstderr: {exc.stderr.decode(errors='replace')}", file=sys.stderr)
        raise

def create_user(name, login):
    if not DARWIN:
        run(["useradd", "--no-user-group", "--gid", "nogroup", "--no-create-home", "--home-dir", "/" if login else "/nonexistent", "--shell", "/bin/sh" if login else "/usr/sbin/nologin", name])
        return
    uid = 510
    while subprocess.run(["dscl", ".", "-search", "/Users", "UniqueID", str(uid)], capture_output=True, check=True).stdout.strip():
        uid += 1
    run(["dscl", ".", "-create", f"/Users/{name}"])
    # The caller records ownership before creating attributes, so partial users are cleaned.
    for key, value in {"UniqueID": str(uid), "PrimaryGroupID": "20", "UserShell": "/bin/sh" if login else "/usr/bin/false", "NFSHomeDirectory": "/var/empty", "IsHidden": "1", "Password": "*"}.items():
        run(["dscl", ".", "-create", f"/Users/{name}", key, value])


def set_password(name, password):
    if not DARWIN:
        run(["chpasswd"], input=f"{name}:{password}\n".encode())
        return
    # On macOS run as root, dscl . -passwd /Users/<name> <old> <new> with "" for old password sets without prompting.
    run(["dscl", ".", "-passwd", f"/Users/{name}", "", password])


def wait_socket():
    deadline = time.monotonic() + 20
    while time.monotonic() < deadline:
        if (RUNTIME / "exec.sock").is_socket() and (RUNTIME / "admin.sock").is_socket():
            return
        time.sleep(0.1)
    raise AssertionError("service did not create IPC sockets")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--bin-dir", type=Path, required=True)
    args = parser.parse_args()
    assert os.geteuid() == 0, "run under sudo on a disposable native CI host"
    assert platform.system() in ("Linux", "Darwin"), "unsupported smoke host"
    state = Path("/private/etc/ssh-credential-broker/install-state" if DARWIN else "/etc/ssh-credential-broker/install-state")
    assert not state.exists(), "smoke refuses to overwrite an existing broker installation"
    token = secrets.token_hex(4)
    harness, login = "bh" + token, "bl" + token
    password = secrets.token_urlsafe(24)
    users = []
    installed = False
    sshd = None
    made_sshd_dir = False
    try:
        for name, shell in ((harness, False), (login, True)):
            try:
                pwd.getpwnam(name)
            except KeyError:
                users.append(name)
            else:
                raise AssertionError("fixture identity collision")
            create_user(name, shell)
        set_password(login, password)
        with tempfile.TemporaryDirectory(prefix="broker-smoke-") as temporary:
            work = Path(temporary)
            run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", work / "host_key"])
            fingerprint = run(["ssh-keygen", "-lf", work / "host_key.pub", "-E", "sha256"]).stdout.decode().split()[1]
            with socket.socket() as listener:
                listener.bind(("127.0.0.1", 0))
                port = listener.getsockname()[1]
            if not DARWIN and not Path("/run/sshd").exists():
                Path("/run/sshd").mkdir(mode=0o755)
                made_sshd_dir = True
            config = work / "sshd_config"
            config.write_text(f"Port {port}\nListenAddress 127.0.0.1\nHostKey {work / 'host_key'}\nPidFile {work / 'sshd.pid'}\nPasswordAuthentication yes\nKbdInteractiveAuthentication no\nPubkeyAuthentication no\nPermitEmptyPasswords no\nPermitRootLogin no\nUsePAM {'yes' if DARWIN else 'no'}\nAllowUsers {login}\nAllowTcpForwarding no\nX11Forwarding no\nPermitTunnel no\nPermitTTY yes\nLogLevel VERBOSE\n")
            run(["/usr/sbin/sshd", "-t", "-f", config])
            with (work / "sshd.log").open("wb") as log:
                sshd = subprocess.Popen(["/usr/sbin/sshd", "-D", "-e", "-f", str(config)], stdout=log, stderr=log)
                deadline = time.monotonic() + 10
                while True:
                    try:
                        with socket.create_connection(("127.0.0.1", port), timeout=0.2):
                            break
                    except OSError:
                        assert sshd.poll() is None and time.monotonic() < deadline, "fixture sshd unavailable"
                        time.sleep(0.1)
                installed = True  # Covers partial installer failures during cleanup.
                run(["bash", ROOT / "scripts/install.sh", "--bin-dir", args.bin_dir.resolve(), "--operator", "root", "--harness", harness])
                wait_socket()
                identity = pwd.getpwnam(harness)
                groups = os.getgrouplist(harness, identity.pw_gid)

                def drop():
                    os.setgroups(groups)
                    os.setgid(identity.pw_gid)
                    os.setuid(identity.pw_uid)

                def ctl(*arguments, data=None):
                    return run([INSTALLED / "brokerctl", "--admin-socket", RUNTIME / "admin.sock", *arguments], input=data)

                def execute(command="true", data=b"", timeout=40):
                    return subprocess.run([str(INSTALLED / "broker-ssh"), "--socket", str(RUNTIME / "exec.sock"), "127.0.0.1", "--port", str(port), "--", command], input=data, capture_output=True, preexec_fn=drop, timeout=timeout)

                def expect_error(result, code):
                    assert result.returncode == 125, f"expected local error {code}"
                    assert json.loads(result.stderr)["code"] == code, f"wrong classified outcome for {code}"

                assert (RUNTIME.stat().st_mode & 0o777) == 0o751
                assert (RUNTIME / "exec.sock").stat().st_gid == grp.getgrnam("sshbroker-exec").gr_gid
                assert (RUNTIME / "admin.sock").stat().st_gid == grp.getgrnam("sshbroker-admin").gr_gid
                for sock in ("exec.sock", "admin.sock"):
                    assert ((RUNTIME / sock).stat().st_mode & 0o777) == 0o660
                expect_error(execute(), "BROKER_LOCKED")
                oversized_probe = "import socket,struct,sys\ns=socket.socket(socket.AF_UNIX); s.settimeout(3); s.connect(sys.argv[1]); s.sendall(struct.pack('>I',65537))\ntry: s.recv(65540)\nexcept ConnectionResetError: pass\n"
                malformed = subprocess.run([sys.executable, "-c", oversized_probe, str(RUNTIME / "exec.sock")], capture_output=True, preexec_fn=drop, timeout=5)
                assert malformed.returncode == 0, "oversized frame was not rejected promptly"
                expect_error(execute(), "BROKER_LOCKED")
                next_password = secrets.token_urlsafe(24)
                entries = [{"username": login, "password": secrets.token_urlsafe(24)}, {"username": login, "password": password}, {"username": login, "password": next_password}]
                payload = json.dumps(entries).encode()
                ctl("unlock", "--ttl-seconds", "1800", "--harness-uid", str(identity.pw_uid), "--private-json-stdin", data=struct.pack(">I", len(payload)) + payload)
                expect_error(execute(), "APPROVAL_REQUIRED")
                pending = json.loads(ctl("pending").stdout)["PendingList"]
                assert any(item["host_key_fingerprint"] == fingerprint and item["resolved_ip"] == "127.0.0.1" for item in pending), "pending identity does not match independently generated fixture key"
                assert not re.search(rb"(Failed|Accepted) password", (work / "sshd.log").read_bytes()), "password authentication occurred before operator approval"
                ctl("approve", "127.0.0.1", "--port", str(port), "--pinned-ip", "127.0.0.1", "--fingerprint", fingerprint)
                rejected = execute()
                assert rejected.returncode == 125 and json.loads(rejected.stderr)["code"] in ("AUTHENTICATION_REJECTED", "BUDGET_EXHAUSTED"), "ordered first credential did not fail safely"
                ctl("budget", "127.0.0.1", "--port", str(port), "--additional-attempts", "1")
                result = execute("printf COMMAND_OK")
                observed_auth = (work / "sshd.log").read_bytes()
                print(f"DEBUG: after 2nd attempt, sshd.log:\n{observed_auth.decode(errors='replace')}", file=sys.stderr)
                assert result.returncode == 0 and result.stdout == b"COMMAND_OK", f"next ordered credential failed: rc={result.returncode}, stdout={result.stdout!r}, stderr={result.stderr!r}"
                assert b"Failed password" in observed_auth and b"Accepted password" in observed_auth, "fixture did not observe the ordered rejected and accepted authentications"
                expect_error(execute(), "BUDGET_EXHAUSTED")
                ctl("budget", "127.0.0.1", "--port", str(port), "--additional-attempts", "6")
                # Invalid outcome descriptors must be rejected before authentication or command work.
                auth_before = len(re.findall(rb"(Failed|Accepted) password", (work / "sshd.log").read_bytes()))
                marker = Path("/tmp") / ("broker-smoke-outcome-" + token)
                assert not marker.exists(), "fixture marker collision"
                read_only = os.open("/dev/null", os.O_RDONLY)
                try:
                    for descriptor, inherited in ((999999, ()), (read_only, (read_only,))):
                        invalid = subprocess.run([str(INSTALLED / "broker-ssh"), "--outcome-fd", str(descriptor), "--socket", str(RUNTIME / "exec.sock"), "127.0.0.1", "--port", str(port), "--", f"printf UNEXPECTED > {marker}"], input=b"", capture_output=True, pass_fds=inherited, preexec_fn=drop, timeout=5)
                        expect_error(invalid, "LOCAL_IO")
                        assert not marker.exists(), "invalid outcome descriptor allowed remote command work"
                finally:
                    os.close(read_only)
                    marker.unlink(missing_ok=True)
                assert auth_before == len(re.findall(rb"(Failed|Accepted) password", (work / "sshd.log").read_bytes())), "invalid outcome descriptor consumed a password submission"
                custom_signal = execute("kill -USR2 $$")
                assert custom_signal.returncode == 128 + int(signal.SIGUSR2), "custom remote signal exit code was not mapped for the native platform"
                signal_outcome = json.loads(custom_signal.stderr)
                assert signal_outcome["outcome"] == "remote_signal" and signal_outcome["code"] == "REMOTE_SIGNAL" and signal_outcome["signal"] == "USR2", "custom remote signal was not preserved"
                # Reporting failure after a real remote result must be classified as local I/O failure.
                read_end, broken_outcome = os.pipe()
                os.close(read_end)
                try:
                    failed_report = subprocess.run([str(INSTALLED / "broker-ssh"), "--outcome-fd", str(broken_outcome), "--socket", str(RUNTIME / "exec.sock"), "127.0.0.1", "--port", str(port), "--", "true"], input=b"", capture_output=True, pass_fds=(broken_outcome,), preexec_fn=drop, timeout=20)
                    expect_error(failed_report, "LOCAL_IO")
                finally:
                    os.close(broken_outcome)
                # Outgoing input exceeds SSH windows while concurrent output drains and the peer
                # deliberately stops reading for longer than the establishment timeout.
                slow_input = bytes(range(256)) * 32768
                slow = execute("dd if=/dev/zero bs=65536 count=64 2>/dev/null; sleep 35; cat", slow_input, timeout=60)
                assert slow.returncode == 0 and slow.stdout == bytes(4 * 1024 * 1024) + slow_input and slow.stderr == b"", "established stdin backpressure timed out or full-duplex bytes were corrupted"
                binary = bytes(range(256)) * 4096
                result = execute("cat; printf STDERR_OK >&2; exit 7", binary)
                assert result.returncode == 7 and result.stdout == binary and result.stderr == b"STDERR_OK", "binary streams, EOF, or remote exit were corrupted"
                result = execute("id -un")
                assert result.returncode == 0 and result.stdout.strip().decode() == login, "full shell username visibility is expected"
                # Actual interactive shell via a controlling PTY, including resize delivery.
                child, terminal = pty.fork()
                if child == 0:
                    drop()
                    os.execv(str(INSTALLED / "broker-ssh"), ["broker-ssh", "--socket", str(RUNTIME / "exec.sock"), "127.0.0.1", "--port", str(port)])
                output = b""
                try:
                    os.write(terminal, b"printf 'PTY_READY\\n'\n")
                    deadline = time.monotonic() + 10
                    while b"PTY_READY\r\n" not in output and time.monotonic() < deadline:
                        readable, _, _ = select.select([terminal], [], [], 0.1)
                        if readable:
                            output += os.read(terminal, 4096)
                    assert b"PTY_READY\r\n" in output, "interactive shell did not become ready"
                    fcntl.ioctl(terminal, termios.TIOCSWINSZ, struct.pack("HHHH", 37, 91, 0, 0))
                    os.kill(child, signal.SIGWINCH)
                    os.write(terminal, b"sleep 30\n")
                    time.sleep(0.3)
                    os.write(terminal, b"\x03")
                    os.write(terminal, b"printf 'PTY_INTERRUPTED\\n'; stty size; exit 9\n")
                    deadline = time.monotonic() + 10
                    status = None
                    while time.monotonic() < deadline:
                        readable, _, _ = select.select([terminal], [], [], 0.1)
                        if readable:
                            try:
                                output += os.read(terminal, 4096)
                            except OSError:
                                pass
                        finished, current = os.waitpid(child, os.WNOHANG)
                        if finished:
                            status = current
                            break
                    assert status is not None, "interactive session timed out"
                    assert os.waitstatus_to_exitcode(status) == 9 and b"PTY_INTERRUPTED\r\n" in output and b"37 91" in output, "interactive shell, resize, or Ctrl-C failed"
                finally:
                    os.close(terminal)
                    try:
                        os.kill(child, signal.SIGKILL)
                        os.waitpid(child, 0)
                    except (ProcessLookupError, ChildProcessError):
                        pass
                denied = subprocess.run([str(INSTALLED / "brokerctl"), "--admin-socket", str(RUNTIME / "admin.sock"), "status"], capture_output=True, preexec_fn=drop, timeout=5)
                assert denied.returncode == 125, "harness accessed operator administration"
                replacement = subprocess.run(["/bin/sh", "-c", 'test -w "$1" || test -w "$2"', "sh", str(INSTALLED), str(INSTALLED / "ssh-brokerd")], capture_output=True, preexec_fn=drop, timeout=5)
                assert replacement.returncode != 0, "harness can replace daemon binary"
                if DARWIN:
                    service_info = run(["launchctl", "print", "system/com.ssh-credential-broker.daemon"]).stdout.decode()
                    daemon_pid = int(re.search(r"\bpid = (\d+)", service_info).group(1))
                    probe = "import ctypes,sys; c=ctypes.CDLL('/usr/lib/libSystem.B.dylib'); task=ctypes.c_uint(); me=ctypes.c_uint.in_dll(c,'mach_task_self_').value; sys.exit(0 if c.task_for_pid(me,int(sys.argv[1]),ctypes.byref(task)) != 0 else 1)"
                else:
                    daemon_pid = int(run(["systemctl", "show", "--property=MainPID", "--value", "ssh-brokerd.service"]).stdout)
                    probe = "import ctypes,sys; c=ctypes.CDLL(None,use_errno=True); result=c.ptrace(16,int(sys.argv[1]),0,0); sys.exit(0 if result == -1 and ctypes.get_errno() in (1,13) else 1)"
                denied_debug = subprocess.run([sys.executable, "-c", probe, str(daemon_pid)], capture_output=True, preexec_fn=drop, timeout=5)
                assert denied_debug.returncode == 0, "harness acquired debugger access to the daemon"
                hostile_and_pre_session(drop, INSTALLED, RUNTIME, token, work / "sshd.log", entries)
                dns_pinning(ctl, drop, INSTALLED, RUNTIME, port, fingerprint, token, work / "sshd.log")
                # Cached failure must stop at renewal, then resume after the rejected cached entry.
                set_password(login, next_password)
                # First attempt with changed password fails authentication and sets renewal_required.
                expect_error(execute(), "AUTHENTICATION_REJECTED")
                ctl("budget", "127.0.0.1", "--port", str(port), "--additional-attempts", "1")
                expect_error(execute(), "RENEWAL_REQUIRED")
                ctl("resume", "127.0.0.1", "--port", str(port), "--additional-attempts", "1")
                assert execute("true").returncode == 0, "explicit renewal did not use the next credential"
                ctl("budget", "127.0.0.1", "--port", str(port), "--additional-attempts", "1")
                def spawn(command):
                    return subprocess.Popen([str(INSTALLED / "broker-ssh"), "--socket", str(RUNTIME / "exec.sock"), "127.0.0.1", "--port", str(port), "--", command], stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE, preexec_fn=drop)
                racers = [spawn("printf RACER"), spawn("printf RACER")]
                raced = []
                for racer in racers:
                    out, err = racer.communicate(timeout=20)
                    raced.append((racer.returncode, out, err))
                assert sorted(item[0] for item in raced) == [0, 125], "concurrent cached logins exceeded one remaining attempt"
                assert json.loads(next(item[2] for item in raced if item[0] == 125))["code"] == "BUDGET_EXHAUSTED"
                ctl("budget", "127.0.0.1", "--port", str(port), "--additional-attempts", "2")
                # This is the real execution socket and a real SSH command. A separate harness
                # process deliberately leaves output unread, then checks every framed response.
                raw_probe = textwrap.dedent("""
                    import json, select, socket, struct, sys, time
                    connection = socket.socket(socket.AF_UNIX)
                    connection.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 4096)
                    connection.settimeout(10)
                    connection.connect(sys.argv[1])
                    request = {"Connect": {"version": 1, "target": "127.0.0.1", "port": int(sys.argv[2]), "command": "dd if=/dev/zero bs=65536 count=128 2>/dev/null; sleep 120", "pty": None}}
                    payload = json.dumps(request).encode()
                    connection.sendall(struct.pack(">I", len(payload)) + payload)
                    deadline = None
                    def exact(length):
                        result = bytearray()
                        while len(result) < length:
                            if deadline is not None:
                                remaining = deadline - time.monotonic()
                                assert remaining > 0, "revocation output did not drain before the deadline"
                                connection.settimeout(remaining)
                            chunk = connection.recv(length - len(result))
                            assert chunk, "execution response contained a truncated frame"
                            result.extend(chunk)
                        return bytes(result)
                    def frame():
                        length = struct.unpack(">I", exact(4))[0]
                        assert 0 < length <= 65536, "execution response frame length was corrupted"
                        return json.loads(exact(length))
                    assert frame() == "SessionReady", "raw execution session did not open"
                    assert select.select([connection], [], [], 10)[0], "raw execution command emitted no output"
                    time.sleep(1)
                    print("BACKPRESSURE_READY", flush=True)
                    assert sys.stdin.buffer.read(1) == b"D", "operator did not resume draining"
                    deadline = time.monotonic() + 4
                    frames = 0
                    received = 0
                    while True:
                        message = frame()
                        frames += 1
                        assert isinstance(message, dict), "unexpected execution control response"
                        if "StdoutData" in message:
                            data = message["StdoutData"]
                            assert isinstance(data, list) and not any(data), "remote output bytes were corrupted"
                            received += len(data)
                        elif "StderrData" in message:
                            assert message["StderrData"] == [], "unexpected remote stderr"
                        else:
                            assert message.get("Error", {}).get("code") == "BROKER_LOCK", "revocation did not produce the classified lock outcome"
                            break
                    assert received > 0, "raw execution exercised no queued output"
                    print(json.dumps({"frames": frames, "stdout_bytes": received, "code": "BROKER_LOCK"}), flush=True)
                    connection.close()
                """)
                raw_client = subprocess.Popen([sys.executable, "-c", raw_probe, str(RUNTIME / "exec.sock"), str(port)], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, preexec_fn=drop)
                active = None
                flood = None
                try:
                    assert select.select([raw_client.stdout], [], [], 15)[0], "raw execution did not reach output backpressure"
                    assert raw_client.stdout.readline() == b"BACKPRESSURE_READY\n", "raw execution client failed before revocation"
                    active = spawn("printf ACTIVE_SESSION; sleep 2; printf ADMISSION_ALIVE; sleep 120")
                    assert select.select([active.stdout], [], [], 10)[0], "active command did not open"
                    assert os.read(active.stdout.fileno(), len(b"ACTIVE_SESSION")) == b"ACTIVE_SESSION"
                    flood = AdmissionFlood(drop, RUNTIME)
                    assert select.select([active.stdout], [], [], 5)[0], "existing SSH channel stopped producing output during admission pressure"
                    assert os.read(active.stdout.fileno(), len(b"ADMISSION_ALIVE")) == b"ADMISSION_ALIVE", "admission pressure corrupted the existing channel"
                    flood.reject_malformed()
                    ctl("status")
                    ctl("lock")
                    # Resume immediately, within the daemon's five-second bounded drain period.
                    raw_output, raw_error = raw_client.communicate(input=b"D", timeout=6)
                    assert raw_client.returncode == 0 and not raw_error, "backpressured revocation produced malformed, truncated, or late frames"
                    assert json.loads(raw_output)["code"] == "BROKER_LOCK"
                    _, ended = active.communicate(timeout=10)
                    assert active.returncode == 125 and json.loads(ended)["code"] == "BROKER_LOCK", "lock did not revoke an active channel"
                finally:
                    try:
                        if flood is not None:
                            flood.close()
                    finally:
                        for client in (raw_client, active):
                            if client is not None and client.poll() is None:
                                client.kill()
                                client.wait(timeout=5)
                expect_error(execute(), "BROKER_LOCKED")
                if DARWIN:
                    run(["launchctl", "kickstart", "-k", "system/com.ssh-credential-broker.daemon"])
                else:
                    run(["systemctl", "restart", "ssh-brokerd.service"])
                wait_socket()
                expect_error(execute(), "BROKER_LOCKED")
                # A changed key at an approved endpoint must fail before a password is sent.
                renewed = json.dumps([{"username": login, "password": next_password}]).encode()
                ctl("unlock", "--ttl-seconds", "60", "--harness-uid", str(identity.pw_uid), "--private-json-stdin", data=struct.pack(">I", len(renewed)) + renewed)
                expect_error(execute(), "APPROVAL_REQUIRED")
                ctl("approve", "127.0.0.1", "--port", str(port), "--pinned-ip", "127.0.0.1", "--fingerprint", fingerprint)
                sshd.terminate()
                sshd.wait(timeout=5)
                run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", work / "rekey"])
                new_fingerprint = run(["ssh-keygen", "-lf", work / "rekey.pub", "-E", "sha256"]).stdout.decode().split()[1]
                config.write_text(config.read_text().replace(str(work / "host_key"), str(work / "rekey")))
                sshd = subprocess.Popen(["/usr/sbin/sshd", "-D", "-e", "-f", str(config)], stdout=log, stderr=log)
                deadline = time.monotonic() + 5
                while True:
                    try:
                        with socket.create_connection(("127.0.0.1", port), timeout=0.2):
                            break
                    except OSError:
                        assert sshd.poll() is None and time.monotonic() < deadline, "rekeyed fixture sshd unavailable"
                        time.sleep(0.1)
                expect_error(execute(), "HOST_KEY_MISMATCH")
                expect_error(execute(), "APPROVAL_REQUIRED")
                ctl("approve", "127.0.0.1", "--port", str(port), "--pinned-ip", "127.0.0.1", "--fingerprint", new_fingerprint)
                expiring = spawn("printf EXPIRY_SESSION; sleep 120")
                try:
                    assert select.select([expiring.stdout], [], [], 10)[0], "expiry command did not open"
                    assert os.read(expiring.stdout.fileno(), len(b"EXPIRY_SESSION")) == b"EXPIRY_SESSION"
                    _, ended = expiring.communicate(timeout=65)
                    assert expiring.returncode == 125 and json.loads(ended)["code"] == "BROKER_EXPIRED", "expiry did not revoke an active channel"
                finally:
                    if expiring.poll() is None:
                        expiring.kill()
                        expiring.wait(timeout=5)
                expect_error(execute(), "BROKER_LOCKED")
                assert password.encode() not in (work / "sshd.log").read_bytes(), "fixture secret appeared in server diagnostics"
                report = {"platform": platform.platform(), "operator_uid": 0, "harness_uid": identity.pw_uid, "broker_uid": pwd.getpwnam("sshbroker").pw_uid, "result": "native smoke passed", "coverage": ["startup and restart locked", "private credential input", "pending approval", "verified host key and changed-key refusal", "ordered discovery and budget addition", "cached login budget", "cached rejection and explicit renewal", "concurrent cached single-budget login", "1MiB binary full duplex, EOF, remote status", "interactive shell, resize, and Ctrl-C", "username visibility", "harness admin denial", "native debugger denial", "binary replacement denial", "active-session lock and expiry"], "limits": "Partial acceptance coverage; not all A01-A31 or a complete isolation audit."}
                report["coverage"].extend(["outcome descriptor preflight before authentication", "outcome write failure", "custom USR2 remote signal", "35-second stdin backpressure with concurrent large output"])
                report["coverage"].append("framed lock outcome under real Unix-socket output backpressure")
                report["coverage"].extend(["native resolver change after numeric pinning", "hostname-alias budget sharing", "96 idle IPC admission attempts plus malformed frames with an existing channel", "pre-SessionReady nine-frame streaming rejection during stalled SSH identification", "hostile SSH banner classification without credential submission"])
    finally:
        cleanup_errors = []
        if installed:
            try:
                run(["bash", ROOT / "scripts/uninstall.sh", "--purge-account"])
            except (subprocess.SubprocessError, OSError):
                cleanup_errors.append("broker uninstall failed")
        if sshd is not None:
            sshd.terminate()
            try:
                sshd.wait(timeout=5)
            except subprocess.TimeoutExpired:
                sshd.kill()
                sshd.wait(timeout=5)
        for name in reversed(users):
            if name == harness and cleanup_errors:
                continue  # Retain the identity required to retry a failed tracked uninstall.
            # Fixture cleanup is an explicit administrator action, not a broker guarantee.
            try:
                fixture_uid = str(pwd.getpwnam(name).pw_uid)
                subprocess.run(["pkill", "-TERM", "-u", fixture_uid], capture_output=True)
                time.sleep(0.2)
                subprocess.run(["pkill", "-KILL", "-u", fixture_uid], capture_output=True)
            except KeyError:
                pass
            command = ["dscl", ".", "-delete", f"/Users/{name}"] if DARWIN else ["userdel", name]
            if subprocess.run(command, capture_output=True).returncode:
                cleanup_errors.append("fixture identity removal failed")
        if made_sshd_dir:
            try:
                Path("/run/sshd").rmdir()
            except OSError:
                cleanup_errors.append("fixture sshd directory removal failed")
        if cleanup_errors:
            raise AssertionError("; ".join(cleanup_errors))
    print(json.dumps(report))


if __name__ == "__main__":
    main()
