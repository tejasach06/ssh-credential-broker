"""Additional disposable native acceptance cases. No production hosts or credentials."""
from contextlib import contextmanager
import json
from pathlib import Path
import platform
import re
import select
import socket
import subprocess
import sys
import textwrap
import threading


def _run(arguments, **kwargs):
    return subprocess.run([str(value) for value in arguments], check=True, capture_output=True, timeout=8, **kwargs)


def _auth_count(path):
    return len(re.findall(rb"(Failed|Accepted) password", path.read_bytes()))


def dns_pinning(ctl, drop, installed, runtime, port, fingerprint, token, auth_log):
    """Change actual native resolver input after approving a fresh hostname alias."""
    hosts = Path("/private/etc/hosts" if platform.system() == "Darwin" else "/etc/hosts")
    assert not hosts.is_symlink() and hosts.stat().st_uid == 0, "unsafe fixture hosts file"
    original = hosts.read_bytes()
    name = "broker-" + token + ".invalid"
    assert name.encode() not in original, "fixture hostname collision"

    def set_address(address):
        # Preserve the inode, ownership, mode, and all original bytes. Do not replace /etc/hosts.
        with hosts.open("r+b") as stream:
            stream.write(original + b"\n" + address.encode() + b" " + name.encode() + b"\n")
            stream.truncate()
        if platform.system() == "Darwin":
            _run(["dscacheutil", "-flushcache"])
        resolved = {entry[4][0] for entry in socket.getaddrinfo(name, port, type=socket.SOCK_STREAM)}
        assert resolved == {address}, "native resolver did not observe the fixture hosts change"

    def request():
        return subprocess.run([str(installed / "broker-ssh"), "--socket", str(runtime / "exec.sock"), name, "--port", str(port), "--", "printf PINNED_DESTINATION"], input=b"", capture_output=True, preexec_fn=drop, timeout=10)

    try:
        set_address("127.0.0.1")
        initial = request()
        assert initial.returncode == 125 and json.loads(initial.stderr)["code"] == "APPROVAL_REQUIRED"
        ctl("approve", name, "--port", str(port), "--pinned-ip", "127.0.0.1", "--fingerprint", fingerprint)
        # The alias shares the original identity's exhausted budget, rather than resetting it.
        before = _auth_count(auth_log)
        exhausted = request()
        assert exhausted.returncode == 125 and json.loads(exhausted.stderr)["code"] == "BUDGET_EXHAUSTED"
        assert _auth_count(auth_log) == before, "a hostname alias reset the existing identity budget"
        ctl("budget", name, "--port", str(port), "--additional-attempts", "1")
        set_address("127.0.0.2")
        result = request()
        assert result.returncode == 0 and result.stdout == b"PINNED_DESTINATION", "approved hostname followed the changed resolver address"
    finally:
        with hosts.open("r+b") as stream:
            stream.write(original)
            stream.truncate()
        if platform.system() == "Darwin":
            _run(["dscacheutil", "-flushcache"])
        assert hosts.read_bytes() == original, "fixture did not restore the exact original hosts bytes"


@contextmanager
def _tcp_fixture(hostile_banner=None):
    """A deliberately incomplete SSH peer, never a substitute successful SSH transport."""
    listener = socket.socket()
    listener.bind(("127.0.0.1", 0))
    listener.listen(1)
    listener.settimeout(0.1)
    stop = threading.Event()
    traffic = threading.Event()
    received = bytearray()
    connections = []
    errors = []

    def serve():
        try:
            while not stop.is_set():
                try:
                    connection, _ = listener.accept()
                    break
                except socket.timeout:
                    continue
            else:
                return
            connections.append(connection)
            connection.settimeout(0.1)
            if hostile_banner is not None:
                connection.sendall(hostile_banner + b"\r\n" + b"\xff" * 8)
            while not stop.is_set():
                try:
                    data = connection.recv(4096)
                except socket.timeout:
                    continue
                if not data:
                    break
                received.extend(data)
                traffic.set()
        except ConnectionResetError:
            pass
        except OSError:
            if not stop.is_set() and hostile_banner is None:
                errors.append("stalled SSH fixture failed")

    worker = threading.Thread(target=serve, daemon=True)
    worker.start()
    try:
        yield listener.getsockname()[1], received, traffic
    finally:
        stop.set()
        for connection in connections:
            connection.close()
        listener.close()
        worker.join(timeout=2)
        assert not worker.is_alive() and not errors, "TCP fixture did not stop cleanly"


def hostile_and_pre_session(drop, installed, runtime, token, auth_log, credentials):
    before = _auth_count(auth_log)
    marker = "SYNTHETIC_SECRET_LIKE_BANNER_" + token
    with _tcp_fixture(("SSH-2.0-" + marker).encode()) as (port, received, _):
        failed = subprocess.run([str(installed / "broker-ssh"), "--socket", str(runtime / "exec.sock"), "127.0.0.1", "--port", str(port), "--", "printf UNREACHABLE"], input=b"", capture_output=True, preexec_fn=drop, timeout=8)
        assert failed.returncode == 125 and json.loads(failed.stderr)["code"] == "TRANSPORT_FAILURE", "hostile banner was not classified"
        assert marker.encode() not in failed.stdout + failed.stderr, "raw hostile banner escaped in diagnostics"
    assert _auth_count(auth_log) == before, "hostile unapproved destination triggered password authentication"
    for credential in credentials:
        assert all(credential[field].encode() not in received for field in ("username", "password")), "hostile unapproved peer received credential material"
    probe = textwrap.dedent("""
        import json, socket, struct, sys
        connection = socket.socket(socket.AF_UNIX)
        connection.settimeout(4)
        connection.connect(sys.argv[1])
        def encode(value):
            payload = json.dumps(value).encode()
            return struct.pack('>I', len(payload)) + payload
        request = {'Connect': {'version': 1, 'target': '127.0.0.1', 'port': int(sys.argv[2]), 'command': 'printf MUST_NOT_EXECUTE', 'pty': None}}
        connection.sendall(encode(request))
        assert sys.stdin.buffer.read(1) == b'S', 'stalled SSH phase was not confirmed'
        connection.sendall(b''.join(encode({'StdinData': [65]}) for _ in range(9)) + encode('Cancel'))
        def exact(length):
            result = bytearray()
            while len(result) < length:
                data = connection.recv(length - len(result))
                assert data, 'pre-session response was truncated'
                result.extend(data)
            return bytes(result)
        length = struct.unpack('>I', exact(4))[0]
        assert 0 < length <= 65536, 'invalid pre-session rejection frame'
        response = json.loads(exact(length))
        assert response.get('Error', {}).get('code') == 'PROTOCOL_ERROR', 'pre-session streaming was not rejected'
        connection.close()
    """)
    with _tcp_fixture() as (port, received, traffic):
        client = subprocess.Popen([sys.executable, "-c", probe, str(runtime / "exec.sock"), str(port)], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, preexec_fn=drop)
        try:
            assert traffic.wait(timeout=5), "broker did not reach the deliberately stalled SSH identification phase"
            _, errors = client.communicate(input=b"S", timeout=6)
            assert client.returncode == 0 and not errors, "pre-session streaming rejection waited for SSH establishment or returned an invalid outcome"
        finally:
            if client.poll() is None:
                client.kill()
                client.wait(timeout=3)
        # This peer sends no SSH identification or key. Its observed client identification
        # proves the real network phase began, without allowing authentication or execution.
        assert len(received) < 1024, "stalled SSH peer received unexpected authentication traffic"
    assert _auth_count(auth_log) == before, "pre-session streaming caused password authentication"
    for credential in credentials:
        assert all(credential[field].encode() not in received for field in ("username", "password")), "stalled unapproved peer received credential material"


_ADMISSION_PROBE = textwrap.dedent("""
    import json, select, socket, struct, sys, time
    sockets = []
    rejected = 0
    def response(connection):
        connection.settimeout(0.2)
        def exact(length):
            result = bytearray()
            while len(result) < length:
                data = connection.recv(length - len(result))
                if not data:
                    return None
                result.extend(data)
            return bytes(result)
        try:
            header = exact(4)
            if header is None:
                return 'CLOSED'
            length = struct.unpack('>I', header)[0]
            assert 0 < length <= 65536, 'admission response exceeds frame bound'
            body = exact(length)
            assert body is not None, 'admission response was truncated'
            return json.loads(body).get('Error', {}).get('code')
        except ConnectionResetError:
            return 'CLOSED'
    try:
        for _ in range(96):
            connection = socket.socket(socket.AF_UNIX)
            connection.settimeout(0.02)
            try:
                connection.connect(sys.argv[1])
            except OSError:
                rejected += 1
                connection.close()
            else:
                sockets.append(connection)
        deadline = time.monotonic() + 1
        while time.monotonic() < deadline:
            ready, _, _ = select.select(sockets, [], [], 0.05)
            for connection in ready:
                code = response(connection)
                assert code in ('RESOURCE_LIMIT', 'CLOSED'), 'idle admission failed without a bounded rejection'
                rejected += 1
                sockets.remove(connection)
                connection.close()
        assert rejected > 0, '96 idle connections did not reach the admission bound'
        print(json.dumps({'phase': 'idle', 'attempted': 96, 'rejected': rejected}), flush=True)
        assert sys.stdin.buffer.read(1) == b'M'
        malformed = 0
        for index, connection in enumerate(sockets[:16]):
            if index % 2:
                payload = json.dumps('StdinEof').encode()
                wire = struct.pack('>I', len(payload)) + payload
            else:
                wire = struct.pack('>I', 65537)
            connection.settimeout(0.2)
            connection.sendall(wire)
            assert response(connection) in ('PROTOCOL_ERROR', 'CLOSED'), 'malformed frame was not rejected promptly'
            malformed += 1
            sockets.remove(connection)
            connection.close()
        assert malformed >= 9, 'insufficient live connections exercised malformed frames'
        print(json.dumps({'phase': 'malformed', 'rejected': malformed}), flush=True)
        assert sys.stdin.buffer.read(1) == b'D'
    finally:
        for connection in sockets:
            connection.close()
""")


class AdmissionFlood:
    """Coordinate idle and malformed real harness IPC while an established SSH channel runs."""
    def __init__(self, drop, runtime):
        self.child = subprocess.Popen([sys.executable, "-c", _ADMISSION_PROBE, str(runtime / "exec.sock")], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, preexec_fn=drop)
        try:
            assert self._phase(6)["phase"] == "idle"
        except BaseException:
            self.child.kill()
            self.child.wait(timeout=3)
            raise

    def _phase(self, timeout):
        assert select.select([self.child.stdout], [], [], timeout)[0], "admission rejection exceeded its deadline"
        line = self.child.stdout.readline()
        assert line, "admission probe exited before its bounded rejection report"
        return json.loads(line)

    def reject_malformed(self):
        self.child.stdin.write(b"M")
        self.child.stdin.flush()
        assert self._phase(5)["phase"] == "malformed"

    def close(self):
        try:
            _, errors = self.child.communicate(input=b"D", timeout=4)
            assert self.child.returncode == 0 and not errors, "admission probe did not release its resources cleanly"
        finally:
            if self.child.poll() is None:
                self.child.kill()
                self.child.wait(timeout=3)
