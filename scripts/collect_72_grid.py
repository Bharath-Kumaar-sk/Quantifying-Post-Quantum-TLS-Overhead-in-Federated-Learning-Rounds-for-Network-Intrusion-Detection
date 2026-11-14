from __future__ import annotations

import argparse
import csv
import datetime as dt
import json
import logging
import math
import os
import platform
import pwd
import re
import select
import shutil
import signal
import socket
import ssl
import statistics
import subprocess
import sys
import time
import uuid
from functools import lru_cache
from dataclasses import dataclass, asdict
from pathlib import Path
from typing import Any, Optional


CLIENT_COUNTS = (5, 10, 20)
ROUND_COUNTS = (10, 50, 100)
RESUMPTIONS = ("OFF", "ON")

# Linux tcpdump/libpcap capture tuning. Preserve the empirically successful
# immediate-mode + packet-buffered mode; increase only the receive buffer.
CAPTURE_BUFFER_KIB = 65536       # 64 MiB
CAPTURE_RMEM_MAX_BYTES = 134217728  # 128 MiB (Linux SO_RCVBUF ceiling)
CAPTURE_TMPFS_MIN_FREE_BYTES = 134217728  # Reserve at least 128 MiB in /dev/shm
TShARK_ANALYSIS_TIMEOUT_S = 300

@dataclass(frozen=True)
class TLSProfile:
    name: str
    port: int
    expected_group: str
    expected_signature: str
    ca_file: str


def project_root_default() -> Path:
    return Path(os.environ.get("QUANTUM_ROOT", str(Path.home() / "quantum"))).expanduser().resolve()


def profiles_for_root(root: Path) -> dict[str, TLSProfile]:
    return {
        "K1": TLSProfile("K1", 4431, "X25519", "ecdsa_secp256r1_sha256", str(root / "certificates/ca/ca-ecdsa.crt")),
        "H1": TLSProfile("H1", 4433, "X25519MLKEM768", "ecdsa_secp256r1_sha256", str(root / "certificates/ca/ca-ecdsa.crt")),
        "H2": TLSProfile("H2", 4434, "X25519MLKEM768", "mldsa65", str(root / "certificates/ca/ca-mldsa65.crt")),
        "P1": TLSProfile("P1", 4435, "MLKEM768", "mldsa65", str(root / "certificates/ca/ca-mldsa65.crt")),
    }

SAMPLE_FIELDS = [
    "Run_ID", "Timestamp_UTC", "Clients", "Rounds", "Config", "Resumption",
    "Client_ID", "Round_ID", "Connection_ID", "Local_Port", "TCP_Stream",
    "TCP_Connect_ms", "TLS_Handshake_ms", "Total_Connection_ms",
    "Session_Reused", "Session_Offered", "Resumption_Status", "Session_Ticket_Received",
    "Handshake_Status", "TLS_Version", "Cipher", "Negotiated_Group",
    "Signature_Algorithm", "Error",
]

AGG_FIELDS = [
    "Run_ID", "Clients", "Rounds", "Config", "Resumption", "Execution_Model",
    "Attempted_Connections", "TCP_Connected", "Successful_Connections",
    "Failed_Connections", "Full_Handshakes", "Resumed_Handshakes",
    "Resumption_Attempts", "Sessions_Offered", "Resumption_Misses", "Resumption_Failures",
    "Sessions_Unavailable", "Session_Tickets_Received", "Session_Ticket_Failures",
    "Resumption_Hit_Rate_pct", "Mean_TCP_Connect_ms",
    "Mean_Handshake_ms", "Median_Handshake_ms", "P95_Handshake_ms",
    "Total_Handshake_ms", "TCP_Traffic_Bytes", "TLS_Traffic_Bytes",
    "Captured_TCP_Streams", "Mapped_TCP_Connections", "TLS_Evidence_Streams",
    "Missing_TCP_Local_Ports", "Capture_Packets_Captured", "Capture_Packets_Received_By_Filter",
    "Capture_Packets_Dropped", "Capture_Process_Status", "Capture_Filter_Mode",
    "Capture_Validation_Detail", "Capture_Valid", "Profile_Validation", "PCAP_File",
]


class BenchmarkError(RuntimeError):
    pass


def percentile(values: list[float], p: float) -> Optional[float]:
    if not values:
        return None
    values = sorted(values)
    if len(values) == 1:
        return values[0]
    pos = (len(values) - 1) * p
    lo = math.floor(pos)
    hi = math.ceil(pos)
    if lo == hi:
        return values[lo]
    return values[lo] + (values[hi] - values[lo]) * (pos - lo)


def verify_runtime(root: Path, profiles: dict[str, TLSProfile]) -> tuple[str, str, str]:
    version = ssl.OPENSSL_VERSION
    if sys.version_info < (3, 15):
        raise BenchmarkError(
            f"Python {platform.python_version()} is too old. This collector requires Python 3.15+ "
            "because it must explicitly set TLS 1.3 groups and server signature algorithms. "
            "Run it with ~/python-3.15.2/bin/python3.15."
        )
    missing_tls_api = [
        name for name in ("set_groups", "get_groups", "set_server_sigalgs")
        if not hasattr(ssl.SSLContext, name)
    ]
    if missing_tls_api:
        raise BenchmarkError(
            "Python ssl is missing required TLS configuration APIs: " + ", ".join(missing_tls_api)
        )
    if not version.startswith("OpenSSL 3.5."):
        raise BenchmarkError(
            f"Python ssl is linked to '{version}', not OpenSSL 3.5.x. "
            "Source ~/quantum/env.sh and check `python3 -c 'import ssl; print(ssl.OPENSSL_VERSION)'`."
        )
    for key, profile in profiles.items():
        ca = Path(profile.ca_file)
        if not ca.is_file():
            raise BenchmarkError(f"Missing CA certificate for {key}: {ca}")
    tshark = shutil.which("tshark")
    tcpdump = shutil.which("tcpdump")
    sudo = shutil.which("sudo")
    if not tshark:
        raise BenchmarkError("tshark was not found in PATH. Install Wireshark/TShark before collecting PCAPs.")
    if not tcpdump:
        raise BenchmarkError("tcpdump was not found in PATH. Install it with: sudo apt install tcpdump")
    if os.geteuid() != 0 and not sudo:
        raise BenchmarkError("sudo is required to grant tcpdump packet-capture privileges.")
    return version, tshark, tcpdump


def make_context(profile: TLSProfile, keylog_path: Path) -> ssl.SSLContext:
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_3
    ctx.maximum_version = ssl.TLSVersion.TLSv1_3
    ctx.verify_mode = ssl.CERT_REQUIRED
    ctx.check_hostname = True
    ctx.load_verify_locations(cafile=profile.ca_file)

    try:
        available_groups = {group.lower() for group in ctx.get_groups()}
        if profile.expected_group.lower() not in available_groups:
            raise BenchmarkError(
                f"{profile.name}: required TLS group {profile.expected_group!r} is not available. "
                f"Groups reported by this OpenSSL: {sorted(available_groups)}"
            )
        ctx.set_groups(profile.expected_group)
        ctx.set_server_sigalgs(profile.expected_signature)
    except BenchmarkError:
        raise
    except (AttributeError, NotImplementedError, ValueError, ssl.SSLError) as exc:
        raise BenchmarkError(
            f"{profile.name}: could not configure TLS group {profile.expected_group} "
            f"and server signature {profile.expected_signature}: {type(exc).__name__}: {exc}"
        ) from exc

    keylog_path.parent.mkdir(parents=True, exist_ok=True)
    keylog_path.touch(mode=0o600, exist_ok=True)
    os.chmod(keylog_path, 0o600)
    ctx.keylog_filename = str(keylog_path)

    return ctx



def ensure_capture_buffer_limit() -> int:
    """Ensure Linux permits the requested tcpdump receive-buffer size.

    Linux may cap SO_RCVBUF below the value requested by tcpdump -B. The limit
    is raised once, before the grid begins, and never during a measured handshake.
    """
    proc_path = Path("/proc/sys/net/core/rmem_max")
    try:
        current = int(proc_path.read_text().strip())
    except (OSError, ValueError) as exc:
        raise BenchmarkError(f"Cannot read {proc_path}: {exc}") from exc

    if current >= CAPTURE_RMEM_MAX_BYTES:
        return current

    sysctl = shutil.which("sysctl")
    if not sysctl:
        raise BenchmarkError("sysctl was not found; cannot raise net.core.rmem_max for tcpdump.")

    command = [sysctl, "-w", f"net.core.rmem_max={CAPTURE_RMEM_MAX_BYTES}"]
    if os.geteuid() != 0:
        sudo = shutil.which("sudo")
        if not sudo:
            raise BenchmarkError("sudo is required to raise net.core.rmem_max.")
        subprocess.run([sudo, "-v"], check=True)
        command = [sudo, "-n", *command]

    result = subprocess.run(command, capture_output=True, text=True, check=False)
    if result.returncode != 0:
        detail = (result.stderr or result.stdout).strip()
        raise BenchmarkError(
            "Could not raise net.core.rmem_max to "
            f"{CAPTURE_RMEM_MAX_BYTES}: {detail or 'sysctl failed'}"
        )

    try:
        actual = int(proc_path.read_text().strip())
    except (OSError, ValueError) as exc:
        raise BenchmarkError(f"Cannot verify {proc_path} after sysctl update: {exc}") from exc
    if actual < CAPTURE_RMEM_MAX_BYTES:
        raise BenchmarkError(
            f"net.core.rmem_max is {actual}, below required {CAPTURE_RMEM_MAX_BYTES}."
        )
    return actual



def choose_capture_staging_dir() -> Optional[Path]:
    """Use RAM-backed /dev/shm for live PCAP writes when sufficient space exists.

    The completed PCAP is moved to the persistent project directory before
    analysis. This keeps per-packet -U writes away from the project filesystem
    during the high-rate loopback capture.
    """
    shm = Path("/dev/shm")
    if not shm.is_dir():
        return None
    user_stage = shm / f"quantum_tls_capture_{os.getuid()}"
    try:
        user_stage.mkdir(mode=0o700, parents=False, exist_ok=True)
        if user_stage.stat().st_uid != os.getuid():
            return None
        os.chmod(user_stage, 0o700)
        if shutil.disk_usage(user_stage).free >= CAPTURE_TMPFS_MIN_FREE_BYTES:
            return user_stage
    except OSError:
        return None
    return None


def start_capture(tcpdump: str, interface: str, pcap_path: Path,
                  log_path: Path, startup_timeout: float) -> subprocess.Popen:
    """Start tcpdump using the proven WSL loopback capture settings.

    The pilot demonstrated complete 50/50 TCP visibility with immediate-mode
    delivery and packet-buffered writes. Keep those proven flags and enlarge the
    kernel receive buffer to 64 MiB to absorb high-volume PQ-TLS bursts.

    No live capture filter is applied. TShark restricts analysis to the profile
    port after capture. If the collector is not root, sudo is used only for the
    capture process; its credential is refreshed and verified once per condition,
    outside all measured TCP/TLS intervals. The sudo process remains in the
    caller's session so tty-scoped sudo credentials remain valid.
    """
    pcap_path.parent.mkdir(parents=True, exist_ok=True)
    log_path.parent.mkdir(parents=True, exist_ok=True)

    command_prefix: list[str] = []
    if os.geteuid() != 0:
        sudo = shutil.which("sudo")
        if not sudo:
            raise BenchmarkError("sudo is required to capture packets as a normal user.")
        try:
            # Authenticate against the caller's interactive terminal before the
            # condition starts. sudo -v only prompts when the timestamp is stale.
            subprocess.run([sudo, "-v"], check=True)
            # Confirm non-interactive use is now authorized from this same
            # terminal/session. This catches sudoers/TTY-ticket issues early.
            probe = subprocess.run(
                [sudo, "-n", "true"], capture_output=True, text=True, check=False
            )
            if probe.returncode != 0:
                detail = (probe.stderr or probe.stdout).strip()
                raise BenchmarkError(
                    "sudo authentication succeeded/was attempted, but `sudo -n true` "
                    "still cannot use the credential from this terminal. "
                    f"Details: {detail or 'no sudo diagnostic'}"
                )
        except subprocess.CalledProcessError as exc:
            raise BenchmarkError(
                "Could not refresh sudo credentials for tcpdump. Run `sudo -v` "
                "in this terminal and retry."
            ) from exc
        command_prefix = [sudo, "-n"]

    log_handle = log_path.open("w", encoding="utf-8", buffering=1)
    # Drop tcpdump privileges to the invoking user after opening the capture
    # device. This keeps RAM-staged PCAPs owned by the benchmark user.
    capture_user = pwd.getpwuid(os.getuid()).pw_name
    cmd = command_prefix + [
        tcpdump,
        "-Z", capture_user,
        "-i", interface,
        "-nn",
        "-s", "0",
        "-B", str(CAPTURE_BUFFER_KIB),
        "--immediate-mode",
        "-U",
        "-w", str(pcap_path),
    ]

    # Keep the capture process in the caller's session; stop_capture sends SIGINT
    # directly to the sudo process, which forwards it to tcpdump.
    proc = subprocess.Popen(
        cmd, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
        stderr=log_handle,
    )
    proc._benchmark_log_handle = log_handle  # type: ignore[attr-defined]
    proc._benchmark_log_path = log_path  # type: ignore[attr-defined]
    deadline = time.monotonic() + startup_timeout
    while time.monotonic() < deadline:
        if proc.poll() is not None:
            detail = log_path.read_text(errors="replace")[-3000:]
            log_handle.close()
            raise BenchmarkError(
                f"tcpdump exited before capture readiness (exit={proc.returncode}). Log: {detail}"
            )
        detail = log_path.read_text(errors="replace") if log_path.exists() else ""
        if "listening on" in detail.lower() and pcap_path.exists() and pcap_path.stat().st_size >= 24:
            return proc
        time.sleep(0.02)  # capture readiness polling only; not inside timed handshakes

    proc.terminate()
    try:
        proc.wait(timeout=3)
    except subprocess.TimeoutExpired:
        proc.kill()
        proc.wait()
    log_handle.close()
    detail = log_path.read_text(errors="replace")[-3000:] if log_path.exists() else ""
    raise BenchmarkError(
        f"tcpdump did not confirm capture readiness within {startup_timeout:.1f}s. Log: {detail}"
    )


def capture_log_summary(log_path: Path) -> dict[str, Any]:
    """Parse tcpdump's final packet and kernel-drop counters without guessing."""
    text = log_path.read_text(errors="replace") if log_path.exists() else ""
    captured_match = re.search(r"(?im)^\s*(\d+)\s+packets?\s+captured\b", text)
    received_match = re.search(
        r"(?im)^\s*(\d+)\s+packets?\s+received\s+by\s+filter\b", text
    )

    drop_values = re.findall(
        r"(?im)^\s*(\d+)\s+packets?\s+dropped(?:\s+by\s+(?:kernel|interface))?\s*$",
        text,
    )
    dropped = sum(int(value) for value in drop_values) if drop_values else None
    return {
        "captured_packets": int(captured_match.group(1)) if captured_match else None,
        "received_packets": int(received_match.group(1)) if received_match else None,
        "dropped_packets": dropped,
        "log_text": text,
    }


def stop_capture(proc: subprocess.Popen) -> dict[str, Any]:
    """Stop tcpdump with SIGINT so it writes final PCAP and drop statistics."""
    was_running = proc.poll() is None
    status = "STOPPED_CLEANLY"
    if was_running:
        try:
            # sudo relays SIGINT to tcpdump; this mirrors the successful manual test.
            proc.send_signal(signal.SIGINT)
            proc.wait(timeout=30)
        except ProcessLookupError:
            proc.wait(timeout=3)
        except subprocess.TimeoutExpired:
            status = "STOP_TIMEOUT"
            proc.terminate()
            try:
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait()
    else:
        status = "EXITED_BEFORE_STOP"

    handle = getattr(proc, "_benchmark_log_handle", None)
    if handle and not handle.closed:
        handle.flush()
        handle.close()
    log_path = getattr(proc, "_benchmark_log_path", None)
    summary = capture_log_summary(Path(log_path)) if log_path else {
        "captured_packets": None, "received_packets": None,
        "dropped_packets": None, "log_text": ""
    }
    summary["exit_code"] = proc.returncode
    if status == "STOPPED_CLEANLY" and proc.returncode not in (0, None):
        status = f"EXIT_CODE_{proc.returncode}"
    summary["process_status"] = status
    return summary


def wait_for_session_ticket(tls_sock: ssl.SSLSocket, timeout_s: float) -> tuple[Optional[ssl.SSLSession], bool, str]:
    """Drive TLS 1.3 post-handshake reads until OpenSSL processes a session ticket.

    This is event-driven socket I/O. It does not inject a delay into handshake timing.
    """
    deadline = time.monotonic() + timeout_s
    tls_sock.setblocking(False)
    want_read, want_write = True, False
    saw_app_data = False
    last_error = ""
    while time.monotonic() < deadline:
        session = tls_sock.session
        if session is not None and getattr(session, "has_ticket", False):
            return session, True, ""
        remaining = max(0.0, deadline - time.monotonic())
        readable, writable, _ = select.select(
            [tls_sock] if want_read else [], [tls_sock] if want_write else [], [], remaining
        )
        if not readable and not writable:
            break
        try:
            # OpenSSL consumes post-handshake TLS control records while servicing recv().
            data = tls_sock.recv(1)
            want_read, want_write = True, False
            if data:
                saw_app_data = True
                last_error = "Unexpected application data received while waiting for TLS ticket"
        except ssl.SSLWantReadError:
            want_read, want_write = True, False
        except ssl.SSLWantWriteError:
            want_read, want_write = False, True
        except (ssl.SSLZeroReturnError, ssl.SSLEOFError) as exc:
            last_error = f"Peer closed while waiting for session ticket: {exc}"
            break
        except (OSError, ssl.SSLError) as exc:
            last_error = f"Session-ticket read failed: {type(exc).__name__}: {exc}"
            break
    session = tls_sock.session
    if session is not None and getattr(session, "has_ticket", False):
        return session, True, ""
    if saw_app_data and not last_error:
        last_error = "Application data arrived before a session ticket"
    return session, False, last_error or f"No TLS 1.3 NewSessionTicket observed within {timeout_s:.1f}s"


def connect_with_unique_source_port(
    server_port: int, timeout: float, used_local_ports: set[int]
) -> tuple[socket.socket, int, int]:
    """Connect to loopback using a source port unique within this PCAP condition.

    The collector correlates client sockets to tcp.stream values by source port.
    Linux may reuse loopback TIME-WAIT ports (tcp_tw_reuse=2), so a port can
    otherwise identify multiple streams in one capture. Bind explicitly and
    reject any source port already used in this condition.

    Returns (connected_socket, connect_start_ns, connect_end_ns). Socket creation
    and bind are outside the measured TCP connect interval.
    """
    last_error: Optional[OSError] = None
    for _ in range(128):
        candidate = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            candidate.settimeout(timeout)
            candidate.bind(("127.0.0.1", 0))
            local_port = int(candidate.getsockname()[1])
            if local_port in used_local_ports:
                candidate.close()
                continue
            connect_start_ns = time.perf_counter_ns()
            candidate.connect(("127.0.0.1", server_port))
            connect_end_ns = time.perf_counter_ns()
            used_local_ports.add(local_port)
            return candidate, connect_start_ns, connect_end_ns
        except OSError as exc:
            last_error = exc
            candidate.close()
            # Retry bind/allocation collisions. A real connection failure should
            # be surfaced immediately rather than hidden by repeated attempts.
            if exc.errno not in (98, 99, 10048, 10049):
                raise
    raise OSError(
        f"Could not allocate a unique loopback source port after 128 attempts; "
        f"last error: {last_error}"
    )


def run_connection(profile: TLSProfile, context: ssl.SSLContext, client_id: int,
                   round_id: int, clients: int, rounds: int, resumption: str,
                   session_cache: dict[int, ssl.SSLSession], connect_timeout: float,
                   ticket_timeout: float, connection_id: int,
                   used_local_ports: set[int]) -> dict[str, Any]:
    record: dict[str, Any] = {
        "Timestamp_UTC": dt.datetime.now(dt.timezone.utc).isoformat(timespec="milliseconds"),
        "Clients": clients, "Rounds": rounds, "Config": profile.name,
        "Resumption": resumption, "Client_ID": client_id, "Round_ID": round_id,
        "Connection_ID": connection_id, "Local_Port": "", "TCP_Stream": "",
        "TCP_Connect_ms": None, "TLS_Handshake_ms": None, "Total_Connection_ms": None,
        "Session_Reused": None, "Session_Offered": False, "Resumption_Status": "NOT_REQUESTED",
        "Session_Ticket_Received": None, "Handshake_Status": "FAILURE",
        "TLS_Version": "", "Cipher": "", "Negotiated_Group": "",
        "Signature_Algorithm": "", "Error": "",
    }
    raw_sock: Optional[socket.socket] = None
    tls_sock: Optional[ssl.SSLSocket] = None
    tcp_start = time.perf_counter_ns()
    try:
        raw_sock, tcp_connect_start, tcp_connected = connect_with_unique_source_port(
            profile.port, connect_timeout, used_local_ports
        )
        tcp_start = tcp_connect_start
        record["TCP_Connect_ms"] = (tcp_connected - tcp_connect_start) / 1_000_000
        record["Local_Port"] = raw_sock.getsockname()[1]
        raw_sock.settimeout(connect_timeout)

        requested_session = session_cache.get(client_id) if resumption == "ON" else None
        record["Session_Offered"] = requested_session is not None
        tls_sock = context.wrap_socket(
            raw_sock,
            server_hostname="localhost",
            do_handshake_on_connect=False,
            session=requested_session,
        )
        handshake_start = time.perf_counter_ns()
        tls_sock.do_handshake()
        handshake_end = time.perf_counter_ns()
        record["TLS_Handshake_ms"] = (handshake_end - handshake_start) / 1_000_000
        record["Total_Connection_ms"] = (handshake_end - tcp_start) / 1_000_000
        record["Session_Reused"] = bool(tls_sock.session_reused)
        record["TLS_Version"] = tls_sock.version() or ""
        cipher = tls_sock.cipher()
        record["Cipher"] = cipher[0] if cipher else ""
        record["Handshake_Status"] = "SUCCESS"

        if resumption == "OFF":
            record["Resumption_Status"] = "DISABLED"
            record["Session_Ticket_Received"] = "NOT_CHECKED"
        else:
            if requested_session is None:
                record["Resumption_Status"] = "INITIAL_FULL_HANDSHAKE" if round_id == 1 else "NO_SESSION_AVAILABLE"
            elif tls_sock.session_reused:
                record["Resumption_Status"] = "RESUMED"
            else:
                record["Resumption_Status"] = "RESUMPTION_MISS"
            new_session, ticket_received, ticket_error = wait_for_session_ticket(tls_sock, ticket_timeout)
            record["Session_Ticket_Received"] = ticket_received
            if new_session is not None and getattr(new_session, "has_ticket", False):
                # Session objects are scoped to this SSLContext/profile and simulated client.
                session_cache[client_id] = new_session
            elif ticket_error:
                record["Error"] = ticket_error

    except (OSError, ssl.SSLError, TimeoutError) as exc:
        record["Handshake_Status"] = "FAILURE"
        record["Error"] = f"{type(exc).__name__}: {exc}"
        if record["TCP_Connect_ms"] is None:
            record["TCP_Connect_ms"] = (time.perf_counter_ns() - tcp_start) / 1_000_000
        if resumption == "ON":
            record["Resumption_Status"] = "RESUMPTION_CONNECTION_FAILURE" if record["Session_Offered"] else "CONNECTION_FAILURE"
    finally:
        # Closing is outside the measured do_handshake() interval.
        try:
            if tls_sock is not None:
                tls_sock.close()
            elif raw_sock is not None:
                raw_sock.close()
        except OSError:
            pass
    return record


def run_tshark_fields(tshark: str, pcap: Path, display_filter: str,
                      fields: list[str], keylog_path: Optional[Path] = None,
                      timeout: float = TShARK_ANALYSIS_TIMEOUT_S,
                      decode_as_port: Optional[int] = None) -> list[list[str]]:
    cmd = [tshark, "-n", "-r", str(pcap), "-o", "tcp.desegment_tcp_streams:TRUE",
           "-o", "tls.desegment_ssl_records:TRUE"]
    if decode_as_port is not None:
        # Test endpoints use nonstandard ports (4431/4433/4434/4435).
        # Force TLS dissection rather than relying on heuristic detection.
        cmd.extend(["-d", f"tcp.port=={decode_as_port},tls"])
    if keylog_path is not None and keylog_path.is_file():
        cmd.extend(["-o", f"tls.keylog_file:{keylog_path}"])
    cmd.extend(["-Y", display_filter, "-T", "fields"])
    for field in fields:
        cmd.extend(["-e", field])
    cmd.extend(["-E", "separator=\t", "-E", "quote=d", "-E", "occurrence=a", "-E", "aggregator=;"])
    result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    if result.returncode != 0:
        raise BenchmarkError(f"TShark analysis failed for filter '{display_filter}': {result.stderr.strip()}")
    rows: list[list[str]] = []
    for line in result.stdout.splitlines():
        try:
            rows.append(next(csv.reader([line], delimiter="\t", quotechar='"')))
        except csv.Error:
            continue
    return rows


@lru_cache(maxsize=4)
def tshark_available_fields(tshark: str) -> set[str]:
    result = subprocess.run([tshark, "-G", "fields"], capture_output=True, text=True, timeout=30)
    if result.returncode != 0:
        return set()
    fields: set[str] = set()
    for line in result.stdout.splitlines():
        cols = line.split("\t")
        if len(cols) >= 3 and cols[0] == "F":
            fields.add(cols[2])
    return fields


def first_field(available: set[str], candidates: tuple[str, ...]) -> Optional[str]:
    return next((x for x in candidates if x in available), None)


def _field_values(value: str) -> list[str]:
    """Split TShark's repeated-field aggregation into non-empty values."""
    return [part.strip() for part in str(value or "").split(";") if part.strip()]


def analyze_pcap(tshark: str, pcap: Path, port: int, sample_rows: list[dict[str, Any]],
                 expected_tcp_connected: int, expected_successful: int,
                 keylog_path: Optional[Path] = None,
                 capture_summary: Optional[dict[str, Any]] = None,
                 capture_runtime_error: str = "") -> dict[str, Any]:
    if not pcap.is_file() or pcap.stat().st_size < 28:
        raise BenchmarkError(f"PCAP missing or too small: {pcap}")

    available = tshark_available_fields(tshark)
    group_field = first_field(available, (
        "tls.handshake.extensions_key_share_group",
        "tls.handshake.extensions.key_share.group",
    ))
    signature_field = first_field(available, (
        "tls.handshake.sig_hash_alg",
        "tls.handshake.signature_algorithm",
    ))
    handshake_type_field = first_field(available, (
        "tls.handshake.type", "ssl.handshake.type",
    ))
    tls_record_field = first_field(available, (
        "tls.record.content_type", "ssl.record.content_type",
    ))

    # Read the PCAP once. The earlier implementation launched separate TShark
    # passes for TCP, TLS bytes, ServerHello groups, and CertificateVerify
    # signatures. A single pass reduces disk churn and keeps all stream metadata
    # tied to the same dissector/reassembly run.
    fields = ["frame.len", "tcp.stream", "tcp.srcport", "tcp.dstport"]
    if tls_record_field:
        fields.append(tls_record_field)
    if handshake_type_field:
        fields.append(handshake_type_field)
    if group_field:
        fields.append(group_field)
    if signature_field:
        fields.append(signature_field)

    rows = run_tshark_fields(
        tshark, pcap, f"tcp.port == {port}", fields,
        keylog_path=keylog_path, timeout=TShARK_ANALYSIS_TIMEOUT_S,
        decode_as_port=port,
    )

    tcp_bytes = 0
    tls_bytes = 0
    streams: set[int] = set()
    tls_streams: set[int] = set()
    local_to_streams: dict[int, set[int]] = {}
    groups_by_stream: dict[int, str] = {}
    signatures_by_stream: dict[int, str] = {}

    idx = {field: i for i, field in enumerate(fields)}
    for row in rows:
        if len(row) < len(fields):
            row.extend([""] * (len(fields) - len(row)))
        try:
            frame_len = int(row[idx["frame.len"]]) if row[idx["frame.len"]] else 0
            stream = int(row[idx["tcp.stream"]]) if row[idx["tcp.stream"]] else None
            src = int(row[idx["tcp.srcport"]]) if row[idx["tcp.srcport"]] else None
            dst = int(row[idx["tcp.dstport"]]) if row[idx["tcp.dstport"]] else None
        except (ValueError, KeyError):
            continue

        tcp_bytes += frame_len
        if stream is None:
            continue
        streams.add(stream)

        # Identify the ephemeral client port from either packet direction.
        if src == port and dst is not None:
            local_to_streams.setdefault(dst, set()).add(stream)
        elif dst == port and src is not None:
            local_to_streams.setdefault(src, set()).add(stream)

        if tls_record_field and row[idx[tls_record_field]]:
            tls_bytes += frame_len
            tls_streams.add(stream)

        # Restrict the evidence to the negotiated ServerHello group (type 2)
        # and the server CertificateVerify scheme (type 15). The same group and
        # signature fields can also occur in ClientHello offer lists; those are
        # not proof of what the server actually negotiated.
        handshake_types = (
            _field_values(row[idx[handshake_type_field]])
            if handshake_type_field else []
        )
        is_server_hello = any(
            normalized(value) == "2" or normalized(value).startswith("serverhello")
            for value in handshake_types
        )
        is_certificate_verify = any(
            normalized(value) == "15" or normalized(value).startswith("certificateverify")
            for value in handshake_types
        )
        if group_field and is_server_hello:
            group_values = _field_values(row[idx[group_field]])
            if group_values:
                groups_by_stream[stream] = group_values[-1]
        if signature_field and is_certificate_verify:
            signature_values = _field_values(row[idx[signature_field]])
            if signature_values:
                signatures_by_stream[stream] = signature_values[-1]

    # Compatibility fallback for older TShark builds without tls.record.content_type.
    # Still use only one additional pass, and only when the field is unavailable.
    if not tls_record_field:
        tls_rows = run_tshark_fields(
            tshark, pcap, f"tcp.port == {port} && tls", ["frame.len", "tcp.stream"],
            keylog_path=keylog_path, timeout=TShARK_ANALYSIS_TIMEOUT_S,
            decode_as_port=port,
        )
        for row in tls_rows:
            row += [""] * (2 - len(row))
            try:
                if row[0]:
                    tls_bytes += int(row[0])
                if row[1]:
                    tls_streams.add(int(row[1]))
            except ValueError:
                continue

    expected_local_ports: list[int] = []
    successful_local_ports: list[int] = []
    for sample in sample_rows:
        try:
            local = int(sample.get("Local_Port") or 0)
        except (TypeError, ValueError):
            local = 0
        if not local:
            continue
        expected_local_ports.append(local)
        if sample.get("Handshake_Status") == "SUCCESS":
            successful_local_ports.append(local)
        mapped = local_to_streams.get(local, set())
        if len(mapped) == 1:
            stream = next(iter(mapped))
            sample["TCP_Stream"] = stream
            sample["Negotiated_Group"] = groups_by_stream.get(stream, "")
            sample["Signature_Algorithm"] = signatures_by_stream.get(stream, "")

    missing_tcp = sorted(set(expected_local_ports) - set(local_to_streams))
    ambiguous_tcp = sorted(
        port_id for port_id in expected_local_ports
        if len(local_to_streams.get(port_id, set())) > 1
    )
    missing_tls = []
    for local in successful_local_ports:
        mapped = local_to_streams.get(local, set())
        if len(mapped) != 1 or next(iter(mapped), None) not in tls_streams:
            missing_tls.append(local)

    summary = capture_summary or {}
    dropped = summary.get("dropped_packets")
    process_status = summary.get("process_status", "UNKNOWN")
    if capture_runtime_error:
        process_status = "EXITED_DURING_RUN"
    drop_check_ok = dropped == 0
    process_check_ok = process_status == "STOPPED_CLEANLY" and not capture_runtime_error
    stream_check_ok = (
        len(expected_local_ports) == expected_tcp_connected
        and not missing_tcp
        and not ambiguous_tcp
        and len(set(local_to_streams)) == expected_tcp_connected
    )
    tls_check_ok = (
        len(missing_tls) == 0
        and len(successful_local_ports) == expected_successful
    )
    capture_valid = bool(
        tcp_bytes > 0 and tls_bytes > 0 and stream_check_ok and tls_check_ok
        and drop_check_ok and process_check_ok
    )

    detail_parts = []
    if missing_tcp:
        detail_parts.append(f"missing_tcp_local_ports={','.join(map(str, missing_tcp))}")
    if ambiguous_tcp:
        detail_parts.append(f"ambiguous_tcp_local_ports={','.join(map(str, ambiguous_tcp))}")
    if missing_tls:
        detail_parts.append(
            f"successful_connections_without_tls_frames={','.join(map(str, missing_tls))}"
        )
    if dropped not in (None, 0):
        detail_parts.append(f"capture_dropped_packets={dropped}")
    if dropped is None:
        detail_parts.append("capture_drop_counter_unavailable")
    if not process_check_ok:
        detail_parts.append(f"capture_process={process_status}")
    if capture_runtime_error:
        detail_parts.append(capture_runtime_error)
    if tcp_bytes <= 0 or tls_bytes <= 0:
        detail_parts.append("no_tcp_or_tls_frame_bytes")
    if not detail_parts:
        detail_parts.append("all_expected_tcp_streams_and_tls_frames_captured")

    return {
        "TCP_Traffic_Bytes": tcp_bytes,
        "TLS_Traffic_Bytes": tls_bytes,
        "Captured_TCP_Streams": len(streams),
        "Mapped_TCP_Connections": len(expected_local_ports) - len(missing_tcp) - len(ambiguous_tcp),
        "TLS_Evidence_Streams": len(tls_streams),
        "Missing_TCP_Local_Ports": ";".join(map(str, missing_tcp)),
        "Capture_Packets_Captured": "" if summary.get("captured_packets") is None else summary.get("captured_packets"),
        "Capture_Packets_Received_By_Filter": "" if summary.get("received_packets") is None else summary.get("received_packets"),
        "Capture_Packets_Dropped": "" if dropped is None else dropped,
        "Capture_Process_Status": process_status,
        "Capture_Filter_Mode": (
            f"TCPDUMP_IMMEDIATE_UNBUFFERED_WRITE_{CAPTURE_BUFFER_KIB}KIB_"
            "UNFILTERED_UNIQUE_SOURCE_PORT_SINGLE_PASS_TSHARK"
        ),
        "Capture_Validation_Detail": "; ".join(detail_parts),
        "Capture_Valid": "VALID" if capture_valid else "INVALID",
        "Group_Field": group_field or "UNAVAILABLE",
        "Signature_Field": signature_field or "UNAVAILABLE",
    }


def normalized(value: Any) -> str:
    return "".join(ch.lower() for ch in str(value) if ch.isalnum())


def matches_expected(actual: Any, expected: str) -> bool:
    if actual is None or str(actual).strip() == "":
        return False

    aliases = {
        "x25519": {"x25519", "29", "0x001d"},
        "x25519mlkem768": {"x25519mlkem768", "x25519_mlkem768", "4588", "0x11ec"},
        "mlkem768": {"mlkem768", "513", "0x0201"},
        "ecdsa_secp256r1_sha256": {
            "ecdsasecp256r1sha256", "ecdsa256sha256", "0x0403", "1027"
        },
        "mldsa65": {"mldsa65", "0x0905", "2309"},
    }
    expected_aliases = {normalized(x) for x in aliases.get(expected.lower(), {expected})}

    # TShark may display a name with its IANA identifier in parentheses,
    # e.g. "X25519 (29)". Compare exact normalized components, not substrings:
    # substring matching would incorrectly accept X25519MLKEM768 as X25519.
    raw = str(actual).strip().lower()
    candidates = {normalized(raw)}
    for component in re.findall(r"\(([^)]*)\)", raw):
        candidates.add(normalized(component))
    candidates.add(normalized(raw.split("(", 1)[0]))
    return bool(candidates & expected_aliases)


def aggregate_condition(run_id: str, clients: int, rounds: int, profile: TLSProfile,
                        resumption: str, rows: list[dict[str, Any]], pcap_metrics: dict[str, Any],
                        pcap_path: Path) -> dict[str, Any]:
    attempted = clients * rounds
    successes = [r for r in rows if r["Handshake_Status"] == "SUCCESS"]
    failures = attempted - len(successes)
    tcp_connected = sum(1 for r in rows if r.get("Local_Port"))
    full = sum(1 for r in successes if r.get("Session_Reused") is False)
    resumed = sum(1 for r in successes if r.get("Session_Reused") is True)

    # Every client-round after round 1 is a resumption attempt when ON, whether
    # or not a ticket was successfully obtained and offered. This prevents a
    # missing ticket from silently shrinking the denominator and inflating hits.
    eligible_resumption_rows = [
        r for r in rows if resumption == "ON" and int(r.get("Round_ID") or 0) > 1
    ]
    resumption_attempts = len(eligible_resumption_rows)
    sessions_offered = sum(1 for r in eligible_resumption_rows if r.get("Session_Offered") is True)
    misses = sum(1 for r in eligible_resumption_rows if r.get("Session_Reused") is not True
                 and r.get("Handshake_Status") == "SUCCESS")
    resumption_failures = sum(1 for r in eligible_resumption_rows if r.get("Handshake_Status") != "SUCCESS")
    sessions_unavailable = sum(1 for r in eligible_resumption_rows if r.get("Session_Offered") is not True)
    tickets_received = sum(1 for r in rows if r.get("Session_Ticket_Received") is True)
    ticket_failures = sum(1 for r in rows if r.get("Session_Ticket_Received") is False)

    hs = [float(r["TLS_Handshake_ms"]) for r in successes if r.get("TLS_Handshake_ms") is not None]
    tcp = [float(r["TCP_Connect_ms"]) for r in rows if r.get("TCP_Connect_ms") is not None]
    hit_rate = (resumed / resumption_attempts * 100.0) if resumption_attempts else ""

    # Validate profile parameters against full certificate-authenticated TLS 1.3
    # handshakes only. TLS 1.3 PSK resumptions normally omit CertificateVerify.
    full_successes = [r for r in successes if r.get("Session_Reused") is False]
    group_values = [r.get("Negotiated_Group", "") for r in full_successes]
    signature_values = [r.get("Signature_Algorithm", "") for r in full_successes]
    versions = [r.get("TLS_Version", "") for r in successes]

    if not successes:
        profile_validation = "NO_SUCCESSFUL_HANDSHAKES"
    elif any(v != "TLSv1.3" for v in versions):
        profile_validation = "MISMATCH_TLS_VERSION"
    elif not full_successes:
        profile_validation = "NO_FULL_HANDSHAKE_EVIDENCE"
    elif pcap_metrics.get("Group_Field") in (None, "UNAVAILABLE") or \
         pcap_metrics.get("Signature_Field") in (None, "UNAVAILABLE"):
        profile_validation = "METADATA_UNAVAILABLE"
    elif any(not v for v in group_values) or any(not v for v in signature_values):
        profile_validation = "INCOMPLETE"
    elif not all(matches_expected(v, profile.expected_group) for v in group_values):
        profile_validation = "MISMATCH_GROUP"
    elif not all(matches_expected(v, profile.expected_signature) for v in signature_values):
        profile_validation = "MISMATCH_SIGNATURE"
    else:
        profile_validation = "MATCH"

    return {
        "Run_ID": run_id, "Clients": clients, "Rounds": rounds, "Config": profile.name,
        "Resumption": resumption, "Execution_Model": "SEQUENTIAL_NxR",
        "Attempted_Connections": attempted, "TCP_Connected": tcp_connected,
        "Successful_Connections": len(successes), "Failed_Connections": failures,
        "Full_Handshakes": full, "Resumed_Handshakes": resumed,
        "Resumption_Attempts": resumption_attempts, "Sessions_Offered": sessions_offered,
        "Resumption_Misses": misses, "Resumption_Failures": resumption_failures,
        "Sessions_Unavailable": sessions_unavailable,
        "Session_Tickets_Received": tickets_received, "Session_Ticket_Failures": ticket_failures,
        "Resumption_Hit_Rate_pct": round(hit_rate, 4) if isinstance(hit_rate, float) else "",
        "Mean_TCP_Connect_ms": round(statistics.fmean(tcp), 6) if tcp else "",
        "Mean_Handshake_ms": round(statistics.fmean(hs), 6) if hs else "",
        "Median_Handshake_ms": round(statistics.median(hs), 6) if hs else "",
        "P95_Handshake_ms": round(percentile(hs, 0.95), 6) if hs else "",
        "Total_Handshake_ms": round(sum(hs), 6),
        "TCP_Traffic_Bytes": pcap_metrics.get("TCP_Traffic_Bytes", ""),
        "TLS_Traffic_Bytes": pcap_metrics.get("TLS_Traffic_Bytes", ""),
        "Captured_TCP_Streams": pcap_metrics.get("Captured_TCP_Streams", ""),
        "Mapped_TCP_Connections": pcap_metrics.get("Mapped_TCP_Connections", ""),
        "TLS_Evidence_Streams": pcap_metrics.get("TLS_Evidence_Streams", ""),
        "Missing_TCP_Local_Ports": pcap_metrics.get("Missing_TCP_Local_Ports", ""),
        "Capture_Packets_Captured": pcap_metrics.get("Capture_Packets_Captured", ""),
        "Capture_Packets_Received_By_Filter": pcap_metrics.get("Capture_Packets_Received_By_Filter", ""),
        "Capture_Packets_Dropped": pcap_metrics.get("Capture_Packets_Dropped", ""),
        "Capture_Process_Status": pcap_metrics.get("Capture_Process_Status", "UNKNOWN"),
        "Capture_Filter_Mode": pcap_metrics.get("Capture_Filter_Mode", "UNKNOWN"),
        "Capture_Validation_Detail": pcap_metrics.get("Capture_Validation_Detail", ""),
        "Capture_Valid": pcap_metrics.get("Capture_Valid", "INVALID"),
        "Profile_Validation": profile_validation,
        "PCAP_File": str(pcap_path),
    }


def write_csv(path: Path, fields: list[str], rows: list[dict[str, Any]], overwrite: bool) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    mode = "w" if overwrite or not path.exists() else "a"
    write_header = mode == "w" or path.stat().st_size == 0
    with path.open(mode, newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fields, extrasaction="ignore")
        if write_header:
            writer.writeheader()
        writer.writerows(rows)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Collect the independent TLS 72-condition benchmark using tcpdump + TShark")
    parser.add_argument("--project-root", type=Path, default=project_root_default())
    parser.add_argument("--config", choices=("K1", "H1", "H2", "P1"), help="Run one profile only (pilot/debug)")
    parser.add_argument("--clients", type=int, choices=CLIENT_COUNTS, help="Run one client-count value")
    parser.add_argument("--rounds", type=int, choices=ROUND_COUNTS, help="Run one round-count value")
    parser.add_argument("--resumption", choices=RESUMPTIONS, help="Run one resumption mode")
    parser.add_argument("--tag", default="", help="Output suffix, e.g. pilot; keeps test data separate")
    parser.add_argument("--interface", default="lo", help="Capture interface (default: lo)")
    parser.add_argument("--connect-timeout", type=float, default=5.0)
    parser.add_argument("--ticket-timeout", type=float, default=3.0)
    parser.add_argument("--capture-startup-timeout", type=float, default=8.0)
    parser.add_argument("--dry-run", action="store_true", help="Print selected conditions without connecting")
    parser.add_argument("--overwrite", action="store_true", help="Allow replacing output CSVs with this tag")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    root = args.project_root.expanduser().resolve()
    profiles = profiles_for_root(root)
    results_csv = root / "results" / "csv"
    pcap_dir = root / "pcaps" / "raw"
    log_dir = root / "logs" / "benchmark"
    results_csv.mkdir(parents=True, exist_ok=True)
    pcap_dir.mkdir(parents=True, exist_ok=True)
    log_dir.mkdir(parents=True, exist_ok=True)

    configs = [args.config] if args.config else list(profiles)
    clients_list = [args.clients] if args.clients else list(CLIENT_COUNTS)
    rounds_list = [args.rounds] if args.rounds else list(ROUND_COUNTS)
    resumption_list = [args.resumption] if args.resumption else list(RESUMPTIONS)
    conditions = [(n, r, cfg, resume) for n in clients_list for r in rounds_list
                  for cfg in configs for resume in resumption_list]

    if args.dry_run:
        print(f"Selected {len(conditions)} condition(s):")
        for i, (n, r, cfg, resume) in enumerate(conditions, 1):
            p = profiles[cfg]
            print(f"{i:02d}. N={n:2d} R={r:3d} Config={cfg} Resume={resume} Port={p.port} Group={p.expected_group} Signature={p.expected_signature}")
        return 0

    selected_profiles = {cfg: profiles[cfg] for cfg in configs}
    version, tshark, tcpdump = verify_runtime(root, selected_profiles)
    capture_rmem_max = ensure_capture_buffer_limit()
    run_id = dt.datetime.now(dt.timezone.utc).strftime("%Y%m%dT%H%M%SZ") + "_" + uuid.uuid4().hex[:8]
    capture_staging_dir = choose_capture_staging_dir()
    suffix = f"_{args.tag}" if args.tag else ""
    sample_path = results_csv / f"handshake_samples{suffix}.csv"
    aggregate_path = results_csv / f"raw_measurements{suffix}.csv"
    if not args.overwrite and (sample_path.exists() or aggregate_path.exists()):
        raise BenchmarkError(
            f"Output already exists ({sample_path.name} or {aggregate_path.name}). "
            "Choose a new --tag or pass --overwrite to replace it."
        )

    logging.basicConfig(
        filename=log_dir / f"collector_{run_id}.log", level=logging.INFO,
        format="%(asctime)s %(levelname)s %(message)s",
    )
    print(f"Python: {platform.python_version()} | {version}")
    print(f"TShark (offline analysis): {tshark}")
    print(f"Capture tool (live capture): {tcpdump}")
    print(
        f"Capture mode: tcpdump -B {CAPTURE_BUFFER_KIB} KiB + --immediate-mode + -U; "
        f"unfiltered {args.interface}; TShark single-pass offline analysis"
    )
    print(f"Kernel net.core.rmem_max: {capture_rmem_max} bytes")
    print(
        "Live PCAP staging: " + (str(capture_staging_dir) if capture_staging_dir else "project filesystem (no suitable /dev/shm space)")
    )
    print(f"Project root: {root}")
    print(f"Run ID: {run_id} | Conditions: {len(conditions)}")
    print("Execution model: sequential N x R fresh connections; independent of Flower.")

    # Create output files up front, then flush each completed condition so an
    # interrupted full grid does not discard already completed measurements.
    write_csv(sample_path, SAMPLE_FIELDS, [], overwrite=True)
    write_csv(aggregate_path, AGG_FIELDS, [], overwrite=True)
    for index, (n, r, cfg, resume) in enumerate(conditions, 1):
        profile = profiles[cfg]
        tag = f"{cfg}_N{n}_R{r}_{resume}_{run_id}"
        pcap_path = pcap_dir / f"{tag}.pcap"
        live_pcap_path = (
            capture_staging_dir / f"quantum_{tag}.pcap"
            if capture_staging_dir else pcap_path
        )
        capture_log = log_dir / f"tcpdump_{tag}.log"
        keylog_path = root / "sessions" / "keylogs" / f"{tag}.keys"
        print(f"[{index:02d}/{len(conditions):02d}] N={n}, R={r}, {cfg}, resumption={resume}", flush=True)
        context = make_context(profile, keylog_path)
        session_cache: dict[int, ssl.SSLSession] = {}
        # Source-port IDs are used for PCAP correlation; keep them unique within
        # this condition even when Linux loopback TIME-WAIT reuse is enabled.
        used_local_ports: set[int] = set()
        condition_rows: list[dict[str, Any]] = []
        capture_proc: Optional[subprocess.Popen] = None
        tcp_connected = 0
        capture_runtime_error = ""
        try:
            capture_proc = start_capture(tcpdump, args.interface, live_pcap_path,
                                         capture_log, args.capture_startup_timeout)
            connection_id = 0
            for round_id in range(1, r + 1):
                for client_id in range(1, n + 1):
                    connection_id += 1
                    row = run_connection(
                        profile, context, client_id, round_id, n, r, resume,
                        session_cache, args.connect_timeout, args.ticket_timeout, connection_id,
                        used_local_ports,
                    )
                    row["Run_ID"] = run_id
                    condition_rows.append(row)
                    if row.get("Local_Port"):
                        tcp_connected += 1
                    if row["Handshake_Status"] == "FAILURE":
                        logging.error("%s connection %d failed: %s", tag, connection_id, row.get("Error"))
                    if capture_proc.poll() is not None and not capture_runtime_error:
                        capture_runtime_error = (
                            f"tcpdump exited during benchmark after connection {connection_id} "
                            f"(exit={capture_proc.returncode})"
                        )
                        logging.error("%s: %s", tag, capture_runtime_error)
            if capture_proc.poll() is not None and not capture_runtime_error:
                capture_runtime_error = f"tcpdump exited before normal stop (exit={capture_proc.returncode})"
            capture_summary = stop_capture(capture_proc)
            capture_proc = None
            if live_pcap_path != pcap_path:
                if not live_pcap_path.is_file():
                    raise BenchmarkError(f"Live capture did not produce a PCAP: {live_pcap_path}")
                shutil.move(str(live_pcap_path), str(pcap_path))
            try:
                metrics = analyze_pcap(tshark, pcap_path, profile.port, condition_rows,
                                       tcp_connected,
                                       sum(1 for x in condition_rows if x.get("Handshake_Status") == "SUCCESS"),
                                       keylog_path=keylog_path,
                                       capture_summary=capture_summary,
                                       capture_runtime_error=capture_runtime_error)
            except Exception as exc:
                metrics = {
                    "TCP_Traffic_Bytes": "", "TLS_Traffic_Bytes": "",
                    "Captured_TCP_Streams": "", "Mapped_TCP_Connections": "",
                    "TLS_Evidence_Streams": "", "Missing_TCP_Local_Ports": "",
                    "Capture_Packets_Captured": "", "Capture_Packets_Received_By_Filter": "",
                    "Capture_Packets_Dropped": "", "Capture_Process_Status": "ANALYSIS_ERROR",
                    "Capture_Filter_Mode": (
                        f"TCPDUMP_IMMEDIATE_UNBUFFERED_WRITE_{CAPTURE_BUFFER_KIB}KIB_"
                        "UNFILTERED_UNIQUE_SOURCE_PORT_SINGLE_PASS_TSHARK"
                    ),
                    "Capture_Validation_Detail": f"{type(exc).__name__}: {exc}",
                    "Capture_Valid": "INVALID", "Group_Field": "UNAVAILABLE",
                    "Signature_Field": "UNAVAILABLE",
                }
                logging.exception("PCAP analysis failed for %s", tag)
            agg = aggregate_condition(run_id, n, r, profile, resume, condition_rows, metrics, pcap_path)
            write_csv(sample_path, SAMPLE_FIELDS, condition_rows, overwrite=False)
            write_csv(aggregate_path, AGG_FIELDS, [agg], overwrite=False)
            try:
                keylog_path.unlink(missing_ok=True)
            except OSError:
                logging.exception("Could not remove temporary TLS key log %s", keylog_path)
            print(
                f"  attempts={n*r}, success={agg['Successful_Connections']}, "
                f"failed={agg['Failed_Connections']}, resumed={agg['Resumed_Handshakes']}, "
                f"TCP_bytes={agg['TCP_Traffic_Bytes']}, TLS_bytes={agg['TLS_Traffic_Bytes']}, "
                f"streams={agg['Captured_TCP_Streams']}/{agg['TCP_Connected']}, "
                f"capture={agg['Capture_Valid']}, profile={agg['Profile_Validation']}",
                flush=True,
            )
        finally:
            if capture_proc is not None:
                stop_capture(capture_proc)

    print("\nCollection finished.")
    print(f"Per-connection samples: {sample_path}")
    print(f"72-grid aggregates:     {aggregate_path}")
    print(f"PCAP captures:          {pcap_dir}")
    passed_capture = 0
    passed_profile = 0
    final_rows: list[dict[str, str]] = []
    try:
        with aggregate_path.open(newline="", encoding="utf-8") as f:
            final_rows = list(csv.DictReader(f))
        passed_capture = sum(r.get("Capture_Valid") == "VALID" for r in final_rows)
        passed_profile = sum(r.get("Profile_Validation") == "MATCH" for r in final_rows)
    except OSError as exc:
        raise BenchmarkError(f"Could not read final aggregate CSV for validation summary: {exc}")
    print(f"Final validation: capture={passed_capture}/{len(conditions)}, profile={passed_profile}/{len(conditions)}")
    if len(final_rows) != len(conditions) or passed_capture != len(conditions) or passed_profile != len(conditions):
        print("RESULT: INCOMPLETE — do not treat this grid as a fully valid empirical dataset.")
        return 3
    print("RESULT: ALL 72 CONDITIONS PASSED CAPTURE AND TLS PROFILE VALIDATION.")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except BenchmarkError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        raise SystemExit(2)
