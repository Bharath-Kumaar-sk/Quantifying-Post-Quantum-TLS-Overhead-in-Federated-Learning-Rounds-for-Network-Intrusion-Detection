#!/usr/bin/env bash
set -Eeuo pipefail

PROJECT_ROOT="${QUANTUM_HOME:-$HOME/quantum}"
ENV_FILE="$PROJECT_ROOT/env.sh"
OPENSSL_BIN="$HOME/openssl-3.5/bin/openssl"
CERT_DIR="$PROJECT_ROOT/certificates"
CA_DIR="$CERT_DIR/ca"
SERVER_DIR="$CERT_DIR/servers"
LOG_DIR="$PROJECT_ROOT/logs/tls_servers"
PID_DIR="$PROJECT_ROOT/logs/tls_servers/pids"

if [[ ! -f "$ENV_FILE" ]]; then
  echo "ERROR: Environment file not found: $ENV_FILE" >&2
  exit 1
fi
# shellcheck disable=SC1090
source "$ENV_FILE"

if [[ ! -x "$OPENSSL_BIN" ]]; then
  echo "ERROR: OpenSSL executable not found: $OPENSSL_BIN" >&2
  exit 1
fi

mkdir -p "$LOG_DIR" "$PID_DIR"

# The experiment's four TLS profiles.
NAMES=(K1 H1 H2 P1)
PORTS=(4431 4433 4434 4435)
TLS_GROUPS=(X25519 X25519MLKEM768 X25519MLKEM768 MLKEM768)
SIGALGS=(ecdsa_secp256r1_sha256 ecdsa_secp256r1_sha256 mldsa65 mldsa65)
CERTS=(server-ecdsa.crt server-ecdsa.crt server-mldsa65.crt server-mldsa65.crt)
KEYS=(server-ecdsa.key server-ecdsa.key server-mldsa65.key server-mldsa65.key)

usage() {
  cat <<USAGE
Usage: $0 {start|stop|status|restart}

Starts/stops four local TLS 1.3 test servers:
  K1  127.0.0.1:4431  X25519          ECDSA P-256
  H1  127.0.0.1:4433  X25519MLKEM768  ECDSA P-256
  H2  127.0.0.1:4434  X25519MLKEM768  ML-DSA-65
  P1  127.0.0.1:4435  MLKEM768        ML-DSA-65

Logs: $LOG_DIR
PID files: $PID_DIR
USAGE
}

is_listening() {
  local port="$1"
  ss -H -ltn "sport = :$port" 2>/dev/null | grep -q .
}

start_one() {
  local i="$1" name port group sigalg cert key pidfile logfile pid
  name="${NAMES[$i]}"
  port="${PORTS[$i]}"
  group="${TLS_GROUPS[$i]}"
  sigalg="${SIGALGS[$i]}"
  cert="$SERVER_DIR/${CERTS[$i]}"
  key="$SERVER_DIR/${KEYS[$i]}"
  pidfile="$PID_DIR/${name}.pid"
  logfile="$LOG_DIR/${name}.log"

  [[ -s "$cert" ]] || { echo "ERROR: Missing certificate: $cert" >&2; return 1; }
  [[ -s "$key" ]] || { echo "ERROR: Missing private key: $key" >&2; return 1; }

  if [[ -f "$pidfile" ]]; then
    pid="$(cat "$pidfile" 2>/dev/null || true)"
    if [[ "$pid" =~ ^[0-9]+$ ]] && kill -0 "$pid" 2>/dev/null; then
      if is_listening "$port"; then
        echo "$name already running (PID $pid, port $port)."
        return 0
      fi
    fi
    rm -f "$pidfile"
  fi

  if is_listening "$port"; then
    echo "ERROR: Port $port is already occupied, but is not tracked by $pidfile." >&2
    echo "Inspect with: sudo ss -ltnp 'sport = :$port'" >&2
    return 1
  fi

  echo "Starting $name on 127.0.0.1:$port (group=$group, sigalg=$sigalg)..."
  nohup "$OPENSSL_BIN" s_server \
    -provider default \
    -provider oqsprovider \
    -accept "127.0.0.1:$port" \
    -cert "$cert" \
    -key "$key" \
    -tls1_3 \
    -groups "$group" \
    -sigalgs "$sigalg" \
    -www \
    -state \
    >"$logfile" 2>&1 </dev/null &
  pid=$!
  printf '%s\n' "$pid" > "$pidfile"

  for _ in $(seq 1 50); do
    if ! kill -0 "$pid" 2>/dev/null; then
      echo "ERROR: $name server exited during startup. Last log lines:" >&2
      tail -n 30 "$logfile" >&2 || true
      rm -f "$pidfile"
      return 1
    fi
    if is_listening "$port"; then
      echo "$name is listening (PID $pid). Log: $logfile"
      return 0
    fi
    sleep 0.1
  done

  echo "ERROR: Timed out waiting for $name on port $port." >&2
  tail -n 30 "$logfile" >&2 || true
  kill "$pid" 2>/dev/null || true
  rm -f "$pidfile"
  return 1
}

stop_one() {
  local i="$1" name port pidfile pid args
  name="${NAMES[$i]}"
  port="${PORTS[$i]}"
  pidfile="$PID_DIR/${name}.pid"
  if [[ ! -f "$pidfile" ]]; then
    echo "$name has no PID file."
    return 0
  fi
  pid="$(cat "$pidfile" 2>/dev/null || true)"
  if [[ "$pid" =~ ^[0-9]+$ ]] && kill -0 "$pid" 2>/dev/null; then
    args="$(ps -p "$pid" -o args= 2>/dev/null || true)"
    if [[ "$args" == *"s_server"* && "$args" == *"$port"* ]]; then
      kill "$pid"
      for _ in $(seq 1 30); do
        kill -0 "$pid" 2>/dev/null || break
        sleep 0.1
      done
      kill -0 "$pid" 2>/dev/null && kill -9 "$pid" 2>/dev/null || true
      echo "Stopped $name (PID $pid)."
    else
      echo "PID $pid is not the expected $name server; not killing it." >&2
    fi
  else
    echo "$name is not running."
  fi
  rm -f "$pidfile"
}

status_one() {
  local i="$1" name port pidfile pid
  name="${NAMES[$i]}"
  port="${PORTS[$i]}"
  pidfile="$PID_DIR/${name}.pid"
  pid=""
  [[ -f "$pidfile" ]] && pid="$(cat "$pidfile" 2>/dev/null || true)"
  if [[ "$pid" =~ ^[0-9]+$ ]] && kill -0 "$pid" 2>/dev/null && is_listening "$port"; then
    echo "$name: RUNNING (PID $pid, port $port)"
  elif is_listening "$port"; then
    echo "$name: PORT $port LISTENING (PID not confirmed; inspect process)"
  else
    echo "$name: STOPPED"
  fi
}

case "${1:-}" in
  start)
    for i in "${!NAMES[@]}"; do start_one "$i"; done
    ;;
  stop)
    for i in 3 2 1 0; do stop_one "$i"; done
    ;;
  status)
    for i in "${!NAMES[@]}"; do status_one "$i"; done
    ;;
  restart)
    for i in 3 2 1 0; do stop_one "$i"; done
    for i in "${!NAMES[@]}"; do start_one "$i"; done
    ;;
  *)
    usage
    exit 2
    ;;
esac
