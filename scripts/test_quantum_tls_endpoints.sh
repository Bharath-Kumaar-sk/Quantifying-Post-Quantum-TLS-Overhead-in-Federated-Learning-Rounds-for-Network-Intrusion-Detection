#!/usr/bin/env bash
set -Eeuo pipefail

PROJECT_ROOT="${QUANTUM_HOME:-$HOME/quantum}"
ENV_FILE="$PROJECT_ROOT/env.sh"
OPENSSL_BIN="$HOME/openssl-3.5/bin/openssl"
LOG_DIR="$PROJECT_ROOT/logs/endpoint_tests"
CA_DIR="$PROJECT_ROOT/certificates/ca"

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

mkdir -p "$LOG_DIR"

NAMES=(K1 H1 H2 P1)
PORTS=(4431 4433 4434 4435)
TLS_GROUPS=(X25519 X25519MLKEM768 X25519MLKEM768 MLKEM768)
SIGALGS=(ecdsa_secp256r1_sha256 ecdsa_secp256r1_sha256 mldsa65 mldsa65)
CA_FILES=(ca-ecdsa.crt ca-ecdsa.crt ca-mldsa65.crt ca-mldsa65.crt)

failures=0

printf 'OpenSSL: %s\n' "$($OPENSSL_BIN version)"
printf 'Testing TLS 1.3 endpoints with default + OQS providers.\n\n'

for i in "${!NAMES[@]}"; do
  name="${NAMES[$i]}"
  port="${PORTS[$i]}"
  group="${TLS_GROUPS[$i]}"
  sigalg="${SIGALGS[$i]}"
  ca_file="$CA_DIR/${CA_FILES[$i]}"
  logfile="$LOG_DIR/${name}.log"

  echo "===== $name: port=$port group=$group sigalg=$sigalg ====="

  if [[ ! -s "$ca_file" ]]; then
    echo "FAIL: CA certificate missing: $ca_file" | tee "$logfile"
    failures=$((failures + 1))
    continue
  fi

  if ! ss -H -ltn "sport = :$port" 2>/dev/null | grep -q .; then
    echo "FAIL: No server is listening on port $port." | tee "$logfile"
    echo "Start the endpoints with: $PROJECT_ROOT/scripts/start_quantum_tls_servers.sh start"
    failures=$((failures + 1))
    continue
  fi

  request=$'GET / HTTP/1.0\r\nHost: localhost\r\nConnection: close\r\n\r\n'
  if output=$(printf '%s' "$request" | "$OPENSSL_BIN" s_client \
      -provider default \
      -provider oqsprovider \
      -connect "127.0.0.1:$port" \
      -servername localhost \
      -verify_hostname localhost \
      -verify_return_error \
      -CAfile "$ca_file" \
      -tls1_3 \
      -groups "$group" \
      -sigalgs "$sigalg" \
      -brief 2>&1); then
    printf '%s\n' "$output" | tee "$logfile"
    if grep -q 'Protocol version: TLSv1.3' <<<"$output" && \
       grep -q 'Verification: OK' <<<"$output"; then
      echo "PASS: $name completed TLS 1.3 with successful certificate verification."
    else
      echo "FAIL: $name returned success but expected TLS/version/verification markers were missing."
      failures=$((failures + 1))
    fi
  else
    printf '%s\n' "$output" | tee "$logfile"
    echo "FAIL: $name handshake or certificate verification failed."
    failures=$((failures + 1))
  fi
  echo
 done

if (( failures == 0 )); then
  echo "ALL FOUR ENDPOINT TESTS PASSED."
  echo "Detailed client outputs: $LOG_DIR"
  exit 0
else
  echo "$failures endpoint test(s) failed. Inspect logs in: $LOG_DIR" >&2
  exit 1
fi
