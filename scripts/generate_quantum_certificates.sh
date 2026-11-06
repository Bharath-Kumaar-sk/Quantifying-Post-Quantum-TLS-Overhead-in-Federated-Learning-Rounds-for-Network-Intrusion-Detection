#!/usr/bin/env bash
set -Eeuo pipefail

# Generate fresh ECDSA P-256 and ML-DSA-65 CA/server credentials for the
# independent ~/quantum TLS 1.3 benchmark.
#
# Output:
#   certificates/ca/ca-ecdsa.{key,crt}
#   certificates/ca/ca-mldsa65.{key,crt}
#   certificates/servers/server-ecdsa.{key,csr,crt}
#   certificates/servers/server-mldsa65.{key,csr,crt}
#   certificates/servers/server.ext
#   certificates/certificate_manifest.txt
#
# The script refuses to overwrite existing output files. Move existing files
# aside or use a new project directory before generating another PKI set.

PROJECT_ROOT="${QUANTUM_HOME:-$HOME/quantum}"
ENV_FILE="$PROJECT_ROOT/env.sh"
CA_DIR="$PROJECT_ROOT/certificates/ca"
SERVER_DIR="$PROJECT_ROOT/certificates/servers"
CERT_ROOT="$PROJECT_ROOT/certificates"

if [[ ! -f "$ENV_FILE" ]]; then
  echo "ERROR: Environment file not found: $ENV_FILE" >&2
  echo "Create ~/quantum/env.sh first." >&2
  exit 1
fi

# Load the project's OpenSSL 3.5.x / liboqs / oqs-provider environment.
# shellcheck source=/dev/null
source "$ENV_FILE"

OPENSSL_BIN="$HOME/openssl-3.5/bin/openssl"
OQS_MODULE="${OPENSSL_MODULES:-$HOME/openssl-3.5/lib64/ossl-modules}/oqsprovider.so"

if [[ ! -x "$OPENSSL_BIN" ]]; then
  echo "ERROR: Expected OpenSSL binary not found: $OPENSSL_BIN" >&2
  exit 1
fi
if [[ ! -f "$OQS_MODULE" ]]; then
  echo "ERROR: oqsprovider module not found: $OQS_MODULE" >&2
  exit 1
fi

mkdir -p "$CA_DIR" "$SERVER_DIR"
umask 077

# Prevent accidental replacement of an existing PKI or manifest.
outputs=(
  "$CA_DIR/ca-ecdsa.key" "$CA_DIR/ca-ecdsa.crt"
  "$CA_DIR/ca-mldsa65.key" "$CA_DIR/ca-mldsa65.crt"
  "$SERVER_DIR/server-ecdsa.key" "$SERVER_DIR/server-ecdsa.csr" "$SERVER_DIR/server-ecdsa.crt"
  "$SERVER_DIR/server-mldsa65.key" "$SERVER_DIR/server-mldsa65.csr" "$SERVER_DIR/server-mldsa65.crt"
  "$SERVER_DIR/server.ext"
  "$CERT_ROOT/certificate_manifest.txt"
)
for f in "${outputs[@]}"; do
  if [[ -e "$f" ]]; then
    echo "ERROR: Refusing to overwrite existing file: $f" >&2
    echo "Move the existing certificate set to an archive directory before rerunning." >&2
    exit 1
  fi
done

# Every cryptographic command explicitly loads both providers. On OpenSSL 3.5,
# standardized ML-DSA is supplied by the default provider; oqsprovider is loaded
# alongside it for the project's OQS environment.
ossl() {
  local subcommand="$1"
  shift
  "$OPENSSL_BIN" "$subcommand" -provider default -provider oqsprovider "$@"
}

VERSION="$("$OPENSSL_BIN" version)"
echo "Using: $VERSION"
echo "Checking providers..."
PROVIDERS="$(ossl list -providers)"
printf '%s\n' "$PROVIDERS"
grep -q 'OpenSSL Default Provider' <<<"$PROVIDERS" || { echo "ERROR: default provider is not active" >&2; exit 1; }
grep -q 'OpenSSL OQS Provider' <<<"$PROVIDERS" || { echo "ERROR: OQS provider is not active" >&2; exit 1; }

# Check that the default provider exposes the exact ML-DSA key type needed.
ossl list -signature-algorithms | grep -qi 'mldsa65' || {
  echo "ERROR: ML-DSA-65 is not available in the combined provider context." >&2
  exit 1
}

STAGE="$(mktemp -d "$CERT_ROOT/.certgen.XXXXXX")"
cleanup() { rm -rf "$STAGE"; }
trap cleanup EXIT
mkdir -p "$STAGE/ca" "$STAGE/servers"

CA_TMP="$STAGE/ca"
SRV_TMP="$STAGE/servers"

 echo "[1/7] Generating ECDSA P-256 CA key and self-signed certificate..."
ossl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 \
  -out "$CA_TMP/ca-ecdsa.key"
ossl req -new -x509 -key "$CA_TMP/ca-ecdsa.key" \
  -out "$CA_TMP/ca-ecdsa.crt" -days 3650 \
  -subj "/CN=Quantum Benchmark ECDSA P-256 CA" \
  -addext "basicConstraints=critical,CA:TRUE,pathlen:0" \
  -addext "keyUsage=critical,keyCertSign,cRLSign" \
  -addext "subjectKeyIdentifier=hash"

 echo "[2/7] Generating ML-DSA-65 CA key and self-signed certificate..."
ossl genpkey -algorithm ML-DSA-65 -out "$CA_TMP/ca-mldsa65.key"
ossl req -new -x509 -key "$CA_TMP/ca-mldsa65.key" \
  -out "$CA_TMP/ca-mldsa65.crt" -days 3650 \
  -subj "/CN=Quantum Benchmark ML-DSA-65 CA" \
  -addext "basicConstraints=critical,CA:TRUE,pathlen:0" \
  -addext "keyUsage=critical,keyCertSign,cRLSign" \
  -addext "subjectKeyIdentifier=hash"

 echo "[3/7] Generating ECDSA P-256 server key and CSR..."
ossl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 \
  -out "$SRV_TMP/server-ecdsa.key"
ossl req -new -key "$SRV_TMP/server-ecdsa.key" \
  -out "$SRV_TMP/server-ecdsa.csr" \
  -subj "/CN=localhost"

 echo "[4/7] Generating ML-DSA-65 server key and CSR..."
ossl genpkey -algorithm ML-DSA-65 -out "$SRV_TMP/server-mldsa65.key"
ossl req -new -key "$SRV_TMP/server-mldsa65.key" \
  -out "$SRV_TMP/server-mldsa65.csr" \
  -subj "/CN=localhost"

 echo "[5/7] Creating server certificate extensions..."
cat > "$SRV_TMP/server.ext" <<'EXTENSIONS'
basicConstraints=critical,CA:FALSE
keyUsage=critical,digitalSignature
extendedKeyUsage=serverAuth
subjectAltName=DNS:localhost,IP:127.0.0.1
subjectKeyIdentifier=hash
authorityKeyIdentifier=keyid,issuer
EXTENSIONS

 echo "[6/7] Signing server certificates with their corresponding CAs..."
# The ECDSA CA signs the ECDSA leaf. SHA-256 is selected explicitly for this
# classical signature. The ML-DSA command deliberately has no digest option:
# ML-DSA performs its standardized internal message processing.
ossl x509 -req -in "$SRV_TMP/server-ecdsa.csr" \
  -CA "$CA_TMP/ca-ecdsa.crt" -CAkey "$CA_TMP/ca-ecdsa.key" \
  -CAcreateserial -out "$SRV_TMP/server-ecdsa.crt" \
  -days 825 -sha256 -extfile "$SRV_TMP/server.ext"

ossl x509 -req -in "$SRV_TMP/server-mldsa65.csr" \
  -CA "$CA_TMP/ca-mldsa65.crt" -CAkey "$CA_TMP/ca-mldsa65.key" \
  -CAcreateserial -out "$SRV_TMP/server-mldsa65.crt" \
  -days 825 -extfile "$SRV_TMP/server.ext"

 echo "[7/7] Verifying certificate chains, hostnames, CA constraints, and key matches..."
ossl verify -CAfile "$CA_TMP/ca-ecdsa.crt" -purpose sslserver \
  -verify_hostname localhost "$SRV_TMP/server-ecdsa.crt"
ossl verify -CAfile "$CA_TMP/ca-mldsa65.crt" -purpose sslserver \
  -verify_hostname localhost "$SRV_TMP/server-mldsa65.crt"

# Compare DER-encoded public keys extracted from each private key and leaf cert.
for kind in ecdsa mldsa65; do
  ossl pkey -in "$SRV_TMP/server-$kind.key" -pubout -outform DER \
    -out "$STAGE/server-$kind.from-key.der"
  ossl x509 -in "$SRV_TMP/server-$kind.crt" -pubkey -noout \
    -out "$STAGE/server-$kind.pub.pem"
  ossl pkey -pubin -in "$STAGE/server-$kind.pub.pem" -outform DER \
    -out "$STAGE/server-$kind.from-cert.der"
  cmp -s "$STAGE/server-$kind.from-key.der" "$STAGE/server-$kind.from-cert.der" || {
    echo "ERROR: server-$kind private key does not match its certificate" >&2
    exit 1
  }
done

# Ensure the CA certificates are actually CA certificates and inspect the
# public-key and issuer-signature algorithms that will be recorded in results.
for kind in ecdsa mldsa65; do
  ossl x509 -in "$CA_TMP/ca-$kind.crt" -noout -text |
    grep -q 'CA:TRUE' || { echo "ERROR: ca-$kind.crt lacks CA:TRUE" >&2; exit 1; }
done

# Build a reproducibility manifest before committing the staged files.
{
  echo "Quantum TLS benchmark certificate manifest"
  echo "Generated: $(date -Is)"
  echo "OpenSSL: $VERSION"
  echo "OQS provider module: $OQS_MODULE"
  echo "Project root: $PROJECT_ROOT"
  echo
  for f in \
    "$CA_TMP/ca-ecdsa.crt" "$SRV_TMP/server-ecdsa.crt" \
    "$CA_TMP/ca-mldsa65.crt" "$SRV_TMP/server-mldsa65.crt"; do
    echo "===== $(basename "$f") ====="
    ossl x509 -in "$f" -noout -subject -issuer -serial -dates -fingerprint -sha256
    ossl x509 -in "$f" -noout -text | grep -m1 'Public Key Algorithm'
    ossl x509 -in "$f" -noout -text | grep -m1 'Signature Algorithm'
    echo
  done
} > "$STAGE/certificate_manifest.txt"

# Commit generated files only after every validation succeeded.
mv "$CA_TMP"/* "$CA_DIR/"
mv "$SRV_TMP"/* "$SERVER_DIR/"
mv "$STAGE/certificate_manifest.txt" "$CERT_ROOT/certificate_manifest.txt"

chmod 700 "$CA_DIR" "$SERVER_DIR"
chmod 600 "$CA_DIR"/*.key "$SERVER_DIR"/*.key
chmod 644 "$CA_DIR"/*.crt "$SERVER_DIR"/*.crt "$SERVER_DIR"/*.csr "$SERVER_DIR"/*.ext "$CERT_ROOT/certificate_manifest.txt"

echo
echo "SUCCESS: Fresh benchmark certificates generated and verified."
echo "CA certificates:      $CA_DIR"
echo "Server certificates:  $SERVER_DIR"
echo "Manifest:             $CERT_ROOT/certificate_manifest.txt"
echo
echo "K1/H1 use server-ecdsa.crt + server-ecdsa.key and trust ca-ecdsa.crt."
echo "H2/P1 use server-mldsa65.crt + server-mldsa65.key and trust ca-mldsa65.crt."
