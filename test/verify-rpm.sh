#!/usr/bin/env bash
set -euo pipefail

# Check for required parameters
if [[ $# -lt 2 ]]; then
  echo "Usage: $0 <GPG_KEY_FILE_OR_KEY_ID> <PATH_TO_RPM_FILE>"
  echo "Example (Key File):    $0 oracle_key.pub kernel-6.12.0.rpm"
  echo "Example (Fingerprint): $0 6fedfc85 kernel-6.12.0.rpm"
  exit 1
fi

KEY_INPUT="$1"
RPM_FILE="$2"

# Ensure the RPM file exists
if [[ ! -f "$RPM_FILE" ]]; then
  echo "Error: RPM file '$RPM_FILE' not found." >&2
  exit 1
fi

# Create isolated temporary directory
TMP_DIR=$(mktemp -d -t rpm_verify_XXXXXX)

# Automatic cleanup on exit or termination signals
cleanup() {
  rm -rf "$TMP_DIR"
}
trap cleanup EXIT INT TERM

# Handle Local File vs Remote Key ID / Fingerprint
if [[ -f "$KEY_INPUT" ]]; then
  echo "==> Detected local key file '$KEY_INPUT'. Preparing key..."
  cp "$KEY_INPUT" "$TMP_DIR/signing_key.pub"
else
  echo "==> Assuming '$KEY_INPUT' is a key ID/fingerprint. Fetching from keyserver..."
  gpg --quiet --keyserver hkps://keyserver.ubuntu.com --recv-keys "$KEY_INPUT"
  gpg --quiet --export --armor "$KEY_INPUT" > "$TMP_DIR/signing_key.pub"
fi

echo "==> Initializing temporary RPM database..."
rpmdb --dbpath "$TMP_DIR" --initdb

echo "==> Importing public key into temporary RPM database..."
rpm --dbpath "$TMP_DIR" --import "$TMP_DIR/signing_key.pub"

echo -e "==> Verifying signature for $RPM_FILE using rpm -Kv ... :\n"
rpm --dbpath "$TMP_DIR" -Kv "$RPM_FILE"

echo -e "==> Verifying signature for $RPM_FILE using client --verify ... :\n"
../bin/client -v --verify --pub-key ${KEY_INPUT} ${RPM_FILE}
