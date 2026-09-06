#!/usr/bin/env bash
set -euo pipefail

if [[ $# -lt 2 ]]; then
  echo "Usage: $0 <file with gpg public key to use for signature verification> <detached GPG signature file> <file with signed data>"
  exit 1
fi

KEY_INPUT="$1"
SIGNATURE_INPUT="$2"
SIGNED_FILE="$3"

# Create isolated temporary directory to hold GPG keyring
TMP_DIR=$(mktemp -d -t rpm_verify_XXXXXX)

# Automatic cleanup on exit or termination signals
cleanup() {
  rm -rf "$TMP_DIR"
}
trap cleanup EXIT INT TERM

gpg --homedir ${TMP_DIR} --import ${KEY_INPUT} 

# 2. Extract the fingerprint of the newly imported key
FINGERPRINT=$(gpg --homedir ${TMP_DIR} --with-colons --list-keys | awk -F: '/^fpr/ {print $10; exit}')

# 3. Assign ultimate trust (level 6) to that fingerprint
echo "${FINGERPRINT}:6:" | gpg --homedir ${TMP_DIR} --import-ownertrust 2>&1 &>/dev/null

gpg --homedir ${TMP_DIR} --verify ${SIGNATURE_INPUT} ${SIGNED_FILE} 
