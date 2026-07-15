#!/bin/sh
set -e

# Init-Service: erzeugt den Bearer-Token einmalig, falls er noch nicht
# existiert.  Das Token wird niemals in Logs oder das Image geschrieben.

TOKEN_FILE="/data/bridge-token"
TOKEN_DIR="$(dirname "$TOKEN_FILE")"
mkdir -p "$TOKEN_DIR"

if [ ! -s "$TOKEN_FILE" ]; then
    TMP_FILE="${TOKEN_FILE}.tmp.$$"
    if command -v openssl >/dev/null 2>&1; then
        openssl rand -hex 32 > "$TMP_FILE"
    else
        head -c 32 /dev/urandom | xxd -p -c 64 > "$TMP_FILE"
    fi
    chmod 600 "$TMP_FILE"
    mv "$TMP_FILE" "$TOKEN_FILE"
fi

echo "Token initialised"
