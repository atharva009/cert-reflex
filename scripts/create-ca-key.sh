#!/usr/bin/env bash
# Creates the CA signing key inside the LocalStack container and records its id
# in a gitignored .env at the repo root. Idempotent: a second run reuses the key
# already in .env rather than creating another one.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ENV_FILE="$REPO_ROOT/.env"

if [[ -f "$ENV_FILE" ]]; then
  existing="$(grep -E '^CA_KEY_ID=' "$ENV_FILE" | tail -1 | cut -d= -f2- | tr -d '\r' || true)"
  if [[ -n "${existing:-}" ]]; then
    echo "CA key already exists, reusing it."
    echo "CA_KEY_ID=$existing"
    exit 0
  fi
fi

cd "$REPO_ROOT"

echo "Creating CA signing key in LocalStack KMS..."
response="$(docker compose exec -T localstack awslocal kms create-key \
  --key-usage SIGN_VERIFY \
  --key-spec ECC_NIST_P256 \
  --description "cert-reflex intermediate signing key")"

# Pull KeyId out of the JSON without depending on jq being installed.
key_id="$(printf '%s' "$response" \
  | tr -d '\r' \
  | grep -o '"KeyId"[[:space:]]*:[[:space:]]*"[^"]*"' \
  | head -1 \
  | sed 's/.*"\([^"]*\)"[[:space:]]*$/\1/')"

if [[ -z "$key_id" ]]; then
  echo "Could not parse KeyId from KMS response:" >&2
  echo "$response" >&2
  exit 1
fi

# Replace any empty CA_KEY_ID line, then append the real one.
if [[ -f "$ENV_FILE" ]]; then
  grep -v -E '^CA_KEY_ID=' "$ENV_FILE" > "$ENV_FILE.tmp" || true
  mv "$ENV_FILE.tmp" "$ENV_FILE"
fi
echo "CA_KEY_ID=$key_id" >> "$ENV_FILE"

echo "Wrote $ENV_FILE"
echo "CA_KEY_ID=$key_id"
