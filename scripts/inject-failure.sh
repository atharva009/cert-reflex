#!/usr/bin/env bash
# Thin wrapper around POST /internal/failures/<service>?type=<TYPE>, so a demo
# does not depend on anyone remembering the URL.
set -euo pipefail

BASE_URL="${BASE_URL:-http://localhost:8080}"

usage() {
  echo "usage: $(basename "$0") <service> <EXPIRE|CORRUPT>" >&2
  echo "example: $(basename "$0") demo-a CORRUPT" >&2
  exit 2
}

[[ $# -eq 2 ]] || usage
service="$1"
type="$(echo "$2" | tr '[:lower:]' '[:upper:]')"

case "$type" in
  EXPIRE|CORRUPT) ;;
  *) echo "Unknown failure type '$2'" >&2; usage ;;
esac

echo "Injecting $type into $service via $BASE_URL"
curl -sS -X POST "$BASE_URL/internal/failures/$service?type=$type" -w '\n'
