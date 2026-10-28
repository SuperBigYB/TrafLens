#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
GO_BIN="${TRAFLENS_GO:-go}"
if ! "$GO_BIN" version | grep -q ' go1.26.2 '; then
  echo 'Console requires Go 1.26.2; set TRAFLENS_GO to that executable.' >&2
  exit 1
fi
mkdir -p "$ROOT/.traflens/bin"
(cd "$ROOT/traflens/console" && GOTOOLCHAIN=local GOWORK=off "$GO_BIN" build -trimpath -o "$ROOT/.traflens/bin/traflens-console" .)
if [[ "${1:-}" == build ]]; then
  echo "$ROOT/.traflens/bin/traflens-console"
  exit 0
fi
exec "$ROOT/.traflens/bin/traflens-console" "$@"
