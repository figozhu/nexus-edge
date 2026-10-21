#!/bin/sh
set -eu
NEXUS_EDGE_SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
if command -v bun >/dev/null 2>&1; then
  exec bun "$NEXUS_EDGE_SCRIPT_DIR/nexus-edge.ts"
elif [ -x "$HOME/.bun/bin/bun" ]; then
  exec "$HOME/.bun/bin/bun" "$NEXUS_EDGE_SCRIPT_DIR/nexus-edge.ts"
else
  printf '%s\n' 'Bun 1.4.3 or newer is required.' 'Install Bun from https://bun.sh/docs/installation and open a new terminal.' >&2
  exit 1
fi
