#!/bin/sh
set -eu

# ==============================================================================
# Crux-Cell Fast Entrypoint (<0.5s Cold Start)
# Boots the Crux-Cell Daemon (`SessionDAG`, `SecurityFirewall`, `ConsensusLedger`,
# `Crux-Evals`) immediately while keeping the Full OS Desktop (`Xvfb :99`) and
# Chromium Browser (`:9222`) in LAZY SOCKET-ACTIVATED STANDBY until requested.
# ==============================================================================

CELL_ID="${CRUX_CELL_ID:-cell-01}"
ROLE="${CRUX_CELL_ROLE:-generalist}"
SPINE_URL="${CRUX_SPINE_URL:-http://crux-spine:8890}"
WORKSPACE="${CRUX_CELL_WORKSPACE:-/var/opt/crux-cell/workspace}"
PORT="${CRUX_CELL_PORT:-8765}"

mkdir -p "${WORKSPACE}" "${CRUX_CELL_STATE_DIR:-/var/opt/crux-cell/state}"

exec python3 -m crux_swarm.cli cell \
    --cell-id "${CELL_ID}" \
    --role "${ROLE}" \
    --workspace "${WORKSPACE}" \
    --spine-url "${SPINE_URL}" \
    --port "${PORT}"
