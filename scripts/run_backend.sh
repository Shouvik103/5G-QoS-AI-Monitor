#!/usr/bin/env bash
set -euo pipefail

# ── Resolve project root (one level up from scripts/) ──
ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

BACKEND_FILE="${BACKEND_FILE:-$ROOT_DIR/src/backend_5g_qos.py}"
OUT_FILE="${OUT_FILE:-$ROOT_DIR/output/qos_output.json}"
PORT="${PORT:-5050}"
MODE="${MODE:-pcap}"
IFACE="${IFACE:-en0}"
DURATION="${DURATION:-0}"
PCAP_FILE="${PCAP_FILE:-$ROOT_DIR/data/longrun.pcap}"

PYTHON_BIN="${PYTHON_BIN:-$ROOT_DIR/.venv/bin/python}"

if [[ ! -x "$PYTHON_BIN" ]]; then
  echo "Python interpreter not found: $PYTHON_BIN"
  echo "Run: python3 -m venv .venv && .venv/bin/pip install -r requirements.txt"
  exit 1
fi

if [[ ! -f "$BACKEND_FILE" ]]; then
  echo "Backend file not found: $BACKEND_FILE"
  exit 1
fi

mkdir -p "$(dirname "$OUT_FILE")"

if [[ "$MODE" == "live" ]]; then
  exec "$PYTHON_BIN" "$BACKEND_FILE" \
    --live \
    --iface "$IFACE" \
    --duration "$DURATION" \
    --out "$OUT_FILE" \
    --serve \
    --port "$PORT"
elif [[ "$MODE" == "pcap" ]]; then
  if [[ ! -f "$PCAP_FILE" ]]; then
    echo "PCAP file not found: $PCAP_FILE"
    exit 1
  fi
  exec "$PYTHON_BIN" "$BACKEND_FILE" \
    --pcap "$PCAP_FILE" \
    --out "$OUT_FILE" \
    --serve \
    --port "$PORT"
else
  echo "Invalid MODE: $MODE"
  echo "Use MODE=live or MODE=pcap"
  exit 1
fi
