#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BACKEND_FILE="${BACKEND_FILE:-$ROOT_DIR/backend_5g_qos (3).py}"
OUT_FILE="${OUT_FILE:-$ROOT_DIR/qos_output.json}"
PORT="${PORT:-5050}"
MODE="${MODE:-live}"
IFACE="${IFACE:-en0}"
DURATION="${DURATION:-0}"
PCAP_FILE_DEFAULT="$ROOT_DIR/5G_QoS_AI_Monitor/longrun (1).pcap"
PCAP_FILE="${PCAP_FILE:-$PCAP_FILE_DEFAULT}"

PYTHON_BIN="${PYTHON_BIN:-$ROOT_DIR/5G_QoS_AI_Monitor/.venv/bin/python}"
if [[ ! -x "$PYTHON_BIN" ]]; then
  PYTHON_BIN="$ROOT_DIR/.venv/bin/python"
fi

if [[ ! -x "$PYTHON_BIN" ]]; then
  echo "Python interpreter not found. Expected one of:"
  echo "  $ROOT_DIR/5G_QoS_AI_Monitor/.venv/bin/python"
  echo "  $ROOT_DIR/.venv/bin/python"
  exit 1
fi

if [[ ! -f "$BACKEND_FILE" ]]; then
  echo "Backend file not found: $BACKEND_FILE"
  exit 1
fi

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
