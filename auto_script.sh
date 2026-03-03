#!/usr/bin/env bash
set -eo pipefail

# Debug: uncomment if needed
# set -x

IDA="/Applications/IDA Professional 9.0.app/Contents/MacOS/idat64"

BIN=""
OUT=""

usage () {
  echo "Usage: $0 --binary <path-to-bin> --out <output-dir>"
}

# Parse args
while [[ $# -gt 0 ]]; do
  case "$1" in
    --binary) BIN="$2"; shift 2;;
    --out)    OUT="$2"; shift 2;;
    -h|--help) usage; exit 0;;
    *) echo "Unknown arg: $1"; usage; exit 1;;
  esac
done

if [[ -z "${BIN}" || -z "${OUT}" ]]; then
  usage
  exit 1
fi

if [[ ! -x "$IDA" ]]; then
  echo "[!] IDA not found or not executable: $IDA"
  exit 1
fi

if [[ ! -f "$BIN" ]]; then
  echo "[!] Binary not found: $BIN"
  exit 1
fi

# Resolve absolute paths without python
BIN_ABS="$(cd "$(dirname "$BIN")" && pwd -P)/$(basename "$BIN")"
OUT_ABS="$(mkdir -p "$OUT" && cd "$OUT" && pwd -P)"

DB_OUT="$OUT_ABS/$(basename "$BIN_ABS").i64"
LOG="$OUT_ABS/ida_export.log"
SCRIPT="$(cd "$(dirname "$0")" && pwd -P)/auto_ida_export.py"

echo "[*] IDA : $IDA"
echo "[*] BIN : $BIN_ABS"
echo "[*] OUT : $OUT_ABS"
echo "[*] DB  : $DB_OUT"
echo "[*] LOG : $LOG"
echo "[*] PY  : $SCRIPT"

CHECKSEC_OUT="$OUT_ABS/checksec.txt"

echo "[*] Running checksec..."
checksec --file="$BIN_ABS" > "$CHECKSEC_OUT" 2>&1 || true

# Run headless IDA
"$IDA" -A -c -L"$LOG" -o"$DB_OUT" -S"$SCRIPT --out $OUT_ABS" "$BIN_ABS"