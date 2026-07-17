#!/bin/bash
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

INPUT_FILE="$1"

if [ -z "$INPUT_FILE" ]; then
    echo "Usage: $0 <capture.pcapng> [hid_usb_parser.py args...]"
    exit 1
fi
shift

TMP_FILE="$(mktemp -t usb_packets).txt"
trap 'rm -f "$TMP_FILE"' EXIT

"$SCRIPT_DIR/extract_usb_packets.sh" "$INPUT_FILE" "$TMP_FILE"
python3 "$SCRIPT_DIR/hid_usb_parser.py" "$TMP_FILE" "$@"
