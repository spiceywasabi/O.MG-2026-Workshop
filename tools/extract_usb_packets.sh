#!/bin/bash

INPUT_FILE="$1"
OUTPUT_FILE="$2"

if [ -z "$INPUT_FILE" ] || [ -z "$OUTPUT_FILE" ]; then
    echo "Usage: $0 <capture.pcapng> <output.txt>"
    exit 1
fi

echo -e "pid\taddr\tendpoint\tdata" > "$OUTPUT_FILE"

tshark -r "$INPUT_FILE" \
    -T fields \
    -E separator=$'\t' \
    -E header=n \
    -e usbll.pid \
    -e usbll.device_addr \
    -e usbll.endp \
    -e usbll.data \
    >> "$OUTPUT_FILE"

echo "Wrote USB packet data to $OUTPUT_FILE"
