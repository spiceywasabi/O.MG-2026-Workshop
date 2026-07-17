# O.MG HID Workshops


For the 2025 and 2026 Workshops at BSidesLV and DefCon. Materials from a hands-on workshop on O.MG HID-injection devices (BadUSB-style keystroke injection hardware): USB packet captures for analysis, example DuckyScript payloads, PowerShell PoCs, and a small toolkit for parsing HID traffic out of `.pcapng` captures.

Educational / authorized-testing use only — see [Disclaimer](#disclaimer).

## Repository layout

```
captures/    USB packet captures (.pcapng) for parsing/analysis exercises
payloads/    DuckyScript payloads and PowerShell scripts used by the payloads
tools/       Scripts to extract and decode HID reports from a capture
HID WORKSHOP 2026 SLIDES.pdf   Workshop slide deck
```

### `captures/`

Wireshark/tshark captures (`usbll` link-layer) of USB traffic, used as input to the tools below:

- `capture-usb-keyboard*.pcapng` — plain USB keyboard traffic (simple and complex sessions)
- `capture-*-omg-plug-elite-hidx.pcapng` — traffic from an O.MG Elite device with HIDX enabled
- `capture-usb-flashdrive-*.pcapng` — USB mass-storage read/write/format traffic

### `payloads/`

DuckyScript examples, roughly in teaching order:

- `duckyscript-hello-world.txt` — minimal payload
- `duckyscript-notepad-var-greeting.txt` — `DEFINE` variables
- `duckyscript-functions-and-variables.txt` — functions with parameters
- `duckyscript-blocks-rem-stringln.txt` — `REM_BLOCK` / `STRINGLN_BLOCK` multi-line syntax
- `duckyscript-inline-powershell.txt` — dropping and running an inline PowerShell block (`powershell-collect-and-zip.ps1` equivalent)
- `duckyscript-simplified-hidx-shell-base.txt` / `duckyscript-hidx-shell.txt` — write-to-disk-and-execute pattern used to stage the HIDX shell PoC

PowerShell scripts referenced/staged by the payloads above:

- `powershell-collect-and-zip.ps1` — recursively collects files matching an extension into a temp folder and zips them
- `win-hidexfil.ps1` — PoC for low-and-slow data exfiltration over an O.MG Elite's HIDX interface (`HIDXExfil` function)
- `win-hidexfil.ps1` (via the ducky payload) also stages `HIDXShell`, a bidirectional shell PoC over the same HIDX channel

These scripts locate the O.MG device by VID/PID (default `D3C0:D34D`) via WMI and open a raw file handle to its HID interface to exchange data.

### `tools/`

Command-line helpers for turning a raw capture into decoded HID input:

- `extract_usb_packets.sh <capture.pcapng> <output.txt>` — uses `tshark` to dump PID, device address, endpoint, and data fields for every USB packet into a TSV file
- `hid_usb_parser.py <packets.txt> [--endpoint N] [--raw] [--verbose]` — groups packets into transactions, enumerates USB devices and endpoints from control transfers, and decodes boot-protocol keyboard/mouse HID reports (reconstructing typed text, held keys/modifiers, and mouse movement)
- `analyze_usb_capture.sh <capture.pcapng> [parser args...]` — convenience wrapper that runs the two steps above in one command

**Requirements:** `tshark` (Wireshark) and Python 3.

**Usage:**

```sh
tools/analyze_usb_capture.sh captures/capture-simple-usb-keyboard.pcapng
tools/analyze_usb_capture.sh captures/capture-simple-usb-keyboard.pcapng --verbose
tools/analyze_usb_capture.sh captures/capture-simple-usb-keyboard.pcapng --endpoint 1 --raw
```

## Disclaimer

These payloads and captures are provided for security research and authorized penetration-testing/red-team engagements. Only use them against systems you own or have explicit written permission to test. You are responsible for complying with applicable laws and your engagement's rules of authorization.
