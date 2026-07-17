#!/usr/bin/env python3
import argparse
import struct
import sys
from collections import namedtuple

Packet = namedtuple("Packet", "pid addr endpoint data")

TOKEN_KIND = {0x2D: "SETUP", 0xE1: "OUT", 0x69: "IN"}
DATA_PIDS = {0xC3, 0x4B, 0x87, 0x0F}
NAK_PID = 0x5A


def load_packets(file_path):
    try:
        input_file = open(file_path, "r")
    except FileNotFoundError:
        print(f"Could not find file: {file_path}")
        print("Run extract_usb_packets.sh first to create it.")
        sys.exit(1)

    lines = input_file.readlines()
    input_file.close()

    packets = []
    for line in lines[1:]:
        line = line.rstrip("\n")
        fields = line.split("\t")

        while len(fields) < 4:
            fields.append("")

        pid_text = fields[0]
        addr_text = fields[1]
        endpoint_text = fields[2]
        data_text = fields[3]

        if pid_text == "":
            pid = None
        else:
            pid = int(pid_text, 16)

        if addr_text == "":
            addr = None
        else:
            addr = int(addr_text)

        if endpoint_text == "":
            endpoint = None
        else:
            endpoint = int(endpoint_text)

        if data_text == "" or data_text == "<none>":
            data = b""
        else:
            data_text = data_text.replace(":", "")
            data = bytes.fromhex(data_text)

        packets.append(Packet(pid, addr, endpoint, data))

    return packets


Transaction = namedtuple("Transaction", "kind addr endpoint data")


def group_into_transactions(packets):
    transactions = []
    i = 0
    while i < len(packets):
        token = packets[i]

        if token.pid in TOKEN_KIND:
            j = i + 1
            while j < len(packets) and packets[j].pid == NAK_PID:
                j += 1

            if j < len(packets) and packets[j].pid in DATA_PIDS:
                kind = TOKEN_KIND[token.pid]
                data = packets[j].data
                transactions.append(Transaction(kind, token.addr, token.endpoint, data))
                i = j + 1
                continue

        i += 1

    return transactions


SET_ADDRESS = 0x05
GET_DESCRIPTOR = 0x06
DEVICE_DESCRIPTOR = 0x01
CONFIGURATION_DESCRIPTOR = 0x02
STRING_DESCRIPTOR = 0x03
INTERFACE_DESCRIPTOR = 0x04
ENDPOINT_DESCRIPTOR = 0x05
HID_CLASS = 0x03


class Device:
    def __init__(self, addr):
        self.addr = addr
        self.vendor_id = None
        self.product_id = None
        self.manufacturer = ""
        self.product = ""
        self.endpoints = {}

    def label(self):
        if self.vendor_id is None:
            vendor_id_text = "????"
        else:
            vendor_id_text = f"{self.vendor_id:04x}"

        if self.product_id is None:
            product_id_text = "????"
        else:
            product_id_text = f"{self.product_id:04x}"

        name = ""
        if self.manufacturer != "" and self.product != "":
            name = self.manufacturer + " " + self.product
        elif self.manufacturer != "":
            name = self.manufacturer
        elif self.product != "":
            name = self.product

        text = f"addr={self.addr} VID:PID={vendor_id_text}:{product_id_text}"
        if name != "":
            text = text + f'  "{name}"'
        return text


def read_control_transfers(transactions):
    reads = []
    i = 0
    while i < len(transactions):
        setup = transactions[i]

        if setup.kind == "SETUP" and len(setup.data) == 8:
            request_type, request, value, index, length = struct.unpack("<BBHHH", setup.data)

            if request == GET_DESCRIPTOR and length > 0:
                collected = bytearray()
                packet_size = None
                j = i + 1
                while j < len(transactions):
                    reply = transactions[j]
                    if reply.kind != "IN" or reply.addr != setup.addr or reply.endpoint != setup.endpoint:
                        break

                    collected.extend(reply.data)
                    if packet_size is None:
                        packet_size = len(reply.data)
                    j += 1

                    if len(reply.data) < packet_size or len(collected) >= length:
                        break

                descriptor_type = value >> 8
                descriptor_index = value & 0xFF
                reads.append({
                    "addr": setup.addr,
                    "descriptor_type": descriptor_type,
                    "descriptor_index": descriptor_index,
                    "data": bytes(collected),
                })

        i += 1

    return reads


def parse_configuration_descriptor(data, endpoints_out):
    offset = 0
    current_interface = None
    while offset + 2 <= len(data):
        length = data[offset]
        descriptor_type = data[offset + 1]
        if length == 0:
            break

        descriptor = data[offset:offset + length]

        if descriptor_type == INTERFACE_DESCRIPTOR and len(descriptor) >= 9:
            current_interface = {
                "number": descriptor[2],
                "class": descriptor[5],
                "subclass": descriptor[6],
                "protocol": descriptor[7],
            }
        elif descriptor_type == ENDPOINT_DESCRIPTOR and len(descriptor) >= 7:
            endpoint_address = descriptor[2]
            endpoints_out[endpoint_address] = {
                "number": endpoint_address & 0x0F,
                "direction_in": bool(endpoint_address & 0x80),
                "transfer_type": descriptor[3] & 0x03,
                "interface": current_interface,
            }

        offset += length


def find_devices(transactions):
    devices = {}

    for t in transactions:
        if t.kind == "SETUP" and len(t.data) == 8:
            request_type, request, value, index, length = struct.unpack("<BBHHH", t.data)
            if request == SET_ADDRESS:
                new_addr = value
                if new_addr not in devices:
                    devices[new_addr] = Device(new_addr)

    manufacturer_index = {}
    product_index = {}

    for read in read_control_transfers(transactions):
        addr = read["addr"]
        if addr not in devices:
            devices[addr] = Device(addr)
        dev = devices[addr]
        data = read["data"]

        if read["descriptor_type"] == DEVICE_DESCRIPTOR and len(data) >= 18:
            dev.vendor_id, dev.product_id = struct.unpack_from("<HH", data, 8)
            manufacturer_index[addr] = data[14]
            product_index[addr] = data[15]

        elif read["descriptor_type"] == CONFIGURATION_DESCRIPTOR:
            parse_configuration_descriptor(data, dev.endpoints)

        elif read["descriptor_type"] == STRING_DESCRIPTOR and len(data) > 2:
            text = data[2:].decode("utf-16-le", errors="replace")
            if read["descriptor_index"] == manufacturer_index.get(addr):
                dev.manufacturer = text
            elif read["descriptor_index"] == product_index.get(addr):
                dev.product = text

    return devices


HID_KEYCODES = {
    0x04: ('a', 'A'), 0x05: ('b', 'B'), 0x06: ('c', 'C'), 0x07: ('d', 'D'),
    0x08: ('e', 'E'), 0x09: ('f', 'F'), 0x0a: ('g', 'G'), 0x0b: ('h', 'H'),
    0x0c: ('i', 'I'), 0x0d: ('j', 'J'), 0x0e: ('k', 'K'), 0x0f: ('l', 'L'),
    0x10: ('m', 'M'), 0x11: ('n', 'N'), 0x12: ('o', 'O'), 0x13: ('p', 'P'),
    0x14: ('q', 'Q'), 0x15: ('r', 'R'), 0x16: ('s', 'S'), 0x17: ('t', 'T'),
    0x18: ('u', 'U'), 0x19: ('v', 'V'), 0x1a: ('w', 'W'), 0x1b: ('x', 'X'),
    0x1c: ('y', 'Y'), 0x1d: ('z', 'Z'),
    0x1e: ('1', '!'), 0x1f: ('2', '@'), 0x20: ('3', '#'), 0x21: ('4', '$'),
    0x22: ('5', '%'), 0x23: ('6', '^'), 0x24: ('7', '&'), 0x25: ('8', '*'),
    0x26: ('9', '('), 0x27: ('0', ')'),
    0x28: ('\n', '\n'), 0x29: ('[ESC]', '[ESC]'), 0x2a: ('[BKSP]', '[BKSP]'),
    0x2b: ('\t', '\t'), 0x2c: (' ', ' '),
    0x2d: ('-', '_'), 0x2e: ('=', '+'), 0x2f: ('[', '{'), 0x30: (']', '}'),
    0x31: ('\\', '|'), 0x33: (';', ':'), 0x34: ("'", '"'), 0x35: ('`', '~'),
    0x36: (',', '<'), 0x37: ('.', '>'), 0x38: ('/', '?'),
    0x39: ('[CAPS]', '[CAPS]'),
    0x3a: ('[F1]', '[F1]'), 0x3b: ('[F2]', '[F2]'), 0x3c: ('[F3]', '[F3]'),
    0x3d: ('[F4]', '[F4]'), 0x3e: ('[F5]', '[F5]'), 0x3f: ('[F6]', '[F6]'),
    0x40: ('[F7]', '[F7]'), 0x41: ('[F8]', '[F8]'), 0x42: ('[F9]', '[F9]'),
    0x43: ('[F10]', '[F10]'), 0x44: ('[F11]', '[F11]'), 0x45: ('[F12]', '[F12]'),
    0x4a: ('[HOME]', '[HOME]'), 0x4b: ('[PGUP]', '[PGUP]'),
    0x4c: ('[DEL]', '[DEL]'), 0x4d: ('[END]', '[END]'),
    0x4e: ('[PGDN]', '[PGDN]'), 0x4f: ('[RIGHT]', '[RIGHT]'),
    0x50: ('[LEFT]', '[LEFT]'), 0x51: ('[DOWN]', '[DOWN]'), 0x52: ('[UP]', '[UP]'),
    0x53: ('[NUMLOCK]', '[NUMLOCK]'), 0x54: ('/', '/'), 0x55: ('*', '*'),
    0x56: ('-', '-'), 0x57: ('+', '+'), 0x58: ('\n', '\n'),
    0x59: ('1', '1'), 0x5a: ('2', '2'), 0x5b: ('3', '3'), 0x5c: ('4', '4'),
    0x5d: ('5', '5'), 0x5e: ('6', '6'), 0x5f: ('7', '7'), 0x60: ('8', '8'),
    0x61: ('9', '9'), 0x62: ('0', '0'), 0x63: ('.', '.'),
}
HID_MODIFIER_BITS = {
    0x01: 'LCtrl', 0x02: 'LShift', 0x04: 'LAlt', 0x08: 'LGUI',
    0x10: 'RCtrl', 0x20: 'RShift', 0x40: 'RAlt', 0x80: 'RGUI',
}
SHIFT_BITS = 0x02 | 0x20


def decode_keyboard_reports(reports):
    previously_held = set()
    typed_characters = []
    events = []

    for data in reports:
        if len(data) < 8:
            continue

        modifiers = data[0]
        key_codes = data[2:8]

        held = set()
        for key_code in key_codes:
            if key_code != 0:
                held.add(key_code)

        shift_is_down = False
        if modifiers & SHIFT_BITS:
            shift_is_down = True

        newly_pressed = []
        for key_code in held:
            if key_code not in previously_held:
                newly_pressed.append(key_code)

        for key_code in newly_pressed:
            if key_code in HID_KEYCODES:
                unshifted_char, shifted_char = HID_KEYCODES[key_code]
            else:
                unshifted_char = f"[0x{key_code:02x}]"
                shifted_char = unshifted_char

            if shift_is_down:
                typed_characters.append(shifted_char)
            else:
                typed_characters.append(unshifted_char)

        active_modifier_names = []
        for bit, name in HID_MODIFIER_BITS.items():
            if modifiers & bit:
                active_modifier_names.append(name)

        events.append((active_modifier_names, sorted(held)))
        previously_held = held

    typed_text = "".join(typed_characters)
    return typed_text, events


def decode_mouse_reports(reports):
    events = []
    button_names = {0x01: 'L', 0x02: 'R', 0x04: 'M'}

    for data in reports:
        if len(data) < 3:
            continue

        buttons = data[0]
        dx = struct.unpack_from("<b", data, 1)[0]
        dy = struct.unpack_from("<b", data, 2)[0]

        if len(data) > 3:
            wheel = struct.unpack_from("<b", data, 3)[0]
        else:
            wheel = 0

        pressed_buttons = []
        for bit, name in button_names.items():
            if buttons & bit:
                pressed_buttons.append(name)

        events.append((pressed_buttons, dx, dy, wheel))

    return events


def print_device(dev):
    print(f"=== Device {dev.label()} ===")

    if len(dev.endpoints) == 0:
        print("  (no endpoint descriptors captured)")

    transfer_type_names = {0: "control", 1: "isochronous", 2: "bulk", 3: "interrupt"}

    endpoint_addresses = sorted(dev.endpoints.keys())
    for endpoint_address in endpoint_addresses:
        info = dev.endpoints[endpoint_address]
        interface = info["interface"]
        if interface is None:
            interface = {}

        if info["direction_in"]:
            direction = "IN"
        else:
            direction = "OUT"

        transfer_type_number = info["transfer_type"]
        if transfer_type_number in transfer_type_names:
            transfer_type_text = transfer_type_names[transfer_type_number]
        else:
            transfer_type_text = "?"

        interface_number = interface.get("number")
        interface_class = interface.get("class", 0)
        interface_subclass = interface.get("subclass", 0)
        interface_protocol = interface.get("protocol", 0)

        line = f"  EP 0x{endpoint_address:02x} ({direction}, {transfer_type_text}"
        line += f", iface {interface_number}, class=0x{interface_class:02x}"
        line += f" subclass=0x{interface_subclass:02x} protocol=0x{interface_protocol:02x})"
        if interface_class == HID_CLASS:
            line += "  <-- HID"
        print(line)

    print()


def print_hid_endpoint(dev, addr, endpoint_number, reports, raw_only, verbose):
    endpoint_address = endpoint_number | 0x80

    if dev is None:
        return
    if endpoint_address not in dev.endpoints:
        return

    info = dev.endpoints[endpoint_address]
    interface = info["interface"]
    if interface is None:
        interface = {}

    if interface.get("class") != HID_CLASS:
        return

    interface_number = interface.get("number")
    protocol = interface.get("protocol", 0)

    print(f"\naddr={addr} endpoint=0x{endpoint_address:02x} iface={interface_number} "
          f"protocol=0x{protocol:02x}  ({len(reports)} reports)")

    if raw_only:
        for report in reports:
            print(" ", report.hex())
        return

    if protocol == 0x01:
        typed_text, events = decode_keyboard_reports(reports)
        if verbose:
            for modifiers, keys in events:
                key_hex_list = []
                for key in keys:
                    key_hex_list.append(hex(key))
                print("   mods=%-20s keys=%s" % (modifiers, key_hex_list))
        print("  reconstructed text:", repr(typed_text))

    elif protocol == 0x02:
        events = decode_mouse_reports(reports)
        for pressed, dx, dy, wheel in events:
            if pressed or dx != 0 or dy != 0 or wheel != 0:
                if pressed:
                    pressed_text = pressed
                else:
                    pressed_text = "-"
                print(f"   buttons={pressed_text} dx={dx:+d} dy={dy:+d} wheel={wheel:+d}")

    else:
        print("  (non-boot-protocol HID interface; showing raw reports)")
        previous_report = None
        for report in reports:
            if report != previous_report:
                print(" ", report.hex())
            previous_report = report


def analyze(path, endpoint_filter=None, raw_only=False, verbose=False):
    packets = load_packets(path)
    transactions = group_into_transactions(packets)
    devices = find_devices(transactions)

    reports_by_endpoint = {}
    for t in transactions:
        if t.kind == "IN":
            key = (t.addr, t.endpoint)
            if key not in reports_by_endpoint:
                reports_by_endpoint[key] = []
            reports_by_endpoint[key].append(t.data)

    print(f"{len(packets)} USB packets -> {len(transactions)} transactions, "
          f"{len(devices)} device address(es): {sorted(devices.keys())}\n")

    device_addresses = sorted(devices.keys())
    for addr in device_addresses:
        print_device(devices[addr])

    print("=== HID endpoint reports ===")
    endpoint_keys = sorted(reports_by_endpoint.keys())
    for addr, endpoint_number in endpoint_keys:
        if endpoint_filter is not None and endpoint_number != endpoint_filter:
            continue
        reports = reports_by_endpoint[(addr, endpoint_number)]
        dev = devices.get(addr)
        print_hid_endpoint(dev, addr, endpoint_number, reports, raw_only, verbose)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("packets_file", help="path to the .txt file created by extract_usb_packets.sh")
    parser.add_argument("--endpoint", type=int, default=None, help="restrict to this endpoint number")
    parser.add_argument("--raw", action="store_true", help="dump raw report hex only, skip decoding")
    parser.add_argument("--verbose", action="store_true", help="print per-report modifier/keycode detail")
    args = parser.parse_args()

    analyze(args.packets_file, endpoint_filter=args.endpoint, raw_only=args.raw, verbose=args.verbose)


if __name__ == "__main__":
    sys.exit(main())
