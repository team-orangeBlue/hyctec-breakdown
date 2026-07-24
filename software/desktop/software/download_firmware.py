# HYCTEC Breakdown
# Copyright 2026 team-orangeBlue. Some rights reserved.
# Copyright 2026 klks
# Re-licensed under the GNU General Public License v3

"""
download_firmware.py — attempt the CopyKey Manager update download, with heavy logging.

Pipeline (reverse-engineered, see COMMANDS.md):
  1. cmd 0x82  update-check        (fully known)  -> version/size/date/firmware MD5
  2. cmd 0x27  begin-download (45B) -> file id / total size / (maybe first chunk)   [best-guess]
  3. cmd 0x2A  chunk (17B: key+fileId+offset) in a loop -> reassemble -> verify MD5 [best-guess]

Steps 2-3 are reconstructed statically and NOT yet confirmed on the wire, so this script:
  * defaults to a DRY RUN: it only does step 1 and PRINTS the exact step-2 request it would send.
  * with --download it actually sends steps 2-3, logging every frame (tx + rx, raw + decoded)
    to ./download_debug.log and saving every reply + the reassembled image to ./pulled_files/.

Run the DRY RUN first, paste me download_debug.log, and we refine the field offsets from real bytes
before hammering the server. Requires: pip install lz4 cryptography
"""
import argparse
import hashlib
import os
import struct
import sys
import time

import copykey
from copykey import CopyKeyClient, HOST, PORT, parse_update_response, save_xml_blobs

OUT_DIR = "pulled_files"
LOG_PATH = "download_debug.log"
PRODUCT_ID = struct.pack('<II', 0x00240910, 0x01002019)

_logf = None


def log(msg=""):
    print(msg)
    if _logf:
        _logf.write(msg + "\n")
        _logf.flush()


def hexdump(data: bytes, indent="    ", maxlen=512):
    if data is None:
        log(indent + "<none>")
        return
    shown = data[:maxlen]
    for i in range(0, len(shown), 16):
        chunk = shown[i:i + 16]
        hexs = ' '.join(f'{b:02x}' for b in chunk)
        asci = ''.join(chr(b) if 32 <= b < 127 else '.' for b in chunk)
        log(f"{indent}{i:04x}  {hexs:<48}  {asci}")
    if len(data) > maxlen:
        log(f"{indent}... (+{len(data) - maxlen} more bytes, {len(data)} total)")


def build_check_payload(exe_path, flag=0x02):
    token = hashlib.md5(open(exe_path, 'rb').read()).digest()
    return token + PRODUCT_ID + b'\x00' * 20 + bytes([flag]) + b'\x00' * 128


def build_begin_download_payload(reply_payload: bytes, kind="soft", device_id=None) -> bytes:
    """cmd 0x27 begin-download, 45 bytes. Two variants (sub_4FA820):
      kind='soft'  (loc_4FA9F8, flag 1, msg 0xFBE): SOFTWARE update — no device id, no device
                   lookup. Works without the hardware.
      kind='fw'    (loc_4FA8E5, flag 2, msg 0xFD9): DEVICE FIRMWARE — embeds an 8-byte device id at
                   [9:17]. Normally read from the attached device; here it can be supplied via
                   device_id (e.g. an id the device's owner gave you). The server validates it,
                   so only a real, server-known id will be accepted.
    Field sources relative to the 0x82 reply, base = payload[1:] (the handler base)."""
    b = reply_payload[1:]
    p = bytearray(45)
    if kind == "fw":
        # Real X5 layout (from copykey_update_x5.pcapng):
        #   [0]=2 [1:5]=date [5:9]=version [9:13]=cfg(4c002200) [13]=0x0b
        #   [14:14+len]=ascii serial ("Q140430") [37:45]=token (63021011 + 4 varying bytes)
        # device_id (8 bytes) here = the trailing token; serial/cfg come from build_fw_begin().
        p[0] = 0x02
        p[1:5] = b[0x2D:0x31]                # date
        p[5:9] = b[0x31:0x35]                # version
    else:  # soft
        p[0] = 0x01
        p[1:9] = PRODUCT_ID                  # product id
        p[0x1D:0x21] = b[0x2D:0x31]
        p[0x21:0x25] = b[0x31:0x35]          # version
    return bytes(p)


def build_fw_begin(reply_payload, serial: bytes, token: bytes) -> bytes:
    """cmd 0x27 firmware begin-download, real X5 layout. serial=ASCII device serial,
    cfg=4-byte device config word, token=8-byte trailing token (e.g. from the device/0x81)."""
    p = bytearray(build_begin_download_payload(reply_payload, kind="fw"))
    p[9:21] = serial[:12].ljust(12, b'\x00')
    p[37:45] = token[:8].ljust(8, b'\x00')
    return bytes(p)


def build_fw_detail(reply_payload, serial: bytes, token: bytes) -> bytes:
    """cmd 0x81 firmware-detail request (173B), real X5 layout:
    [0:16]=token md5 (here the firmware/check md5) [16:20]=date [20:24]=version
    [24:28]=cfg [28]=0x0b [29:29+len]=serial [36:44]=token."""
    b = reply_payload[1:]
    p = bytearray(173)
    p[0:16] = reply_payload[30:46]           # firmware md5 from the 0x82 reply
    p[16:20] = b[0x2D:0x31]                   # date
    p[20:24] = b[0x31:0x35]                   # version
    p[24:36] = serial[:12].ljust(12, b'\x00')
    p[36:44] = token[:8].ljust(8, b'\x00')
    return bytes(p)


def derive_key(file_id: bytes) -> bytes:
    """Best-guess of the [ebx+2F] key derivation at 0x525A.. : two 4-byte big-endian halves of
    file-id bytes, XORed. UNCONFIRMED — the live 0x2A exchange will tell us if this is right."""
    if len(file_id) < 8:
        file_id = file_id.ljust(8, b'\x00')
    hi = int.from_bytes(file_id[0:4], 'big')
    lo = int.from_bytes(file_id[4:8], 'big')
    return struct.pack('<I', (hi ^ lo) & 0xFFFFFFFF)


def build_chunk_payload(key4: bytes, file_id: bytes, offset: int) -> bytes:
    """cmd 0x2A, 17 bytes: key(4) + fileId(8) + offset(4) + 0."""
    return key4 + file_id[:8].ljust(8, b'\x00') + struct.pack('<I', offset) + b'\x00'


def log_exchange(tag, client, cmd, seq, payload, ok):
    log(f"\n--- {tag}: cmd=0x{cmd:02X} seq={seq} checksum_ok={ok} payload={len(payload)}B ---")
    log("  TX frame (raw on wire):")
    hexdump(client.last_tx)
    log("  RX frame (raw on wire):")
    hexdump(client.last_rx)
    log("  RX decoded payload:")
    hexdump(payload)


def main():
    global _logf
    ap = argparse.ArgumentParser()
    ap.add_argument('--host', default=HOST)
    ap.add_argument('--port', type=int, default=PORT)
    ap.add_argument('--exe', default="CopyKey Manager V2.0.1.0.230223.exe")
    ap.add_argument('--download', action='store_true',
                    help="actually send begin-download + chunk loop (default: dry run)")
    ap.add_argument('--max-chunks', type=int, default=4,
                    help="safety cap on chunk requests (default 4 — raise once confirmed)")
    ap.add_argument('--chunk-step', type=int, default=0,
                    help="offset increment per chunk; 0 = use returned size")
    ap.add_argument('--kind', choices=['soft', 'fw'], default='soft',
                    help="soft = software update (no device needed); fw = device firmware")
    ap.add_argument('--device-serial', default=None,
                    help="device serial string for --kind fw (e.g. an owner-provided 'Q140430')")
    ap.add_argument('--fw-token', default=None,
                    help="8-byte token for the 0x27 begin-download, hex (e.g. 63021011f930ad2e)")
    ap.add_argument('--fw-token-detail', default=None,
                    help="8-byte token for the 0x81 firmware-detail, hex (differs from --fw-token; "
                         "defaults to --fw-token if omitted)")
    args = ap.parse_args()

    #cfg = bytes.fromhex(args.device_cfg.replace(' ', '')) if args.device_cfg else b''
    sn = bytes.fromhex(args.device_serial.replace(' ','')) if args.device_serial else b''
    token = bytes.fromhex(args.fw_token.replace(' ', '')) if args.fw_token else b''
    token81 = bytes.fromhex(args.fw_token_detail.replace(' ', '')) if args.fw_token_detail else token
    if args.kind == 'fw' and not args.device_serial:
        print("note: --kind fw needs --device-serial; without them the server"
              "will refuse to provide a file. These are device-specific values, not a single id.")

    os.makedirs(OUT_DIR, exist_ok=True)
    _logf = open(LOG_PATH, 'w', encoding='utf-8')
    log(f"# download_firmware.py  {time.ctime()}  host={args.host}:{args.port}")

    c = CopyKeyClient(args.host, args.port)
    log(f"connecting to {args.host}:{args.port} ...")
    c.connect()
    srv_token=""
    try:
        # ---- step 1: update check (known-good) ----
        chk = build_check_payload(args.exe)
        cmd, seq, payload, ok = c.request(0x82, chk)
        log_exchange("STEP 1  update-check (0x82)", c, cmd, seq, payload, ok)
        log("  TX frame (decrypted):")
        hexdump(chk)
        info = parse_update_response(payload)
        log("\n  parsed: " + ", ".join(f"{k}={v!r}" for k, v in info.items()))
        with open(os.path.join(OUT_DIR, "update_check_reply.bin"), 'wb') as f:
            f.write(payload)
        if not info.get("update_available"):
            log("\nno update available -> nothing to download. Done.")
            #return
        fw_md5 = info["firmware_md5"]
        fw_size = info["firmware_size"]

        # ---- step 2: build begin-download (0x27) ----
        if args.kind == 'fw':
            begin = build_fw_begin(payload, sn or '', token)
        else:
            begin = build_begin_download_payload(payload, kind='soft')
        log(f"\nSTEP 2  begin-download (0x27, kind={args.kind}) request payload (45B):")
        hexdump(begin)
        if not args.download:
            log("\n[dry run] not sending. Re-run with --download to attempt.")
            return

        # ---- step 1b: 0x85 ack -> server replies 01 0b ----
        cmd, seq, ack, ok = c.request(0x85, PRODUCT_ID + b'\x02')
        #log_exchange("STEP 1b  0x85 ack", c, cmd, seq, ack, ok)

        # ---- firmware needs the 0x81 firmware-detail step first ----
        if args.kind == 'fw':
            det = build_fw_detail(payload, sn or '', token81)
            cmd, seq, dr, ok = c.request(0x81, det)
            log_exchange("STEP 1c  0x81 firmware-detail", c, cmd, seq, dr, ok)
            # the server returns the 0x27 download token (offset 46) + firmware size (offset 54)
            if dr[27] or len(dr)>74: # not zero, passed
                import binascii
                srv_token = dr[46:54] if not token else token
                srv_size = struct.unpack_from('<I', dr, 54)[0]
                log(f"  server-issued 0x27 token = {srv_token.hex()}  firmware size = {srv_size}")
                begin = build_fw_begin(payload, sn or '', srv_token)
                log("  rebuilt 0x27 request with server-issued token:")
                hexdump(begin, maxlen=64)
            else:
                log("failed: server rejected data or sent a short payload")
                if not token: return
                log("proceeding with provided DL token")
        # ---- step 2: begin-download (0x27) -> ONE big frame = the file ----
        # The real client uses a fresh TCP connection per request, and the download arrives on its
        # own connection. Reconnect so the server replies to 0x27 (reusing the socket hangs recv).
        log("\n  reconnecting for the download request (per-request connection) ...")
        c.close()
        c.connect()
        log("  sending 0x27, waiting for firmware frame (can be large/slow) ...")
        if _logf:
            _logf.flush()
        cmd, seq, dl, ok = c.request(0x27, begin)
        log(f"\n--- STEP 2  download (0x27): cmd=0x{cmd:02X} seq={seq} ok={ok} payload={len(dl)}B ---")
        log("  TX frame (raw):"); hexdump(c.last_tx, maxlen=96)
        log(f"  RX frame: {len(c.last_rx)} bytes on wire (decoded payload {len(dl)} B)")
        if len(dl) <= 2:
            log(f"\n  !! rejected (status {dl[0] if dl else None}). 0x03 = wrong version given "
                "; 0x04 = wrong sn given.")
            return

        # download payload = header + file. The header length differs (software=29, firmware=42),
        # but [1:5] is always the file size, so the file is the trailing `size` bytes.
        def u32(buf, off):
            return struct.unpack_from('<I', buf, off)[0]
        size = u32(dl, 1)
        hdr_len = len(dl) - size
        body = dl[hdr_len:]
        log(f"  payload={len(dl)}  size field={size}  header={hdr_len}B  file={len(body)}B "
            f"(0x82 said {fw_size})")
        log(f"  header bytes: {dl[:hdr_len].hex()}")

        got = hashlib.md5(body).hexdigest()
        # the image's OWN md5 is the last 16 bytes of the download header (works for soft + fw).
        # (fw_md5 from the 0x82 reply is the SOFTWARE update's md5 — not this image's.)
        embedded_md5 = dl[hdr_len - 16:hdr_len].hex() if hdr_len >= 16 else ''
        ext = ".exe" if body[:2] == b"MZ" else (".zip" if body[:2] == b"PK" else ".bin")
        name = f"CopyKey_{args.kind}_{args.device_serial or info['sw_version']}{"_"+srv_token.hex() if srv_token else None}{ext}"
        out = os.path.join(OUT_DIR, name)
        with open(out, 'wb') as f:
            f.write(body)
        log(f"\n  saved -> {out}")
        log(f"  md5(file)      = {got}")
        log(f"  header md5      = {embedded_md5}  -> {'*** MATCH ***' if got == embedded_md5 else 'MISMATCH'}")
        log(f"  (0x82 sw md5 was {fw_md5} — different artifact, ignore)")
        log(f"  type: {'PE/MZ executable' if body[:2]==b'MZ' else 'raw/encrypted (' + body[:4].hex() + ')'}")
    finally:
        c.close()
        log(f"\nlog written to {LOG_PATH}; raw replies in {OUT_DIR}/")
        if _logf:
            _logf.close()


if __name__ == "__main__":
    main()
