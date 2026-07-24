# HYCTEC Breakdown
# Copyright 2026 team-orangeBlue. Some rights reserved.
# Licensed under the GNU General Public License v3

"""
fakeserver.py - impersonate client.copykey.hyctec.cn:6390 so the CopyKey Manager
app thinks the plugged-in cloner has a firmware update waiting. The app then
downloads the "update" from us and pushes it over USB, where we sniff it.

Setup:
  1. Add to C:\Windows\System32\drivers\etc\hosts (as Administrator):
         127.0.0.1  client.copykey.hyctec.cn
  2. Add `--fw` argument with the firmware you want to serve. This file **must** be encrypted for your serial number - the script will NOT encrypt it on its own!

"""

import argparse
import hashlib
import logging
import os
import socket
import socketserver
import struct
import threading
import time

from copykey import build_frame, parse_frame, MAGIC

log = logging.getLogger("fakeserver")


# ---------- config the caller sets before start() ----------
class Config:
    fw_path       = "firmware.bin"          # bytes we serve as the "update"
    fw_md5_hex    = None                    # override header MD5 (else md5(fw))
    # -- fields we ECHO back if the request omits them, or forge if it hasn't
    #    been received yet (e.g. an X100 that we haven't sniffed one 0x81 from):
    default_cfg      = bytes.fromhex("55003200")
    default_marker   = 0x15
    default_serial   = bytes.fromhex("51323037363138")           # 7 ASCII chars, right-pad NULs
    # -- 8-byte "firmware product/family ID" that goes in 0x81 reply [6:14].
    #    The real server just ECHOES what the app sent in the 0x81 request at
    #    [16:24]. Leave `override_product_id = None` to echo (safe default);
    #    set to 8 raw bytes only if the app turns out to also do a version
    #    comparison here and needs a bumped value to trigger the prompt.
    #    NOTE: this is NOT the per-device "630..." firmware token — that's
    #    handled at runtime in FakeServer.srv_token() and needs no config.
    override_product_id = None                    # or e.g. bytes.fromhex("1304260021200002")
    # -- GBK description shown in the update prompt (Simplified Chinese)
    description      = "测试固件（伪造服务器）"
    # -- datetime displayed in the prompt (year/month/day/hh/mm/ss)
    show_date        = (2026, 7, 4, 12, 0, 0)


CFG = Config()


# ---------- codec helpers ----------
def _next_seq():
    _next_seq.n += 1
    return _next_seq.n
_next_seq.n = 0


def send_reply(sock, cmd, payload):
    """Wrap payload in a CopyKey frame, prefix with u32 LE total, send."""
    seq = _next_seq()
    frame = build_frame(cmd, seq, payload)
    sock.sendall(struct.pack('<I', len(frame)) + frame)
    log.debug("TX cmd=0x%02X seq=%d payload=%dB frame=%dB",
              cmd, seq, len(payload), len(frame))


def recv_request(sock, timeout=30.0):
    """Read exactly one C2S frame from the socket. Returns (cmd, seq, payload, ok)."""
    sock.settimeout(timeout)
    buf = bytearray()
    # header is 10 bytes: 7E FA + origLen(4) + total(4). Then body + 0x7E trailer.
    while len(buf) < 10:
        chunk = sock.recv(4096)
        if not chunk:
            raise ConnectionError("client closed before header")
        buf.extend(chunk)
    if buf[0] != MAGIC or buf[1] != 0xFA:
        raise ValueError(f"bad magic {buf[:2].hex()}")
    _orig, total = struct.unpack_from('<II', buf, 2)
    while len(buf) < total:
        chunk = sock.recv(65536)
        if not chunk:
            raise ConnectionError("client closed mid-frame")
        buf.extend(chunk)
    frame = bytes(buf[:total])
    return parse_frame(frame)


# ---------- reply builders ----------
def reply_82_no_update(req_payload: bytes) -> bytes:
    """0x82 reply saying 'no app update'. 173 B, mostly zeros; echo date/version."""
    reply = bytearray(173)
    reply[0] = 0x01                              # status ok
    reply[1:5] = struct.pack('<I', 0x62)         # length-like field seen on wire
    reply[5] = 0x82                              # cmd echo
    reply[6:10]  = req_payload[16:20]            # echo date
    reply[10:14] = req_payload[20:24]            # echo version
    # payload[+0x1D..] = update_available flag (u32) — leave 0 for "no update"
    return bytes(reply)


def reply_81_update_available(req_payload: bytes, fw_size: int, srv_token: bytes) -> bytes:
    """0x81 reply saying 'update available' with firmware metadata."""
    # Layout of the 0x81 REQUEST (from pcap, req has 173 B):
    #    [16:20]=date  [20:24]=version  [24:28]=cfg  [28]=marker
    #    [29:36]=serial (ASCII, 7B)     [36:44]=device firmware token
    #
    # We echo cfg/marker/serial so the app matches it to the device. We
    # advertise a NEW version/date, and hand back a fresh (or echoed) token
    # that the app will forward in the subsequent 0x27 begin-download.
    req_product = req_payload[16:24] if len(req_payload) >= 24 else b"\x00" * 8
    req_cfg     = req_payload[24:28] if len(req_payload) >= 36 else CFG.default_cfg
    req_marker  = req_payload[28:29] if len(req_payload) >= 36 else bytes([CFG.default_marker])
    req_serial  = req_payload[29:36] if len(req_payload) >= 36 else CFG.default_serial
    req_dev_tok = req_payload[36:44] if len(req_payload) >= 44 else b"\x00" * 8

    # product ID: echo from request by default, override if user set one
    product_id  = CFG.override_product_id or req_product

    # datetime fields
    y, mo, d, hh, mm, ss = CFG.show_date

    reply = bytearray(74)
    reply[0]     = 0x01
    reply[1:5]   = struct.pack('<I', 0x62)
    reply[5]     = 0x81
    reply[6:14]  = product_id                   # 8B: family + version halves
    reply[14:18] = req_cfg
    reply[18:19] = req_marker
    reply[19:26] = req_serial
    reply[26]    = 0x01                         # 'update available' flag
    # 27..45 = zeros (18 bytes gap)
    reply[46:54] = srv_token
    reply[54:58] = struct.pack('<I', fw_size)
    reply[58:60] = struct.pack('<H', y)
    reply[60:62] = struct.pack('<H', mo)
    # 62..64 = gap (2B)
    reply[64:66] = struct.pack('<H', d)
    reply[66:68] = struct.pack('<H', hh)
    reply[68:70] = struct.pack('<H', mm)
    reply[70:72] = struct.pack('<H', ss)
    reply[72:74] = b'\x7e\x07'

    desc_gbk = CFG.description.encode('gbk', 'replace')
    return bytes(reply) + desc_gbk + b'\x00'


def reply_27_download(req_payload: bytes, fw_bytes: bytes, fw_md5: bytes) -> bytes:
    """0x27 reply: 42-byte header + full firmware body, all in one frame."""
    # 0x27 REQUEST layout (45B, from pcap):
    #    [0]=0x02  [1:5]=date  [5:9]=version
    #    [9:13]=cfg  [13]=marker  [14:21]=serial
    #    [37:45]=srv_token
    cfg    = req_payload[9:13]  if len(req_payload) >= 13 else CFG.default_cfg
    marker = req_payload[13:14] if len(req_payload) >= 14 else bytes([CFG.default_marker])
    serial = req_payload[14:21] if len(req_payload) >= 21 else CFG.default_serial
    srv_token = req_payload[37:45] if len(req_payload) >= 45 else b'\x00' * 8

    size = len(fw_bytes)
    header = (
        b'\x01' +                          # status
        struct.pack('<I', size) +          # size
        cfg +                              # 4B
        marker +                           # 1B
        serial +                           # 7B (ASCII)
        b'\x02' +                          # constant seen in pcap
        srv_token +                        # 8B
        fw_md5                             # 16B
    )
    assert len(header) == 42, f"header should be 42B, got {len(header)}"
    return header + fw_bytes


def reply_85_ack(req_payload: bytes) -> bytes:
    """0x85 finished-ack reply: 12 bytes as seen in pcap."""
    return b'\x01\x0b' + b'\x00' * 10


# ---------- per-connection handler ----------
class Handler(socketserver.BaseRequestHandler):
    def handle(self):
        peer = self.client_address
        try:
            cmd, seq, payload, ok = recv_request(self.request)
        except Exception as e:
            log.warning("recv failed from %s: %s", peer, e)
            return
        log.info("RX from %s: cmd=0x%02X seq=%d payload=%dB checksum_ok=%s",
                 peer, cmd, seq, len(payload), ok)
        log.debug("RX payload hex: %s", payload.hex())

        # dispatch
        if cmd == 0x82:
            resp = reply_82_no_update(payload)
        elif cmd == 0x81:
            fw = self.server.fw_bytes
            resp = reply_81_update_available(
                payload, fw_size=len(fw), srv_token=self.server.srv_token(payload)
            )
        elif cmd == 0x27:
            fw = self.server.fw_bytes
            md5 = self.server.fw_md5
            resp = reply_27_download(payload, fw, md5)
        elif cmd == 0x85:
            resp = reply_85_ack(payload)
        else:
            log.warning("unhandled cmd 0x%02X payload=%s", cmd, payload.hex())
            # blind-echo: reply with status=1 and an empty body so the socket
            # closes cleanly instead of hanging
            resp = b'\x01' + b'\x00' * 8

        try:
            send_reply(self.request, cmd, resp)
        except Exception as e:
            log.warning("send failed to %s (cmd 0x%02X): %s", peer, cmd, e)


class FakeServer(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True

    def __init__(self, addr, fw_bytes, fw_md5):
        super().__init__(addr, Handler)
        self.fw_bytes = fw_bytes
        self.fw_md5 = fw_md5

    def srv_token(self, req_payload):
        # If the device sent a token in 0x81, echo it; else return a fresh one.
        if len(req_payload) >= 44:
            dev_tok = req_payload[36:44]
            if dev_tok != b'\x00' * 8:
                return dev_tok
        return b'\x63\x0f\x10\x11\xf6\x30\x00\x00'   # arbitrary


# ---------- entrypoint ----------
def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--host', default='0.0.0.0', help='bind address (default: 0.0.0.0)')
    ap.add_argument('--port', type=int, default=6390)
    ap.add_argument('--fw', default=CFG.fw_path, help='firmware file to serve')
    ap.add_argument('--md5', default=None,
                    help='override header MD5 (hex, 32 chars). Default: md5(fw)')
    ap.add_argument('-v', '--verbose', action='store_true')
    args = ap.parse_args()

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format='%(asctime)s %(levelname)s %(message)s')

    with open(args.fw, 'rb') as f:
        fw_bytes = f.read()
    fw_md5 = bytes.fromhex(args.md5) if args.md5 else hashlib.md5(fw_bytes).digest()
    log.info("serving firmware %s (%d B, md5=%s, header-md5=%s)",
             args.fw, len(fw_bytes),
             hashlib.md5(fw_bytes).hexdigest(), fw_md5.hex())

    srv = FakeServer((args.host, args.port), fw_bytes, fw_md5)
    log.info("listening on %s:%d — point CopyKey Manager here via hosts file",
             args.host, args.port)
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        log.info("bye")


if __name__ == "__main__":
    main()
