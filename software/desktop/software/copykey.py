# HYCTEC Breakdown
# Copyright 2026 team-orangeBlue. Some rights reserved.
# Copyright 2026 klks
# Re-licensed under the GNU General Public License v3

"""
copykey.py — client library for the CopyKey Manager binary protocol.

Reverse-engineered from "CopyKey Manager V2.0.1.0.230223.exe".
Server: client.copykey.hyctec.cn:6390 (raw TCP, no TLS — libcurl CONNECT_ONLY).

Wire format
-----------
Outer frame (both directions):
    7E FA | u32 origLen | u32 compLen | AES(LZ4_block(record)) | 7E
      where the AES blob length = frameLen - 11 (multiple of 16).

Inner record (plaintext, before LZ4):
    cmd(1) | seq(4 LE) | recLen(4 LE) | payload | checksum16(2 LE)
      recLen     = len(payload) + 11
      checksum16 = sum(record[:-2]) & 0xFFFF
      payload    = a serialized protobuf message (per-command schema)

Crypto: AES-128-CBC + PKCS7, embedded default key/iv.
Compression: raw LZ4 block (LZ4_decompress_safe / LZ4_compress).

Requires:  pip install lz4 cryptography
"""
import hashlib
import os
import re
import socket
import struct

import lz4.block
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

# --- embedded default key/IV (from .data: unk_6589E8 / unk_6589F8) ---
KEY = bytes([0x12, 0x40, 0x15, 0x07, 0x85, 0x06, 0x92, 0x87,
             0x81, 0x19, 0x29, 0x26, 0x5C, 0x04, 0x93, 0x35])
IV  = bytes([0xE3, 0xA4, 0x79, 0x97, 0x8C, 0x16, 0x49, 0x30,
             0xBB, 0x6E, 0xF5, 0x9C, 0xA8, 0x1D, 0xCE, 0xB3])

MAGIC = 0x7E
TYPE  = 0xFA
HOST  = "client.copykey.hyctec.cn"
PORT  = 6390


# ---------------- crypto (sub_4DDF80 / sub_4DDDF0) ----------------
def aes_encrypt(data: bytes, key: bytes = KEY, iv: bytes = IV) -> bytes:
    pad = 16 - (len(data) % 16)                      # PKCS7 (full block if aligned)
    data += bytes([pad]) * pad
    enc = Cipher(algorithms.AES(key), modes.CBC(iv)).encryptor()
    return enc.update(data) + enc.finalize()


def aes_decrypt(data: bytes, key: bytes = KEY, iv: bytes = IV) -> bytes:
    dec = Cipher(algorithms.AES(key), modes.CBC(iv)).decryptor()
    pt = dec.update(data) + dec.finalize()
    pad = pt[-1] if pt else 0
    if 1 <= pad <= 16 and pt[-pad:] == bytes([pad]) * pad:   # mirror sub_4DDDF0 unpad
        return pt[:-pad]
    return pt                                                 # default-key fallback path


# ---------------- lz4 raw block (sub_4E0A80 / sub_4E0A30) ----------------
def lz4_compress(data: bytes) -> bytes:
    return lz4.block.compress(data, store_size=False)


def lz4_decompress(data: bytes, out_size: int) -> bytes:
    return lz4.block.decompress(data, uncompressed_size=out_size)


# ---------------- inner record (sub_4CFFD0 + checksum sub_4B2CE0) ----------------
def build_record(cmd: int, seq: int, payload: bytes) -> bytes:
    rec_len = len(payload) + 11
    rec = struct.pack('<BII', cmd, seq, rec_len) + payload
    rec += struct.pack('<H', sum(rec) & 0xFFFF)            # checksum16 over rec[:-2]
    return rec


def parse_record(rec: bytes):
    cmd, seq, rec_len = struct.unpack_from('<BII', rec, 0)
    payload = rec[9:rec_len - 2]
    chk = struct.unpack_from('<H', rec, rec_len - 2)[0]
    ok = (sum(rec[:rec_len - 2]) & 0xFFFF) == chk
    return cmd, seq, payload, ok


# ---------------- outer frame ----------------
def build_frame(cmd: int, seq: int, payload: bytes) -> bytes:
    rec = build_record(cmd, seq, payload)
    body = aes_encrypt(lz4_compress(rec))
    total = 11 + len(body)                                 # whole frame incl. magics
    hdr = struct.pack('<BBII', MAGIC, TYPE, len(rec), total)
    return hdr + body + bytes([MAGIC])


def parse_frame(frame: bytes):
    # A frame may arrive with a 4-byte LE length prefix (server->client replies do).
    if len(frame) >= 5 and frame[0] != MAGIC and frame[4] == MAGIC:
        n = struct.unpack_from('<I', frame, 0)[0]
        frame = frame[4:4 + n]
    if frame[0] != MAGIC or frame[-1] != MAGIC:
        raise ValueError("bad magic (need a full 7E..7E frame)")
    orig_len, total = struct.unpack_from('<II', frame, 2)
    body = frame[10:-1]                                    # = frameLen - 11
    rec = lz4_decompress(aes_decrypt(body), orig_len)
    return parse_record(rec)


def iter_frames(stream: bytes):
    """Walk one direction of a captured TCP stream, yielding decoded frames.

    Uses the header compLen, but falls back to scanning for the trailing 0x7E so
    it still works if the on-wire length field differs from the body length.
    """
    i = 0
    n = len(stream)
    while i + 11 <= n:
        if stream[i] != MAGIC or stream[i + 1] != TYPE:
            i += 1
            continue
        orig_len, comp_len = struct.unpack_from('<II', stream, i + 2)
        candidates = []
        if comp_len % 16 == 0 and i + 10 + comp_len < n and stream[i + 10 + comp_len] == MAGIC:
            candidates.append(comp_len)
        # fallback: try every 16-aligned body length terminated by 0x7E
        for blen in range(16, n - i - 10, 16):
            if i + 10 + blen < n and stream[i + 10 + blen] == MAGIC and blen not in candidates:
                candidates.append(blen)
        decoded = None
        for blen in candidates:
            frame = stream[i:i + 11 + blen]
            try:
                decoded = (frame, parse_frame(frame))
                i += 11 + blen
                break
            except Exception:
                continue
        if decoded is None:
            i += 1
            continue
        yield decoded[1]


# ---------------- update-check (cmd 0x82) response parsing ----------------
# Field layout reverse-engineered from update_form's parser (sub @0x515A..).
# The dispatcher (0x4FC883) hands the handler &payload[1] after checking status==1,
# so these offsets are relative to (payload + 1). Confirmed structurally against the
# "no update" capture (all fields zero); verify magnitudes against a real update.
def parse_update_response(payload: bytes) -> dict:
    if len(payload) < 0x4B:
        return {"status": payload[0] if payload else None, "raw_short": True}
    b = payload[1:]                                  # handler base = &payload[1]
    out = {"status": payload[0]}                     # 1 = ok
    out["code"] = struct.unpack_from('<I', payload, 1)[0]
    out["update_available"] = struct.unpack_from('<I', b, 0x19)[0] != 0
    out["firmware_md5"] = payload[30:46].hex()       # MD5 of the firmware image
    out["firmware_size"] = struct.unpack_from('<I', b, 0x35)[0]   # bytes
    # software version: 2 bytes at +0x31 shown as %X.%X.%X.%X (nibbles of 2 bytes)
    v0, v1 = b[0x31], b[0x32]
    out["sw_version"] = f"{v0 & 0xF:X}.{v0 >> 4:X}.{v1 & 0xF:X}.{v1 >> 4:X}"
    out["size_kb"] = out["firmware_size"] >> 10
    yr = struct.unpack_from('<H', b, 0x39)[0]
    mo = struct.unpack_from('<H', b, 0x3B)[0]
    dy = struct.unpack_from('<H', b, 0x3F)[0]
    hh = struct.unpack_from('<H', b, 0x41)[0]
    mm = struct.unpack_from('<H', b, 0x43)[0]
    ss = struct.unpack_from('<H', b, 0x45)[0]
    out["date"] = f"{yr:04d}-{mo:02d}-{dy:02d} {hh:02d}:{mm:02d}:{ss:02d}"
    desc = b[0x49:]
    nul = desc.find(b'\x00')
    desc = desc[:nul if nul >= 0 else len(desc)]
    # description is GB2312/GBK encoded (Simplified Chinese), not UTF-8
    out["description"] = desc.decode('gbk', 'replace')
    return out


# ---------------- local XML persistence (requirement: always keep a copy) ----------------
def _decode_xml_bytes(blob: bytes):
    """Return (text, encoding) if blob contains an XML document, else None.
    Handles UTF-8/ASCII and UTF-16 LE/BE."""
    for enc in ('utf-8', 'utf-16-le', 'utf-16-be'):
        try:
            text = blob.decode(enc)
        except Exception:
            continue
        if '<?xml' in text or re.search(r'<[A-Za-z_][\w:.\-]*[\s>/]', text):
            # trim to the xml/root extent
            start = text.find('<?xml')
            if start < 0:
                start = text.find('<')
            end = text.rfind('>')
            if start >= 0 and end > start:
                return text[start:end + 1], enc
    return None


def save_xml_blobs(blob: bytes, outdir: str, tag: str = "resource"):
    """Detect any XML inside `blob` and write a copy to outdir. Returns saved paths.

    Filenames prefer a server resource path found inside the data (e.g.
    copykey/update_info.xml -> update_info.xml); otherwise fall back to `tag`.
    Dedups by content hash so re-running won't pile up copies."""
    found = _decode_xml_bytes(blob)
    if not found:
        return []
    text, enc = found
    os.makedirs(outdir, exist_ok=True)
    # try to name it after a referenced resource path
    m = re.search(r'([A-Za-z0-9_\-]+)\.xml', text)
    base = (m.group(1) if m else tag)
    digest = hashlib.sha1(text.encode('utf-8', 'replace')).hexdigest()[:8]
    path = os.path.join(outdir, f"{base}.{digest}.xml")
    if not os.path.exists(path):
        with open(path, 'w', encoding='utf-8') as f:
            f.write(text)
    return [path]


# ---------------- transport (sub_4D9700, plain TCP) ----------------
class CopyKeyClient:
    def __init__(self, host: str = HOST, port: int = PORT, timeout: float = 90.0):
        self.host, self.port, self.timeout = host, port, timeout
        self.seq = 0
        self.sock = None
        self.last_tx = None        # raw bytes of the last frame sent
        self.last_rx = None        # raw bytes of the last frame received

    def connect(self):
        self.sock = socket.create_connection((self.host, self.port), timeout=self.timeout)

    def close(self):
        if self.sock:
            self.sock.close()
            self.sock = None

    def _recvn(self, n: int) -> bytes:
        buf = b''
        while len(buf) < n:
            chunk = self.sock.recv(n - len(buf))
            if not chunk:
                raise ConnectionError("connection closed mid-frame")
            buf += chunk
        return buf

    def _recv_frame(self) -> bytes:
        # Replies are framed as: u32 LE total | 7E FF ... 7E   (total = frame length)
        prefix = self._recvn(4)
        n = struct.unpack_from('<I', prefix, 0)[0]
        if not (0 < n < 1 << 24):
            raise ValueError(f"implausible reply length {n} (prefix {prefix.hex()})")
        frame = self._recvn(n)
        return prefix + frame

    def request(self, cmd: int, payload: bytes = b''):
        self.seq += 1
        tx = build_frame(cmd, self.seq, payload)
        self.last_tx = tx
        self.sock.sendall(tx)
        rx = self._recv_frame()
        self.last_rx = rx
        return parse_frame(rx)


if __name__ == "__main__":
    # quick self-test of the codec (no network)
    f = build_frame(0x2E, 1, b"hello-payload")
    print("frame:", f.hex())
    print("decoded:", parse_frame(f))
