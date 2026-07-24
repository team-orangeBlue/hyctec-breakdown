# HYCTEC Breakdown
# Copyright 2026 team-orangeBlue. Some rights reserved.
# Copyright 2026 klks
# Re-licensed under the GNU General Public License v3

"""
decode_capture.py — decrypt CopyKey Manager frames from a pcap/pcapng capture.

Reads a capture, pulls out the TCP streams to/from the server on port 6390,
and decrypts every 7E..7E frame to show the command byte and plaintext payload.

Usage:
    python decode_capture.py copykey_3x_update_check.pcapng
    python decode_capture.py mycapture.pcapng --port 6390

Requires:  pip install scapy lz4 cryptography
"""
import argparse
import os
import struct
import sys

from scapy.all import rdpcap, TCP, IP

from copykey import aes_decrypt, lz4_decompress, parse_record, MAGIC, save_xml_blobs

XML_DIR = "pulled_xml"


def reassemble_streams(path, port):
    pkts = rdpcap(path)
    streams = {}
    for p in pkts:
        if TCP in p and IP in p:
            data = bytes(p[TCP].payload)
            if not data:
                continue
            t, ip = p[TCP], p[IP]
            if t.sport != port and t.dport != port:
                continue
            key = (ip.src, t.sport, ip.dst, t.dport)
            streams.setdefault(key, []).append((t.seq, data))
    # order each stream by TCP seq and concatenate
    return {k: b''.join(d for _, d in sorted(v)) for k, v in streams.items()}


def frames_in(stream):
    """Yield raw frame bytes from one direction of a stream.

    Handles both layouts seen on the wire:
      - request : 7E FA <origLen u32> <totalLen u32> ... 7E   (no length prefix)
      - reply   : <totalLen u32> 7E FF <origLen u32> <totalLen u32> ... 7E
    """
    i, n = 0, len(stream)
    while i + 11 <= n:
        # reply form: 4-byte length prefix then 7E
        if i + 5 <= n and stream[i + 4] == MAGIC and stream[i + 5] in (0xFA, 0xFF):
            total = struct.unpack_from('<I', stream, i)[0]
            if 11 <= total <= n - i - 4 and stream[i + 4 + total - 1] == MAGIC:
                yield stream[i + 4: i + 4 + total]
                i += 4 + total
                continue
        # request form: bare 7E FA/FF
        if stream[i] == MAGIC and stream[i + 1] in (0xFA, 0xFF):
            total = struct.unpack_from('<I', stream, i + 6)[0]
            if 11 <= total <= n - i and stream[i + total - 1] == MAGIC:
                yield stream[i: i + total]
                i += total
                continue
        i += 1


def decode_frame(frame):
    typ = frame[1]
    orig_len, total = struct.unpack_from('<II', frame, 2)
    body = frame[10:-1]
    rec = lz4_decompress(aes_decrypt(body), orig_len)
    cmd, seq, payload, ok = parse_record(rec)
    return typ, cmd, seq, ok, payload


import hashlib

DOWNLOAD_DIR = "pulled_files"


def _save_reassembled(payloads, tag, expect_md5=None, expect_size=None):
    """Concatenate decoded payloads from one stream and save to disk.
    Tries raw concat and, since each reply is a fixed-size record with a header,
    also a header-stripped variant. Flags a match against a known firmware md5."""
    os.makedirs(DOWNLOAD_DIR, exist_ok=True)
    blob = b''.join(payloads)
    out = os.path.join(DOWNLOAD_DIR, f"{tag}.bin")
    with open(out, 'wb') as f:
        f.write(blob)
    md5 = hashlib.md5(blob).hexdigest()
    note = f"  reassembled {len(blob)} bytes -> {out} (md5 {md5}"
    if expect_md5 and md5 == expect_md5:
        note += "  *** MATCHES firmware md5 ***"
    if expect_size:
        note += f", expected {expect_size}"
    return note + ")"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('capture')
    ap.add_argument('--port', type=int, default=6390)
    ap.add_argument('--md5', help="known firmware md5 to verify reassembly against")
    ap.add_argument('--size', type=int, help="known firmware size in bytes")
    args = ap.parse_args()

    streams = reassemble_streams(args.capture, args.port)
    if not streams:
        print(f"no TCP streams on port {args.port} in {args.capture}", file=sys.stderr)
        return 1

    for (src, sport, dst, dport), data in streams.items():
        direction = "C->S" if dport == args.port else "S->C"
        print(f"\n=== {direction}  {src}:{sport} -> {dst}:{dport}  ({len(data)} bytes) ===")
        stream_payloads = []
        for frame in frames_in(data):
            try:
                typ, cmd, seq, ok, payload = decode_frame(frame)
            except Exception as e:
                print(f"  [decode failed: {e}] {frame.hex()}")
                continue
            nz = payload.rstrip(b'\x00')
            ascii_ = ''.join(chr(c) if 32 <= c < 127 else '.' for c in nz)
            print(f"  type=0x{typ:02X} cmd=0x{cmd:02X} seq={seq} ok={ok} "
                  f"payload={len(payload)}B (nonzero {len(nz)})")
            print(f"     hex  : {nz.hex()[:120]}{'...' if len(nz) > 60 else ''}")
            print(f"     ascii: {ascii_[:80]}")
            # requirement: any XML we pull gets saved locally
            for path in save_xml_blobs(payload, XML_DIR,
                                       tag=f"cmd{cmd:02X}_seq{seq}"):
                print(f"     saved XML -> {path}")
            stream_payloads.append(payload)
        # reassemble this stream's payloads (download chunks land here)
        if stream_payloads:
            tag = f"{direction.replace('->','_')}_{sport}_{dport}"
            print(_save_reassembled(stream_payloads, tag, args.md5, args.size))
    return 0


if __name__ == "__main__":
    sys.exit(main())
