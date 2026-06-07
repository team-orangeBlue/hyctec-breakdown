# HYCTEC Breakdown
# Copyright 2026 team-orangeBlue. Some rights reserved.
# Licensed under the GNU General Public License v3

# Code to decrypt the flow from and to the CopyKey cloner with port 6390.
# To simplify input, use Wireshark's "Follow TCP stream" functionality, and copy all strings into a ''' with a .split().

def decrypt_frames(hex_frames):
    """
    hex_frames: iterable of hex strings (one frame per string, may include start/end bytes)
    Returns: single hex string of concatenated decrypted payloads (headers/trailers removed)
    Assumes frame format: 7A SS SS CT C0 35 6C <payload...> A7
    Uses cyclic XOR with the recovered key (hex).
    """
    key_hex = ("58c035c6021f67141ca925dd81fc4a88a3e82fa87bbe3d2c7a8ac877e0503be"
               "04de58148272aaf2b4e0388f1e602c85b2fea032f4e644bbfaacb99df3632c6be")
    key = bytes.fromhex(key_hex)

    out = bytearray()
    for h in hex_frames:
        h = h.strip()
        if not h:
            continue
        b = bytes.fromhex(h)
        # basic sanity: must start with 0x7A and end with 0xA7
        if not (b[0] == 0x7A and b[-1] == 0xA7):
            raise ValueError("frame does not start with 0x7A and end with 0xA7")
        # header is 7 bytes: 7A SS SS CT C0 35 6C
        if len(b) < 8:
            continue  # nothing to decrypt
        payload = b[3:-1]
        if not payload:
            continue
        # cyclic XOR with key
        plain = bytes(p ^ key[i % len(key)] for i, p in enumerate(payload))
        #out.extend(plain)
        print(plain.hex())
    #return out.hex()
