# HYCTEC Breakdown
# Copyright 2026 team-orangeBlue. Some rights reserved.
# Licensed under the GNU General Public License v3

# Code to decrypt the flow from and to the CopyKey cloner on USB.
# To simplify input, use tshark after capturing on USB.
# 1. Set a filter of `usb.capdata`. Additionally, to filter for host/cloner messages only, you can set the USB sender filter to =="host" and !="host"
# 2. Export the visible packets
# 3. Use tshark: `tshark -Y "usb.capdata" -T fields -e usb.capdata -r USBpacket.pcapng > USBdata.txt`

import binascii
def tsx(a, b): # Two String XOR
    c=bytearray()
    aa=binascii.unhexlify(a)
    bb=binascii.unhexlify(b)
    for x in range(len(aa)):
        c.append(aa[x]^bb[x])
    return binascii.hexlify(c).decode()

def permute_bits(byte, order):
    out = 0
    for i, src_bit in enumerate(order):
        out |= ((byte >> src_bit) & 1) << (len(order) - 1 - i)
    return out

# Checks counted from bytes enumerated from 0
# WARNING: incorrect bit permutation at byte 1
# Decrypted: b1
#  Expected: 4b
# Decrypted: 81
#  Expected: 41
# Decrypted: f5
#  Expected: 7b
# Decrypted: 90
#  Expected: 42
# WARNING: incorrect bit permutation at byte 25
# Decrypted: 28
#  Expected: 88
# Decrypted: 42
#  Expected: 24
# WARNING: incorrect bit permutation at byte 35
# Decrypted: 31
#  Expected: 0b
# Decrypted: 0b
#  Expected: 85
# WARNING: incorrect bit permutation at byte 50
# Decrypted: c1
#  Expected: 61
# WARNING: incorrect bit permutation at byte 55
# Decrypted: 72
#  Expected: 2e
# Decrypted: 13
#  Expected: 07
# Decrypted: cc
#  Expected: f0
# Decrypted: 04
#  Expected: 10


def cb(arr): # Cipher block
    # Step 1: XOR by last byte
    for a in arr:
        LBX = 0x00
        WS = binascii.unhexlify(a)
        WSX = bytearray()
        for x in range(len(WS)):
            WSX.append(WS[x]^LBX)
            LBX = WS[x]
        # Step 2: Deobfuscate
        # Count from 1
        # Odd bytes: Do bitwise criss-cross for 2 bits
        # Even bytes: flip semibytes
        WSO = bytearray()
        for x in range(len(WSX)):
            tbX = 0
            tbA = WSX[x]
            if (x+1)%2:
                # I have no ideas
                if tbA & 0x80: tbX |= 0x40
                if tbA & 0x40: tbX |= 0x80
                if tbA & 0x20: tbX |= 0x10
                if tbA & 0x10: tbX |= 0x20
                if tbA & 0x8: tbX |= 0x4
                if tbA & 0x4: tbX |= 0x8
                if tbA & 0x2: tbX |= 0x1
                if tbA & 0x1: tbX |= 0x2
            else:
                tbX = permute_bits(tbA, [7,2,1,0,3,6,5,4])
            WSO.append(tbX)
        # Step 3: do global XOR
        key=("1008066106700a02a555"*7)[:128]
        WSO=binascii.unhexlify(tsx(key, binascii.hexlify(WSO).decode()))
        WSOF=bytearray()
        # Step 4: do bit permutation based on positional patterns
        for x in range(len(WSO)):
            tbX = WSO[x]
            if x==2:
                tbX = permute_bits(tbX, [6,3,0,1,2,7,4,5])
                WSOF.append(tbX)
            elif (x>=9 and (x-9)%6 == 0): # Exception rule
                tbX = permute_bits(tbX, [3,7,6,2,5,1,4,0])
                WSOF.append(tbX)
            else:
                WSOF.append(tbX)
        print(binascii.hexlify(WSOF).decode())
    return 
