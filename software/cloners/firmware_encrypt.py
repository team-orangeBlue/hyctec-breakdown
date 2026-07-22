# HYCTEC Breakdown
# Copyright 2026 team-orangeBlue. Some rights reserved.
# Licensed under the GNU General Public License v3

# Code to encrypt firmwares sent from servers to end-user devices
# Firmwares sent from the servers, both for-device and for-PC, are obfuscated. The obfuscation is done per-device and after that, globally.
# WARNING: while this code seems to work (files are identical after re-encryption, changes made in decrypted version are accurate), there may be reason to believe that it could make errors.
# For your safety, ALWAYS do a check between the original and new obfuscated firmware to make sure there are no differences in places where you did not make them.
# You risk bricking the device otherwise!

import binascii
import os
import argparse

def isPrime(n):
    for x in range(2,int(n**0.5)+1):
        if n%x==0: return False
    return True

def permute_bits(byte, order, enc=False):
    # If decrypting, take the bits given and give out them in order.
    # If encrypting. take number and place bits in order
    out = 0
    if not enc:
        for i, src_bit in enumerate(order):
            out |= ((byte >> src_bit) & 1) << (len(order) - 1 - i)
    else:
        for i, src_bit in enumerate(order):
            out |= ((byte >> (7 - i)) & 1) << src_bit
    return out
    
def tsx(a, b):
    c=bytearray()
    aa=binascii.unhexlify(a)
    bb=binascii.unhexlify(b)
    for x in range(len(aa)):
        c.append(aa[x]^bb[x])
    return binascii.hexlify(c).decode()

def tsx_cyclic(data_bytes, key_hex):
    """
    Performs a cyclic bitwise XOR between data_bytes and a repeating hex key string.
    """
    key_bytes = binascii.unhexlify(key_hex)
    key_len = len(key_bytes)
    
    output = bytearray(len(data_bytes))
    for i in range(len(data_bytes)):
        output[i] = data_bytes[i] ^ key_bytes[i % key_len]
    return bytes(output)

def deviceKdf(serial_bytes):
    key = bytearray(20)
    for byte in range(10):
        for bit in range(7, -1, -1):
            if (serial_bytes[byte] >> bit) & 1:
                for x in range(byte, byte+10):
                    key[x] ^= 1 << bit
    return bytes(key)

forced_primes = [0x9, 0xf, 0x15, 0x19, 0x1b, 0x21, 0x23, 0x27, 0x2d, 0x31, 0x33, 0x37, 0x39, 0x3f, 0x55, 0x5b, 0x63, 0x73, 0x77, 0x79, 0x8f, 0x99, 0x9b, 0xa1, 0xb1, 0xb7, 0xb9, 0xc9, 0xcf, 0xd5, 0xd9, 0xdb, 0xe1, 0xe7, 0xed, 0xf3, 0xf7, 0xf9, 0xff]
forced_composites = [0x2, 0x3, 0x5, 0x7, 0xb, 0xd, 0x11, 0x13, 0x17, 0x1d, 0x1f, 0x25, 0x29, 0x2b, 0x2f, 0x35, 0x3b, 0x3d, 0x43, 0x47, 0x53, 0x65, 0x6b, 0x83, 0x8b, 0x97, 0x9d, 0xb5, 0xc1, 0xc5, 0xc7, 0xd3, 0xdf, 0xe5, 0xe9, 0xef, 0xfb]
def cipher_file_block(input_filename, output_filename, deviceSerial, key="f1390fdde32ebf9b5fa71b6e15b4fb8236e0d2a8e46a1d248c0cfbd26ac736f539ed0447e0c816693fabf8a15810b5d70a248592dd052dce581ea4070b711b22"):

    if not os.path.exists(input_filename):
        print(f"Error: source file '{input_filename}' not found.")
        return None

    # Step 0: Read the raw obfuscated file payload directly into memory
    with open(input_filename, "rb") as f:
        raw_data = f.read()
    # Step 1: cyclic XOR
    mkey=(key*4)[:512] # Cyclic key is 64 bytes 
    raw_data=tsx_cyclic(raw_data, mkey)
    # Step 2: bit permutations
    WS=bytearray()
    for chunk in range(len(raw_data)//256):
        cdata = raw_data[chunk*256:(chunk+1)*256]
        for x in range(len(cdata)):
            # Supposedly we have 3 permutations:
            # 1. Permute bits if index is a prime
            # 2. Permute bits if index is an odd composite
            # 3. Permute bits if index is even and composite (everything not a 2)
            tbX = 0
            tbA = cdata[x]
            if x%2==0 and x!=2:
                tbX = permute_bits(tbA, [6,7,4,5,2,3,0,1], True)
            elif x in forced_composites:
                tbX = permute_bits(tbA, [7,2,1,0,3,6,5,4], True)
            elif x in forced_primes:
                tbX = permute_bits(tbA, [3,7,2,6,1,5,0,4], True)
            elif isPrime(x%64):
                tbX = permute_bits(tbA, [3,7,2,6,1,5,0,4], True)
            elif x & 1:
                tbX = permute_bits(tbA, [7,2,1,0,3,6,5,4], True)
            WS.append(tbX)
            
    # Compensation step
    cdata = raw_data[(chunk+1)*256:len(raw_data)]
    for x in range(len(cdata)):
        tbX = 0
        tbA = cdata[x]
        if x%2==0 and x!=2:
            tbX = permute_bits(tbA, [6,7,4,5,2,3,0,1], True)
        elif x in forced_composites:
            tbX = permute_bits(tbA, [7,2,1,0,3,6,5,4], True)
        elif x in forced_primes:
            tbX = permute_bits(tbA, [3,7,2,6,1,5,0,4], True)
        elif isPrime(x%64):
            tbX = permute_bits(tbA, [3,7,2,6,1,5,0,4], True)
        elif x & 1:
            tbX = permute_bits(tbA, [7,2,1,0,3,6,5,4], True)
        WS.append(tbX)
        
    
    # Step 3: CBC XOR
    WSX = bytearray()
    for chunk in range(len(WS)//256): # Do not add 1 to avoid thinking last chunk is 256 bytes instead of being shorter
        LBX = 0x00
        WSC=WS[chunk*256:(chunk+1)*256]
        for x in range(len(WSC)):
            WSX.append(WSC[x]^LBX)
            LBX = WSC[x]^LBX
     
    # Compensation step
    LBX = 0x00
    WSC=WS[(chunk+1)*256:len(WS)]
    for x in range(len(WSC)):
        WSX.append(WSC[x]^LBX)
        LBX = WSC[x]^LBX
    # Step 4: Protect per-device
    dkey = (deviceKdf(binascii.unhexlify(deviceSerial))*13)[:256] # function returns bytes
    for byte in range(len(WSX)):
        WSX[byte] ^= dkey[byte%256]
    
    
    if output_filename:
        with open(output_filename, "wb") as f_out:
            f_out.write(WSX)
        print(f"[+] Reencrypted binary saved successfully to: {output_filename}")

    return
    
parser = argparse.ArgumentParser(prog='CopyKey firmware obfuscator', description='Copykey cloner firmware binary obfuscation utility')
parser.add_argument('inputFile')
parser.add_argument('deviceSerial')
parser.add_argument('--outputFile')
parser.add_argument('--key')
args = parser.parse_args()
resName=''
if args.outputFile: resName=args.outputFile
else: resName=args.inputFile+'.enc'
if args.key:
    cipher_file_block(args.inputFile, resName, args.deviceSerial, args.key)
else:
    cipher_file_block(args.inputFile, resName, args.deviceSerial)
