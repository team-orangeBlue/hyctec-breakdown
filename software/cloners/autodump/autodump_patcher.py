# HYCTEC Breakdown
# Copyright 2026 team-orangeBlue. Some rights reserved.
# Licensed under the GNU General Public License v3

# Script to patch CopyKEY firmware binaries to enable autodumping over USB
# All firmwares have the instructions to copy register data to R1 that looks like this: 01 68 CD F8 0B 10 41 68 CD F8 ...
# This can be used to locate the LDR to r5 above and patch instructions as necessary

import argparse
import binascii

ap = argparse.ArgumentParser()
ap.add_argument('inputFile', help='Firmware file to patch')
ap.add_argument('--outputFile', help='Firmware file to write patched version to')
args = ap.parse_args()

patchBinaryName = ''
if args.outputFile: patchBinaryName = args.outputFile
else: patchBinaryName = args.inputFile+'.patch'

binary=open(args.inputFile,"rb").read()
targetIns = b"\x01\x68\xCD\xF8\x0B\x10\x41\x68\xCD\xF8\x0F\x10"
if targetIns in binary:
    insOffset = binary.index(targetIns) - 22
else:
    print("Could not find matching instructions!\nPlease share your firmware and open an issue")
    print("Are you sure your firmware is decrypted?")
    quit()
print("Found matching instructions at", hex(insOffset).replace('0x',''))
# Backtrack 22 bytes for instructions
print(binascii.hexlify(binary[insOffset:insOffset+48]).decode())
patchBinaryBytes = bytearray(binary)
# Replace
patchIns = b"\x01\x20\x8D\xF8\x02\x00\x43\xF2\xB4\x34\xC2\xF2\x00\x04\x20\x68\x00\xBF\x00\xBF\x00\xBF\x01\x68\xCD\xF8\x0B\x10\x41\x68\xCD\xF8\x0F\x10\x81\x68\xCD\xF8\x13\x10\x00\xF1\x0C\x00\x20\x60\x00\x24"
for x in range(len(patchIns)):
    patchBinaryBytes[insOffset+x] = patchIns[x]
# Write
patchBinary=open(patchBinaryName,"wb")
patchBinary.write(patchBinaryBytes)
patchBinary.close()

print("Patch complete\nOutput written to", patchBinaryName)