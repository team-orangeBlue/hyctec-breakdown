import hid
import binascii
import crcmod

def crc_frame(hex_frame):
    crc8 = crcmod.Crc(0x101, initCrc=0xaa, xorOut=0x00, rev=False)
    crc8.update(bytes.fromhex(hex_frame))
    return hex_frame+f"{crc8.crcValue:02x}"

def tsx(a, b):
    c=bytearray()
    aa=binascii.unhexlify(a)
    bb=binascii.unhexlify(b)
    for x in range(len(aa)):
        try:
            c.append(aa[x]^bb[x])
        except IndexError:
            return binascii.hexlify(c).decode() # I do not know why this happens
    return binascii.hexlify(c).decode()

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


def cb(arr, enc):
    key=("1008066106700a02a555"*7)[:128]
    for a in arr:
        if not enc:
            LBX = 0x00
            WS = binascii.unhexlify(a)
            WSX = bytearray()
            for x in range(len(WS)):
                WSX.append(WS[x]^LBX)
                LBX = WS[x]
            # Step 3: Deobfuscate
            # Count from 1
            # Odd bytes: Do bitwise criss-cross for 2 bits
            # Even bytes: flip semibytes
            WSO = bytearray()
            for x in range(len(WSX)):
                tbX = 0
                tbA = WSX[x]
                if (x+1)%2:
                    tbX = permute_bits(tbA, [6,7,4,5,2,3,0,1], enc)
                else:
                    tbX = permute_bits(tbA, [7,2,1,0,3,6,5,4], enc)
                WSO.append(tbX)
            
            WSO=binascii.unhexlify(tsx(key, binascii.hexlify(WSO).decode()))
            WSOF=bytearray()
            for x in range(len(WSO)):
                tbX = WSO[x]
                if x==1 or x==25 or x==35 or x==49 or x==55 or (x>=9 and (x-9)%6 == 0):
                    tbX = permute_bits(tbX, [3,7,6,2,5,1,4,0], enc)
                    WSOF.append(tbX)
                elif x==2:
                    tbX = permute_bits(tbX, [6,3,0,1,2,7,4,5], enc)
                    WSOF.append(tbX)
                else:
                    WSOF.append(tbX)
            return(binascii.hexlify(WSOF).decode())
        else:
            WSO = binascii.unhexlify(a)
            WSOF=bytearray()
            for x in range(len(WSO)):
                tbX = WSO[x]
                if x==1 or x==25 or x==35 or x==49 or x==55 or (x>=9 and (x-9)%6 == 0):
                    tbX = permute_bits(tbX, [3,7,6,2,5,1,4,0], enc)
                    WSOF.append(tbX)
                elif x==2:
                    tbX = permute_bits(tbX, [6,3,0,1,2,7,4,5], enc)
                    WSOF.append(tbX)
                else:
                    WSOF.append(tbX)
            WSX=binascii.unhexlify(tsx(key, binascii.hexlify(WSOF).decode()))
            WS = bytearray()
            for x in range(len(WSX)):
                tbX = 0
                tbA = WSX[x]
                if (x+1)%2:
                    tbX = permute_bits(tbA, [6,7,4,5,2,3,0,1], enc)
                else:
                    tbX = permute_bits(tbA, [7,2,1,0,3,6,5,4], enc)
                WS.append(tbX)
            LBX = 0x00
            W = bytearray()
            for x in range(len(WS)):
                W.append(WS[x]^LBX)
                LBX = WS[x]^LBX
            return(binascii.hexlify(W).decode())

def transmit_receive(udev, payload, silent):
    sdata = bytes.fromhex(payload)
    udev.write(sdata)
    resp = dev.read(64, timeout=500)
    if not silent: print(cb([binascii.hexlify(resp).decode()], False))
    return cb([binascii.hexlify(resp).decode()], False)

for d in hid.enumerate():
    if d["vendor_id"] == 0x6300 and d["product_id"] == 0x1991:
        dpath = d["path"]
        break
else:
    raise RuntimeError("Device not found")

dev = hid.Device(path=dpath)

negotiate = "00958d84929b9c99b9d77526141d0b020500207a2f23d5d7d95069a570eca6237b62747d7a5a7a2d785c8b8987e6ad05154fe4cfd56353996bc0e0baefdfd71d39"
negotiate2 = "00958d84929b9c99b995fea87a73656c6b6e4e14414dbbb9b73e07cb1e82c84d150c1a13143414431632e5e7e988c36b7b218aa1bb0d3df705ae8ed481b1b99cb8"
askOTA = "00958c85939a9d98b8e2b7979f9680898e8babf1a4848c85939a9d98b8e2b7979f9680898e8babf1a4848c85939a9d98b8e2b7979f9680898e8babf1a4848c6642"
# In case you want to repurpose this script for your needs here is a way to manually send readable commands
# writeLF = "00"+cb([crc_frame('7a513530304b487a0000000000004944000000000000000000000513001a1b9e000000000000000000000000000000000000000000000000000000000000')+"0d"], True)
print("How many bytes to dump?")
firmware_size = int(input("If unsure, enter 262145: "))
print('''Make sure your device runs a firmware patched to allow autodumping
If it does, the serial number reported by the companion app should be incorrect and no real device details should be visible
Make sure your device has been power cycled (at least with the power button) and not connected to anything that can interface with it at a high level before you run this script

Negotiate if you do not see a prompt of "USB is connected"''')
while input("Negotiate? (enter anything if yes) "):
    for i in range(2):
        transmit_receive(dev, negotiate, True)
        transmit_receive(dev, negotiate2, True)
print("Starting autodump process")
binary=open("autodump_result.bin","wb")
for x in range(firmware_size//12):
    binary.write(binascii.unhexlify(transmit_receive(dev, askOTA, True)[22:46]))
    print(f"Reading {x*12:05X} / {firmware_size:05X}", end="\r")
print("Performing basic sanity check")
# If the dump is successful then for hopefully obvious reasons the MSPs and RVs must have appropriate bytes
binary.close() # Writable file is not really readable 
binary=open("autodump_result.bin","rb").read()
success = True
success &= binary[2] == 0 and binary[3] == 0x20
for step in range(1,32): # Check BL
    if step in [7, 8, 9, 10, 13]: continue # RFUs
    success &= binary[step*4+2] == 0 and binary[step*4+3] == 8
    
success &= binary[0x4002] == 0 and binary[0x4003] == 0x20
for step in range(1,32): # Check app
    if step in [7, 8, 9, 10, 13]: continue # RFUs
    success &= (binary[0x4000+step*4+2] == 0 or binary[0x4000+step*4+2] == 1) and binary[0x4000+step*4+3] == 8

print("MCU dumped successfully") if success else print("MCU dump may have errors! MSP and/or RVs do not check out.")
