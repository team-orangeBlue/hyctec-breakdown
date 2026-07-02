# Cloner USB

All data handled appears to be severely obfuscated. A python script to partially decrypt the payloads is present in this folder.

## Formatting

All payloads are 64 bytes in size.

As handling data without prior deobfuscation is completely pointless, the reference will be for plaintext.

### Request
```
7A] IN (payload) cc [0D

7A] - Header
IN - Instruction
(payload) - Actual data, may be zero
cc - CRC8 over entire frame before this byte; poly = 0x01, init = 0xaa; no reverse, no output XOR
[0D - Trailer
```

### Response
```
7A] IN RC (payload) cc [0D

7A] - Header
IN - Instruction
RC - Result code; 01 - ACK (omitted from command formatting info unless specified)
(payload) - Actual data, may be zero
cc - CRC8, generation data unknown
[0D - Trailer
```

## Command formatting

All commands will assume that you have calculated the counter, serial number, and other static data.

The marker ZZ indicates the zero point, after which all data is 00.

### 01 (USB negotiation)

#### Request

```
000000000000 a8058f33 080000000000000000000000e0fccc08200000001a001300c8facc087c233101c0facc087fd0c3771d000000200000006018 // Step 1
000000000000 af7acc62 00000000dc0b00000070c90100bc5c039d4ec677bc00002000000000c60447007413000000000000f4c9fac7c60447003800 // Step 1
000000000000 4d47416b b102000000000000dc0b000000c4c901f859400800000000b400000100000000c60447004882000000000000c60447003800 // Step 1
000000000000 3486f889 b102000000000000dc0b000000c4c90150045903000000008c00000100000000c60447005ca1000000000000c60447003800 // Step 1
000000000000 b9adb9ad 080000000000000000000000e0fccc08200000001a001300c8facc087c233101c0facc087fd0c3771d000000200000006018 // Step 2, randomized is retained, following is shared from step 1
^^^^^^^^^^^^ <- Always zero
             ^^^^^^^^ <- Randomized element?
           Unknown -> ^^^^ ->

```

#### Response

```
000000 231d2c00 f8880400 ZZ
000000 34234858 ffffffff ZZ
^^^^^^ <- Always zero
       ^^^^^^^^ <- Static per initial auth attempt
                ^^^^^^^^ <- Unknown
```

### 02 (Unknown)

#### Request

```
ZZ
```

#### Response

```
ZZ
```

### 03 (Version info query)

#### Request

```
ZZ
```

#### Response

```
630210117d2ead2e 4c0022000b51313430343330 0000000000000000 00802ad30b1740ef 0000000000000000 00c8002a95ae40 ad2e 010000000000
^^^^^^^^^^^^^^^^ <- Current version token
                 ^^^^^^^^^^^^^^^^^^^^^^^^ <- Device serial
                                    ?? -> ^^^^^^ ->
```

### 15 (Upload tag data)

**WARNING:** Unconfirmed

**WARNING:** Nonstandard formatting. Frames do NOT begin or end with expected data during data uploads

Usually executed after reading a HF tag.

#### Request

```
2ac04e80 60 00 0000 04838a2ac04e80 00000000 07 ZZ // Mifare ultralight (16pg)
3b4b0536 80 04 0000 3b4b0536000000 00000000 04 ZZ // Mifare Classic
f4d9085e 80 04 0000 f4d9085e000000 00000000 04 ZZ // Mifare Mini
f4d9085e7b890400c8230020000000200000000000000000000000000000000000000000000000000000000000000000ffffffffffffff078069ffffffffffff // Block data for mifare mini
```

#### Response

```
ZZ
```

### 30 (HF tag search)

#### Request

```
ZZ
```

#### Response

```
2ac04e80 4400 00 04838a2ac04e80 00000000 07 ZZ // 04838a2ac04e80
00010000 0400 09 00010000000000 00000000 04 ZZ // 00010000
^^^^^^^^                                       -> Last CL UID
         ^^^^                                  -> ATQA (reversed)
              ^^                               -> SAK
                 ^^^^^^^^^^^^^^                -> Full UID
                                ^^^^^^^^       -> Always 00
                                         ^^    -> UID size
```

### 31 (Mifare Classic key auth)

**WARNING: May be incorrect**

#### Request

```
00 00 ffffffffffff 3b4b0536 ZZ // Auth to key 0A with FFFFFFFFFFFF on tag with UID 3B4B0536
44 01 4b791bea7bcc 3b4b0536 ZZ // Auth to key 17B with 4b791bea7bcc on tag with UID 3B4B0536 (ECC sector)
^^                             -> Target block number
   ^^                          -> Target key (00: A, 01: B)
      ^^^^^^^^^^^^             -> Key
                   ^^^^^^^^    -> Tag UID
```

#### Response

```
01 ZZ
^^    -> ACK/NACK
```

### 32 (Mifare Classic block read)

#### Request

```
03 ZZ // Read block 3 (ST of sector 0)
00 ZZ // Read block 0
^^    -> Block number
```

#### Response
```
10 000000000000ff078069ffffffffffff ZZ
10 3b4b053643880400c843002000000024 ZZ
^^                                     -> Likely amount of received bytes
   ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^    -> Block data
```

### 41 (Unknown)

Used during tag reads. No exact format defined yet.

### 50 (LF/Data-On-Powerup tag search)

#### Request

```
ZZ
```

#### Response

**WARNING:** Incomplete data collected

```
3132354b487a 000000000000 4944 00000000000000000000 05 6500e59df3 ZZ       // 125kHz EM4100 tag
3132354b487a 000000000000 4749443634 00000000000000 08 90012000000ff800 ZZ // Bugged read determined as a "GID64" tag
3137354b487a 000000000000 4944 00000000000000000000 05 13001a1b9e ZZ       // 175kHz "AID" tag
3137354b487a 000000000000 4944 00000000000000000000 05 130019a9b0 ZZ       // 175kHz "AID" tag
3235304b487a 000000000000 4944 00000000000000000000 05 52002d1487 ZZ       // 250kHz Keanda (KAD) 科安达 M1 tag
31332e35364d487a0 0000000 4e5343 000000000000000000 05 58006dd122 ZZ       // 13.56MHz Huarui 华睿 NSC tag
^^^^^^^^^^^^-^^^^                                                          -> ASCII label for frequency
                          ^^^^-^-^^^                                       -> ASCII label for tag type (ID for LF, NSC for HF, others as needed)
                                                    ^^                     -> Size of payload (always 5 for EM, differs for others/...)
                                                       ^^^^^^^^^^-^^^^^    -> Effective PACS payload
```

### 51 (LF/Data-On-Powerup tag data submit)

#### Request

*Request payload data has to be identical to payload received from command 84h, or formatted correctly*

#### Response

```
ZZ
```
