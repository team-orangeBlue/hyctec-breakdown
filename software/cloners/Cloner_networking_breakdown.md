# Cloner networking

All networking is protected by cyclic XOR with the key of `58c035c6021f67141ca925dd81fc4a88a3e82fa87bbe3d2c7a8ac877e0503be04de58148272aaf2b4e0388f1e602c85b2fea032f4e644bbfaacb99df3632c6be` starting from byte 3, right after the frame size.

## Formatting

```
7A] SS SS (payload) [A7

7A] - Header
SS SS - Frame size, including start+end; little endian
(payload) - actual data packet, ciphered
[A7 - Trailer
```

After decrypting the payload, you will see the follwing format:

```
CT CT CT CT SE SE IN SN SN SN SN SN SN SN SN SN SN SN SN (payload) CR

CT - counter from 00000001; little endian
SE SE - Ciphertext size; little endian
IN - instruction to server
SN - Serial number on back label
(payload) - actual data packet
CR - CRC8 over payload bytes; polynomial = 0x01, initial = 0xaa
```

Please be aware that the server adds a 00 (ACK) after the instruction code, effectively shifting everything afterwards right by 1 byte.

Formatting seems to be inconsistent at times. Refer to valid exchanges in matching document.

## Command formatting

All commands will assume that you have calculated the counter, serial number, and other static data.

### 9D (MFKey32 calculation)

#### Query

```
34aa4e41 02 00000000 a6ccf3a7 855e9f9f 00000000 8eb1fc15 75de8e5b // "Standard" mode
7a5227b4 08 00000000 78ceea3b 0d1764dc 00000000 00e45496 38022fbc 00000000 cdded947 cd87d715 00000000 9513f828 c8c4851e 00000000 ed9252c4 eeaf25a4 00000000 2c887d63 addca5a1 00000000 e07c1486 10c50b6f 00000000 7934484c 96c7e4b2 // "CopyKey enhanced" mode (grab multiple at once)
f4c0b2ab 08 00000000 3af14c85 a21f5cc7 00000000 42ff10e2 b7f543bd 00000000 6050e1f9 f5dc9841 00000000 202d13fb 95bdce1e 00000000 310258c7 ac12810b 00000000 89f182ea 79d17523 00000000 bbb4391e b56150e4 00000000 ab81d761 a1261dd6 // Another run of enhanced mode with each pair having its own key

^^^^^^^^ <- Tag UID
         ^^ <- Amount of NtNrAr sets
            ^^^^^^^^ <- Nt0_0                                              ---------------\
                     ^^^^^^^^ <-Nr0_0                                                      \
                              ^^^^^^^^ <- Ar0_0                                             \
                                       ^^^^^^^^ <- Nt1_0                                    /
                                                ^^^^^^^^ <-Nr1_0                           /
                                                         ^^^^^^^^ <- Ar1_0 ---------------/
                                                         Nt0_1 -> ^^^^^^^^
```

#### Response

```
34aa4e41 01 a0a1a2a3a4a5 000000000000 000000000000 000000000000 000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
7a5227b4 01 a0a1a2a3a4a5 000000000000 000000000000 000000000000 000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
f4c0b2ab 04 a0a1a2a3a4a5 b0b1b2b3b4b5 c0c1c2c3c4c5 d0d1d2d3d4d5 000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
^^^^^^^^ <- Tag UID
         ^^ <- Amount of keys
            ^^^^^^^^^^^^ <- Key 0              ---------------\
                         ^^^^^^^^^^^^ <- Key 1 ---------------/
```

### A0 (update check)

**WARNING:** Query uses nonstandard formatting. Full frame attached.

**WARNING:** Not fully confirmed. Better return zeroes.

#### Query

```
01000000 4400 a0 630210117d2e ad2e 4c0022000b51313430343330 0000000000000000 00802ad30b1740ef 0000000000000000 00c8002a95ae40 ad2e 00000000 0001 00 18
^^^^^^^^ <- Message counter, usually 1
         ^^^^ <- Frame size, LE
              ^^ <- Command
                 ^^^^^^^^^^^^ <- Current version token
                              ^^^^ <- Device assembly date, not relevant, ignored
                                   ^^^^^^^^^^^^^^^^^^^^^^^^ <- Device serial number
                                           ???, then crc -> ^^^^^^^^^^^^^^^^ ^^^^^^^^^^^^^^^^ -> 
```

#### Response

```
01000000 a200 a0 00 4c0022000b51313430343330 01 000000000000 30f911100263 2cbf0300 829c dd 01 687474703a2f2f636f70796b65792e6879637465632e636e2f5570646174652f7a78636f7079392e68746d6c 0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000004
^^^^^^^^ <- Message counter, usually 1
         ^^^^ <- Frame size, LE
              ^^ <- Command
                 ^^ <- ACK (00)
                    ^^^^^^^^^^^^^^^^^^^^^^^^ <- Device serial number
                                             ^^ <- Update ACK: if 01, fields set; if 00, firmware is latest (or version/serial doesn't exist) and all following fields are 00
                                   Always 00 -> ^^^^^^^^^^^^
                      New version with flipped endianness -> ^^^^^^^^^^^^
                                         New version size in bytes, LE -> ^^^^^^^^
                            Downloaded package CRC16 (unknown poly/init values) -> ^^^^
                               Deciphered package CRC8(?) (unknown poly/init values) -> ^^
                                             Probably always 01, presence of changelog? -> ^^
                                                      Changelog URL, then zeroes, then CRC -> ^^^^^^^^ ->
```

### A1 (update download)

*Caution:* doing this without a prior A0 command will return an E0 NACK instead of an ACK.

#### Query

```
00000000 0001
^^^^^^^^      -> File offset, LE (in this case, 0 bytes from start)
         ^^^^ -> Query size, LE (in this case, 256 bytes)
```

#### Response
```
00000000 0001 5ef4ae71fbe4aa2f0af39afcb6ab570d76be6ddb296d612bb35b9f60c50570a7b30d0eee0fb7ae0c7fc51381d0da935a2df9ffb478283dc7bc28420ef3454245cb4d73920694a716ec3a16e28e57900c0e03c042e6b1aebcb7ef549f5f6755fa8a447cfb10b8b3a5e629ec42a1b0867d2d4b0a10b83d138e11f389bac1c5d3cd789bd80d8b2d5951b85a4d1f7915c0c9fb26f6cc243e5c1e7052ae36e50108c2cff0daa60a50486a12b8001ea26112b80e334bd662b8862ff7442d2a6a0b604aedd2d67fea90df5ace7277d28438fec1bf862ba911faddaaa037f00fd66f74a3e987bef661fd980c66f80748dda9e3226b294108ed8ca33ca8ffeb9bc99cb0e6
^^^^^^^^ <- File offset, LE
         ^^^^ <- Real sent payload size (at the end, for example, the server may not give a full 256 byte chunk)
              ^^^^^^^^ <- Ciphered firmware data ->
```

### AF (update cancel?)

#### Query

```
ff000000
^^^^^^^^ -> ???
```

#### Response
```
00
^^ -> ACK
```

### B1 (calculate nested)

#### Query

```
7a5227b4 00 13 00 0c038003 6f452dc7 73ebb591 5a769867 00000000 00000000 // 04-A (752e697394ca)
7a5227b4 00 13 01 0c038003 1e3e366a 73ebb591 f37c54ea 00000000 00000000 // 04-B (856e4d48b3b6)
7a5227b4 00 17 00 0c038003 038ec580 73ebb591 32b09ca0 00000000 00000000 // 05-A (be4b66712630)
7a5227b4 00 17 01 0c038003 0043392d 73ebb591 a8f26c2d 00000000 00000000 // 05-B (fc1678c5116d)
7a5227b4 00 1b 00 0c038003 6ad4ce7e 73ebb591 2cceab7e 00000000 00000000 // 06-A (db25d48a0f78)
7a5227b4 00 1b 01 0c038003 2c02eead 73ebb591 6ce97bad 00000000 00000000 // 06-B (31957443e1d6)
^^^^^^^^                                                                -> Tag UID
         ^^                                                             -> Always 00 (part of block nr.?)
            ^^                                                          -> Block number (number in hex)
               ^^                                                       -> A (00), B (01)
                  ^^^^^^^^                                              -> Nt-A
                           ^^^^^^^^                                     -> Ks-A
                                    ^^^^^^^^                            -> Nt-B
                                             ^^^^^^^^                   -> Ks-B
                                                      ^^^^^^^^ ^^^^^^^^ -> Always 00 (?)
```

The key can be generated by providing the Nonce-Tag + KeyStream values into the proxmark client's `mf_nested` function.

#### Response
```
7a5227b4 0100000001 752e697394ca
7a5227b4 0100000001 856e4d48b3b6
7a5227b4 0100000001 be4b66712630
7a5227b4 0100000001 fc1678c5116d
7a5227b4 0100000001 db25d48a0f78
7a5227b4 0100000001 31957443e1d6
^^^^^^^^                         -> Tag UID
         ^^^^^^^^^^              -> ?
                    ^^^^^^^^^^^^ -> Crypto1 key
```

### D0 (upload tag dump)

#### Query
```
7a5227b4 0000000000000004 0004 0000 0002 7a5227b4bb08040062636465666768690000000000000000000000000000000000000000000000000000000000000000a9814a825aad7f078869ede58312b71806000000f9ffffff0600000004fb04fb00000000000000000000000000000000000000000000000000000000000000006c60e951da847f078869b2048072fb14000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000d9670db534a17f07886977ca08a5cd46000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000fc755431459f7f0788696170cd946acf000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000752e697394ca7f078869856e4d48b3b6000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000be4b667126307f078869fc1678c5116d000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000db25d48a0f787f07886931957443e1d6000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000160929454cd37f078869f8526760a8f40c
7a5227b4 0000000000000004 0004 0002 0002 000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000c091916306297f078869c61353212f640000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000002137247561667f078869f65427acfd23000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000eabc895123317f078869663e1f54277b000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000a614934ffe097f0788690c1ef39516d0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000943423f96ba27f07886921634f1fd1f7000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000c14b58b151c67f07886969669d7edbbdaabbccddeeff0011223344556677a5a5000000000000000000000000000000000000000000000000000000000000000076469a7f2aef7f078869c04bbf5b7c0f01000000feffffff010000003cc33cc30000000000000000000000000000000000000000000000000000000000000000a0a1a2a3a4a5ff078069b0b1b2b3b4b5b3
^^^^^^^^ <- Tag UID
         ^^^^^^^^^^^^^^^^ <- ?
                          ^^^^ <- ?
                               ^^^^ <- 256-byte chunks to skip from start(?)
                                    ^^^^ <- 256-byte chunks of size(?)
                        Raw dump data -> ^^^^^^^^^^^->
```

#### Response
```
00
^^ -> ACK/NACK (00: ACK likely)
```

### D1 (nested prep? check tag existence in database?)

#### Query

```
04aa5728 fa9e80 00000000 07 // 7-byte UID
7a5227b4 000000 00000000 04 // 4-byte UID
^^^^^^^^ ^^^^^^             -> Tag UID
                ^^^^^^^^    -> ?
                         ^^ -> UID length
```

The device doesn't seem to be able to read CL3 tags.

#### Response

```
f0
^^ -> Status code, supposedly F0 for fail (tag not in DB), probably not the case though
```

### E0 (query keys to bruteforce?)

#### Query

[ unknown ]

#### Response

[ unknown ]
