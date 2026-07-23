## Software

### CopyKey cloners

*Does not include the Mini series.*

#### Boot flow

The boot flow, from power given to the chip, appears to go as follows (does not cover assets used by CopyKey X6):
1. Turn on keyboard LEDs, initialize SPI flash
2. Load FAT12 FS driver, BMP processor and font decoder; initialize TFT display, read matching boot logo, add boot labels as necessary and send to display
  - The BMP processor is given RGB565 images in 320x240. It is unknown whether other formats can be given to it. The images can be made with GIMP, and should be 150.1KB in size.
  - BOOT1.bmp is used for the Copykey X5 and likely X3.
  - BOOT1-NB.bmp is used for the Copykey X5E. The name comes from the fact that the device is also known as "NB-X5E".
  - BOOT-IC.bmp is used for the iCopyKey X100.
3. Initialize backlight, if sound is fully on, do a brief high-pitch beep
4. Wait 2 seconds
5. Send BK1-1.bmp (BK2-1.bmp for iCopyKey) to screen, load matching language disclaimer, enable keyboard
  - Send MCU to sleep if POWER is pressed; otherwise continue
6. Send BK1.bmp (BK2.bmp for iCopyKey) to screen, load IC .bmp's as needed per device, load labels, enable more keys of the keyboard

#### Code and asset storage

Most of the logic of the cloners relies on the main MCU. It drives all the peripherals that are described in the hardware.

The MCU is configured to be in RDP1, as such reading out internal flash is impossible with a debugger. However the firmware can read itself.

As the MCU only has 256KB of usable space, it is impossible to keep all assets in it, especially backgrounds. As such, next to the MCU is an 64Mbit SPI flash.
The flash appears to be mapped out as follows (addresses in hex):

START  | END    | USAGE 
 ---   |   ---  |  ---
000000 | 200000 | External USB drive for storing cloner software
200000 | 500000 | Internal FAT12 filesystem for storing image + font assets
300000 | ?????? | Internal FAT12 filesystem for storing image + font assets for CopyKey X6 exclusively
480000 | 480020 | Device settings storage; protected by decoding from RC4 with the key of the device's serial number
481000 | ?????? | Unknown
482000 | 48200C | Update payload info
483000 | 500000 | Obfuscated update payload
500000 |?50B000 | Storage for 16 IC chips with each being max 4K in size
601000 | ?????? | Unicode-GBK16 table (2nd..?)

It is impossible to dump the SPI flash with a clip, as the MCU overtakes control. Desoldering is required.

The SPI flash is seemingly not verified on boot in any way whatsoever. As such, it is possible to modify the flash, and, for example, alter the backgrounds + icons loaded.

The device shows that it has the ability to store...
* 16 Mifare Classic tags, each up to 4KB in size
* 1920 key maps; this has not been understood yet - the assumption is 1 keymap = 80 keys of a tag; at 480 bytes/tag, this is 921600 bytes in flash, which appears reasonable
* 6 network configurations (not present in iCopyKey X100)

There appears to be no way to extract these dumps out of the SPI flash with software only.

#### Settings

The settings in 480000 at SPI are protected by RC4. The raw bytes can be extracted by encoding the string with RC4 against the device serial number. After that, the format takes on the following:
```
69 3d 34 01 // Magic word
00 // Likely language; 00 = zh-CN, 01 = zh-TW, 02 = en; unset values (like on X100) are unknown
02 // Unknown
01 // probably APD (00 = 60s; 01 = 120s; 02 = no APD)
02 // Unknown, may be volume control (00 = high + low; 01 = low only; 02 = muted)
03 // brightness (01-10, multiplied by 10 to get a value on a 100% scale)
12 34 56 12 34 56 // mfc key 1
a0 a1 a2 a3 a4 a5 // mfc key 2
d3 f7 d3 f7 d3 f7 // mfc key 3
2a 95 ae 40 c8 // Unknown
```

#### Updating

The bootloader checks the SPI at offset 482000 on boot for a string as follows:
```
693D3401 ssssssss cccccccc
^^^^^^^^                   - Magic word
         ^^^^^^^^          - Firmware size in LE
                  ^^^^^^^^ - CRC16 for firmware image (poly, init unknown)
```

Should it see this info, the bootloader will do a CRC check for the firmware image and then write in the image to internal flash.
If the magic word is FFFFFFFF, the bootloader will skip the update process.

#### Functionality

All items arranged as seen on CopyKey X5. Functionality explained per button.

##### Smart Copy

* The arrow keys change the frequency that the tag will be read at (right, down to go forward; left, up to go back). By default - 13,56MHz (i.e. NFC). Made redundant by the fact that the cloner will try to go through every frequency until a tag is read.
* C key is non-functional.
* Return key returns to main menu.
* Read key cycles all frequencies forward one time to detect a tag to read.
  - If an LF tag is detected...
    * EM410x chips have the full ID displayed in hex under UID, as well as the format selected with the EDIT key under "Card number". The tip is hardcoded to "use K8678 chips".
    * HID tags and other LF formats do not have their ID displayed, nor can have one entered. The tip is hardcoded to "use T5577 chips".
  - If an HF tag is detected...
    * The device attempts to determine the tag type based on the SAK + ATQA. The combinations are labelled as follows:
      | ATQA | SAK | Label |
      | ---  | --- | ---   |
      | 0004 | 08  | `IC/M1-S50` |
      | 0004 | 08  | `IC/MF1-S50` if code is entered manually |
      | 0044 | 08  | `IC/M17B-S50` |
      | 0002 | 18  | `IC/M1-S70` |
      | 0042 | 18  | `IC/M17B-S70` |
      | 00x4 | 08  | `IC/M1-S50+` (if sector 17 exists) |
      | 00xx | (2)8  | `M1+CPU` |
      | 0xx4 | 20  | `CPU` |
      | 0044 | 00  | Depends on version data, either `N21x` for NTAG, or `UL_xxx` for Ultralight |
      | xxxx | xx  | `IC` |
      
    * If a chip has MFC support (M1 label exists), the device tries to read sectors with the key of `FFFFFFFFFFFF` and all keys stored in its' keystore. In case any read fails, the process stops immediately and enables the OK button to launch the nested app.
    * MFC interactions are finished with an attempt to do WupC1 (40(7)) to attempt dumping a tag this way.
    * If an Ultralight chip rejects page reads after a certain point, the cloner will add a hint of `OK: xxP.`, with xx being the amount of password-free readable pages.
    * Smartcard functionality is not implemented in any way whatsoever - basic support for FMCOS tags is not implemented.
* Write key writes the read tag back.
  - For LF tags...
    * Writing is done to ATA5577s, EM4305s, Hitag u (8265) and Hitag S chips (8268, 8310, 8678). Passwords for each chip are `19920427`, `84AC15E2`, `9AC4999C` and `BBDD3399` respectively.
    * Writing is done blindly, so the success is determined by the fact that the data read from the field after writing matches the data in RAM.
  - For HF tags...
    * Alongside the writes to gen1 and USCUID, CopyKey also attempts to execute KDFs for QingLong88 and HUID chips if the dump has any custom keys set.
      - QL88 auths happen at `A0 B0 B0 A0 A0 B0 B0 A0 A1 B1 B1 A1 A1 B1 B1 A1 ->A1<-`
      - HUID auths happen at `A0 B0 B0 A0 A0 B0 B0 A0 A1 B1 B1 A1 A1 B1 B1 A1 A1 B1 A1 A1 B1 A1 ->A0<-` - should this pass, the cloner will write-protect block 0 and ACLs for sector 0 as the tags are custom-keyed Gen2's
     
* Edit key allows you to manually enter a tag ID of the selected frequency.
  - The format setting is retained; for proper UID entry, use HEX; for better display, use 8H-10D.
  - This cannot be used to enter non-EM LF IDs or NSC IDs.
* Detect key is non-functional.
* Simulate key emulates the currently read tag.
  - On the CopyKey X5 w/ firmware 230329-230513, the following formats can be emulated:
    * Any EM ID in the range of 125-500KHz
    * Any NSC ID
  - The following formats cannot be emulated:
    * Any ISO14443A tag
    * Any non-EM LF tag
    * Any LF tag with frequency above 500KHz
  - **BUG** the CopyKey X5 fails to emulate LF tags if it's set to English and rebooted
* Other key is non-functional.

##### Cloud decode

* Arrow keys are non-functional.
* C key is non-functional.
* Return key returns to main menu.
* Read key reads the tag UID and starts Wi-Fi to crack the tag. The exchange goes as follows:
  - CopyKey gets ~12 nonces from tag's target key, finds ones usable for nested, and provides server with UID, block number, key type, nt1+ks1, nt2+ks2 pairs.
  - The server replies with a crypto1 key, which the device uses on the target sector, then the entire tag to check usability.
  - After the tag is dumped, the cloner uploads the full dump to the server.
* Write key writes the tag if a dump is loaded. 
* Edit key is non-functional.
* Simulate key is non-functional.
* Other key is non-functional.

##### Flow detection

* Arrow keys are only functional to pick the one-key or three-key mode.
* C key is non-functional.
* Return key returns to previous menu.
* Read key reads the tag UID, then starts mfkey32. The green LED is engaged.
  - *The network exchange has not been examined yet.*
* Write key is non-functional.
* Edit key is non-functional.
* Detect key is non-functional.
* Simulate key is non-functional.
* Other key is non-functional.

##### Super Decrypt

* OK key allows to change KDF used.
* Arrow keys are only functional to pick the KDF.
* C key is non-functional.
* Return key returns to main menu.
* Read key reads the tag UID, then starts hardnested.
  - *The network exchange has not been examined yet.*
* Write key is untested.
* Edit key is non-functional.
* Detect key is non-functional.
* Simulate key is non-functional.
* Other key is non-functional.

##### NFC Simulate

* Arrow keys are non-functional.
* OK key is enabled if the card cannot be fully dumped.
* C key is non-functional.
* Return key returns to main menu.
* Read key reads the tag UID.
* Write key writes read UID to a gen1a or gen2 tag.
* Edit key is non-functional.
* Detect key is non-functional.
* Simulate key writes the rest of the dump into the tag.
* Other key is non-functional.

With the intention to make a phone, smart watch or other digital device a copy of the card, the process goes as follows:
1. Read the original tag to write into the device.
2. Write the UID of the original tag to a blank tag.
3. Add the blank tag to the wallet of the device to enable writing.
4. As the device now simulates a fully functional Mifare Classic chip, write the chip fully with the rest of the data from the dump without needing to touch block 0 that is write-protected.

##### Frequency detection

* Arrow keys are non-functional.
* OK key starts frequency detection on the rear antennas.
* C key is non-functional.
* Return key stops the detection and returns to main menu if already stopped.
* 6 function keys are non-functional.

##### Hotel card

*Functionality unknown*

* Read key starts password detection(?).
* Return key stops the detection and returns to main menu if already stopped.

##### Miscellaneous inputs

###### USB disk mode (settings)

* Pressing Other-Other-Other-C makes the device mount the 2nd, internal disk contained on SPI that has the image assets and font. For the X6, this is the 2nd disk.

###### System info (settings)

* Pressing Other-Other-Other-Other-C makes the device enter "debug mode" - all network requests instead of being sent to production servers get sent to `192.168.2.90:6391`.

#### Networking

The device communicates with `copykey.hyctec.cn:6391`. The connection is done via TCP.

The frame format is as follows:
```
7A] SS SS | CT CT CT CT SE SE IN SN SN SN SN SN SN SN SN SN SN SN SN (payload) | [A7

7A] - Header
SS SS - Frame size, including start+end; big endian
| Ciphertext border
CT - counter from 00000001; big endian
SE SE - Ciphertext size; big endian
IN - instruction to server
SN - Serial number
(payload) - actual data packet
| Ciphertext border
[A7 - Trailer
```

Ciphertext is produced by using cyclic XOR with the key of `58c035c6021f67141ca925dd81fc4a88a3e82fa87bbe3d2c7a8ac877e0503be04de58148272aaf2b4e0388f1e602c85b2fea032f4e644bbfaacb99df3632c6be`.

A decryptor implementation is available in this folder.

See matching document for command reference, formatting, replies and other values.

#### USB

USB exchange is obfuscated.

Nobody has looked into it yet.

### PC companion app

The app appears to be a mostly static-linked executable without dependencies on .NET or other external libraries. 

It has the ability to do nested, hardnested and after 2024 updates - static encrypted nonce attacks.

The app is also able to self-update and update the attached cloner.

#### Networking

The application connects to `client.copykey.hyctec.cn:6390`. The connection is done via TCP.

The frame format is as follows (likely wrong):

```
7E] -- -- -- -- -- SS SS SS SS | (PAYLOAD) | [7E

7E] - Header
SS SS SS SS - Frame size, including start+end; big endian
| Ciphertext border
(payload) - actual data packet
| Ciphertext border
[7E - Trailer
```

Ciphertext is produced by packing the data with LZ4 (?), then encrypting it with AES128 using key `1240150785069287811929265C049335`, IV `E3A479978C164930BB6EF59CA81DCEB3` and padding with PKCS7.

Decryptor scripts, as well as manual interface scripts, will probably be added later.

### Servers

Nobody knows how they work.

It's likely that you're being spied on with them. So don't trust them.

A reimplementation is to be made.
