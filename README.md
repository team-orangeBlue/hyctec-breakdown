# hyctec-breakdown
A thorough explanation of how the ecosystem of HYCTEC's CopyKey cloners functions and runs.

## Table of Contents
* Introduction
* Software
  - CopyKey cloners
  - PC companion app
  - Servers
* Hardware
  - CopyKey cloners
    * iCopyKey X100
    * CopyKey X3
    * CopyKey X5E
    * CopyKey X5
    * CopyKey Mini
    * CopyKey X6
 
## Introduction

HYCTEC is a company operated in the Chinese Mainland under the ICP number of 闽ICP备18004668号.
Its' activity seems to start off in 2021, although it's likely that the people running it have existed in the cloner scene earlier under, or with Zonsin.

The company owns the site of https://hyctec.cn, however it doesn't have any A/AAAA records. MX resolves to some strange site, CNAME resolves to hichina.com (which is also inaccessible), NS resolves to AliDNS.

The subdomains in use are...
* https://copykey.hyctec.cn (cloner online services on TCP port 6391)
* https://client.copykey.hyctec.cn (desktop app online services on TCP port 6390)
* https://doc.copykey.hyctec.cn (Changelogs for chinese cloners, usage info, and other miscellaneous posts)
* https://en.doc.copykey.hyctec.cn (Changelogs for Copykey X5E, effectively pointless)

The main product is the lineup of dual-tech RFID cloners branded CopyKey (拷贝齐, pinyin: kaobeiqi). The lineup consists of several models, with each being more advanced than the previous, notably:
* iCopyKey (爱拷贝) X100 (6315-10)
  - Average price of RMB200/unit
  - Powered by 4x AAA batteries
  - System menu presents the following options:
    * Smart copy
    * M1 formatting
    * NFC Simulation
    * System settings
  - System settings present the following options (220403-220421):
    1. Brightness settings (11-step from 0 to 10)
    2. Beeper settings (button press+action result, button press only, mute)
    3. Auto Power Down (after 60 seconds, after 120 seconds, off)
    4. Storage settings
    5. Mount as USB drive
    6. Language (zh-CN, zh-TW, en-US)
    7. System info
  - **Device is incapable of performing any Mifare Classic attack standalone** - a USB host is needed (PC/phone)
* CopyKey X3/X5E (6314-10-10)
  - **Hard to find**
  - Average price of RMB290/unit
  - **Adds ESP12F Wi-Fi module**
  - Menu replaces M1 formatting with Cloud decrypt (online ks-driven nested attack)
  - Settings add
    * Card formatting
    * Card Package Download (likely removed in 2024 firmware update)
    * Cloud decryption additional keys (3 keys stored in MCU for online nested, usage unknown, likely useless)
    * Wi-Fi settings  
* CopyKey X5 (6302-10-11)
  - Average price of RMB400/unit
  - **Adds li-ion battery instead of AAA cells**
  - **Unlocks use of MFkey32, hardnested, ATA5577/EM4305 dumping, NSC support**
  - Menu adds
    * Password detection (mfkey32)
    * Super Decrypt (hardnested, with support for various chinese KDFs)
    * Frequency Detection (show frequency at which reader is operating)
    * Hotel Card (capture ATA5577/EM4305 password and dump tag)
* CopyKey X6 (6306-11-10)
  - Average price of RMB460/unit
  - **Support for M+ tags**
  - **Bluetooth support**
  - *Appears to be a cashgrab* - supposedly refuses to work with anything that is not M+, and adds no real new features
* CopyKey Mini 
  - Divided into 3 seemingly software-locked devices
    * Mini (SE) (6104-10) - average price RMB80/unit
      - Basic cloner functionality, similar to iCopyKey X100 excluding rare LF (non-125K, tags other than EM4100 and FSK Wiegand) tag support
    * Mini Plus (6102-10) - average price RMB120/unit
      - Added support for card emulation
      - Added support for online nested
      - Added support for nonstandard LF frequencies
    * Mini Pro (6101-10-10) - average price RMB200/unit
      - Added support for making NDEF payloads
      - Added support for non-standard LF tags (e.g. Noralsy)
      - Unlocks working with 4K tags as well as 7-byte UIDs
  - **No screen**, meant to be operated by a phone via Bluetooth

## Software

*See the software README for more details + assets. To Be Done.*

## Hardware

*See the hardware README for board + component information. To Be Done.*
