# HYCTEC Breakdown
# Copyright 2026 team-orangeBlue. Some rights reserved.
# Licensed under the GNU General Public License v3

def dateconvert(stamp: int):
    # CopyKEY date conversion function
    # Receives a 16 bit number. Make sure to give the function a hex number, NOT a string!
    print(f"Decoded date: {2000+(stamp>>9)}-{stamp>>5 & 15:02}-{stamp & 0x1F:02}")
    print(f"As displayed: {stamp>>9}{stamp>>5 & 15:02}{stamp & 0x1F:02}")
