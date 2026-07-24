# CopyKey firmware autodump

As the device's MCU is set to RDP1, read out of its' internal flash is impossible to achieve with an SWD debugger.

However, since the device can self-update, as well as read internal flash, the firmware can be patched to enable self-readout.

## Theory (or how this even works)

There are a couple of places where the device interfaces with its' internal flash and passes that information to connected devices.
One place, where this is done at the very least, is in the code reading out the device's serial number and assembly date, then passing it to either the settings or USB device.
For automation purposes, we will aim at USB.

While the readout of the serial number is done from RAM, there is no mechanism to prevent re-addressing this read to a different memory location. 
As such, the register that was pointing to an address in RAM can be changed to point to an address in flash.

Since the goal is to read flash consecutively, a stepper is also needed. Since it's likely that all registers are in use, the only way to go here is to store the offset in RAM.

The 4 bytes after the serial number are guaranteed to be zero (in all fairness, RAM on the devices is barely maxed). 
Since the device boots from internal flash, address 0 will be aliased to MCU flash at address 8000000h.

Now that we know we can change the register pointing to the serial number to an address in flash and consecutively step it up, let's look for instructions to alter.

## Practice (how this script works)

As we're targetting the 03 command on USB, we can edit its' reply bytes to work for us. We won't be needing some zero fields, model info fields and other parts.

Because of this, code on the iCopy X100's 30F6 build at offset 2C2CAh will take on the following form:

```assembly
movs r0,#1 ; Set ACK byte
strb.w r0,[sp,#2] ; Write ACK byte
movw r4,#0x33b4
movt r4,#0x2000 ; Set R4 to hijacked RAM address (used in our code)
ldr r0,[r4,#0] ; Load flash pointer to R0
nop
nop
nop ; This instruction originally set R0 to the RAM pointer
ldr r1,[r0,#0]
str.w r1,[sp,#SNPart1]
ldr r1,[r0,#4]
str.w r1,[sp,#SNPart2]
ldr r1,[r0,#8]
str.w r1,[sp,#SNPart3] ; Write SN to payload
add.w r0,r0,#12 ; Add 12 as step
str r0,[r4,#0] ; Write to RAM
movs r4,#0 ; Reset R4 back to 0
```

Now every 03 command sent to the device over USB will read flash instead of internal memory, and on top of that - step up the read by 12 bytes every time it's invoked.

Since code is re-used across many devices and RAM is treated without much care on a lot of the devices as well, the address of 200033B4 can be repurposed with other firmwares as well.

## How-to

0. Obtain the desktop companion app and the matching scripts from [this repository](https://github.com/team-orangeBlue/hyctec-breakdown/tree/main/software/desktop/software).
1. Use the `download_firmware.py` script to fetch an encrypted firmware for your device. You will need your device's serial number as displayed and a valid firmware token.
   - A firmware token looks like this: `630F1011F6300000`. You will need to enter the matching PID (lower half as hex! in example, 6315 would be displayed on device), version values (as seen), then a date token which can be referenced with the [timestamp converter](https://github.com/team-orangeBlue/hyctec-breakdown/blob/main/software/dateconvert.py). The assembly date is not checked and may be left as 0000.
2. Use the [firmware decryptor](https://github.com/team-orangeBlue/hyctec-breakdown/blob/main/software/cloners/firmware_decrypt.py) to decrypt the firmware
3. Patch the decrypted result with the patcher
4. Use the [firmware encryptor](https://github.com/team-orangeBlue/hyctec-breakdown/blob/main/software/cloners/firmware_encrypt.py) to encrypt the patched firmware
5. Host a fake server using the [script](https://github.com/team-orangeBlue/hyctec-breakdown/blob/main/software/desktop/software/fakeserver.py) in this repository and update the device
6. Run the `autodump.py` script to dump the firmware. Use default values
7. Reflash original firmware back to the device by forcing an update to the file you originally downloaded
