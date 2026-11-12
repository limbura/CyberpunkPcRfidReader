# Cyb_Nfctool: native HID protocol

Status: based on static analysis; read/write and host-control confirmed on the
user’s 0483:4343 device on 2026-11-12. Indication remains experimental.
The fixtures in `test_cyb_reader.py` are constructed from that analysis; they are
not physical-device captures. Do not treat passing tests as hardware validation.

Source: user-provided `Cyb_Nfctool.exe` (60,875,211 bytes), SHA-256
`bfe062a1dba672b0bff0289bb10e0ebec1077ec712ef3951ff27caceb1ed84cc`.
PE image base 0x400000. Executable code and DWARF descriptions were examined without
running the executable. Addresses below refer to that image, not newer downloads.
The proprietary executable is not added to this repository.

## Identification and USB

`UsbThreadClass::FindDeviceAndOpen` at 0x4AC8DC tries PIDs 0x4300 and 0x4343.
`FindDevIsOk` at 0x4AC42C enumerates VID 0x0483, then tests these substrings:

| HID field | Required substring |
|---|---|
| manufacturer_string | CYBDZKJ-BSJ |
| product_string | TCC-TSY-TBY |
| serial_number | BEGIN-2025 |

Strings are at 0x67B15C, 0x67B168, 0x67B174. These checks are retained: a matching
ST VID/PID alone does not authorize opening an unrelated device. A diagnostic
inventory can reveal firmware with different descriptors, without sending commands.

`sendData_slot` at 0x4ACD5A splits the stream into chunks of at most 64 bytes and
prepends report ID 0. It passes actual chunk length + 1 to hid_write, without
explicitly padding the final chunk. The receive loop at 0x4ACA90 reads up to 65
bytes and feeds the received bytes to a stream parser. The library additionally
accepts a 65-byte report with a leading zero ID and zero padding after frames.
Actual platform/report descriptor behavior must be checked on hardware.

## Framing

Encoder 0x4615B0; receive parser 0x461880:

`55 | command:u16be | payload_length:u16be | payload | xor_complement | xor`

XOR covers the payload only. The original helper uses an 8-bit length, so for
payloads >=256 it covers only the first `length & 255` bytes; normal library
requests are much smaller. Empty payload checksum is FF 00. Maximum payload is
2041 bytes. Response command equals the request command; no sequence ID is present.

Examples, excluding the USB report ID:

- Enable host control: `55 00 51 00 01 01 FE 01`.
- Disable host control: `55 00 51 00 01 00 FF 00`.
- Card information: `55 00 69 00 00 FF 00`.
- Read block 1: `55 00 6C 00 0F 01 01 00 FF FF FF FF FF FF FF FF FF FF FF FF FF 00`.

A bounded input drain runs before each request. Unrelated valid notification
frames are ignored while waiting under the same deadline. Malformed frames,
short writes, timeouts and unexpected result sizes fail explicitly.
For a short HID write, either the requested length or 65 is accepted: Windows
HIDAPI zero-pads to OutputReportByteLength and returns the padded count. Other
counts still fail; the command is never resent. Both counts are logged. Requests are
never automatically retransmitted. A late response to an identical previous
command cannot be distinguished perfectly without sequence IDs; keep exclusive
access to the reader. USB reads and drains are bounded.

## Host control

`CMD_SYS_HOST_TAKEOVER_ENABLE=0x51` in DWARF.
Function 0x4AB7C6 sends one byte (1 to enable, 0 to disable) and expects that byte
back. Its caller enables around a task and disables afterward. The library does
this per opened session, including cleanup after failures. Cleanup errors do not
replace a primary error: they are attached via `add_note`. If no earlier error
exists, a release error is reported; a write may already have succeeded.

## Card information

`CMD_HF_MIFARE_INFO=0x69`, no request payload; function 0x492780.
Response: `present:u8 | card_type:u8 | iso14a_card_select_t:17 bytes | optional data`.
The original code requires >=19 bytes and treats a zero first byte as no card.
The library follows that shape; shorter no-card replies from other firmware are
not silently assumed valid and need a capture to support them.

DWARF typedef `iso14a_card_select_t` (CU 0xC5BACF):

| Offset within 17-byte structure | Field |
|---|---|
| 0..9 | UID storage |
| 10 | UID length |
| 11..12 | ATQA |
| 13 | SAK |
| 14 | cascade level |
| 15 | sector count |
| 16 | magic type |

Only 4/7-byte UIDs and the existing Classic SAK allowlist are accepted. ATQA is
reversed from presumed ISO14443A wire order to the existing PN-style API order;
this byte-order normalization specifically requires hardware comparison.
The library requests information before and after each block read to detect a
card replacement. This cannot distinguish physically different cloned cards
with identical UID/content, and it is not an atomic card-lock operation.

## Normal block read/write

DWARF `READR_COM_CMD_E`: READBL=0x6C, WRITEBL=0x6A.
Common function 0x491E50 constructs:

`start_block:u8 | block_count:u8 | mode:u8 | key_a:6 | key_b:6 | [write data]`

Keys are serialized big-endian (0x45D260). The library uses start=1, count=1,
mode=0 (ordinary access), both keys FF FF FF FF FF FF. Mode 0 is visible in the
normal read caller at 0x4A8EBD. No magic-card commands or key discovery are used.
Unlike the old PN path which explicitly authenticates with Key A, the native
Cyb operation receives both keys and firmware chooses authentication internally.
A failed read mask does not distinguish authentication from RF/read failure;
it is reported as CardReadError rather than a guessed AuthenticationError.

Read response: 4-byte big-endian success bitmask followed by 16 bytes per block.
Write response: 4-byte big-endian success bitmask. For one block success is 1;
other masks fail. This follows 0x491E50 and callers testing individual bits.

Only block 1 is accessed. The shared write procedure preserves bytes outside
the requested slice, compares optional expected_uid/expected_block before writing,
sends one write command, and then performs fresh information/block requests.
All 16 bytes and UID must match. Cyb uses native operations; it does not send the
old PN RF-reset commands. Cache/RF behavior must be verified on hardware.

## Indication (1.5.2)

Command 0x55 takes A B C D and sends no acknowledgement. User hardware
experiments establish A as the pause between signals (03 vs 0F increases it),
B as sound duration, C as count. A=0 merges audible pulses. Units are unknown.
D has no observed effect in tested values 00/01/04; always transmit zero.

beep(t, count) sends 01 max(1,t-4) min(count,255) 00. count must be a positive
integer; legacy wCopy ignores count and still sends one signal.
red/green send 00 01 01 00 (silent red LED on); off sends 00 00 00 00.
Combined feedback sends LED first, sound second, to avoid cancelling sound;
the sound pattern may turn LED back on even when color=off.
No host takeover by default for indication. Explicit initialize=True still
releases host control on exit. Selected Cyb indication I/O failures are logged
and suppressed, while argument/discovery errors and card-operation errors remain
visible. No retry and no fabricated acknowledgement: return empty bytes.
These mappings are based on manual hardware observations; the integrated API
still needs a hardware smoke test. Existing wCopy packets remain unchanged.

## Hardware acceptance

Run `tests_and_other/cyb_diagnostics.py` first without --write. Check identification,
no-card behavior, UID/ATQA/SAK, block 1 and number against the original application.
Then test a spare card with explicit --write and verify with the original app and,
if available, the old reader. Check both removal and reconnection, and existing
application behavior. Fix protocol assumptions from actual captures before
promoting this branch as confirmed support. Exercise LED/beep separately after card verification.

## First hardware diagnostic / Windows correction (1.5.1)

The user's 2026-11-12 diagnostic (1.5.0) identified 0483:4343, interface 1,
usage page 255, with all three expected descriptor strings. All three attempts
stopped at the write-count check during initialize; no response was read.
The old log omitted the returned count, so the precise value is not established.
No card read/write command was reached.

Inspection of HIDAPI 0.15.0 `windows/hid.c`, hid_write lines 1085–1107 and
1120–1137, confirms zero-padding and returning the padded WriteFile count:
https://github.com/libusb/hidapi/blob/hidapi-0.15.0/windows/hid.c

The equality check was wrong for this Windows behavior. Version 1.5.1 accepts
requested length or the known 65-byte report size and logs both values. Regression
tests emulate a Windows backend returning 65 for every short write and ensure
write/read-back/release work without resending the write. A repeat hardware
run is still required; these logs did not yet validate the frame responses.

## Indication investigation / hardware observations

The follow-up 1.5.1 hardware runs confirmed card absence, repeated reading,
writing 2 → 555 with full-block/UID read-back, and release. USB writes returned
65 for short reports. This validates the Windows count correction for this device.

User observation: in autonomous operation without host commands, card presentation
causes two beeps; the LED is always red. Neither a controllable LED nor a physically
power-wired LED is established by this observation.

Additional DWARF evidence (CU 0xC5BACF, declaration file 166): AGREEMEN_BEEP_E
contains BEEP_2_CNT=0 and BEEP_LONG=1. Function 0x461CC0 branches on this value:

| Enum | First three payload bytes | Fourth byte |
|---|---|---|
| 0 / BEEP_2_CNT | 01 01 02 | Uninitialized stack byte in inspected caller |
| 1 / BEEP_LONG | 00 05 01 | Uninitialized stack byte in inspected caller |

Both send command 0x55 with 4 bytes via 0x4615B0 and return without waiting for
an acknowledgement. General helper 0x461C90 takes a 16-bit value and an 8-bit value
and serializes them little-endian into the first three bytes in the same layout.
No calls selecting explicit red/green/off modes were located in the inspected
executable. The command's BEEP_LED name alone does not prove LED control.

`cyb_feedback_diagnostics.py` uses the two known first-three-byte patterns, with
fourth byte deterministically zero; this is an explicit test assumption. It first
records the user's autonomous baseline, then tests without any card present.
Group 1: host-control baseline, double/long pattern, release baseline. Group 2:
same without taking host control. Group 3: optional 01 01 01 00, 00 01 01 00,
00 03 01 00 to distinguish count and duration hypotheses. No LED bit sweep or
card operations are included. No command is retried on missing reply. Raw replies
and physical observations are saved separately; USB write success is not physical
confirmation. Public indication functions will not claim success until the
sound/light behavior and parameter meanings are established.
