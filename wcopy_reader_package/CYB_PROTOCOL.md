# Cyb_Nfctool: native HID protocol

Status: implementation based on static analysis, **not yet tested on hardware**.
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
short writes, timeouts and unexpected result sizes fail explicitly. Requests are
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

## Indication: intentionally incomplete

DWARF names command 0x55 `CMD_SYS_DEV_BEEP_LED_SET`. Functions 0x461C90 and
0x461CC0 send four payload bytes; the last byte appears uninitialized, and the
meaning/units of the other fields are insufficiently established to implement
compatible arbitrary LED colors and beep(t). No guessed indication packets are
sent. Public indication calls raise FeedbackError. Read/write and watch_cards()
without feedback remain usable. Existing wCopy indication code is unchanged.

## Hardware acceptance

Run `tests_and_other/cyb_diagnostics.py` first without --write. Check identification,
no-card behavior, UID/ATQA/SAK, block 1 and number against the original application.
Then test a spare card with explicit --write and verify with the original app and,
if available, the old reader. Check both removal and reconnection, and existing
application behavior. Fix protocol assumptions from actual captures before
promoting this branch as confirmed support. LED/beep require a separate investigation.
