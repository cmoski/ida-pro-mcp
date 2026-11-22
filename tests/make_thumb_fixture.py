"""Generate tests/thumb_fixture.elf: a minimal 32-bit ARM ELF with ARM and Thumb code.

No toolchain needed; the bytes are hand-assembled. Layout (one RX PT_LOAD at
0x8000, entry 0x8000 in ARM mode):

    0x8000  ARM    mov r0, #0          e3a00000
    0x8004  ARM    bx  lr              e12fff1e
    0x8008  ARM    nop (mov r0, r0)    e1a00000  x2 (padding)
    0x8010  THUMB  movs r0, #1         2001      <- unreferenced; decodes as a
    0x8012  THUMB  bx   lr             4770         4-byte ARM insn in ARM mode
    0x8014  THUMB  nop                 bf00         and as 2-byte Thumb insns
    0x8016  THUMB  nop                 bf00         in Thumb mode.
    0x8018  ARM    mov r0, #3          e3a00003  <- back to ARM after the Thumb run
    0x801c  ARM    bx  lr              e12fff1e

Run: python tests/make_thumb_fixture.py
"""

import struct
from pathlib import Path

BASE = 0x8000
CODE = (
    struct.pack("<IIII", 0xE3A00000, 0xE12FFF1E, 0xE1A00000, 0xE1A00000)
    + struct.pack("<HHHH", 0x2001, 0x4770, 0xBF00, 0xBF00)
    + struct.pack("<II", 0xE3A00003, 0xE12FFF1E)
)

EHDR_SIZE = 52
PHDR_SIZE = 32
CODE_OFF = 0x100


def build() -> bytes:
    e_ident = b"\x7fELF" + bytes([1, 1, 1, 0]) + bytes(8)  # 32-bit, LE, v1, SYSV
    ehdr = e_ident + struct.pack(
        "<HHIIIIIHHHHHH",
        2,  # ET_EXEC
        40,  # EM_ARM
        1,  # EV_CURRENT
        BASE,  # e_entry (ARM mode: bit 0 clear)
        EHDR_SIZE,  # e_phoff
        0,  # e_shoff
        0x05000200,  # e_flags: EABI v5, soft-float
        EHDR_SIZE,
        PHDR_SIZE,
        1,  # e_phnum
        0,
        0,
        0,
    )
    phdr = struct.pack(
        "<IIIIIIII",
        1,  # PT_LOAD
        CODE_OFF,
        BASE,
        BASE,
        len(CODE),
        len(CODE),
        5,  # PF_R | PF_X
        0x1000,
    )
    blob = bytearray(ehdr + phdr)
    blob += bytes(CODE_OFF - len(blob))
    blob += CODE
    return bytes(blob)


if __name__ == "__main__":
    out = Path(__file__).with_name("thumb_fixture.elf")
    out.write_bytes(build())
    print(f"wrote {out} ({out.stat().st_size} bytes)")
