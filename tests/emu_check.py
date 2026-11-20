#!/usr/bin/env python3
"""Emulate the injected lk-protection / fake-lock code and check its behaviour.

Usage: python3 tests/emu_check.py <patched lk.img>

Requires the ``unicorn`` package.  The check is purely offline: it maps the
lk partition, replaces the reply / cmdline stubs with ``ret`` and single-steps
the code caves, so it validates the injected AArch64 without a device.
"""

import struct
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from liblk.image import LkImage  # noqa: E402

from lk_unlock.protect import find_fastboot_handler, find_reply_fn  # noqa: E402

try:
    from unicorn import Uc, UC_ARCH_ARM64, UC_MODE_ARM, UcError
    from unicorn.arm64_const import (
        UC_ARM64_REG_PC,
        UC_ARM64_REG_SP,
        UC_ARM64_REG_X0,
        UC_ARM64_REG_LR,
    )
except ImportError:  # pragma: no cover
    sys.exit("unicorn is required: pip install unicorn")

PAC = (0xD503233F, 0xD50323BF)
SENTINEL = 0xDEADBEEF


def branch_target(data, off, base):
    word = struct.unpack_from("<I", data, off)[0]
    if (word & 0xFC000000) not in (0x14000000, 0x94000000):
        return None
    imm = word & 0x03FFFFFF
    if imm & (1 << 25):
        imm -= 1 << 26
    return base + off + imm * 4


class Emu:
    def __init__(self, data, base):
        self.base = base
        self.code = bytearray(data)
        for i in range(0, len(self.code) - 4, 4):
            if struct.unpack_from("<I", self.code, i)[0] in PAC:
                struct.pack_into("<I", self.code, i, 0xD503201F)
        self.mu = Uc(UC_ARCH_ARM64, UC_MODE_ARM)
        self.mu.mem_map(base, 0x400000)
        self.mu.mem_write(base, bytes(self.code))
        self.scratch = 0xFFFF000090000000
        try:
            self.mu.mem_map(self.scratch, 0x1000)
        except UcError:
            pass
        self.calls = []

    def trace_calls(self, entry, fn, max_steps=200):
        mu = self.mu
        mu.reg_write(UC_ARM64_REG_X0, self.scratch)
        mu.reg_write(UC_ARM64_REG_SP, self.scratch + 0x800)
        mu.reg_write(UC_ARM64_REG_LR, SENTINEL)
        mu.reg_write(UC_ARM64_REG_PC, entry)
        out = []
        for _ in range(max_steps):
            pc = mu.reg_read(UC_ARM64_REG_PC)
            if pc == fn:
                out.append(bytes(mu.mem_read(mu.reg_read(UC_ARM64_REG_X0), 64)).split(b"\x00")[0])
            if pc == SENTINEL:
                break
            try:
                mu.emu_start(pc, 0, count=1)
            except UcError:
                break
        return out

    def stub(self, va):
        self.mu.mem_write(va, struct.pack("<I", 0xD65F03C0))

    def run(self, entry, name, watch=(), normal=None, max_steps=400):
        mu = self.mu
        mu.mem_write(self.scratch, b"\x00" * 64)
        mu.mem_write(self.scratch, name + b"\x00")
        mu.reg_write(UC_ARM64_REG_X0, self.scratch)
        mu.reg_write(UC_ARM64_REG_SP, self.scratch + 0x800)
        mu.reg_write(UC_ARM64_REG_LR, SENTINEL)
        mu.reg_write(UC_ARM64_REG_PC, entry)
        for _ in range(max_steps):
            pc = mu.reg_read(UC_ARM64_REG_PC)
            if pc in watch:
                raw = mu.mem_read(mu.reg_read(UC_ARM64_REG_X0), 64).split(b"\x00")[0]
                return pc, raw.decode("latin1")
            try:
                mu.emu_start(pc, 0, count=1)
            except UcError as exc:
                return None, f"error: {exc}"
            pc = mu.reg_read(UC_ARM64_REG_PC)
            if normal is not None and pc == normal:
                return None, None
            if pc == SENTINEL:
                return None, None
        return None, "timeout"


def main(path):
    image = LkImage(open(path, "rb").read())
    lk = image.partitions["lk"]
    data, base = lk.data, lk.lk_address
    emu = Emu(data, base)

    flash = find_fastboot_handler(data, base, b"flash:")
    erase = find_fastboot_handler(data, base, b"erase:")
    flash_cave = branch_target(data, flash - base + 4, base)
    erase_cave = branch_target(data, erase - base + 4, base)
    protect = flash_cave is not None and erase_cave is not None
    if not protect:
        print("note: no lk-protection patch in this image; checking fake-lock only")

    fail_fn = find_reply_fn(data, base, b"FAIL")
    okay_fn = find_reply_fn(data, base, b"OKAY")
    for fn in (fail_fn, okay_fn):
        emu.stub(fn)

    ok = True
    expect_hit = {b"lk", b"lk_a", b"lk_b", b"lk_ab"}
    for name in (() if not protect else (b"lk", b"lk_a", b"lk_b", b"lk_ab", b"lk2", b"boot", b"lk_a1")):
        pc, msg = emu.run(flash_cave, name, watch=(fail_fn, okay_fn), normal=flash + 8)
        hit = pc in (fail_fn, okay_fn)
        want = name in expect_hit
        status = "OK" if hit == want else "FAIL"
        if hit != want:
            ok = False
        print(f"  flash {name.decode():6s} -> {'protected' if hit else 'forwarded'} "
              f"[{status}] {msg or ''}")
    for name in (() if not protect else (b"lk", b"lk_a", b"system")):
        pc, msg = emu.run(erase_cave, name, watch=(fail_fn, okay_fn), normal=erase + 8)
        hit = pc in (fail_fn, okay_fn)
        want = name in (b"lk", b"lk_a", b"lk_b")
        status = "OK" if hit == want else "FAIL"
        if hit != want:
            ok = False
        print(f"  erase {name.decode():6s} -> {'protected' if hit else 'forwarded'} "
              f"[{status}] {msg or ''}")

    # fake lock (optional)
    probe = data.find(b"androidboot.bootreason=reboot\x00")
    crash = data.find(b"androidboot.crash_reason=Normal\x00")
    if probe >= 0 and crash >= 0:
        from lk_unlock.inject import adrp_add_refs

        def call_site(string_off):
            for ref in adrp_add_refs(data, base, base + string_off):
                for k in range(4, 0x18, 4):
                    w = struct.unpack_from("<I", data, ref + k)[0]
                    if (w & 0xFC000000) == 0x94000000:
                        return ref + k
            return None

        site = call_site(probe)
        other = call_site(crash)
        if site and other:
            target = branch_target(data, site, base)
            w = struct.unpack_from("<I", data, other)[0]
            imm = w & 0x03FFFFFF
            if imm & (1 << 25):
                imm -= 1 << 26
            append_fn = base + other + imm * 4
            if target and target != append_fn:
                emu.stub(append_fn)
                msgs = emu.trace_calls(target, append_fn)
                print(f"  fake-lock cave 0x{target:X}: cmdline appends {msgs}")
                if not msgs or b"verifiedbootstate=green" not in msgs[0]:
                    ok = False

    print("RESULT:", "PASS" if ok else "FAIL")
    return 0 if ok else 1


if __name__ == "__main__":
    if len(sys.argv) != 2:
        sys.exit(__doc__)
    raise SystemExit(main(sys.argv[1]))
