"""LK partition write protection and Android-side fake lock state.

Both features are implemented as small code caves injected into the ``lk``
partition of a stock Xiaomi MTK image:

* ``protect`` replaces the fastboot ``flash:`` / ``erase:`` handlers with a
  wrapper that refuses (or silently skips) writes to ``lk`` / ``lk_a`` /
  ``lk_b`` and forwards everything else to the original handler.
* ``fake_lock`` appends ``androidboot.verifiedbootstate=green`` to the kernel
  cmdline, so Android reports a verified/locked boot while the bootloader
  stays unlocked.

The caller is responsible for rebuilding the image and re-running the cert2
bypass afterwards.
"""

import struct

from capstone import Cs, CS_ARCH_ARM64, CS_MODE_ARM

from .inject import (
    Code,
    EQ,
    LDP_FP_LR,
    MOV_FP_SP,
    NE,
    AUTIA,
    PACIA,
    RET,
    STP_FP_LR,
    W0,
    W3,
    adrp_add_refs,
    branch_word,
    bl_word,
    find_all,
    find_zero_region,
)

CAVE_MIN = 0x400

FAIL_MSG = b"lk partition protected by lk-unlock"
OKAY_MSG = b"lk partition skipped (protected)"


def _md():
    md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
    md.detail = True
    return md


def _insn(md, data, base, off):
    return next(md.disasm(data[off : off + 4], base + off), None)


def find_fastboot_handler(data, base, key):
    """Find the handler registered for a fastboot command such as ``flash:``."""
    md = _md()
    for str_off in find_all(data, key + b"\x00"):
        for ref in adrp_add_refs(data, base, base + str_off):
            for k in range(0, 0x40, 4):
                ins = _insn(md, data, base, ref + k)
                if ins is None:
                    break
                if ins.mnemonic == "adr" and ins.op_str.startswith("x1"):
                    target = int(ins.op_str.split("#")[-1], 16)
                    for j in range(4, 0x18, 4):
                        nxt = _insn(md, data, base, ref + k + j)
                        if nxt is not None and nxt.mnemonic == "bl":
                            return target
    raise ValueError(f"fastboot handler for {key!r} not found")


def find_reply_fn(data, base, word):
    """Locate ``fastboot_okay`` / ``fastboot_fail`` by its status string."""
    md = _md()
    str_off = data.find(word + b"\x00")
    if str_off < 0:
        raise ValueError(f"{word!r} string not found")
    for ref in adrp_add_refs(data, base, base + str_off):
        for k in range(4, 0x40, 4):
            ins = _insn(md, data, base, ref - k)
            if ins is not None and ins.mnemonic == "paciasp":
                return base + ref - k
    raise ValueError(f"reply function for {word!r} not found")


def find_cmdline_append(data, base, probe=b"androidboot.bootreason=reboot"):
    """Locate ``cmdline_append`` and one of its call sites."""
    md = _md()
    str_off = data.find(probe + b"\x00")
    if str_off < 0:
        raise ValueError("cmdline probe string not found")
    for ref in adrp_add_refs(data, base, base + str_off):
        for k in range(4, 0x18, 4):
            ins = _insn(md, data, base, ref + k)
            if ins is not None and ins.mnemonic == "bl":
                return ref + k, int(ins.op_str.split("#")[-1], 16)
    raise ValueError("cmdline_append call site not found")


def _emit_name_check(code, hit, normal, a_path):
    """Match "lk", "lk_a", "lk_b" and "lk_ab" in the string at x0."""
    code.ldrb(W3, W0, 0)
    code.cmp(W3, ord("l"))
    code.bcond(NE, normal)
    code.ldrb(W3, W0, 1)
    code.cmp(W3, ord("k"))
    code.bcond(NE, normal)
    code.ldrb(W3, W0, 2)
    code.cbz(W3, hit)
    code.cmp(W3, ord("_"))
    code.bcond(NE, normal)
    code.ldrb(W3, W0, 3)
    code.cmp(W3, ord("a"))
    code.bcond(EQ, a_path)
    code.cmp(W3, ord("b"))
    code.bcond(NE, normal)
    code.ldrb(W3, W0, 4)
    code.cbz(W3, hit)
    code.b(normal)
    code.label(a_path)
    code.ldrb(W3, W0, 4)
    code.cbz(W3, hit)
    code.cmp(W3, ord("b"))
    code.bcond(NE, normal)
    code.ldrb(W3, W0, 5)
    code.cbnz(W3, normal)


def _build_protect_code(cave_va, handler_va, sub_sp, reply_va, msg, prefix):
    """Build one wrapper.

    The handler entry keeps its ``paciasp`` (a valid BTI landing pad) and its
    ``sub sp, sp, #N`` is replaced by ``b`` into this cave.  The forwarded
    path replays ``sub sp`` and resumes at ``handler + 8``; the blocked path
    saves the PAC-signed LR, reports the error and returns.
    """
    code = Code(cave_va)

    code.label(f"{prefix}_entry")
    _emit_name_check(code, f"{prefix}_hit", f"{prefix}_normal", f"{prefix}_a")

    code.label(f"{prefix}_hit")
    code.raw(STP_FP_LR)
    code.raw(MOV_FP_SP)
    code.adrp_add_label(W0, f"{prefix}_msg")
    code.bl_va(reply_va)
    code.raw(LDP_FP_LR)
    code.raw(AUTIA)
    code.raw(RET)

    code.label(f"{prefix}_normal")
    code.raw(sub_sp)
    code.b_va(handler_va + 8)

    code.label(f"{prefix}_msg")
    code.data(msg + b"\x00")
    return code.link()


def _sub_sp_imm(data, handler_off):
    """Read/validate the ``sub sp, sp, #imm`` of a handler prologue."""
    word = struct.unpack_from("<I", data, handler_off + 4)[0]
    if (word & 0xFFC03FFF) != 0xD10003FF:
        raise ValueError("unexpected handler prologue (no sub sp, sp, #imm)")
    imm = (word >> 10) & 0xFFF
    return 0xD10003FF | (imm << 10)


def apply_lk_protection(data, base, mode):
    """Return *data* with lk/lk_a/lk_b flash+erase interception installed.

    mode is ``fail`` or ``okay``.  The image still needs its cert2 rebuilt.
    """
    if mode not in ("fail", "okay"):
        raise ValueError(f"unsupported lk protection mode: {mode}")

    flash_va = find_fastboot_handler(data, base, b"flash:")
    erase_va = find_fastboot_handler(data, base, b"erase:")
    reply_va = find_reply_fn(data, base, b"FAIL" if mode == "fail" else b"OKAY")
    msg = FAIL_MSG if mode == "fail" else OKAY_MSG

    flash_sub = _sub_sp_imm(data, flash_va - base)
    erase_sub = _sub_sp_imm(data, erase_va - base)

    cave_off = find_zero_region(data, CAVE_MIN)
    cave_va = base + cave_off

    total = bytearray()
    flash_blob = _build_protect_code(cave_va, flash_va, flash_sub, reply_va, msg, "flash")
    flash_blob += b"\x00" * (-len(flash_blob) % 4)
    total += flash_blob
    erase_va_cave = base + cave_off + len(total)
    erase_blob = _build_protect_code(erase_va_cave, erase_va, erase_sub, reply_va, msg, "erase")
    erase_blob += b"\x00" * (-len(erase_blob) % 4)
    total += erase_blob

    if len(total) > len(data) - cave_off:
        raise ValueError("code cave too small")

    out = bytearray(data)
    out[cave_off : cave_off + len(total)] = total

    flash_off = flash_va - base
    erase_off = erase_va - base
    out[flash_off + 4 : flash_off + 8] = struct.pack(
        "<I", branch_word(flash_va + 4, cave_va)
    )
    out[erase_off + 4 : erase_off + 8] = struct.pack(
        "<I", branch_word(erase_va + 4, erase_va_cave)
    )

    return bytes(out), {
        "flash_handler": flash_va,
        "erase_handler": erase_va,
        "reply": reply_va,
        "cave": cave_va,
        "mode": mode,
        "size": len(total),
    }


def apply_fake_lock(data, base, cave_off=None):
    """Append ``androidboot.verifiedbootstate=green`` to the kernel cmdline."""
    append_site, append_va = find_cmdline_append(data, base)
    green_off = data.find(b"androidboot.verifiedbootstate=green\x00")
    bootreason_off = data.find(b"androidboot.bootreason=reboot\x00")
    if green_off < 0 or bootreason_off < 0:
        raise ValueError("cmdline strings not found")

    if cave_off is None:
        cave_off = find_zero_region(data, 0x100)
    cave_va = base + cave_off

    code = Code(cave_va)
    code.raw(STP_FP_LR)
    code.raw(MOV_FP_SP)
    code.adrp_add(W0, base + green_off)
    code.bl_va(append_va)
    code.adrp_add(W0, base + bootreason_off)
    code.bl_va(append_va)
    code.raw(LDP_FP_LR)
    code.raw(RET)
    blob = code.link()

    out = bytearray(data)
    out[cave_off : cave_off + len(blob)] = blob
    out[append_site : append_site + 4] = struct.pack(
        "<I", bl_word(base + append_site, cave_va)
    )
    return bytes(out), {
        "append_site": base + append_site,
        "append": append_va,
        "cave": cave_va,
        "size": len(blob),
    }
