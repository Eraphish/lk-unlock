"""Low-level AArch64 helpers used by the LK protection / fake-lock patches.

The helpers here only understand the small instruction subset that this
project emits, so the code stays readable and dependency free.
"""

import struct

# --- string / pattern helpers -------------------------------------------------


def find_all(data, needle):
    out = []
    start = 0
    while True:
        idx = data.find(needle, start)
        if idx == -1:
            return out
        out.append(idx)
        start = idx + 1


def string_va(data, base, text):
    """Return the VA of a NUL-terminated string inside *data*."""
    off = data.find(text + b"\x00")
    if off < 0:
        raise ValueError(f"string not found: {text!r}")
    return base + off


def find_zero_region(data, size, start=0x40000, stop=None):
    """Find a NUL-filled, 4-byte aligned run of at least *size* bytes."""
    stop = len(data) if stop is None else stop
    i = start
    while i + size <= stop:
        if data[i] == 0:
            j = i
            while j < stop and data[j] == 0:
                j += 1
            if j - i >= size and i % 4 == 0:
                return i
            i = j + 1
        else:
            i += 1
    raise ValueError("no suitable zero-filled code cave found")


def adrp_add_refs(data, base, target_va):
    """Return offsets of ``adrp/add`` pairs that materialise *target_va*."""
    from capstone import Cs, CS_ARCH_ARM64, CS_MODE_ARM

    md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
    md.detail = True
    refs = []
    for i in range(0, len(data) - 8, 4):
        a = next(md.disasm(data[i : i + 4], base + i), None)
        if a is None or a.mnemonic != "adrp":
            continue
        b = next(md.disasm(data[i + 4 : i + 8], base + i + 4), None)
        if b is None or b.mnemonic != "add":
            continue
        try:
            imm = b.operands[2].imm
        except Exception:
            continue
        if int(a.op_str.split("#")[-1], 16) + imm == target_va:
            refs.append(i)
    return refs


def adr_refs(data, base, target_va):
    """Return offsets of ``adr`` instructions that materialise *target_va*."""
    from capstone import Cs, CS_ARCH_ARM64, CS_MODE_ARM

    md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
    refs = []
    for i in range(0, len(data) - 4, 4):
        ins = next(md.disasm(data[i : i + 4], base + i), None)
        if ins is not None and ins.mnemonic == "adr":
            if int(ins.op_str.split("#")[-1], 16) == target_va:
                refs.append(i)
    return refs


def bl_target(data, off):
    """Return the VA targeted by the ``bl`` at *off* (or None)."""
    word = struct.unpack_from("<I", data, off)[0]
    if (word & 0xFC000000) != 0x94000000:
        return None
    imm = word & 0x03FFFFFF
    if imm & (1 << 25):
        imm -= 1 << 26
    return None if imm == 0 else imm  # caller rebases with its own pc


# --- tiny assembler -----------------------------------------------------------


def _ldrb(rt, rn, imm):
    assert 0 <= imm < 0x1000
    return 0x39400000 | (imm << 10) | (rn << 5) | rt


def _cmp(rt, imm):
    assert 0 <= imm < 0x1000
    return 0x7100001F | (imm << 10) | (rt << 5)


def _adrp(rd, target, pc):
    page = target & ~0xFFF
    pc_page = pc & ~0xFFF
    delta = (page - pc_page) >> 12
    immlo = delta & 0x3
    immhi = (delta >> 2) & 0x7FFFF
    return 0x90000000 | (immlo << 29) | (immhi << 5) | rd


def _add_imm(rd, rn, imm):
    assert 0 <= imm < 0x1000
    return 0x91000000 | (imm << 10) | (rn << 5) | rd


PACIA = 0xD503233F
AUTIA = 0xD50323BF
RET = 0xD65F03C0
STP_FP_LR = 0xA9BF7BFD      # stp x29, x30, [sp, #-16]!
LDP_FP_LR = 0xA8C17BFD      # ldp x29, x30, [sp], #16
MOV_FP_SP = 0x910003FD      # mov x29, sp


class Code:
    """A minimal label-aware assembler for the instruction subset we need."""

    def __init__(self, va):
        self.va = va
        self.items = []          # ('label', name) | ('word', fn) | ('data', bytes)

    # -- primitives -------------------------------------------------------
    def label(self, name):
        self.items.append(("label", name))

    def word(self, fn):
        """fn(pc, labels) -> 32-bit instruction word."""
        self.items.append(("word", fn))

    def data(self, raw):
        self.items.append(("data", raw))

    # -- instructions -----------------------------------------------------
    def ldrb(self, rt, rn, imm):
        self.word(lambda pc, L: _ldrb(rt, rn, imm))

    def cmp(self, rt, imm):
        self.word(lambda pc, L: _cmp(rt, imm))

    def bcond(self, cond, name):
        self.word(lambda pc, L: _bcond(cond, L[name] - (pc - self.va)))

    def b(self, name):
        self.word(lambda pc, L: _b(L[name] - (pc - self.va)))

    def bl_label(self, name):
        self.word(lambda pc, L: _bl(L[name] - (pc - self.va)))

    def bl_va(self, target):
        self.word(lambda pc, L: _bl(target - pc))

    def b_va(self, target):
        self.word(lambda pc, L: _b(target - pc))

    def cbz(self, rt, name):
        self.word(lambda pc, L: _cbz(rt, L[name] - (pc - self.va)))

    def cbnz(self, rt, name):
        self.word(lambda pc, L: _cbnz(rt, L[name] - (pc - self.va)))

    def adrp_add(self, rd, target):
        self.word(lambda pc, L: _adrp(rd, target, pc))
        self.word(lambda pc, L: _add_imm(rd, rd, target & 0xFFF))

    def adrp_add_label(self, rd, name):
        self.word(lambda pc, L: _adrp(rd, self.va + L[name], pc))
        self.word(lambda pc, L: _add_imm(rd, rd, (self.va + L[name]) & 0xFFF))

    def raw(self, word):
        self.word(lambda pc, L: word)

    # -- link -------------------------------------------------------------
    def link(self):
        labels = {}
        off = 0
        for kind, val in self.items:
            if kind == "label":
                labels[val] = off
            elif kind == "word":
                off += 4
            else:
                off += len(val)
        out = bytearray()
        for kind, val in self.items:
            if kind == "label":
                continue
            if kind == "word":
                out += struct.pack("<I", val(self.va + len(out), labels) & 0xFFFFFFFF)
            else:
                out += val
        return bytes(out)


def _b(off):
    assert off % 4 == 0
    imm = off >> 2
    assert -(1 << 25) <= imm < (1 << 25), "b out of range"
    return 0x14000000 | (imm & 0x03FFFFFF)


def _bl(off):
    assert off % 4 == 0
    imm = off >> 2
    assert -(1 << 25) <= imm < (1 << 25), "bl out of range"
    return 0x94000000 | (imm & 0x03FFFFFF)


def _bcond(cond, off):
    assert off % 4 == 0
    imm = off >> 2
    assert -(1 << 18) <= imm < (1 << 18), "b.cond out of range"
    return 0x54000000 | ((imm & 0x7FFFF) << 5) | cond


def _cbz(rt, off):
    assert off % 4 == 0
    imm = off >> 2
    assert -(1 << 18) <= imm < (1 << 18)
    return 0x34000000 | ((imm & 0x7FFFF) << 5) | rt


def _cbnz(rt, off):
    assert off % 4 == 0
    imm = off >> 2
    assert -(1 << 18) <= imm < (1 << 18)
    return 0x35000000 | ((imm & 0x7FFFF) << 5) | rt


EQ, NE, HS, LO, MI, PL, VS, VC, HI, LS, GE, LT, GT, LE = range(14)

W0, W1, W2, W3 = 0, 1, 2, 3
X0, X1, X2, X3 = 0, 1, 2, 3


def branch_word(frm, to):
    """Encode ``b`` from *frm* to *to*."""
    return _b(to - frm)


def bl_word(frm, to):
    """Encode ``bl`` from *frm* to *to*."""
    return _bl(to - frm)
