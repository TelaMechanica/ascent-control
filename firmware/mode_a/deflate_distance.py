"""Measure the largest back-reference distance in a raw DEFLATE stream.

Why this exists: zlib's inflate resolves a back-reference from the output produced in
the same call, not only from its sliding window, so inflating with windowBits=-11
does NOT reject a stream that a strict 11-bit-window inflater would. The only reliable
way to enforce "every distance <= 2048" is to decode the stream and look.

Pure Python, RFC 1951. Also returns the inflated bytes so the result can be checked
against zlib's.
"""
from __future__ import annotations

LEN_BASE = [3, 4, 5, 6, 7, 8, 9, 10, 11, 13, 15, 17, 19, 23, 27, 31, 35, 43, 51, 59,
            67, 83, 99, 115, 131, 163, 195, 227, 258]
LEN_EXTRA = [0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 2, 2, 2, 2, 3, 3, 3, 3, 4, 4, 4, 4, 5, 5, 5, 5, 0]
DIST_BASE = [1, 2, 3, 4, 5, 7, 9, 13, 17, 25, 33, 49, 65, 97, 129, 193, 257, 385, 513, 769,
             1025, 1537, 2049, 3073, 4097, 6145, 8193, 12289, 16385, 24577]
DIST_EXTRA = [0, 0, 0, 0, 1, 1, 2, 2, 3, 3, 4, 4, 5, 5, 6, 6, 7, 7, 8, 8, 9, 9, 10, 10, 11, 11,
              12, 12, 13, 13]
CL_ORDER = [16, 17, 18, 0, 8, 7, 9, 6, 10, 5, 11, 4, 12, 3, 13, 2, 14, 1, 15]


class DeflateError(ValueError):
    pass


class _Bits:
    __slots__ = ("d", "p")

    def __init__(self, d):
        self.d, self.p = d, 0

    def bits(self, n):
        v = 0
        for i in range(n):
            byte = self.p >> 3
            if byte >= len(self.d):
                raise DeflateError("truncated stream")
            v |= ((self.d[byte] >> (self.p & 7)) & 1) << i
            self.p += 1
        return v

    def align(self):
        self.p = (self.p + 7) & ~7


def _huff(lengths):
    """Canonical Huffman decode table: {(len, code): symbol}."""
    maxl = max(lengths) if lengths else 0
    bl_count = [0] * (maxl + 1)
    for l in lengths:
        if l:
            bl_count[l] += 1
    code, next_code = 0, [0] * (maxl + 2)
    for b in range(1, maxl + 1):
        code = (code + bl_count[b - 1]) << 1
        next_code[b] = code
    table = {}
    for sym, l in enumerate(lengths):
        if l:
            table[(l, next_code[l])] = sym
            next_code[l] += 1
    return table, maxl


def _sym(bs, h):
    table, maxl = h
    code = 0
    for l in range(1, maxl + 1):
        code = (code << 1) | bs.bits(1)
        s = table.get((l, code))
        if s is not None:
            return s
    raise DeflateError("bad Huffman code")


_FIXED = None


def _fixed():
    global _FIXED
    if _FIXED is None:
        lit = [8] * 144 + [9] * 112 + [7] * 24 + [8] * 8
        _FIXED = (_huff(lit), _huff([5] * 30))
    return _FIXED


def inflate_measure(data: bytes) -> tuple[bytes, int]:
    """Returns (output, max_distance). Raises DeflateError on a malformed stream."""
    bs, out, maxd = _Bits(data), bytearray(), 0
    while True:
        final, btype = bs.bits(1), bs.bits(2)
        if btype == 0:
            bs.align()
            p = bs.p >> 3
            ln = data[p] | data[p + 1] << 8
            out += data[p + 4:p + 4 + ln]
            bs.p = (p + 4 + ln) * 8
        elif btype in (1, 2):
            if btype == 1:
                lit, dist = _fixed()
            else:
                hlit, hdist, hclen = bs.bits(5) + 257, bs.bits(5) + 1, bs.bits(4) + 4
                cl = [0] * 19
                for i in range(hclen):
                    cl[CL_ORDER[i]] = bs.bits(3)
                clh = _huff(cl)
                lens = []
                while len(lens) < hlit + hdist:
                    s = _sym(bs, clh)
                    if s < 16:
                        lens.append(s)
                    elif s == 16:
                        lens += [lens[-1]] * (3 + bs.bits(2))
                    elif s == 17:
                        lens += [0] * (3 + bs.bits(3))
                    else:
                        lens += [0] * (11 + bs.bits(7))
                lit, dist = _huff(lens[:hlit]), _huff(lens[hlit:])
            while True:
                s = _sym(bs, lit)
                if s < 256:
                    out.append(s)
                elif s == 256:
                    break
                else:
                    s -= 257
                    length = LEN_BASE[s] + bs.bits(LEN_EXTRA[s])
                    ds = _sym(bs, dist)
                    d = DIST_BASE[ds] + bs.bits(DIST_EXTRA[ds])
                    if d > len(out):
                        raise DeflateError("distance before start of output")
                    maxd = max(maxd, d)
                    for _ in range(length):
                        out.append(out[-d])
        else:
            raise DeflateError("reserved block type")
        if final:
            return bytes(out), maxd
