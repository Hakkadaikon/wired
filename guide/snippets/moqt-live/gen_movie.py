#!/usr/bin/env python3
"""Regenerates movie-live.mp4: a tiny, synthetic fragmented-MP4 (same box
shape mp4frag_test.c's fixtures use -- ftyp+moov init segment, then
moof+mdat fragment pairs) with deterministic filler bytes instead of real
video. mp4frag_scan only reads box structure, so this is enough to drive
the live-publish demo without shipping an actual media asset.

    python3 gen_movie.py > movie-live.mp4
"""
import struct
import sys


def box(kind: str, payload: bytes) -> bytes:
    return struct.pack(">I", 8 + len(payload)) + kind.encode("ascii") + payload


def filler(n: int, start: int) -> bytes:
    return bytes((start + i) & 0xFF for i in range(n))


def build() -> bytes:
    out = box("ftyp", filler(4, 0xA0)) + box("moov", filler(8, 0xA0))
    for i, n in enumerate((16, 24, 32)):  # 3 fragments, growing mdat sizes
        out += box("moof", filler(4, 0xB0 + i))
        out += box("mdat", filler(n, 0xC0 + i))
    return out


if __name__ == "__main__":
    sys.stdout.buffer.write(build())
