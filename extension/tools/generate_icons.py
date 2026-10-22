#!/usr/bin/env python3
"""Generate ScamShield PNG icons with only the Python standard library."""

from pathlib import Path
import struct
import zlib

ROOT = Path(__file__).resolve().parents[1]
ICON_DIR = ROOT / "icons"
BLUE = (42, 120, 214, 255)
WHITE = (255, 255, 255, 255)
TRANSPARENT = (0, 0, 0, 0)


def inside_shield(x, y, size):
    cx = size / 2
    top = size * .09
    shoulder = size * .18
    bottom = size * .91
    if y < top or y > bottom:
        return False
    if y < size * .53:
        half = size * .34 - max(0, y - shoulder) * .08
    else:
        half = size * .31 * (bottom - y) / (bottom - size * .53)
    return abs(x - cx) <= max(0, half)


def distance_to_segment(px, py, ax, ay, bx, by):
    dx, dy = bx - ax, by - ay
    length_sq = dx * dx + dy * dy
    t = max(0, min(1, ((px - ax) * dx + (py - ay) * dy) / length_sq))
    qx, qy = ax + t * dx, ay + t * dy
    return ((px - qx) ** 2 + (py - qy) ** 2) ** .5


def make_icon(size):
    scale = 4
    canvas = size * scale
    rows = []
    for oy in range(size):
        row = bytearray()
        for ox in range(size):
            samples = []
            for sy in range(scale):
                for sx in range(scale):
                    x = ox + (sx + .5) / scale
                    y = oy + (sy + .5) / scale
                    color = TRANSPARENT
                    if inside_shield(x, y, size):
                        color = BLUE
                        width = max(1.35, size * .075)
                        d1 = distance_to_segment(x, y, size*.31, size*.49, size*.45, size*.64)
                        d2 = distance_to_segment(x, y, size*.45, size*.64, size*.72, size*.34)
                        if min(d1, d2) <= width:
                            color = WHITE
                    samples.append(color)
            alpha = sum(c[3] for c in samples) // len(samples)
            if alpha == 0:
                row.extend(TRANSPARENT)
            else:
                weighted = [sum(c[i] * c[3] for c in samples) // sum(c[3] for c in samples) for i in range(3)]
                row.extend((*weighted, alpha))
        rows.append(b"\x00" + bytes(row))
    raw = b"".join(rows)
    signature = b"\x89PNG\r\n\x1a\n"
    def chunk(kind, data):
        return struct.pack(">I", len(data)) + kind + data + struct.pack(">I", zlib.crc32(kind + data) & 0xffffffff)
    return signature + chunk(b"IHDR", struct.pack(">IIBBBBB", size, size, 8, 6, 0, 0, 0)) + chunk(b"IDAT", zlib.compress(raw, 9)) + chunk(b"IEND", b"")


ICON_DIR.mkdir(exist_ok=True)
for icon_size in (16, 32, 48, 128):
    (ICON_DIR / f"icon{icon_size}.png").write_bytes(make_icon(icon_size))
