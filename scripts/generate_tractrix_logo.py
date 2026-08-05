#!/usr/bin/env python3
"""
Tractrix logo — the pursuit curve drawn as a pair of XML angle brackets.

A tractrix is the curve traced by a point dragged along a straight line
by a taut string of constant length: it starts at a cusp (both x'(t) and
y'(t) vanish there — a true corner, not just a tight curve) with a
vertical tangent, then flattens asymptotically as it's towed away. Swap
the roles of the two axes and that cusp becomes a sharp vertex with two
arms curving off toward a vertical asymptote — exactly the geometry of
an angle bracket, just drawn with the real pursuit curve instead of a
straight stroke. Two mirrored copies, tips out, give "<>": the shape of
an empty XML tag, which is what this parser spends its life walking.

Rendering borrows the spirit of gonzalez-logo.svg and generate_hopf_logo.py
(mathematically-sampled curves, a rainbow hue sweep, a lit-tube look) but
each bracket is built as one tapered ribbon polygon rather than many
overlapping stroke chunks — at this size a chunked tube leaves visible
seams, where a single outline with a gradient fill and one glossy
centerline stroke stays clean. Width follows a thin-thick-thin
calligraphic taper, thin at the cusp and at both outer tips.

  python3 scripts/generate_tractrix_logo.py
"""
from __future__ import annotations

import math
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "docs" / "assets" / "tractrix-logo.svg"

WIDTH, HEIGHT = 200, 150
CX, CY = WIDTH / 2, HEIGHT / 2

A = 38.0             # tractrix scale (cusp-to-asymptote reach)
GAP = 18.0           # half-distance between the two inner asymptotes
T_MAX = 1.85         # parameter range, kept shy of full flattening so each
                     # arm still reads as a bracket stroke, not a comma
SAMPLES = 160        # points per bracket centerline
TUBE_MIN, TUBE_MAX = 1.6, 13.0


def sech(t: float) -> float:
    return 1.0 / math.cosh(t)


def hsl(h: float, s: float, l: float) -> str:
    h %= 360
    s = max(0.0, min(1.0, s))
    l = max(0.0, min(1.0, l))
    c = (1 - abs(2 * l - 1)) * s
    x = c * (1 - abs((h / 60) % 2 - 1))
    m = l - c / 2
    if h < 60:
        r, g, b = c, x, 0.0
    elif h < 120:
        r, g, b = x, c, 0.0
    elif h < 180:
        r, g, b = 0.0, c, x
    elif h < 240:
        r, g, b = 0.0, x, c
    elif h < 300:
        r, g, b = x, 0.0, c
    else:
        r, g, b = c, 0.0, x
    return (
        f"#{int(round((r + m) * 255)):02x}"
        f"{int(round((g + m) * 255)):02x}"
        f"{int(round((b + m) * 255)):02x}"
    )


def bracket_point(t: float, side: int) -> tuple[float, float]:
    """side=-1 -> "<" (cusp on the left, arms flare right toward the gap);
    side=+1 -> ">" (cusp on the right, arms flare left toward the gap)."""
    x = side * (GAP + A * sech(t))
    y = A * (t - math.tanh(t))
    return CX + x, CY + y


X_MIN, X_MAX = CX - (GAP + A), CX + (GAP + A)


def hue_at(x: float) -> float:
    frac = (x - X_MIN) / (X_MAX - X_MIN)
    return (265 - 305 * frac) % 360


def taper(s: float) -> float:
    """Calligraphic thin-thick-thin profile: thin at the cusp (s=0, the
    middle of the parameter range) AND at the two outer tips (s=1),
    bellying out over each arm in between."""
    return TUBE_MIN + (TUBE_MAX - TUBE_MIN) * math.sin(math.pi * s) ** 0.85


def path_d(xy: list[tuple[float, float]], close: bool = False) -> str:
    parts = [f"M{xy[0][0]:.2f},{xy[0][1]:.2f}"]
    for x, y in xy[1:]:
        parts.append(f"L{x:.2f},{y:.2f}")
    if close:
        parts.append("Z")
    return "".join(parts)


def render_bracket(side: int) -> list[str]:
    n = SAMPLES
    ts = [T_MAX * (2 * i / (n - 1) - 1) for i in range(n)]
    pts = [bracket_point(t, side) for t in ts]
    widths = [taper(abs(t) / T_MAX) for t in ts]

    left_edge = []
    right_edge = []
    for i in range(n):
        px, py = pts[i]
        ax, ay = pts[max(0, i - 1)]
        bx, by = pts[min(n - 1, i + 1)]
        tx, ty = bx - ax, by - ay
        nx, ny = -ty, tx
        norm = math.hypot(nx, ny) or 1.0
        nx, ny = nx / norm, ny / norm
        half = widths[i] / 2
        left_edge.append((px + nx * half, py + ny * half))
        right_edge.append((px - nx * half, py - ny * half))

    polygon = left_edge + list(reversed(right_edge))
    d = path_d(polygon, close=True)

    out = [f'  <path d="{d}" fill="url(#rainbow)" stroke="#1a1a2e" stroke-width="0.6" '
           f'stroke-opacity=".28" stroke-linejoin="round"/>']

    # Thin bright centerline stroke suggesting a glossy, lit tube without
    # the seam artifacts a chunked stroke would leave on a shape this size.
    highlight_d = path_d(pts)
    out.append(
        f'  <path d="{highlight_d}" fill="none" stroke="#ffffff" stroke-width="1.4" '
        f'stroke-linecap="round" stroke-opacity=".38"/>'
    )
    return out


def main() -> None:
    defs = ['  <linearGradient id="rainbow" gradientUnits="userSpaceOnUse" '
            f'x1="{X_MIN:.2f}" y1="0" x2="{X_MAX:.2f}" y2="0">']
    for i in range(9):
        frac = i / 8
        x = X_MIN + frac * (X_MAX - X_MIN)
        defs.append(
            f'    <stop offset="{frac * 100:.1f}%" '
            f'style="stop-color:{hsl(hue_at(x), 0.78, 0.55)}"/>'
        )
    defs.append("  </linearGradient>")

    body = []

    # The towing line: both cusps sit on it by construction (y=0 in the
    # local frame), so it's the actual physical line the point is dragged
    # along, not just a decorative underline.
    body.append(
        f'  <line x1="{X_MIN - 6:.2f}" y1="{CY:.2f}" x2="{X_MAX + 6:.2f}" y2="{CY:.2f}" '
        f'stroke="#9aa0a8" stroke-width="1.1" stroke-dasharray="1.5 4" opacity=".45"/>'
    )

    for side in (-1, 1):
        body.extend(render_bracket(side))
        cusp_x, cusp_y = bracket_point(0.0, side)
        dot_color = hsl(hue_at(cusp_x), 0.78, 0.55)
        body.append(
            f'  <circle cx="{cusp_x:.2f}" cy="{cusp_y:.2f}" r="{TUBE_MIN * 1.3:.2f}" '
            f'fill="{dot_color}"/>'
        )

    svg = (
        '<?xml version="1.0" encoding="UTF-8"?>\n'
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{WIDTH}" height="{HEIGHT}" '
        f'viewBox="0 0 {WIDTH} {HEIGHT}" role="img" aria-label="Tractrix">\n'
        '<title>Tractrix</title>\n'
        '<desc>A tractrix pursuit curve, mirrored, drawn as an XML angle-bracket '
        'pair. Transparent background.</desc>\n'
        "  <defs>\n" + "\n".join(defs) + "\n  </defs>\n"
        + "\n".join(body)
        + "\n</svg>\n"
    )
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(svg)
    print(f"wrote {OUT.relative_to(ROOT)} ({OUT.stat().st_size} bytes)")


if __name__ == "__main__":
    main()
