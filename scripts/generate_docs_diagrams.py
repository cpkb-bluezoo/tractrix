#!/usr/bin/env python3
"""
Generates the SVG diagrams used in the docs and README, replacing the old
ASCII-art `<pre>` blocks. Two figures:

  pipeline.svg            data flow: bytes -> ... -> XmlHandler events,
                           and the writer's reverse direction. Used in both
                           README.md and docs/index.html.
  architecture-diagram.svg ownership: what Parser actually contains (nesting
                           = has-a) versus NamespaceFilter, which wraps the
                           *caller's* handler and is never owned by Parser.
                           Used in docs/architecture.html.

Both are standalone, self-contained SVG files (no <style>, no external
fonts) with a fixed, hardcoded palette chosen to read on both light and
dark backgrounds — README.md embeds these via a plain <img>, which gets
none of the docs site's CSS custom properties, so nothing here can rely on
page theming.

  python3 scripts/generate_docs_diagrams.py
"""
from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
ASSETS = ROOT / "docs" / "assets"

FONT = "ui-monospace, 'Cascadia Code', Menlo, Consolas, monospace"
FONT_SIZE = 13.5
LABEL_SIZE = 10.5
CHAR_W = FONT_SIZE * 0.62
LABEL_CHAR_W = LABEL_SIZE * 0.62

INK = "#1c2733"        # box strokes, component labels
MUTED = "#6b7789"       # arrows, annotation text
ACCENT = "#1a7fa8"      # the one hop/element under discussion, per box kind
ACCENT_SOFT = "#4fa6c9"

BOX_H = 40
PILL_H = 32
PAD_X = 14
PAD_Y = 10


def text_w(s: str, char_w: float) -> float:
    return len(s) * char_w


def esc(s: str) -> str:
    return s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


class Node:
    def __init__(self, text: str, kind: str, x: float, y: float):
        self.text = text
        self.kind = kind  # "endpoint" | "component" | "optional"
        self.w = text_w(text, CHAR_W) + 2 * PAD_X
        self.h = PILL_H if kind == "endpoint" else BOX_H
        self.x = x
        self.y = y  # vertical center

    @property
    def right(self) -> float:
        return self.x + self.w

    @property
    def cy(self) -> float:
        return self.y

    def svg(self) -> str:
        top = self.y - self.h / 2
        if self.kind == "endpoint":
            return (
                f'<rect x="{self.x:.1f}" y="{top:.1f}" width="{self.w:.1f}" height="{self.h:.1f}" '
                f'rx="{self.h/2:.1f}" fill="none" stroke="{MUTED}" stroke-width="1.3"/>'
                f'<text x="{self.x + self.w/2:.1f}" y="{self.y + FONT_SIZE*0.33:.1f}" '
                f'text-anchor="middle" font-family="{FONT}" font-size="{FONT_SIZE}" fill="{MUTED}">{esc(self.text)}</text>'
            )
        dash = ' stroke-dasharray="5 4"' if self.kind == "optional" else ""
        color = ACCENT if self.kind == "component" else ACCENT_SOFT
        return (
            f'<rect x="{self.x:.1f}" y="{top:.1f}" width="{self.w:.1f}" height="{self.h:.1f}" '
            f'rx="6" fill="none" stroke="{color}" stroke-width="1.6"{dash}/>'
            f'<text x="{self.x + self.w/2:.1f}" y="{self.y + FONT_SIZE*0.33:.1f}" '
            f'text-anchor="middle" font-family="{FONT}" font-size="{FONT_SIZE}" font-weight="600" '
            f'fill="{INK}">{esc(self.text)}</text>'
        )


def arrow(x1: float, y: float, x2: float, color: str = MUTED) -> str:
    return (
        f'<line x1="{x1:.1f}" y1="{y:.1f}" x2="{x2 - 8:.1f}" y2="{y:.1f}" '
        f'stroke="{color}" stroke-width="1.4" marker-end="url(#arrow)"/>'
    )


def label_lines(lines: list[str], cx: float, top_y: float, color: str = MUTED) -> str:
    out = []
    for i, line in enumerate(lines):
        out.append(
            f'<text x="{cx:.1f}" y="{top_y + i * (LABEL_SIZE + 3):.1f}" text-anchor="middle" '
            f'font-family="{FONT}" font-size="{LABEL_SIZE}" fill="{color}">{esc(line)}</text>'
        )
    return "".join(out)


def defs() -> str:
    return (
        "<defs>"
        f'<marker id="arrow" viewBox="0 0 10 10" refX="9" refY="5" '
        f'markerWidth="7" markerHeight="7" orient="auto-start-reverse">'
        f'<path d="M0,0 L10,5 L0,10 z" fill="{MUTED}"/>'
        "</marker>"
        "</defs>"
    )


def build_pipeline_svg() -> str:
    row1_y = 55
    gap_min = 92
    x = 20

    specs = [
        ("bytes", "endpoint"),
        ("ExternalEntityDecoder", "component"),
        ("Scanner", "component"),
        ("(NamespaceFilter?)", "optional"),
        ("XmlHandler", "endpoint"),
    ]
    arrow_labels = [
        ["BOM, decl, charset,", "line endings"],
        ["WF + DTD", "+ validation"],
        ["xmlns → namespace", "events"],
        [],
    ]

    nodes: list[Node] = []
    for i, (text, kind) in enumerate(specs):
        if i == 0:
            nx = x
        else:
            prev = nodes[-1]
            lbl = arrow_labels[i - 1]
            lbl_w = (max(text_w(line, LABEL_CHAR_W) for line in lbl) + 16) if lbl else 0
            nx = prev.right + max(gap_min, lbl_w)
        nodes.append(Node(text, kind, nx, row1_y))

    body = []
    for n in nodes:
        body.append(n.svg())
    for i in range(len(nodes) - 1):
        a, b = nodes[i], nodes[i + 1]
        body.append(arrow(a.right, row1_y, b.x))
        lbl = arrow_labels[i]
        if lbl:
            cx = (a.right + b.x) / 2
            body.append(label_lines(lbl, cx, row1_y - 14 - (len(lbl) - 1) * (LABEL_SIZE + 3)))

    total_w = nodes[-1].right + 20

    # Row 2: the writer runs the other way.
    row2_y = row1_y + 100
    w_node = Node("XmlWriter", "component", 20, row2_y)
    b_node = Node("bytes", "endpoint", w_node.right + gap_min, row2_y)
    body.append(w_node.svg())
    body.append(b_node.svg())
    body.append(arrow(w_node.right, row2_y, b_node.x))
    body.append(
        f'<text x="{b_node.right + 14:.1f}" y="{row2_y + FONT_SIZE*0.33:.1f}" '
        f'font-family="{FONT}" font-size="{LABEL_SIZE}" fill="{MUTED}">'
        f"indent · charset/BOM · XML 1.1 · standalone DTD</text>"
    )

    total_w = max(total_w, b_node.right + 320)
    total_h = row2_y + 30

    return (
        '<?xml version="1.0" encoding="UTF-8"?>\n'
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{total_w:.0f}" height="{total_h:.0f}" '
        f'viewBox="0 0 {total_w:.0f} {total_h:.0f}" role="img" '
        'aria-label="Bytes flow through ExternalEntityDecoder, Scanner, and an optional '
        'NamespaceFilter to reach XmlHandler; XmlWriter runs the reverse direction, events to bytes.">\n'
        f"{defs()}\n"
        + "\n".join(body)
        + "\n</svg>\n"
    )


def build_architecture_svg() -> str:
    pad = 22
    inner_y = 106
    arc_apex_y = 30

    decoder = Node("ExternalEntityDecoder", "component", pad + pad, inner_y)
    gap = text_w("bytes → chars", LABEL_CHAR_W) + 24
    scanner = Node("Scanner", "component", decoder.right + gap, inner_y)

    parser_x0 = pad
    parser_x1 = scanner.right + pad
    parser_y0 = inner_y - BOX_H / 2 - 26
    parser_y1 = inner_y + BOX_H / 2 + 20
    parser_h = parser_y1 - parser_y0

    body = []
    body.append(
        f'<rect x="{parser_x0:.1f}" y="{parser_y0:.1f}" width="{parser_x1 - parser_x0:.1f}" '
        f'height="{parser_h:.1f}" rx="8" fill="none" stroke="{INK}" stroke-width="1.6"/>'
    )
    body.append(
        f'<text x="{parser_x0 + 12:.1f}" y="{parser_y0 + 18:.1f}" font-family="{FONT}" '
        f'font-size="{FONT_SIZE}" font-weight="700" fill="{INK}">Parser</text>'
    )

    body.append(decoder.svg())
    body.append(scanner.svg())
    body.append(arrow(decoder.right, inner_y, scanner.x))
    body.append(label_lines(["bytes → chars"], (decoder.right + scanner.x) / 2, inner_y - 14))
    body.append(
        label_lines(["WF + DTD + validation"], scanner.x + scanner.w / 2, scanner.y + scanner.h / 2 + 16)
    )

    # Outside the Parser box: the caller-owned, optional NamespaceFilter, on
    # the same baseline as everything else, plus a real bypass path arcing
    # over it for when it isn't used — two live paths out of Scanner, not
    # one dashed box standing in for "maybe".
    gap2a = text_w("XmlHandler events", LABEL_CHAR_W) + 24
    gap2b = text_w("namespace() events", LABEL_CHAR_W) + 24
    filter_node = Node("NamespaceFilter (optional)", "optional", parser_x1 + gap2a, inner_y)
    handler_node = Node("your XmlHandler", "endpoint", filter_node.right + gap2b, inner_y)

    body.append(arrow(parser_x1, inner_y, filter_node.x))
    body.append(label_lines(["XmlHandler events"], (parser_x1 + filter_node.x) / 2, inner_y - 14))
    body.append(filter_node.svg())
    body.append(arrow(filter_node.right, inner_y, handler_node.x))
    body.append(
        label_lines(["namespace() events"], (filter_node.right + handler_node.x) / 2, inner_y - 14)
    )
    body.append(handler_node.svg())

    bypass_start_x = parser_x1
    bypass_end_x = handler_node.x + handler_node.w / 2
    bypass_top = inner_y - BOX_H / 2
    body.append(
        f'<path d="M{bypass_start_x:.1f},{bypass_top:.1f} '
        f'C{bypass_start_x:.1f},{arc_apex_y:.1f} {bypass_end_x:.1f},{arc_apex_y:.1f} '
        f'{bypass_end_x:.1f},{bypass_top - 6:.1f}" '
        f'fill="none" stroke="{MUTED}" stroke-width="1.4" stroke-dasharray="4 4" marker-end="url(#arrow)"/>'
    )
    body.append(
        label_lines(
            ["bypassed if NamespaceFilter isn't used"],
            (bypass_start_x + bypass_end_x) / 2,
            arc_apex_y - 8,
        )
    )

    total_w = handler_node.right + 30
    total_h = max(parser_y1, handler_node.y + handler_node.h / 2) + 30

    return (
        '<?xml version="1.0" encoding="UTF-8"?>\n'
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{total_w:.0f}" height="{total_h:.0f}" '
        f'viewBox="0 0 {total_w:.0f} {total_h:.0f}" role="img" '
        'aria-label="Parser owns ExternalEntityDecoder and Scanner directly; NamespaceFilter is '
        'not owned by Parser, it wraps the caller'
        "'"
        's own handler, and Scanner'
        "'"
        's events either flow through it or bypass it entirely.">\n'
        f"{defs()}\n"
        + "\n".join(body)
        + "\n</svg>\n"
    )


def main() -> None:
    ASSETS.mkdir(parents=True, exist_ok=True)
    for name, builder in (
        ("pipeline.svg", build_pipeline_svg),
        ("architecture-diagram.svg", build_architecture_svg),
    ):
        out = ASSETS / name
        out.write_text(builder())
        print(f"wrote {out.relative_to(ROOT)} ({out.stat().st_size} bytes)")


if __name__ == "__main__":
    main()
