#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Checks that scripts/a11y-check.py measures what it is for, on made-up screens.

    scripts/a11y-check-test.py

The contrast measure (ATF's ContrastSwatch, ported) on swatches drawn here: anti-aliased text, a row with two text
colours, a ripple caught mid-way, one colour only; the raw capture's two header sizes and its PNG; the large-text
comparison; the keyboard walk. Part of scripts/check.sh.
"""
import contextlib
import importlib.util
import io
import pathlib
import struct
import sys
import tempfile
import zlib

HERE = pathlib.Path(__file__).resolve().parent
sys.dont_write_bytecode = True  # no __pycache__ in scripts/
spec = importlib.util.spec_from_file_location("a11y_check", HERE / "a11y-check.py")
a11y = importlib.util.module_from_spec(spec)
spec.loader.exec_module(a11y)

failures = []


def expect(name, condition, detail=""):
    if not condition:
        failures.append(f"{name}: {detail}")


INK, PAPER, MUTE, PALE = 0x1D1B17, 0xFBF7F0, 0x4A4436, 0xB8B2A6

# Anti-aliased text: paper, ink, and a few grey edge shades of each stroke. The edges must not be taken for the text.
text = {PAPER: 9000, INK: 900, 0x8C8983: 120, 0xC4C1BA: 110, 0x5A5852: 100}
bg, fg = a11y.swatch(text, multiple=True)
expect("anti-aliased text, background", bg == PAPER, f"#{bg:06X}")
expect("anti-aliased text, text first", fg[0] == INK, [f"#{c:06X}" for c in fg])
expect("anti-aliased text passes", all(r >= 4.5 for r in a11y.ratios(bg, fg[:1])), a11y.ratios(bg, fg))
bg, fg = a11y.swatch(text, multiple=False)
expect("anti-aliased text, single foreground", (bg, fg) == (PAPER, [INK]), (f"#{bg:06X}", fg))

# A row's title in ink and its line beneath in a pale grey: both are judged, and the pale one fails.
row = {PAPER: 8000, INK: 700, PALE: 600}
bg, fg = a11y.swatch(row, multiple=True)
low = [c for c, r in zip(fg, a11y.ratios(bg, fg)) if 4.5 - r > a11y.CONTRAST_TOLERANCE]
expect("two text colours, the pale one fails", low == [PALE], [f"#{c:06X}" for c in low])
expect("two text colours, the ink passes", INK in fg and INK not in low, fg)

# A ripple caught mid-way: a slightly darker paper over part of the row. Close to the paper (CIE94 below 2), so it is
# merged into the background, and the text is still judged against the paper.
ripple = {PAPER: 6000, 0xF7F3EC: 2500, INK: 800}
bg, fg = a11y.swatch(ripple, multiple=True)
expect("ripple merged into the background", bg == PAPER and fg[0] == INK, (f"#{bg:06X}", [f"#{c:06X}" for c in fg]))

# One colour only: nothing to judge.
bg, fg = a11y.swatch({PAPER: 100}, multiple=True)
expect("one colour", fg == [bg] == [PAPER], fg)

# The WCAG ratio as ATF computes it, rounded to two places.
expect("ratio", a11y.ratios(PAPER, [INK]) == [16.1], a11y.ratios(PAPER, [INK]))


def capture(width, height, header, pixels):
    body = b"".join(struct.pack("<I", p) for p in pixels)
    head = struct.pack("<III", width, height, 1) + (struct.pack("<I", 1) if header == 16 else b"")
    return head + body


def word(rgb):
    """0xRRGGBB as the capture's RGBA bytes read little-endian."""
    return 0xFF000000 | ((rgb & 255) << 16) | (rgb & 0xFF00) | ((rgb >> 16) & 255)


with tempfile.TemporaryDirectory() as tmp:
    tmp = pathlib.Path(tmp)
    for header in (12, 16):
        raw = tmp / f"frame{header}.raw"
        raw.write_bytes(capture(4, 2, header, [word(PAPER)] * 6 + [word(INK)] * 2))
        frame = a11y.Frame(raw)
        expect(f"capture with a {header}-byte header", a11y.Frame(raw).histogram((0, 0, 4, 2)) == {PAPER: 6, INK: 2}, frame.histogram((0, 0, 4, 2)))
        frame.png(tmp / "frame.png")
        data = (tmp / "frame.png").read_bytes()
        width, height = struct.unpack(">II", data[16:24])
        idat = data[data.index(b"IDAT") + 4:data.index(b"IEND") - 8]
        rows = zlib.decompress(idat)
        expect(f"PNG of a {header}-byte capture", (width, height) == (4, 2) and rows[1:5] == bytes([0xFB, 0xF7, 0xF0, 0xFF]), (width, height, rows[:5]))
    wrong = tmp / "wrong.raw"
    wrong.write_bytes(struct.pack("<III", 2, 1, 4) + b"\0" * 8)
    try:
        a11y.Frame(wrong)
        expect("a capture in another format is refused", False)
    except ValueError:
        pass

    # A screen with a text in a pale grey on paper, as a dump and its capture: the check finds it; in ink it passes.
    def screen(color):
        dump = tmp / "dump.xml"
        dump.write_text('<hierarchy><node package="p" bounds="[0,0][10,4]" clickable="false" enabled="true">'
                        '<node package="p" text="Hello" bounds="[0,0][10,4]" clickable="false" enabled="true"/></node></hierarchy>')
        raw = tmp / "screen.raw"
        raw.write_bytes(capture(10, 4, 16, [word(PAPER)] * 30 + [word(color)] * 10))
        return dump, raw

    # A frame of one colour where the dump has text (a protected screen captured black) fails, as does a frame smaller
    # than the screen the dump describes.
    dump, raw = screen(INK)
    raw.write_bytes(capture(10, 4, 16, [word(0x000000)] * 40))
    with contextlib.redirect_stderr(io.StringIO()):
        expect("a black frame fails", a11y.check([str(dump), "1", "p", "--frame", str(raw)]) == 1)
    raw.write_bytes(capture(5, 4, 16, [word(PAPER)] * 20))
    with contextlib.redirect_stderr(io.StringIO()):
        expect("a frame smaller than the screen fails", a11y.check([str(dump), "1", "p", "--frame", str(raw)]) == 1)
    # Text inside a disabled control is not held to a contrast (WCAG exempts inactive components).
    disabled = tmp / "disabled.xml"
    disabled.write_text('<hierarchy><node package="p" bounds="[0,0][10,4]" clickable="true" enabled="false" text="">'
                        '<node package="p" text="Off" bounds="[0,0][10,4]" clickable="false" enabled="true"/></node></hierarchy>')
    raw.write_bytes(capture(10, 4, 16, [word(PAPER)] * 30 + [word(PALE)] * 10))
    with contextlib.redirect_stderr(io.StringIO()):
        expect("pale text in a disabled control passes", a11y.check([str(disabled), "1", "p", "--frame", str(raw)]) == 0)

    for color, fails in ((PALE, True), (INK, False)):
        dump, raw = screen(color)
        with contextlib.redirect_stderr(io.StringIO()) as err:
            code = a11y.check([str(dump), "1", "p", "--frame", str(raw)])
        expect(f"text in #{color:06X} {'fails' if fails else 'passes'}", code == (1 if fails else 0), err.getvalue())

    # The large-text comparison: a text that grew passes, one that kept its height fails.
    def dump_with(path, height):
        path.write_text(f'<hierarchy><node package="p" text="Title" bounds="[0,0][100,{height}]"/></hierarchy>')
        return str(path)

    # Heights compare in dp: the large pass also makes the display denser (420 to 540 dpi here), so a box of fixed dp
    # measures more pixels without having grown.
    small = dump_with(tmp / "small.xml", 42)
    with contextlib.redirect_stderr(io.StringIO()):
        expect("a text that grew passes", a11y.grew(["p", small, dump_with(tmp / "big.xml", 90), "420", "540"]) == 0)
        expect("a text held at its height fails", a11y.grew(["p", small, dump_with(tmp / "held.xml", 42), "420", "420"]) == 1)
        expect("a text held at its dp, only denser, fails", a11y.grew(["p", small, dump_with(tmp / "denser.xml", 54), "420", "540"]) == 1)

    # The keyboard walk: three buttons in a row, right to left. The walk is a circle (the first key also focuses the
    # first button), read from the button that comes first in reading order. Reaching them from the right passes, also
    # when the walk's record starts at the second; from the left it fails; and missing one fails.
    base = tmp / "base.xml"
    base.write_text('<hierarchy><node package="p" clickable="true" text="A" bounds="[800,0][1000,100]"/>'
                    '<node package="p" clickable="true" text="B" bounds="[450,0][650,100]"/>'
                    '<node package="p" clickable="true" text="C" bounds="[100,0][300,100]"/></hierarchy>')

    def step(name, box, label):
        path = tmp / name
        path.write_text(f'<hierarchy><node package="p" focused="true" text="{label}" bounds="{box}"/></hierarchy>')
        return str(path)

    a, b, c = step("a.xml", "[800,0][1000,100]", "A"), step("b.xml", "[450,0][650,100]", "B"), step("c.xml", "[100,0][300,100]", "C")
    # Another element scrolled into B's place is not B.
    other = step("other.xml", "[450,0][650,100]", "D")
    with contextlib.redirect_stderr(io.StringIO()):
        expect("keys from the right, right to left", a11y.keys(["p", "1", str(base), a, b, c]) == 0)
        expect("keys from the right, the record starting at the second", a11y.keys(["p", "1", str(base), b, c, a, b]) == 0)
        expect("keys from the left, right to left", a11y.keys(["p", "1", str(base), c, b, a]) == 1)
        expect("keys from the left, left to right", a11y.keys(["p", "0", str(base), c, b, a]) == 0)
        expect("a button the keyboard never reaches", a11y.keys(["p", "1", str(base), a, b]) == 1)
        expect("another element in a button's place does not reach it", a11y.keys(["p", "1", str(base), a, other, c]) == 1)

for failure in failures:
    print(f"A11Y-CHECK TEST FAILED: {failure}", file=sys.stderr)
print(f"a11y-check: {'failed' if failures else 'its measures hold'}")
sys.exit(1 if failures else 0)
