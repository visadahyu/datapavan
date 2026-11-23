# SPDX-License-Identifier: Apache-2.0
"""Accessibility checks of Datapavan's screens, from uiautomator dumps and raw screen captures (docs/ACCESSIBILITY.md).

    python3 -I scripts/a11y-check.py DUMP.xml MIN_SIZE_PX [PACKAGE] [--frame RAW --png OUT.png]
    python3 -I scripts/a11y-check.py grew PACKAGE SMALL.xml LARGE.xml SMALL_DPI LARGE_DPI
    python3 -I scripts/a11y-check.py keys PACKAGE RTL BASE.xml STEP.xml...

The first form checks one screen. Every clickable element must have a label that a screen reader can announce (its own
text or content description, or one of its children's), and must be at least the minimum touch size in both
directions. With --frame, the raw capture taken with the dump (`adb exec-out screencap`, no -p): every enabled text
stands at least 4.5:1 against its background, and every clickable element without text (an icon) at least 3:1, measured
as Google's Accessibility Test Framework measures them (ContrastSwatch, below); the capture is written as a PNG to OUT,
so that the picture people review is the frame that was checked. Elements cut off by the edge of a scrolling list are
skipped: the dump measures only their visible part and leaves out the children that are off screen, label included.

"grew" pairs each text of one screen at font scale 1.0 (SMALL) with the same text at the largest scale (LARGE), their
heights in dp at each pass's density: a text that did not grow by a tenth is held by a box that does not let it, and is
cut off on the screen (WCAG 1.4.4), though the dump still gives all its words. A text cut off inside a box that grew
with it, an ellipsis say, does not show here: the pictures are read by eye for that.

"keys" reads a keyboard walk: BASE is the screen before any key, each STEP the screen after one more Tab. Every
clickable element of BASE must take the focus at some step (WCAG 2.1.1), in reading order: down the screen, and along
a row from the right in right-to-left languages (RTL is 1) and from the left otherwise (2.4.3). An element counts as
reached when the focus lands on its bounds with its label, so that another row scrolled into the same place does not.
Only the elements BASE shows are required: the screen as it first opens.

PACKAGE is Basic's by default in the first form; Datapavan Advanced's screens, the network part's "Now" included, give
their own.
"""
import re
import struct
import sys
import xml.etree.ElementTree as ET
import zlib
from collections import Counter

PACKAGE = "org.visadahyu.datapavan"
TEXT_RATIO = 4.5
ICON_RATIO = 3.0


def bounds(node):
    return tuple(int(v) for v in re.findall(r"\d+", node.get("bounds", "")))


def clipped_by_scroll(node, parents):
    """Whether a scrolling list's edge cuts the node off."""
    box = bounds(node)
    ancestor = parents.get(node)
    while ancestor is not None:
        if ancestor.get("scrollable") == "true":
            outer = bounds(ancestor)
            return box[1] <= outer[1] or box[3] >= outer[3]
        ancestor = parents.get(ancestor)
    return False


def label_of(node):
    return next((n.get("text") or n.get("content-desc") for n in node.iter() if n.get("text") or n.get("content-desc")), "")


# ---- ContrastSwatch, ported from Google's Accessibility Test Framework for Android (Apache-2.0), commit
# c65cab02b2a845c29c3da100d6adefd345a144e3, src/main/java/com/google/android/apps/common/testing/accessibility/
# framework/utils/contrast/ContrastSwatch.java and ContrastUtils.java. Colours are 0xRRGGBB integers here; the
# capture's alpha is always opaque. Where this differs from ATF: the order of equal counts follows insertion, where
# ATF's follows a HashMap's; the swatch is the node's bounds, where ATF may use the text's character bounds; and text
# is held to 4.5:1 always, where ATF holds text of unknown size to 3.0:1 (the dump gives no text size).

MAX_FOREGROUND_COLOR = 5
COLOR_DIFFERENCE_LIMIT = 2.0
COLOR_SIGNIFICANCE_PERCENTAGE = 0.03
COLOR_CUTOFF_PERCENTAGE = 0.01
CONTRAST_TOLERANCE = 0.01


def linear(component):
    s = component / 255.0
    return s / 12.92 if s <= 0.03928 else ((s + 0.055) / 1.055) ** 2.4


def luminance(color):
    return 0.2126 * linear((color >> 16) & 255) + 0.7152 * linear((color >> 8) & 255) + 0.0722 * linear(color & 255)


def contrast_ratio(l1, l2):
    return (max(l1, l2) + 0.05) / (min(l1, l2) + 0.05)


def rgb2lab(color):
    r, g, b = linear((color >> 16) & 255), linear((color >> 8) & 255), linear(color & 255)
    x = (r * 0.4124 + g * 0.3576 + b * 0.1805) / 0.95047
    y = (r * 0.2126 + g * 0.7152 + b * 0.0722) / 1.00000
    z = (r * 0.0193 + g * 0.1192 + b * 0.9505) / 1.08883
    f = lambda v: v ** (1 / 3) if v > 0.008856 else 7.787 * v + 16.0 / 116
    x, y, z = f(x), f(y), f(z)
    return 116 * y - 16, 500 * (x - y), 200 * (y - z)


def color_difference(c1, c2):
    """CIE94 with ATF's weights."""
    l1, l2 = rgb2lab(c1), rgb2lab(c2)
    dl, da, db = l1[0] - l2[0], l1[1] - l2[1], l1[2] - l2[2]
    ch1, ch2 = (l1[1] ** 2 + l1[2] ** 2) ** 0.5, (l2[1] ** 2 + l2[2] ** 2) ** 0.5
    dc = ch1 - ch2
    dh = da * da + db * db - dc * dc
    dh = 0 if dh < 0 else dh ** 0.5
    sc, sh = 1.0 + 0.045 * ch1, 1.0 + 0.015 * ch1
    return (dl * dl + (dc / sc) ** 2 + (dh / sh) ** 2) ** 0.5


def swatch(histogram, multiple):
    """ContrastSwatch: (background, [foregrounds]) of a histogram {colour: count}."""
    if not histogram:
        return 0x000000, [0x000000]
    if len(histogram) == 1:
        only = next(iter(histogram))
        return only, [only]
    size = sum(histogram.values())
    average = sum(luminance(c) for c in histogram) / len(histogram)
    if multiple:
        dominant = {}
        for color, count in sorted(((c, n) for c, n in histogram.items() if n >= size * COLOR_CUTOFF_PERCENTAGE), key=lambda e: -e[1]):
            for kept in dominant:
                if color_difference(kept, color) < COLOR_DIFFERENCE_LIMIT:
                    count += dominant[kept]
                    color = kept
                    break
            dominant[color] = count
        if len(dominant) < 2:
            only = next(iter(dominant))
            return only, [only]
        heap = sorted(dominant.items(), key=lambda e: -e[1])
        background = heap.pop(0)[0]
        below = luminance(background) < average
        foregrounds, priority = [], 0
        while heap and len(foregrounds) < MAX_FOREGROUND_COLOR:
            color, count = heap.pop(0)
            if below != (luminance(color) <= average):
                foregrounds.insert(priority, color)
                priority += 1
            elif count > size * COLOR_SIGNIFICANCE_PERCENTAGE:
                foregrounds.append(color)
        return background, foregrounds or [background]
    low = high = -1
    low_count = high_count = 0
    for color, count in histogram.items():
        if luminance(color) < average and count > low_count:
            low_count, low = count, color
        elif luminance(color) >= average and count > high_count:
            high_count, high = count, color
    return (high, [low]) if high_count > low_count else (low, [high])


def ratios(background, foregrounds):
    lb = luminance(background)
    return [round(contrast_ratio(lb, luminance(f)) * 100.0) / 100.0 for f in foregrounds]


# ---- The raw capture: width, height and format (and, since Android 12, a colour space) as little-endian 32-bit words,
# then the pixels, RGBA_8888 row by row (frameworks/base/cmds/screencap).


class Frame:
    def __init__(self, path):
        data = open(path, "rb").read()
        self.w, self.h, fmt = struct.unpack_from("<III", data)
        header = len(data) - self.w * self.h * 4
        if header not in (12, 16) or fmt != 1:
            raise ValueError(f"{path}: not an RGBA_8888 capture (format {fmt}, header {header} bytes)")
        if header == 16 and struct.unpack_from("<I", data, 12)[0] not in (0, 1):
            raise ValueError(f"{path}: a capture in a colour space other than sRGB")
        self.rgba = memoryview(data)[header:]
        self.words = self.rgba.cast("I")

    def histogram(self, box):
        left, top, right, bottom = max(box[0], 0), max(box[1], 0), min(box[2], self.w), min(box[3], self.h)
        counts = Counter()
        for y in range(top, bottom):
            counts.update(self.words[y * self.w + left:y * self.w + right])
        # RGBA bytes read as a little-endian word are 0xAABBGGRR; as 0xRRGGBB:
        return {((c & 255) << 16) | (c & 0xFF00) | ((c >> 16) & 255): n for c, n in counts.items()}

    def png(self, path):
        rows = b"".join(b"\x00" + self.rgba[y * self.w * 4:(y + 1) * self.w * 4].tobytes() for y in range(self.h))

        def chunk(kind, body):
            return struct.pack(">I", len(body)) + kind + body + struct.pack(">I", zlib.crc32(kind + body))

        with open(path, "wb") as out:
            out.write(b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", struct.pack(">IIBBBBB", self.w, self.h, 8, 6, 0, 0, 0))
                      + chunk(b"IDAT", zlib.compress(rows, 6)) + chunk(b"IEND", b""))


def disabled(node, parents):
    while node is not None:
        if node.get("enabled") == "false":
            return True
        node = parents.get(node)
    return False


def contrast_problems(root, parents, package, frame):
    problems = []
    screen = max((bounds(n) for n in root.iter("node") if len(bounds(n)) == 4), key=lambda b: (b[2] - b[0]) * (b[3] - b[1]), default=None)
    if screen and (screen[2] > frame.w or screen[3] > frame.h):
        return [f"the capture is {frame.w} x {frame.h}, smaller than the screen the dump describes ({screen[2]} x {screen[3]})"]
    measured = uniform = 0
    for node in root.iter("node"):
        if node.get("package") != package or disabled(node, parents) or clipped_by_scroll(node, parents):
            continue
        box = bounds(node)
        if len(box) != 4 or box[2] <= box[0] or box[3] <= box[1]:
            continue
        text = node.get("text")
        icon = node.get("clickable") == "true" and not label_text(node)
        if not text and not icon:
            continue
        # ATF's default measure, one text colour against one background: in Compose's dumps each text is a node of
        # its own, so a row's title and the line beneath it are measured apart. The measure of several text colours
        # (multiple=True) would also judge the shades at the edges of small letters, and fail text that reads well.
        background, foregrounds = swatch(frame.histogram(box), multiple=False)
        measured += 1
        if foregrounds == [background]:
            uniform += 1
            continue
        need = TEXT_RATIO if text else ICON_RATIO
        for color, ratio in zip(foregrounds, ratios(background, foregrounds)):
            if need - ratio > CONTRAST_TOLERANCE:
                what = repr(text[:40]) if text else f"icon {label_of(node)[:40]!r}"
                problems.append(f"contrast {ratio}:1 below {need}:1 at {node.get('bounds')}: {what} (#{color:06X} on #{background:06X})")
    # A frame that shows nothing where the dump has text (a protected screen captured black, a blank or a stale frame)
    # would pass every element: it fails instead.
    if measured and uniform * 2 > measured:
        problems.append(f"the capture shows one colour in {uniform} of the {measured} elements measured: blank, black or not this screen")
    return problems


def label_text(node):
    return any(n.get("text") for n in node.iter())


def check(argv):
    path, min_px = argv[0], int(argv[1])
    rest = argv[2:]
    package = rest.pop(0) if rest and not rest[0].startswith("--") else PACKAGE
    options = dict(zip(rest[::2], rest[1::2]))
    root = ET.parse(path).getroot()
    parents = {child: parent for parent in root.iter() for child in parent}
    problems = []
    for node in root.iter("node"):
        if node.get("clickable") != "true" or node.get("package") != package or clipped_by_scroll(node, parents):
            continue
        box = bounds(node)
        label = label_of(node)
        if not label:
            problems.append(f"clickable element without a label at {node.get('bounds')}")
        # Bounds are whole pixels with each edge rounded on its own, so an element of exactly 48 dp
        # can measure one pixel less at densities such as 420 dpi (CI's Pixel 7): 126 px as 125.
        if box[2] - box[0] < min_px - 1 or box[3] - box[1] < min_px - 1:
            problems.append(f"touch target smaller than 48 dp at {node.get('bounds')}: {label[:40]!r}")
    if "--frame" in options:
        frame = Frame(options["--frame"])
        if "--png" in options:
            frame.png(options["--png"])
        problems += contrast_problems(root, parents, package, frame)
    for problem in problems:
        print(f"{path}: {problem}", file=sys.stderr)
    return 1 if problems else 0


def texts(path, package):
    """The screen's texts, each with its height, numbered where one text appears more than once."""
    root = ET.parse(path).getroot()
    parents = {child: parent for parent in root.iter() for child in parent}
    seen, out = Counter(), {}
    for node in root.iter("node"):
        text = node.get("text")
        if not text or node.get("package") != package or clipped_by_scroll(node, parents):
            continue
        box = bounds(node)
        seen[text] += 1
        out[(text, seen[text])] = box[3] - box[1]
    return out


def grew(argv):
    package, small, large, small_dpi, large_dpi = argv[0], argv[1], argv[2], int(argv[3]), int(argv[4])
    before, after = texts(small, package), texts(large, package)
    dp = lambda px, dpi: px * 160 / dpi
    problems = [f"{large}: {text[:40]!r} is {dp(after[key], large_dpi):.0f} dp high at the largest text, against {dp(before[key], small_dpi):.0f} dp at the default: its box holds it"
                for key in sorted(set(before) & set(after)) for text in [key[0]]
                if dp(after[key], large_dpi) < dp(before[key], small_dpi) * 1.1]
    for problem in problems:
        print(problem, file=sys.stderr)
    if not set(before) & set(after):
        print(f"{large}: no text of {small} to compare", file=sys.stderr)
        return 1
    return 1 if problems else 0


def keys(argv):
    package, rtl, base, steps = argv[0], argv[1] == "1", argv[2], argv[3:]
    root = ET.parse(base).getroot()
    parents = {child: parent for parent in root.iter() for child in parent}
    wanted = {(bounds(n), label_of(n)) for n in root.iter("node")
              if n.get("clickable") == "true" and n.get("package") == package and n.get("enabled") != "false" and not clipped_by_scroll(n, parents)}
    order = []
    for step in steps:
        focused = [(bounds(n), label_of(n)) for n in ET.parse(step).getroot().iter("node") if n.get("focused") == "true" and n.get("package") == package]
        if not focused or (order and order[-1] == focused[-1]):
            continue
        # Back at an element it reached before: the focus has gone round, from the last element to the first.
        if focused[-1] in order:
            break
        order.append(focused[-1])
    problems = [f"{base}: the keyboard never reaches {label[:40]!r} at {list(box)}" for box, label in sorted(wanted) if (box, label) not in order]
    labels = dict(wanted)
    wanted = labels
    reached = [box for box, label in order if (box, label) in labels.items()]
    # The first key both leaves touch mode, which focuses the screen's first element, and moves the focus on: the walk
    # is a circle, read from its element that comes first in reading order.
    if reached:
        first = min(reached, key=lambda b: (b[1], -b[2] if rtl else b[0]))
        reached = reached[reached.index(first):] + reached[:reached.index(first)]
    for a, b in zip(reached, reached[1:]):
        same_row = abs(a[1] - b[1]) < (a[3] - a[1]) / 2
        backwards = (b[0] > a[0]) if rtl else (b[0] < a[0])
        if b[1] < a[1] - 8 and not same_row or same_row and backwards:
            problems.append(f"{base}: the keyboard goes from {wanted[a][:30]!r} back to {wanted[b][:30]!r}")
    for problem in problems:
        print(problem, file=sys.stderr)
    return 1 if problems else 0


if __name__ == "__main__":
    if sys.argv[1] == "grew":
        sys.exit(grew(sys.argv[2:]))
    if sys.argv[1] == "keys":
        sys.exit(keys(sys.argv[2:]))
    sys.exit(check(sys.argv[1:]))
