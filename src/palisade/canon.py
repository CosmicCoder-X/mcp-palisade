"""Text forensics and canonicalisation.

Tool descriptions are read by two very different audiences: a human skimming an
approval dialog, and a language model that consumes every byte. Anything that
renders differently for those two audiences is an attack primitive, so this
module's job is to find text that is *present but not visible*, decode it where
it carries a payload, and produce a stable hash of what a server actually said
so that later changes can be detected.
"""

from __future__ import annotations

import hashlib
import json
import re
import unicodedata
from collections.abc import Iterable
from dataclasses import dataclass
from typing import Any

# --------------------------------------------------------------------------
# Character classes
# --------------------------------------------------------------------------

# U+E0000..U+E007F. U+E0020..U+E007E are a shadow copy of printable ASCII, which
# makes this block a ready-made channel for smuggling instructions that no
# terminal, browser or approval dialog will render.
TAG_BLOCK_START = 0xE0000
TAG_BLOCK_END = 0xE007F

# Variation selectors carry no glyph of their own. There are exactly 256 of them
# across the two ranges, so an attacker can encode arbitrary bytes one-to-one.
VS_LOW_START, VS_LOW_END = 0xFE00, 0xFE0F  # VS1..VS16   -> bytes 0x00..0x0F
VS_HIGH_START, VS_HIGH_END = 0xE0100, 0xE01EF  # VS17..VS256 -> bytes 0x10..0xFF

ZERO_WIDTH = {
    0x200B: "ZERO WIDTH SPACE",
    0x200C: "ZERO WIDTH NON-JOINER",
    0x200D: "ZERO WIDTH JOINER",
    0x2060: "WORD JOINER",
    0xFEFF: "ZERO WIDTH NO-BREAK SPACE (BOM)",
    0x00AD: "SOFT HYPHEN",
    0x180E: "MONGOLIAN VOWEL SEPARATOR",
}

BIDI_CONTROLS = {
    0x202A: "LEFT-TO-RIGHT EMBEDDING",
    0x202B: "RIGHT-TO-LEFT EMBEDDING",
    0x202C: "POP DIRECTIONAL FORMATTING",
    0x202D: "LEFT-TO-RIGHT OVERRIDE",
    0x202E: "RIGHT-TO-LEFT OVERRIDE",
    0x2066: "LEFT-TO-RIGHT ISOLATE",
    0x2067: "RIGHT-TO-LEFT ISOLATE",
    0x2068: "FIRST STRONG ISOLATE",
    0x2069: "POP DIRECTIONAL ISOLATE",
}

# Scripts whose letterforms overlap heavily with Latin. Mixing any of these with
# Latin inside a single word is the classic homoglyph construction.
_SCRIPT_RANGES: list[tuple[str, int, int]] = [
    ("Latin", 0x0041, 0x005A),
    ("Latin", 0x0061, 0x007A),
    ("Latin", 0x00C0, 0x024F),
    ("Greek", 0x0370, 0x03FF),
    ("Greek", 0x1F00, 0x1FFF),
    ("Cyrillic", 0x0400, 0x052F),
    ("Armenian", 0x0530, 0x058F),
    ("Hebrew", 0x0590, 0x05FF),
    ("Arabic", 0x0600, 0x06FF),
    ("Cherokee", 0x13A0, 0x13FF),
]


class InvisibleKind(str):
    TAG = "tag-block"
    VARIATION_SELECTOR = "variation-selector"
    ZERO_WIDTH = "zero-width"
    BIDI = "bidi-control"
    OTHER_FORMAT = "other-format"
    PRIVATE_USE = "private-use"


@dataclass(frozen=True)
class InvisibleRun:
    """A maximal run of adjacent non-rendering characters."""

    kind: str
    start: int
    end: int
    codepoints: tuple[int, ...]

    @property
    def length(self) -> int:
        return len(self.codepoints)

    def names(self) -> list[str]:
        return [describe_codepoint(cp) for cp in self.codepoints]


def describe_codepoint(cp: int) -> str:
    if TAG_BLOCK_START <= cp <= TAG_BLOCK_END:
        shadow = cp - TAG_BLOCK_START
        if 0x20 <= shadow <= 0x7E:
            return f"U+{cp:04X} TAG {chr(shadow)!r}"
        return f"U+{cp:04X} TAG CONTROL"
    if cp in ZERO_WIDTH:
        return f"U+{cp:04X} {ZERO_WIDTH[cp]}"
    if cp in BIDI_CONTROLS:
        return f"U+{cp:04X} {BIDI_CONTROLS[cp]}"
    try:
        return f"U+{cp:04X} {unicodedata.name(chr(cp))}"
    except ValueError:
        return f"U+{cp:04X} <unnamed>"


def classify_codepoint(cp: int) -> str | None:
    """Return the invisibility class of ``cp``, or ``None`` if it renders."""
    if TAG_BLOCK_START <= cp <= TAG_BLOCK_END:
        return InvisibleKind.TAG
    if VS_LOW_START <= cp <= VS_LOW_END or VS_HIGH_START <= cp <= VS_HIGH_END:
        return InvisibleKind.VARIATION_SELECTOR
    if cp in ZERO_WIDTH:
        return InvisibleKind.ZERO_WIDTH
    if cp in BIDI_CONTROLS:
        return InvisibleKind.BIDI
    ch = chr(cp)
    category = unicodedata.category(ch)
    if category == "Cf":
        return InvisibleKind.OTHER_FORMAT
    if category == "Co":
        return InvisibleKind.PRIVATE_USE
    return None


def find_invisibles(text: str) -> list[InvisibleRun]:
    """Group every non-rendering character in ``text`` into contiguous runs."""
    runs: list[InvisibleRun] = []
    current_kind: str | None = None
    start = 0
    buf: list[int] = []

    for idx, ch in enumerate(text):
        kind = classify_codepoint(ord(ch))
        if kind is None:
            if buf and current_kind is not None:
                runs.append(InvisibleRun(current_kind, start, idx, tuple(buf)))
            buf, current_kind = [], None
            continue
        if kind != current_kind:
            if buf and current_kind is not None:
                runs.append(InvisibleRun(current_kind, start, idx, tuple(buf)))
            buf, current_kind, start = [], kind, idx
        buf.append(ord(ch))

    if buf and current_kind is not None:
        runs.append(InvisibleRun(current_kind, start, len(text), tuple(buf)))
    return runs


# --------------------------------------------------------------------------
# Payload decoding
# --------------------------------------------------------------------------


def decode_tag_block(text: str) -> str:
    """Recover the ASCII hidden in Unicode tag characters.

    Every tag character in ``U+E0020..U+E007E`` is the invisible twin of a
    printable ASCII character, so decoding is a straight subtraction. A server
    with nothing to hide never emits these.
    """
    out: list[str] = []
    for ch in text:
        cp = ord(ch)
        if TAG_BLOCK_START <= cp <= TAG_BLOCK_END:
            shadow = cp - TAG_BLOCK_START
            if 0x20 <= shadow <= 0x7E:
                out.append(chr(shadow))
    return "".join(out)


def decode_variation_selectors(text: str) -> bytes:
    """Recover bytes encoded as a variation-selector sequence."""
    out = bytearray()
    for ch in text:
        cp = ord(ch)
        if VS_LOW_START <= cp <= VS_LOW_END:
            out.append(cp - VS_LOW_START)
        elif VS_HIGH_START <= cp <= VS_HIGH_END:
            out.append(cp - VS_HIGH_START + 0x10)
    return bytes(out)


def decoded_payloads(text: str) -> list[tuple[str, str]]:
    """Return ``(channel, decoded_text)`` for every channel that yields content."""
    payloads: list[tuple[str, str]] = []

    tag_text = decode_tag_block(text)
    if tag_text.strip():
        payloads.append((InvisibleKind.TAG, tag_text))

    vs_bytes = decode_variation_selectors(text)
    if vs_bytes:
        try:
            decoded = vs_bytes.decode("utf-8")
        except UnicodeDecodeError:
            decoded = vs_bytes.decode("latin-1", errors="replace")
        # A handful of selectors is ordinary emoji styling; a sentence is not.
        if len(vs_bytes) >= 8 and sum(c.isprintable() for c in decoded) >= len(decoded) * 0.8:
            payloads.append((InvisibleKind.VARIATION_SELECTOR, decoded))

    return payloads


# --------------------------------------------------------------------------
# Rendering
# --------------------------------------------------------------------------

_VISUALISE_LABELS = {
    0x200B: "ZWSP",
    0x200C: "ZWNJ",
    0x200D: "ZWJ",
    0x2060: "WJ",
    0xFEFF: "BOM",
    0x00AD: "SHY",
    0x202A: "LRE",
    0x202B: "RLE",
    0x202C: "PDF",
    0x202D: "LRO",
    0x202E: "RLO",
    0x2066: "LRI",
    0x2067: "RLI",
    0x2068: "FSI",
    0x2069: "PDI",
}


def visualize(text: str, max_len: int = 0) -> str:
    """Render ``text`` with every invisible character made explicit.

    Used in reports and rug-pull diffs so a reviewer sees what the model sees
    rather than what their terminal chooses to draw.
    """
    out: list[str] = []
    for ch in text:
        cp = ord(ch)
        if cp in _VISUALISE_LABELS:
            out.append(f"<{_VISUALISE_LABELS[cp]}>")
        elif TAG_BLOCK_START <= cp <= TAG_BLOCK_END:
            shadow = cp - TAG_BLOCK_START
            out.append(f"<TAG:{chr(shadow)}>" if 0x20 <= shadow <= 0x7E else "<TAG>")
        elif VS_LOW_START <= cp <= VS_LOW_END or VS_HIGH_START <= cp <= VS_HIGH_END:
            out.append("<VS>")
        elif classify_codepoint(cp) is not None:
            out.append(f"<U+{cp:04X}>")
        else:
            out.append(ch)
    rendered = "".join(out)
    if max_len and len(rendered) > max_len:
        return rendered[:max_len] + f"... (+{len(rendered) - max_len} chars)"
    return rendered


# --------------------------------------------------------------------------
# Script analysis
# --------------------------------------------------------------------------


def script_of(ch: str) -> str | None:
    cp = ord(ch)
    for name, lo, hi in _SCRIPT_RANGES:
        if lo <= cp <= hi:
            return name
    return None


_WORD_RE = re.compile(r"[^\W\d_]+", re.UNICODE)


@dataclass(frozen=True)
class MixedScriptWord:
    word: str
    start: int
    end: int
    scripts: tuple[str, ...]


def find_mixed_script_words(text: str) -> list[MixedScriptWord]:
    """Find words built from more than one script.

    A tool named ``ѕend_email`` (Cyrillic ``ѕ``) is indistinguishable from
    ``send_email`` on screen but is a different string to every allow-list,
    pin store and equality check in the stack.
    """
    hits: list[MixedScriptWord] = []
    for m in _WORD_RE.finditer(text):
        word = m.group()
        scripts = {s for s in (script_of(c) for c in word) if s}
        if len(scripts) > 1:
            hits.append(MixedScriptWord(word, m.start(), m.end(), tuple(sorted(scripts))))
    return hits


# --------------------------------------------------------------------------
# Canonicalisation and hashing
# --------------------------------------------------------------------------


def canonical_json(value: Any) -> str:
    """Deterministic JSON: sorted keys, no incidental whitespace."""
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def digest(*parts: str) -> str:
    h = hashlib.sha256()
    for p in parts:
        h.update(p.encode("utf-8"))
        h.update(b"\x00")
    return h.hexdigest()


def normalize_for_display(text: str) -> str:
    """Strip invisibles and collapse whitespace.

    This is roughly what a human reviewer perceives. Comparing it against the
    raw string is how we measure how much of a description is hidden.
    """
    kept = [ch for ch in text if classify_codepoint(ord(ch)) is None]
    return re.sub(r"\s+", " ", "".join(kept)).strip()


def hidden_ratio(text: str) -> float:
    """Fraction of characters that a reviewer will never see."""
    if not text:
        return 0.0
    invisible = sum(1 for ch in text if classify_codepoint(ord(ch)) is not None)
    return invisible / len(text)


def iter_text_fields(obj: Any, prefix: str = "") -> Iterable[tuple[str, str]]:
    """Yield ``(json_path, string)`` for every string anywhere in ``obj``.

    Rules use this to reach text an author may have assumed nobody reads, such
    as ``inputSchema.properties.notes.description``.
    """
    if isinstance(obj, str):
        if obj:
            yield prefix or "$", obj
    elif isinstance(obj, dict):
        for k, v in obj.items():
            yield from iter_text_fields(v, f"{prefix}.{k}" if prefix else k)
    elif isinstance(obj, list):
        for i, v in enumerate(obj):
            yield from iter_text_fields(v, f"{prefix}[{i}]")
