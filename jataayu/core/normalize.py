"""
Jataayu input normalization & payload decoding
==============================================
The literature's headline indictment of pattern/classifier guards (Cisco/RobustIntelligence
on Prompt-Guard; arXiv 2504.11168 on the whole commercial guardrail family) is that a *trivial*
input transform — spacing every character, homoglyph substitution, zero-width injection, leetspeak,
or base64-wrapping — defeats them near-100%, regardless of how many patterns they carry.

jataayu's own benchmark reproduced this exactly: space-out evasion 0.97, leetspeak 0.92, because
`pattern.search` ran on the raw string with **no normalization pass**.

This module closes that gap cheaply and deterministically. It produces a small set of *normalized
views* of the input plus any *decoded payloads* hidden inside it. The fast path scans the regex
catalog over every view and takes the max score, so an attacker must defeat the patterns in EVERY
view simultaneously — spacing-out no longer helps, because the deshattered view re-exposes the
trigger tokens.

Design constraints:
  - No new dependencies (stdlib only).
  - Cheap: views are only generated when a cheap heuristic says they could matter.
  - Conservative: views are *additional* scan surfaces; they only ever raise a score. Benign-FPR
    impact is measured in eval/run_injection_bench.py (deleet is the riskiest view and is gated).
"""
from __future__ import annotations

import base64
import binascii
import re
import unicodedata
import urllib.parse

# ---------------------------------------------------------------------------
# Homoglyph / confusable folding
# ---------------------------------------------------------------------------
# Curated map of the most common Latin-confusable codepoints (Cyrillic, Greek, and a few
# symbol lookalikes) -> ASCII. NFKC already folds fullwidth/compatibility forms, so this map
# only needs to cover same-glyph-different-script confusables that NFKC leaves alone.
_CONFUSABLES: dict[str, str] = {
    # Cyrillic -> Latin
    "а": "a", "е": "e", "о": "o", "р": "p", "с": "c",
    "у": "y", "х": "x", "к": "k", "м": "m", "н": "h",
    "т": "t", "в": "b", "і": "i", "ј": "j", "ѕ": "s", "ԁ": "d",
    "А": "A", "Е": "E", "О": "O", "Р": "P", "С": "C",
    "У": "Y", "Х": "X", "К": "K", "М": "M", "Н": "H",
    "Т": "T", "В": "B", "І": "I", "Ј": "J",
    # Greek -> Latin
    "ο": "o", "α": "a", "ν": "v", "ρ": "p", "τ": "t",
    "υ": "u", "χ": "x", "ι": "i", "κ": "k",
    "Α": "A", "Β": "B", "Ε": "E", "Ζ": "Z", "Η": "H",
    "Ι": "I", "Κ": "K", "Μ": "M", "Ν": "N", "Ο": "O",
    "Ρ": "P", "Τ": "T", "Υ": "Y", "Χ": "X",
}
_CONFUSABLE_TABLE = {ord(k): v for k, v in _CONFUSABLES.items()}

# Zero-width / invisible separators an attacker inserts between characters to break word matching.
_ZERO_WIDTH = dict.fromkeys(
    [0x200B, 0x200C, 0x200D, 0x2060, 0xFEFF, 0x00AD, 0x034F, 0x180E]
    + list(range(0x200E, 0x2010))     # LRM/RLM and bidi marks
    + list(range(0x202A, 0x202F))     # bidi embedding/override
    + list(range(0x2066, 0x206A))     # bidi isolates
    + list(range(0xE0000, 0xE0080)),  # Unicode tag chars
    "",
)

_LEET_TABLE = str.maketrans({"@": "a", "3": "e", "1": "i", "0": "o", "5": "s", "$": "s", "!": "i"})


def _strip_invisibles(text: str) -> str:
    return text.translate(_ZERO_WIDTH)


def fold_confusables(text: str) -> str:
    """NFKC-normalize, strip invisibles, and fold homoglyph/confusable characters to ASCII."""
    text = _strip_invisibles(text)
    text = unicodedata.normalize("NFKC", text)
    return text.translate(_CONFUSABLE_TABLE)


# ---------------------------------------------------------------------------
# Deshatter — invert character-spacing attacks ("i g n o r e   a l l")
# ---------------------------------------------------------------------------
# The canonical space-out attack is " ".join(list(s)): every character, including the original
# spaces, becomes separated by a space. Original word boundaries therefore survive as runs of 2+
# spaces. We invert it by splitting on 2+ whitespace (word boundaries) and removing the single
# spaces inside each chunk.
_SHATTER_RUN = re.compile(r"(?:\S\s){4,}\S")


def _looks_shattered(text: str) -> bool:
    """Cheap heuristic: does the text contain a run of single chars separated by whitespace?"""
    return bool(_SHATTER_RUN.search(text))


def deshatter(text: str) -> str:
    """Collapse intra-word character spacing, preserving runs of 2+ spaces as word boundaries.

    The shatter decision is GLOBAL: if a large fraction of the whole input's space-separated
    tokens are single characters, the input is a character-spacing attack and every chunk is
    collapsed (so short words like "all"/"and" reconstruct too). Otherwise the text is returned
    unchanged, so ordinary prose is never mangled.
    """
    text = _strip_invisibles(text)
    toks_all = [t for t in text.split(" ") if t]
    if len(toks_all) < 6:
        return text
    singles = sum(1 for t in toks_all if len(t) == 1)
    if singles < len(toks_all) * 0.6:
        return text  # not globally shattered -> leave prose alone

    # Globally shattered: split on word boundaries (runs of 2+ whitespace / newlines), then join
    # each chunk's characters tight.
    chunks = re.split(r"\s{2,}|\n", text)
    return " ".join("".join(chunk.split(" ")) for chunk in chunks if chunk.strip())


# ---------------------------------------------------------------------------
# Decode-and-rescan — pull plaintext out of base64 / hex / url-encoded payloads
# ---------------------------------------------------------------------------
_B64_BLOB = re.compile(r"(?<![A-Za-z0-9+/=])([A-Za-z0-9+/]{16,}={0,2})(?![A-Za-z0-9+/=])")
_HEX_BLOB = re.compile(r"(?:\\x[0-9a-fA-F]{2}|[0-9a-fA-F]{2}\s?){8,}")
_HEX_ESCAPE = re.compile(r"\\x([0-9a-fA-F]{2})")
_PRINTABLE_RATIO = 0.85


def _is_mostly_printable(s: str) -> bool:
    if not s:
        return False
    printable = sum(1 for c in s if c.isprintable() or c in "\n\t ")
    return printable / len(s) >= _PRINTABLE_RATIO


def decode_payloads(text: str, max_depth: int = 2) -> list[str]:
    """
    Recursively extract decoded plaintext from base64 / hex / url-encoded blobs in `text`.
    Returns the list of decoded fragments that look like real text (so the fast path can re-scan
    them). Depth-limited to bound cost and prevent decode bombs.
    """
    found: list[str] = []
    if max_depth <= 0 or not text:
        return found

    # URL-encoding (cheap, whole-string)
    if "%" in text:
        try:
            unq = urllib.parse.unquote(text)
            if unq != text and _is_mostly_printable(unq):
                found.append(unq)
        except Exception:
            pass

    # \xNN hex escapes
    if "\\x" in text:
        try:
            dec = _HEX_ESCAPE.sub(lambda m: chr(int(m.group(1), 16)), text)
            if dec != text and _is_mostly_printable(dec):
                found.append(dec)
        except Exception:
            pass

    # base64 blobs
    for m in _B64_BLOB.finditer(text):
        blob = m.group(1)
        if len(blob) % 4 != 0:
            continue
        try:
            raw = base64.b64decode(blob, validate=True)
            dec = raw.decode("utf-8", errors="strict")
        except (binascii.Error, ValueError, UnicodeDecodeError):
            continue
        if _is_mostly_printable(dec) and dec.strip():
            found.append(dec)

    # contiguous hex strings (e.g. 69676e6f7265 = "ignore")
    for m in _HEX_BLOB.finditer(text):
        hexstr = re.sub(r"[\\x\s]", "", m.group(0))
        if len(hexstr) % 2 != 0 or len(hexstr) < 8:
            continue
        try:
            dec = bytes.fromhex(hexstr).decode("utf-8", errors="strict")
        except (ValueError, UnicodeDecodeError):
            continue
        if _is_mostly_printable(dec) and dec.strip():
            found.append(dec)

    # Recurse one level into what we just decoded (nested encodings).
    nested: list[str] = []
    for frag in found:
        nested.extend(decode_payloads(frag, max_depth=max_depth - 1))
    return found + nested


# ---------------------------------------------------------------------------
# The public entry point used by the fast path
# ---------------------------------------------------------------------------
def normalized_views(text: str, *, include_deleet: bool = True) -> list[str]:
    """
    Return a deduplicated list of strings the fast path should scan: the original text, a
    confusable-folded view, a deshattered view (only if the input looks character-spaced), an
    optional de-leet view, and any decoded payloads hidden inside the input.

    Each view is an *additional* scan surface — scores are taken as the max across views, so a
    transform that hides the payload in one view (e.g. spacing) is re-exposed in another.
    """
    views: list[str] = [text]

    folded = fold_confusables(text)
    if folded != text:
        views.append(folded)

    # Deshatter both the raw and folded forms (folding first catches homoglyph+spacing combos).
    for base in (text, folded):
        if _looks_shattered(base):
            ds = deshatter(base)
            if ds and ds not in views:
                views.append(ds)

    if include_deleet:
        # De-leet the folded view; only adds value when leet glyphs are present.
        if any(c in folded for c in "@310$!"):
            deleet = folded.translate(_LEET_TABLE)
            if deleet not in views:
                views.append(deleet)

    # Decoded payloads (each becomes its own scan surface).
    for frag in decode_payloads(text):
        if frag not in views:
            views.append(frag)

    return views
