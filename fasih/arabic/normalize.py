"""Arabic text normalization -- the toolkit AR-NORMALIZE points at.

The single most common Arabic-pipeline bug is comparing user text against a
fixed Arabic string and getting a silent mismatch, because the "same" word can
be written many ways: alef variants (U+0623/0625/0622/0671 vs bare alef U+0627),
alef-maqsura vs ya (U+0649 vs U+064A), ta-marbuta vs ha (U+0629 vs U+0647),
hamza carriers (U+0624/0626), the tatweel/kashida elongation (U+0640), combining
diacritics (harakat/tanwin), and zero-width / directional marks.

:func:`normalize_arabic` folds all of these (and Arabic-Indic digits) into one
canonical form. Apply it to *both* sides before comparing, matching, keying a
dict, or deduplicating.

The mapping tables are built from integer code points rather than pasted Arabic
so that combining/invisible characters can't creep into the source unseen --
every entry is auditable by its U+XXXX value.
"""

from __future__ import annotations

from .numeral_check import normalize_arabic_indic_digits

TATWEEL = 0x0640

# Combining diacritics: harakat, tanwin, superscript alef, Quranic marks.
_DIACRITIC_RANGES = (
    (0x0610, 0x061A),  # Arabic signs / honorifics
    (0x064B, 0x065F),  # fathatan..wavy hamza below (harakat + tanwin)
    (0x0670, 0x0670),  # superscript alef
    (0x06D6, 0x06DC),  # Quranic annotation marks
    (0x06DF, 0x06E8),  # Quranic annotation marks
    (0x06EA, 0x06ED),  # Quranic annotation marks
)
_DIACRITICS = {cp for lo, hi in _DIACRITIC_RANGES for cp in range(lo, hi + 1)}

# Letter unification: source code point -> canonical code point.
_LETTER_MAP = {
    0x0622: 0x0627,  # alef with madda        -> alef
    0x0623: 0x0627,  # alef with hamza above  -> alef
    0x0625: 0x0627,  # alef with hamza below  -> alef
    0x0671: 0x0627,  # alef wasla             -> alef
    0x0649: 0x064A,  # alef maqsura           -> ya
    0x0629: 0x0647,  # ta marbuta             -> ha
    0x0624: 0x0648,  # waw with hamza         -> waw
    0x0626: 0x064A,  # ya with hamza          -> ya
}

# Zero-width & directional marks (removed); non-breaking spaces (-> ASCII space).
_REMOVE = {0x200B, 0x200C, 0x200D, 0x200E, 0x200F, 0x061C, 0xFEFF, TATWEEL}
_SPACES = {0x00A0: 0x0020, 0x202F: 0x0020}

# One combined translate table for normalize_arabic(): remove diacritics + marks,
# fold spaces, unify letters -- all in a single pass.
_NORMALIZE_TABLE = {}
_NORMALIZE_TABLE.update({cp: None for cp in _DIACRITICS})
_NORMALIZE_TABLE.update({cp: None for cp in _REMOVE})
_NORMALIZE_TABLE.update(_SPACES)
_NORMALIZE_TABLE.update(_LETTER_MAP)

_TASHKEEL_TABLE = {cp: None for cp in _DIACRITICS}


def strip_tashkeel(text: str) -> str:
    """Remove Arabic diacritics (harakat, tanwin, superscript alef, Quranic
    marks), leaving the bare consonant skeleton."""
    return text.translate(_TASHKEEL_TABLE)


def strip_tatweel(text: str) -> str:
    """Remove the tatweel / kashida elongation character (U+0640)."""
    return text.replace(chr(TATWEEL), "")


def normalize_arabic(text: str) -> str:
    """Fold Arabic text to a canonical form for matching/dedup: strip diacritics,
    tatweel and zero-width marks, unify alef/ya/ta-marbuta/hamza variants, and
    convert Arabic-Indic digits to ASCII. Apply to *both* sides before comparing
    so that spelling variants of the same word collapse to one form."""
    return normalize_arabic_indic_digits(text.translate(_NORMALIZE_TABLE))
