"""Arabic / bilingual pipeline-integration checks and utilities.

The utilities worth importing directly:

    from fasih import normalize_arabic, normalize_arabic_indic_digits
    from fasih import strip_tashkeel, strip_tatweel
"""

from .numeral_check import normalize_arabic_indic_digits
from .normalize import normalize_arabic, strip_tashkeel, strip_tatweel
from .bidi import wrap_ltr, isolate

__all__ = [
    "normalize_arabic_indic_digits",
    "normalize_arabic",
    "strip_tashkeel",
    "strip_tatweel",
    "wrap_ltr",
    "isolate",
]
