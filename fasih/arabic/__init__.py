"""Arabic / bilingual pipeline-integration checks and utilities.

The one export worth importing directly is the digit normalizer:

    from fasih import normalize_arabic_indic_digits
"""

from .numeral_check import normalize_arabic_indic_digits

__all__ = ["normalize_arabic_indic_digits"]
