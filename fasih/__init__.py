"""fasih (فصيح, "eloquent / clear") — a static linter for LLM agents and
bilingual (Arabic/English) pipelines.

Core reliability checks catch the failure modes that survive a passing test
suite — guardrails that fail open, orphaned tools, evals that grade structure
instead of meaning, hardcoded secrets. The optional Arabic module checks the
production pipeline layer that model-level benchmarks don't: JSON encoding,
Arabic-Indic numeral parsing, and more.
"""

from .arabic import (
    isolate,
    normalize_arabic,
    normalize_arabic_indic_digits,
    strip_tashkeel,
    strip_tatweel,
    wrap_ltr,
)

__version__ = "0.3.2"
__all__ = [
    "normalize_arabic",
    "normalize_arabic_indic_digits",
    "strip_tashkeel",
    "strip_tatweel",
    "wrap_ltr",
    "isolate",
    "__version__",
]
