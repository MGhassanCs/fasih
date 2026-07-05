"""fasih (فصيح, "eloquent / clear") — a static linter for LLM agents and
bilingual (Arabic/English) pipelines.

Core reliability checks catch the failure modes that survive a passing test
suite — guardrails that fail open, orphaned tools, evals that grade structure
instead of meaning, hardcoded secrets. The optional Arabic module checks the
production pipeline layer that model-level benchmarks don't: JSON encoding,
Arabic-Indic numeral parsing, and more.
"""

from .arabic import normalize_arabic_indic_digits

__version__ = "0.1.0"
__all__ = ["normalize_arabic_indic_digits", "__version__"]
