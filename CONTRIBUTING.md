# Contributing to fasih

Thanks for your interest. `fasih` aims to be small, precise, and dependency-light.

## Setup

```bash
python -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
pytest -q
```

## The invariants

Two things must always hold, and CI enforces both:

1. **`fasih` scans its own source with zero findings.**
   `fasih scan fasih --arabic --fail-on low` must exit 0. Precision is the whole
   value of the tool — a rule that fires on clean code is a bug in the rule.
2. **Every rule has tests**, including a "does not fire" case. The bundled
   fixture (`examples/broken_agent_example.py`) plants exactly one of every bug
   and then fixes each; `pytest` asserts the exact finding set.

## Adding a rule

- Put per-file analyzers in `fasih/analyzers/`, Arabic ones in `fasih/arabic/`.
- Subclass `Analyzer` (or implement `check`/`collect`/`finalize`); return
  `Finding`s. Register it in `fasih/rules_engine.py`.
- Bias hard toward **precision over recall**. When a match is ambiguous, don't
  flag. Scope "already handled" suppression to the enclosing function, not the
  file (see `AR-NUMERAL` / `AR-NORMALIZE`).
- If the fix is mechanical, attach a byte-span auto-fix (see `fasih/fixes.py`).
- Add the broken + fixed pair to the fixture and a unit test.

## Style

- Standard library first; new runtime dependencies need a strong reason.
- No network calls, no code execution of scanned files, no model/AI calls.
- Keep invisible/combining Unicode out of source — build tables from code
  points (`chr(0x...)`), as `fasih/arabic/normalize.py` does.
