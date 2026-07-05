# fasih

**فصيح — "eloquent, clear."** A static linter for LLM agents and bilingual
(Arabic/English) pipelines. It catches the reliability bugs that survive a
green test suite, and the Arabic pipeline bugs that model-level benchmarks
never look at.

`fasih` is pure AST/regex analysis: no API calls, no model inference, no
network. It runs in well under a second on a laptop and has one runtime
dependency (`rich`, for pretty output).

---

## Why this exists

Two problems, one tool.

**1. Agent reliability failures are invisible to unit tests.** The most
expensive agent bugs are not crashes — they are an agent that keeps *running*
while doing the wrong thing. A moderation guardrail wrapped in a `try/except`
that swallows the error and lets the request through. A fetcher that was never
wired into the pipeline, so the model quietly answers with missing data. An
eval harness that checks the *shape* of a response and reports green while
answer quality regresses. These are the findings that come out of real agent
audits, and none of them fail a test. `fasih` encodes them as lint rules.

**2. Arabic breaks at the pipeline layer, not (only) the model layer.** There
is active, serious work on whether models can *reason and call tools* in Arabic
(see [Positioning](#positioning-the-layer-nobody-else-lints) below). But a
bilingual agent can be served by a perfectly capable model and still ship
broken Arabic because of the plumbing *around* the model:

- `json.dumps(payload)` serializes Arabic as `\uXXXX` escapes, because
  `ensure_ascii` defaults to `True` — so the WhatsApp webhook / log / saved
  file carries mangled text.
- `int(message.text)` *looks* safe — Python even parses `٢٥` as `25` — but
  `float("٣٫٥")` and `int("١٬٠٠٠")` raise on the Arabic decimal/thousands
  separators, and an ASCII-only `[0-9]` regex silently drops Arabic digits
  with no error at all. Bugs that only ever surface for Arabic users.

That plumbing layer is exactly where I've shipped production bilingual agents
(WhatsApp lead-qualification, Arabic/English quotations), and it's the layer
nobody else is linting.

---

## Install

```bash
pip install -e .          # from a clone
# or, once published:
# pip install fasih
```

Python 3.9+.

## Usage

```bash
fasih scan path/to/project                 # core reliability checks
fasih scan path/to/project --arabic        # + Arabic/bilingual pipeline checks
fasih scan path/to/project -v              # add why-it-matters + fix hints
fasih scan path/to/project --format markdown --out report.md
fasih scan path/to/project --format json   # machine-readable
fasih scan path/to/project --fail-on high  # exit 1 in CI on high+ findings
```

Try it on the bundled fixture, which plants one of every bug and then fixes
each one:

```bash
fasih scan examples/broken_agent_example.py --arabic -v
```

## What it checks

### Core reliability (always on)

| Rule | Severity | Catches |
| --- | --- | --- |
| `FAIL-OPEN-GUARD` | high | A safety/moderation/policy call wrapped in a broad `try/except` that swallows the error and continues — the guardrail fails *open*. |
| `ORPHANED-TOOL` | medium | A tool/fetcher defined but never invoked or registered anywhere in the project (references by name-string count as use, to avoid false positives). |
| `STRUCTURE-NOT-SEMANTICS` | medium | An eval/grader that only checks output shape (type, keys, length) and never compares against an expected/reference answer. |
| `HARDCODED-SECRET` | critical / high | Provider API keys and PEM private-key blocks (critical), or a secret-named variable assigned a literal (high). |

### Arabic / bilingual pipeline (`--arabic`)

| Rule | Severity | Catches |
| --- | --- | --- |
| `AR-ENCODING` | medium | `json.dumps()`/`dump()` without `ensure_ascii=False`, which escapes Arabic to `\uXXXX`. |
| `AR-NUMERAL` | medium | `int()`/`float()` on user-supplied text without normalizing Arabic-Indic digits (`٠-٩`, `۰-۹`) first. |

The Arabic module also ships a genuinely useful runtime utility:

```python
import re
from fasih import normalize_arabic_indic_digits

re.findall(r"[0-9]+", "٢٥")                                  # -> []       (silent data loss!)
re.findall(r"[0-9]+", normalize_arabic_indic_digits("٢٥"))   # -> ["25"]
```

## Positioning: the layer nobody else lints

`fasih` is **not** an Arabic-language-model benchmark. Arabic NLP evaluation is
a serious, active field, but every strand of it sits at a different layer than
`fasih`:

- **General Arabic understanding** — [ArabicMMLU](https://arxiv.org/abs/2402.12840),
  [BALSAM](https://arxiv.org/abs/2507.22603),
  [DialectalArabicMMLU](https://arxiv.org/abs/2510.27543). These ask *can the
  model understand and answer in Arabic.*
- **Arabic agentic / tool-calling** — [Arabic Prompts with English Tools: A
  Benchmark](https://arxiv.org/abs/2601.05101) (Jan 2026) was the first
  benchmark for Arabic tool-calling and reported a measurable accuracy drop
  (~5–10%) when the same agent is prompted in Arabic; a
  [March 2026 follow-up](https://arxiv.org/abs/2603.16901) closed most of that
  gap with fine-tuning. Even Arabic *number reading* has its own model
  benchmark, [ArabicNumBench](https://arxiv.org/abs/2602.18776). These ask
  *can the model call the function / read the number in Arabic.*
- **Closed commercial platforms** — [Arabic.ai](https://arabic.ai/) ships
  turnkey Arabic-first agentic workflows (KYC, document processing). It's a
  product, not something you run against your own pipeline.
- **RTL dev tooling** — [RTLify](https://www.rtlify.com/) lints the RTL bugs AI
  coding agents introduce in **CSS** (`margin-left` vs `margin-inline-start`).

That last one is the closest neighbour, and the contrast is the whole point:
RTLify lints the **presentation** layer; `fasih` lints the **data** layer. A
top-of-leaderboard model, wrapped in a pipeline that calls `json.dumps` without
`ensure_ascii=False` and `int()` on `٢٥`, still ships broken Arabic — and none
of the work above catches that, because it isn't a model problem. It's a
plumbing problem, and plumbing is what linters are for.

## Design notes

- `orphaned_tools` is whole-project on purpose (two-pass: `collect()` per file,
  `finalize()` once) because a tool is usually *defined* in one file and
  *invoked* in another.
- The "already normalizes" suppression in `AR-NUMERAL` is scoped to the
  enclosing function, not the whole file, so an unrelated function elsewhere
  that happens to call a normalizer can't mask a real bug.
- `STRUCTURE-NOT-SEMANTICS` treats a comparison against a long string literal
  **or** an `expected_*`/`reference`/`ground_truth`-style variable as a real
  semantic check, and won't flag graders that do either.
- Every rule is tuned for precision: `fasih scan fasih --arabic` on its own
  source reports **zero** findings, and CI enforces that.

## Roadmap

- [ ] Guardrail language-parity check (run a guardrail in EN vs AR, diff the
      decision) — needs a model in the loop, so it's opt-in.
- [ ] `--config` for severity tuning and path ignores.
- [ ] Pre-commit hook wrapper.
- [ ] JS/TS support for LangGraph.js pipelines.
- [ ] More `examples/` fixtures drawn from real (anonymized) production bugs.

## License

MIT © 2026 Mohammed Ghassan
