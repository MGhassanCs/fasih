# fasih report

**10 finding(s) across 1 file(s): 2 high, 7 medium, 1 low**

_3 auto-fixable — run `fasih scan <path> --fix`._

| Severity | Rule | Location | Issue |
| --- | --- | --- | --- |
| HIGH | `FAIL-OPEN-GUARD` | `examples/broken_agent_example.py:25` | Guardrail call `guardrail_check()` is wrapped in a try/except that swallows the error and continues — this fails OPEN. |
| HIGH | `HARDCODED-SECRET` | `examples/broken_agent_example.py:50` | `DATABASE_PASSWORD` is assigned a hardcoded secret literal. |
| MED | `ORPHANED-TOOL` | `examples/broken_agent_example.py:35` | Tool/fetcher `fetch_customer_history` is defined but never invoked or registered anywhere in the scanned project. |
| MED | `STRUCTURE-NOT-SEMANTICS` | `examples/broken_agent_example.py:41` | Eval/grader `evaluate_answer_broken` only checks output *structure* (shape/length/keys), never whether the content is correct. |
| MED | `AR-ENCODING` | `examples/broken_agent_example.py:56` | json.dumps()/dump() without ensure_ascii=False will escape Arabic text to \uXXXX. |
| MED | `AR-NUMERAL` | `examples/broken_agent_example.py:63` | int() parses user-supplied text without normalizing Arabic numerals (٠-٩) to ASCII first. |
| MED | `AR-NORMALIZE` | `examples/broken_agent_example.py:69` | Arabic text is matched (==/in/startswith) without normalization; spelling variants silently miss. |
| MED | `AR-FILE-ENCODING` | `examples/broken_agent_example.py:75` | open() opens text without encoding="utf-8"; Arabic depends on the machine's locale. |
| MED | `AR-ENCODE-ASCII` | `examples/broken_agent_example.py:82` | encode("ascii") cannot represent Arabic and raises UnicodeEncodeError on it. |
| LOW | `AR-BIDI` | `examples/broken_agent_example.py:88` | Arabic and Latin scripts mixed in one string literal may render out of order (bidi). |

### `FAIL-OPEN-GUARD` — HIGH — `examples/broken_agent_example.py:25`

Guardrail call `guardrail_check()` is wrapped in a try/except that swallows the error and continues — this fails OPEN.

```python
allowed = guardrail_check(prompt)  # noqa: F821  (external moderation call)
```

**Why it matters:** If the safety check raises (timeout, API error, bad input), the handler lets execution proceed to the guarded action, so a failure of the guardrail silently ALLOWS the request. Safety checks must fail closed: an error should deny, not permit.

**Fix:** In the handler, deny by default — re-raise, return the blocked verdict, or route to a safe fallback. Never fall through to the guarded action as if the check had passed.

### `HARDCODED-SECRET` — HIGH — `examples/broken_agent_example.py:50`

`DATABASE_PASSWORD` is assigned a hardcoded secret literal.

**Why it matters:** A secret in source is committed to git history and shipped to anyone who can read the repo. Config like this belongs in the environment, not the codebase.

**Fix:** Read it from os.environ / a secret manager at runtime, and rotate it.

### `ORPHANED-TOOL` — MED — `examples/broken_agent_example.py:35`

Tool/fetcher `fetch_customer_history` is defined but never invoked or registered anywhere in the scanned project.

**Why it matters:** An orphaned tool is dead wiring. Either it should be registered with the agent/pipeline and isn't — a silent capability or data gap where you think a fetcher runs but it never does — or it is leftover code that should be removed.

**Fix:** Register/invoke the tool where the agent's tools are wired, or delete it. If it is dispatched dynamically by name, make sure the string literal matches the function name exactly.

### `STRUCTURE-NOT-SEMANTICS` — MED — `examples/broken_agent_example.py:41`

Eval/grader `evaluate_answer_broken` only checks output *structure* (shape/length/keys), never whether the content is correct.

**Why it matters:** A structure-only grader passes any response with the right shape, including confidently wrong answers. Your eval goes green while quality regresses — the failure is invisible precisely because the harness is grading the wrong thing.

**Fix:** Compare against an expected/reference answer (exact, normalized, or semantic-similarity/LLM-judge) in addition to any shape checks.

### `AR-ENCODING` — MED — `examples/broken_agent_example.py:56`

json.dumps()/dump() without ensure_ascii=False will escape Arabic text to \uXXXX.

```python
return json.dumps({"body": reply_text_ar})
```

**Why it matters:** ensure_ascii defaults to True, so Arabic is serialized as \uXXXX escapes. Downstream systems, webhooks, WhatsApp payloads and saved files then carry mangled, unreadable Arabic — or break on it.

**Fix:** Pass ensure_ascii=False to json.dumps / json.dump.

### `AR-NUMERAL` — MED — `examples/broken_agent_example.py:63`

int() parses user-supplied text without normalizing Arabic numerals (٠-٩) to ASCII first.

```python
return int(message.text)
```

**Why it matters:** int()/float() do accept Arabic-Indic digits, so this often looks fine — until it isn't. They still raise on the Arabic decimal and thousands separators found in real Arabic numbers (float('٣٫٥'), int('١٬٠٠٠')), and ASCII-only downstream steps fail silently: an explicit [0-9] regex matches nothing and many APIs/DBs reject non-ASCII digits. It only breaks for Arabic users.

**Fix:** Normalize to ASCII before parsing, e.g. int(normalize_arabic_indic_digits(text)); handle the ٫/٬ separators too.

### `AR-NORMALIZE` — MED — `examples/broken_agent_example.py:69`

Arabic text is matched (==/in/startswith) without normalization; spelling variants silently miss.

```python
return message.strip() == "نعم"
```

**Why it matters:** The same Arabic word has several written forms: alef variants (hamza forms vs bare alef), alef-maqsura vs ya, ta-marbuta vs ha, the tatweel elongation, and optional diacritics. A raw == or `in` against a fixed string matches only one spelling, so real input with a different alef or an extra harakat is silently rejected -- breaking intent detection, keyword guards, routing and dedup, only for Arabic users.

**Fix:** Normalize both sides first, e.g. normalize_arabic(text) == normalize_arabic(expected). fasih ships normalize_arabic() / strip_tashkeel() / strip_tatweel().

### `AR-FILE-ENCODING` — MED — `examples/broken_agent_example.py:75`

open() opens text without encoding="utf-8"; Arabic depends on the machine's locale.

```python
with open("reply.txt", "w") as fh:
```

**Why it matters:** Without an explicit encoding, Python uses the platform locale (cp1252 on Windows, sometimes ASCII in containers). Writing Arabic then mojibakes or raises UnicodeEncodeError, and a file written on one machine is unreadable on another.

**Fix:** Pass encoding="utf-8" (and errors="strict") to open()/write_text()/read_text().

### `AR-ENCODE-ASCII` — MED — `examples/broken_agent_example.py:82`

encode("ascii") cannot represent Arabic and raises UnicodeEncodeError on it.

```python
return reply_text_ar.encode("ascii")
```

**Why it matters:** ascii/latin-1 cover no Arabic code points, so the first Arabic character throws UnicodeEncodeError (or, with errors="ignore", silently drops the text).

**Fix:** Encode as UTF-8: text.encode("utf-8").

### `AR-BIDI` — LOW — `examples/broken_agent_example.py:88`

Arabic and Latin scripts mixed in one string literal may render out of order (bidi).

```python
return "الحالة: OK"
```

**Why it matters:** Latin words, numbers or URLs placed inside Arabic RTL text can be reordered by the Unicode bidi algorithm, so the rendered order differs from the source. It shows up in messages, PDFs and notifications shown to Arabic users.

**Fix:** Isolate the LTR run with bidi isolates, e.g. f"...{wrap_ltr(order_id)}..." -- fasih ships wrap_ltr()/isolate().
