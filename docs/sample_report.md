# fasih report

**6 finding(s) across 1 file(s): 2 high, 4 medium**

| Severity | Rule | Location | Issue |
| --- | --- | --- | --- |
| HIGH | `FAIL-OPEN-GUARD` | `examples/broken_agent_example.py:25` | Guardrail call `guardrail_check()` is wrapped in a try/except that swallows the error and continues — this fails OPEN. |
| HIGH | `HARDCODED-SECRET` | `examples/broken_agent_example.py:50` | `DATABASE_PASSWORD` is assigned a hardcoded secret literal. |
| MED | `ORPHANED-TOOL` | `examples/broken_agent_example.py:35` | Tool/fetcher `fetch_customer_history` is defined but never invoked or registered anywhere in the scanned project. |
| MED | `STRUCTURE-NOT-SEMANTICS` | `examples/broken_agent_example.py:41` | Eval/grader `evaluate_answer_broken` only checks output *structure* (shape/length/keys), never whether the content is correct. |
| MED | `AR-ENCODING` | `examples/broken_agent_example.py:56` | json.dumps()/dump() without ensure_ascii=False will escape Arabic text to \uXXXX. |
| MED | `AR-NUMERAL` | `examples/broken_agent_example.py:62` | int() parses user-supplied text without normalizing Arabic-Indic digits (٠-٩); Arabic numeral input will raise ValueError. |

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

### `AR-NUMERAL` — MED — `examples/broken_agent_example.py:62`

int() parses user-supplied text without normalizing Arabic-Indic digits (٠-٩); Arabic numeral input will raise ValueError.

```python
return int(message.text)
```

**Why it matters:** int('٢٥') raises ValueError — int()/float() only parse ASCII 0-9. When an Arabic-script user types numerals (WhatsApp, forms, voice-to-text), the parse crashes or the value is dropped, and the bug only shows up for Arabic users.

**Fix:** Normalize first, e.g. int(normalize_arabic_indic_digits(text)).
