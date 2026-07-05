"""A deliberately broken mini "agent".

The TOP half plants exactly one instance of every bug fasih detects; the
BOTTOM half does the same six things correctly. Running

    fasih scan examples/broken_agent_example.py --arabic

reports exactly six findings, all in the top half. This file is a static
fixture — it is scanned, not executed, so a few names are intentionally left
undefined (marked ``noqa``).
"""

import json
import os


# =========================================================================
#  BROKEN  — six planted bugs
# =========================================================================


# --- BUG 1 · FAIL-OPEN-GUARD -------------------------------------------------
def handle_request_broken(prompt):
    try:
        allowed = guardrail_check(prompt)  # noqa: F821  (external moderation call)
    except Exception:
        allowed = True  # BUG: on any error we ALLOW — the guardrail fails open
    if allowed:
        return run_agent(prompt)  # noqa: F821
    return "blocked"


# --- BUG 2 · ORPHANED-TOOL ---------------------------------------------------
@tool  # noqa: F821  (framework decorator)
def fetch_customer_history(customer_id):
    """Declared as a tool but never registered or called anywhere → orphaned."""
    return db.query(customer_id)  # noqa: F821


# --- BUG 3 · STRUCTURE-NOT-SEMANTICS -----------------------------------------
def evaluate_answer_broken(response):
    # BUG: checks only the SHAPE of the response, never whether it is correct
    assert isinstance(response, dict)
    assert "answer" in response
    assert len(response["answer"]) > 0
    return True


# --- BUG 4 · HARDCODED-SECRET ------------------------------------------------
DATABASE_PASSWORD = "pr0d-db-9f3a2c7e14b6d508"  # BUG: secret committed in source


# --- BUG 5 · AR-ENCODING -----------------------------------------------------
def to_whatsapp_payload_broken(reply_text_ar):
    # BUG: ensure_ascii defaults True → Arabic becomes \uXXXX in the payload
    return json.dumps({"body": reply_text_ar})


# --- BUG 6 · AR-NUMERAL ------------------------------------------------------
def parse_quantity_broken(message):
    # BUG: user's Arabic numerals break parsing (float("٣٫٥"), int("١٬٠٠٠")) and
    # any ASCII-only downstream ([0-9] regex, APIs) — parse after normalizing
    return int(message.text)


# =========================================================================
#  FIXED  — the same six, done right (fasih reports nothing here)
# =========================================================================


def handle_request_fixed(prompt):
    try:
        allowed = guardrail_check(prompt)  # noqa: F821
    except Exception:
        return "blocked"  # fail CLOSED: an error denies the request
    return run_agent(prompt) if allowed else "blocked"  # noqa: F821


@tool  # noqa: F821
def fetch_order_status(order_id):
    return db.query(order_id)  # noqa: F821


def agent_router(order_id):
    return fetch_order_status(order_id)  # tool is actually invoked → not orphaned


def evaluate_answer_fixed(response, expected_answer):
    # compares against the expected answer → grades meaning, not just shape
    return response.get("answer", "").strip() == expected_answer.strip()


DATABASE_PASSWORD_FIXED = os.environ["DB_PASSWORD"]  # loaded at runtime, not hardcoded


def to_whatsapp_payload_fixed(reply_text_ar):
    return json.dumps({"body": reply_text_ar}, ensure_ascii=False)


def parse_quantity_fixed(message):
    from fasih import normalize_arabic_indic_digits

    return int(normalize_arabic_indic_digits(message.text))
