"""STRUCTURE-NOT-SEMANTICS — an eval that grades output shape, not content.

A grader that only asserts the *structure* of a response (it's a dict, it has
an "answer" key, the answer is non-empty) will happily pass a confidently
wrong answer. This is the eval-harness failure mode that makes a model look
green while it regresses on the thing you actually care about.

We flag a function that (a) is recognisably an eval/grader by name, (b) checks
output structure at least once, and (c) contains *no* semantic signal — no
comparison against an expected value, reference, or long expected string, and
no similarity/judge call. The semantic-signal detection is what keeps this
precise: a grader that compares against ``expected_answer`` or a golden string
is correct and must not be flagged.
"""

from __future__ import annotations

import ast
import re
from typing import Iterable, List

from ..findings import Finding, Severity
from .base import Analyzer, call_name

_EVAL_NAME_RE = re.compile(
    r"(eval|evaluate|grade|grader|grading|score|scorer|judge|rubric|assess|"
    r"verdict|is_correct|check_answer|check_output|check_response)",
    re.IGNORECASE,
)
_EXPECTED_NAME_RE = re.compile(
    r"^(expected|reference|ground_truth|groundtruth|gold|golden|target|"
    r"answer|label|correct|solution|truth|desired)",
    re.IGNORECASE,
)
_SEMANTIC_CALL_TOKENS = (
    "embed", "embedding", "cosine", "similar", "semantic", "bleu", "rouge",
    "meteor", "bertscore", "levenshtein", "edit_distance", "fuzzy", "jaccard",
    "llm_judge", "judge_", "match_meaning",
)
_STRUCTURE_CALL_TOKENS = ("len", "isinstance", "hasattr", "type")
_UNWRAP_METHODS = ("strip", "lower", "upper", "casefold", "rstrip", "lstrip", "title")
_LONG_STR = 12

# An eval grades *model output*, so it takes a response-like argument. Requiring
# one keeps the rule from firing on unrelated functions that merely happen to
# contain "eval"/"score"/"verdict" in their name (e.g. config validators).
_RESPONSE_PARAM_TOKENS = {
    "response", "resp", "output", "out", "outputs", "prediction", "pred",
    "predicted", "completion", "answer", "result", "results", "generated",
    "generation", "actual", "model_output", "reply", "candidate", "hypothesis",
    "got", "y_pred",
}


class EvalStructureAnalyzer(Analyzer):
    rule_id = "STRUCTURE-NOT-SEMANTICS"

    def check(self, tree: ast.AST, filename: str, source: str) -> Iterable[Finding]:
        findings: List[Finding] = []
        for node in ast.walk(tree):
            if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            if not _EVAL_NAME_RE.search(node.name):
                continue
            if not self._grades_model_output(node):
                continue
            has_structure, has_semantic = self._scan_body(node)
            if has_structure and not has_semantic:
                findings.append(
                    Finding(
                        rule_id=self.rule_id,
                        severity=Severity.MEDIUM,
                        message=(
                            f"Eval/grader `{node.name}` only checks output *structure* "
                            f"(shape/length/keys), never whether the content is correct."
                        ),
                        file=filename,
                        line=node.lineno,
                        why=(
                            "A structure-only grader passes any response with the right "
                            "shape, including confidently wrong answers. Your eval goes "
                            "green while quality regresses — the failure is invisible "
                            "precisely because the harness is grading the wrong thing."
                        ),
                        fix=(
                            "Compare against an expected/reference answer (exact, "
                            "normalized, or semantic-similarity/LLM-judge) in addition to "
                            "any shape checks."
                        ),
                    )
                )
        return findings

    @staticmethod
    def _grades_model_output(fn) -> bool:
        a = fn.args
        params = [p.arg.lower() for p in (a.posonlyargs + a.args + a.kwonlyargs)]
        return any(p in _RESPONSE_PARAM_TOKENS for p in params)

    # -- body classification -------------------------------------------------

    def _scan_body(self, fn) -> "tuple[bool, bool]":
        has_structure = False
        has_semantic = False
        for node in ast.walk(fn):
            if isinstance(node, ast.Call):
                name = call_name(node.func).lower()
                if name:
                    short = name.rsplit(".", 1)[-1]
                    if short in _STRUCTURE_CALL_TOKENS:
                        has_structure = True
                    if any(tok in name for tok in _SEMANTIC_CALL_TOKENS):
                        has_semantic = True
            elif isinstance(node, ast.Compare):
                if self._compare_is_semantic(node):
                    has_semantic = True
                else:
                    has_structure = True
        return has_structure, has_semantic

    def _compare_is_semantic(self, node: ast.Compare) -> bool:
        sides = [node.left, *node.comparators]
        return any(self._is_expected_ref(s) or self._is_long_str(s) for s in sides)

    # -- expected-value detection -------------------------------------------

    def _is_expected_ref(self, node: ast.AST) -> bool:
        node = self._unwrap(node)
        if isinstance(node, ast.Name):
            return bool(_EXPECTED_NAME_RE.match(node.id))
        if isinstance(node, ast.Attribute):
            if _EXPECTED_NAME_RE.match(node.attr):
                return True
            return self._is_expected_ref(node.value)
        if isinstance(node, ast.Subscript):
            key = self._const_str(node.slice)
            if key and _EXPECTED_NAME_RE.match(key):
                return True
            return self._is_expected_ref(node.value)
        return False

    def _unwrap(self, node: ast.AST) -> ast.AST:
        """Peel ``.strip()``/``.lower()``/``str(...)`` wrappers so that
        ``expected_answer.strip()`` is still recognised as the expected ref."""
        while isinstance(node, ast.Call):
            func = node.func
            if isinstance(func, ast.Attribute) and func.attr in _UNWRAP_METHODS:
                node = func.value
            elif isinstance(func, ast.Name) and func.id == "str" and node.args:
                node = node.args[0]
            else:
                break
        return node

    @staticmethod
    def _is_long_str(node: ast.AST) -> bool:
        return (
            isinstance(node, ast.Constant)
            and isinstance(node.value, str)
            and len(node.value) >= _LONG_STR
        )

    @staticmethod
    def _const_str(node: ast.AST):
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            return node.value
        return None
