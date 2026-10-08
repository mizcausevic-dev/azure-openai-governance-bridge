"""Small, validated condition grammar for configured policy rules.

The expression comes from an operator-supplied bundle, but must never run as
Python code in the request path. Only string equality/inequality against a
known context field is supported.
"""

from __future__ import annotations

import ast
from typing import Any


def parse_condition(expr: str) -> tuple[str, bool, str]:
    """Parse ``context.get('field') == 'value'`` (or ``!=``).

    Raise ValueError during bundle loading for every other expression.
    """
    if len(expr) > 256:
        raise ValueError("condition expression exceeds 256 characters")
    try:
        parsed = ast.parse(expr, mode="eval").body
    except SyntaxError as exc:
        raise ValueError("invalid condition expression") from exc
    if not isinstance(parsed, ast.Compare) or len(parsed.ops) != 1 or len(parsed.comparators) != 1:
        raise ValueError("condition must compare one context field to a string")
    if not isinstance(parsed.ops[0], (ast.Eq, ast.NotEq)):
        raise ValueError("condition supports only == and !=")
    call = parsed.left
    if (
        not isinstance(call, ast.Call)
        or not isinstance(call.func, ast.Attribute)
        or call.func.attr != "get"
        or not isinstance(call.func.value, ast.Name)
        or call.func.value.id != "context"
        or len(call.args) != 1
        or call.keywords
        or not isinstance(call.args[0], ast.Constant)
        or not isinstance(call.args[0].value, str)
    ):
        raise ValueError("condition must read context.get('field')")
    expected = parsed.comparators[0]
    if not isinstance(expected, ast.Constant) or not isinstance(expected.value, str):
        raise ValueError("condition must compare to a string")
    field = call.args[0].value
    if field not in {"environment", "deployment"}:
        raise ValueError("condition field is not supported")
    return field, isinstance(parsed.ops[0], ast.Eq), expected.value


def matches_condition(expr: str, context: dict[str, Any]) -> bool:
    field, equals, expected = parse_condition(expr)
    value = context.get(field)
    return isinstance(value, str) and ((value == expected) if equals else (value != expected))
