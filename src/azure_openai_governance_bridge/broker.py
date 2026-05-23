"""Deny-trumps-allow evaluator — the same resolution order as mcp-permission-broker.

Kept dependency-free (stdlib + pydantic models) so it loads fast inside an
Azure Function cold start.
"""

from __future__ import annotations

import logging
import re
from typing import Any

from azure_openai_governance_bridge.models import (
    Outcome,
    PermissionDecision,
    PermissionRequest,
    PolicyBundle,
)

logger = logging.getLogger(__name__)


class Broker:
    """In-memory PolicyBundle registry + evaluator."""

    def __init__(self, *, default_outcome: Outcome = "deny") -> None:
        self._bundles: dict[str, PolicyBundle] = {}
        self._default_outcome: Outcome = default_outcome

    def add_bundle(self, bundle: PolicyBundle) -> None:
        self._bundles[bundle.bundle_id] = bundle

    @classmethod
    def from_dicts(cls, bundles: list[dict[str, Any]], **kwargs: Any) -> Broker:
        broker = cls(**kwargs)
        for raw in bundles:
            broker.add_bundle(PolicyBundle.model_validate(raw))
        return broker

    @property
    def bundle_ids(self) -> list[str]:
        return sorted(self._bundles)

    def check(self, request: PermissionRequest) -> PermissionDecision:
        matches = []
        for bundle in self._bundles.values():
            for rule in bundle.rules:
                if self._matches(rule, request):
                    matches.append((rule, bundle))
        matches.sort(key=lambda pair: pair[0].priority, reverse=True)

        for effect in ("deny", "require_approval", "allow"):
            for rule, bundle in matches:
                if rule.effect == effect:
                    return PermissionDecision(
                        outcome=effect,
                        matched_rules=[rule.id],
                        decision_card_refs=[bundle.decision_card_url] if bundle.decision_card_url else [],
                        rationale=f"{effect} by rule {rule.id}",
                    )

        return PermissionDecision(
            outcome=self._default_outcome,
            rationale=f"No rule matched — default {self._default_outcome}",
        )

    def _matches(self, rule: Any, request: PermissionRequest) -> bool:
        if not re.fullmatch(rule.tool_name, request.tool_name):
            return False
        if not re.fullmatch(rule.caller_id, request.caller_id):
            return False
        if rule.when:
            expr = rule.when.get("expr", "")
            if not expr:
                return True
            try:
                return bool(eval(expr, {"__builtins__": {}}, {"context": request.context}))
            except Exception as exc:  # noqa: BLE001 — fail closed
                logger.warning("when.expr failed for rule %s: %s", rule.id, exc)
                return False
        return True
