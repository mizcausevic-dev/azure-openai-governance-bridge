"""Core orchestration — pure + testable, no Azure Functions runtime imports.

evaluate() takes the broker + the salient request fields and returns the
governing PermissionDecision (deny-trumps-allow across the deployment plus
every function-calling tool in the request).
"""

from __future__ import annotations

from typing import Any

from azure_openai_governance_bridge.audit import derive_tool_names
from azure_openai_governance_bridge.broker import Broker
from azure_openai_governance_bridge.models import PermissionDecision, PermissionRequest


def evaluate(
    broker: Broker,
    *,
    caller_id: str,
    deployment: str,
    body: dict[str, Any],
    environment: str = "production",
) -> tuple[PermissionDecision, PermissionRequest]:
    """Evaluate an Azure OpenAI request. Returns the *governing* decision.

    Checks the deployment invocation and each declared tool. Deny-trumps:
    the first deny across all checks governs; otherwise the first
    require_approval; otherwise allow. The returned PermissionRequest is the
    one that produced the governing decision (useful for the audit event).
    """
    context = {"environment": environment, "deployment": deployment}
    tool_names = derive_tool_names(deployment, body)

    decisions: list[tuple[PermissionDecision, PermissionRequest]] = []
    for tool_name in tool_names:
        req = PermissionRequest(caller_id=caller_id, tool_name=tool_name, context=context)
        decisions.append((broker.check(req), req))

    # Deny-trumps-allow across the whole request.
    for outcome in ("deny", "require_approval"):
        for decision, req in decisions:
            if decision.outcome == outcome:
                return decision, req

    # All allowed (or defaulted-allow). Return the deployment-level decision.
    return decisions[0]
