"""Best-effort audit-stream-py emitter — same contract as every Suite producer.

If AUDIT_STREAM_URL is unset, this is a no-op. A failed POST is logged and
swallowed; it never raises back into the request path.
"""

from __future__ import annotations

import logging
import os
import re
from typing import Any

import httpx

from azure_openai_governance_bridge.models import Outcome, PermissionDecision, PermissionRequest

logger = logging.getLogger(__name__)

_EVENT_KIND: dict[Outcome, str] = {
    "allow": "tool_invocation_allowed",
    "deny": "tool_invocation_denied",
    "require_approval": "tool_invocation_required_approval",
}

_SOURCE = "azure-openai-governance-bridge"


def emit_audit_event(
    decision: PermissionDecision,
    request: PermissionRequest,
    *,
    audit_stream_url: str | None = None,
    client: httpx.Client | None = None,
) -> bool:
    """POST one governance event to audit-stream-py. Returns True if POSTed, False if skipped/failed.

    Never raises.
    """
    url = audit_stream_url if audit_stream_url is not None else os.environ.get("AUDIT_STREAM_URL", "")
    if not url:
        return False

    event = {
        "kind": _EVENT_KIND[decision.outcome],
        "source": _SOURCE,
        "payload": {
            "correlation_id": decision.correlation_id,
            "caller_id": request.caller_id,
            "tool_name": request.tool_name,
            "matched_rules": decision.matched_rules,
            "decision_card_refs": decision.decision_card_refs,
            "rationale": decision.rationale,
            "context": request.context,
        },
    }

    try:
        if client is not None:
            response = client.post(url, json=event, timeout=2.0)
        else:
            response = httpx.post(url, json=event, timeout=2.0)
        if response.status_code >= 400:
            logger.warning("audit-stream POST returned HTTP %s", response.status_code)
            return False
        return True
    except Exception as exc:  # noqa: BLE001 — best-effort, never raised
        logger.warning("audit-stream POST failed (best-effort, not raised): %s", type(exc).__name__)
        return False


def derive_tool_names(deployment: str, body: dict[str, Any]) -> list[str]:
    """Turn an Azure OpenAI request into the list of tool_names to check.

    Always includes the deployment itself (`azure-openai.<deployment>`), plus
    one `tool.<name>` per function-calling tool declared in the request body.
    """
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}", deployment):
        raise ValueError("invalid deployment name")
    if not isinstance(body, dict):
        raise ValueError("request body must be a JSON object")
    if "functions" in body or "function_call" in body:
        raise ValueError("legacy function declarations are not supported")
    names = [f"azure-openai.{deployment}"]
    tools = body.get("tools", [])
    if not isinstance(tools, list):
        raise ValueError("tools must be an array")
    if len(tools) > 128:
        raise ValueError("too many declared tools")
    for tool in tools:
        if not isinstance(tool, dict) or tool.get("type") != "function":
            raise ValueError("each tool must declare a function")
        fn = tool.get("function")
        name = fn.get("name") if isinstance(fn, dict) else None
        if not isinstance(name, str) or not re.fullmatch(r"[A-Za-z0-9_-]{1,64}", name):
            raise ValueError("each tool must have a valid function name")
        names.append(f"tool.{name}")
    tool_choice = body.get("tool_choice")
    if isinstance(tool_choice, dict):
        selected = tool_choice.get("function")
        selected_name = selected.get("name") if isinstance(selected, dict) else None
        if (
            tool_choice.get("type") != "function"
            or not isinstance(selected_name, str)
            or f"tool.{selected_name}" not in names
        ):
            raise ValueError("tool_choice must name a declared function")
    elif tool_choice is not None and (
        not isinstance(tool_choice, str) or tool_choice not in {"none", "auto", "required"}
    ):
        raise ValueError("invalid tool_choice")
    return names
