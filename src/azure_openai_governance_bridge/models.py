"""Pydantic models — deliberately identical in shape to mcp-permission-broker
so a PolicyBundle authored for one enforces identically on the other."""

from __future__ import annotations

import uuid
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field

Outcome = Literal["allow", "deny", "require_approval"]


class PermissionRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    caller_id: str = Field(..., description="Identity of the caller (API key hash, app id, agent id).")
    tool_name: str = Field(
        ...,
        description="What is being invoked. e.g. 'azure-openai.gpt-4o' (a deployment) "
        "or 'tool.delete_record' (a function-calling tool in the request).",
    )
    context: dict[str, Any] = Field(default_factory=dict)


class _Because(BaseModel):
    model_config = ConfigDict(extra="ignore")
    decision_card: str | None = None
    condition_id: str | None = None


class PolicyRule(BaseModel):
    model_config = ConfigDict(extra="forbid")

    id: str
    priority: int = 0
    effect: Outcome
    tool_name: str = Field(default=".*", description="Regex matched against request.tool_name.")
    caller_id: str = Field(default=".*", description="Regex matched against request.caller_id.")
    when: dict[str, str] | None = Field(
        default=None, description="Optional {'expr': <python expression over `context`>}."
    )
    because: _Because | None = None


class PolicyBundle(BaseModel):
    model_config = ConfigDict(extra="forbid")

    bundle_id: str
    decision_card_url: str | None = None
    rules: list[PolicyRule] = Field(default_factory=list)


class PermissionDecision(BaseModel):
    model_config = ConfigDict(extra="forbid")

    outcome: Outcome
    matched_rules: list[str] = Field(default_factory=list)
    decision_card_refs: list[str] = Field(default_factory=list)
    correlation_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    rationale: str = ""
