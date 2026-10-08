"""Experimental Azure OpenAI proxy with separate signed-card and tool-rule gates.

The rule shape resembles mcp-permission-broker but uses a restricted condition
grammar. The Azure adapter verifies a pinned buyer Decision Card before
deriving a policy-as-code-engine bundle; bare bundles are not trusted input.
Audit event delivery is optional and best-effort.

Public surface:
    from azure_openai_governance_bridge import (
        Broker, PermissionRequest, PermissionDecision,
        PolicyBundle, PolicyRule, Outcome, emit_audit_event,
    )
"""

from azure_openai_governance_bridge.audit import emit_audit_event
from azure_openai_governance_bridge.broker import Broker
from azure_openai_governance_bridge.models import (
    Outcome,
    PermissionDecision,
    PermissionRequest,
    PolicyBundle,
    PolicyRule,
)

__all__ = [
    "Broker",
    "Outcome",
    "PermissionDecision",
    "PermissionRequest",
    "PolicyBundle",
    "PolicyRule",
    "emit_audit_event",
]
__version__ = "0.1.0"
