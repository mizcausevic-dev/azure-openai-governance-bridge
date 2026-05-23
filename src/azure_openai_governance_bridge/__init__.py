"""azure-openai-governance-bridge — gate Azure OpenAI calls at the edge.

The Azure-native sibling of mcp-permission-broker: same deny-trumps-allow
PolicyBundle contract, applied to Azure OpenAI requests, emitting the same
tool_invocation_* events to the audit-stream-py spine.

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
