"""Azure Functions v2 entry point — the governance proxy in front of Azure OpenAI.

A client POSTs an Azure OpenAI chat-completion payload to
    POST /api/governed/{deployment}/chat/completions
instead of calling Azure OpenAI directly. This function:

  1. Reads the operator-configured caller and environment. Request headers
     cannot claim a different caller or environment.
  2. Verifies an operator-pinned buyer Decision Card and derives its scoped
     policy-as-code-engine bundle; loads the separate per-tool rule set.
  3. Requires both the signed-card gate and every per-tool check to allow.
  4. allow      → forwards to AZURE_OPENAI_ENDPOINT, returns the response.
     deny        → 403 with the rationale; nothing forwarded.
     require_approval → 409 with the rationale (caller must obtain approval).
  5. Emits a tool_invocation_* event to audit-stream-py (best-effort).

App settings (environment variables):
  AZURE_OPENAI_ENDPOINT   e.g. https://my-aoai.openai.azure.com
  AZURE_OPENAI_API_KEY    key for the upstream resource
  AZURE_OPENAI_API_VERSION  default 2024-10-21
  POLICY_BUNDLES_JSON     JSON array of bridge rules[] bundles
  GOVERNANCE_DECISION_CARD_JSON  signed card+attestation envelope
  GOVERNANCE_BUYER_ID, GOVERNANCE_BUYER_KEY_URL,
  GOVERNANCE_BUYER_PUBLIC_KEY_B64, GOVERNANCE_VENDOR_ID  operator pins
  AUDIT_STREAM_URL        optional; audit-stream-py base URL or /events endpoint
  AUDIT_STREAM_TOKEN      bearer token required when audit URL is set
  GOVERNANCE_CALLER_ID    required, one configured workload per Function app
  GOVERNANCE_ENVIRONMENT  default production
  DEFAULT_OUTCOME         must be 'deny'
"""

from __future__ import annotations

import json
import logging
import math
import os
import re
from collections.abc import Iterator

import azure.functions as func
import httpx

from azure_openai_governance_bridge.audit import emit_audit_event
from azure_openai_governance_bridge.bridge import evaluate
from azure_openai_governance_bridge.broker import Broker
from azure_openai_governance_bridge.models import PermissionDecision
from azure_openai_governance_bridge.signed_card import SignedCardGate, load_signed_card_gate

logger = logging.getLogger("azure_openai_governance_bridge")
MAX_REQUEST_BYTES = 1_048_576
MAX_JSON_DEPTH = 64

app = func.FunctionApp(http_auth_level=func.AuthLevel.FUNCTION)


def _load_broker() -> Broker:
    raw = os.environ.get("POLICY_BUNDLES_JSON", "[]")
    if os.environ.get("DEFAULT_OUTCOME", "deny") != "deny":
        raise ValueError("DEFAULT_OUTCOME must be deny")
    if len(raw.encode("utf-8")) > 131_072:
        raise ValueError("POLICY_BUNDLES_JSON exceeds size limit")
    try:
        bundles = json.loads(raw, object_pairs_hook=_unique_object, parse_constant=_invalid_constant)
    except json.JSONDecodeError as exc:
        raise ValueError("POLICY_BUNDLES_JSON is not valid JSON") from exc
    if not isinstance(bundles, list):
        raise ValueError("POLICY_BUNDLES_JSON must be an array")
    return Broker.from_dicts(bundles, default_outcome="deny")


def _unique_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("policy configuration contains a duplicate key")
        result[key] = value
    return result


def _invalid_constant(_value: str) -> None:
    raise ValueError("policy configuration contains a non-finite number")


def _load_workload() -> tuple[str, str]:
    caller_id = os.environ.get("GOVERNANCE_CALLER_ID", "")
    environment = os.environ.get("GOVERNANCE_ENVIRONMENT", "production")
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}", caller_id):
        raise ValueError("GOVERNANCE_CALLER_ID must be an ASCII identifier")
    if environment not in {"production", "staging", "development"}:
        raise ValueError("GOVERNANCE_ENVIRONMENT is invalid")
    return caller_id, environment


def _load_signed_card() -> SignedCardGate:
    return load_signed_card_gate(
        os.environ.get("GOVERNANCE_DECISION_CARD_JSON", ""),
        buyer_id=os.environ.get("GOVERNANCE_BUYER_ID", ""),
        buyer_key_url=os.environ.get("GOVERNANCE_BUYER_KEY_URL", ""),
        buyer_public_key_b64=os.environ.get("GOVERNANCE_BUYER_PUBLIC_KEY_B64", ""),
        vendor_id=os.environ.get("GOVERNANCE_VENDOR_ID", ""),
    )


def _load_upstream() -> tuple[str, str, str]:
    raw_endpoint = os.environ.get("AZURE_OPENAI_ENDPOINT", "")
    api_key = os.environ.get("AZURE_OPENAI_API_KEY", "")
    api_version = os.environ.get("AZURE_OPENAI_API_VERSION", "2024-10-21")
    try:
        endpoint = httpx.URL(raw_endpoint)
    except httpx.InvalidURL as exc:
        raise ValueError("invalid Azure OpenAI endpoint") from exc
    if (
        raw_endpoint != raw_endpoint.strip()
        or endpoint.scheme != "https"
        or not re.fullmatch(r"[a-z0-9][a-z0-9-]{0,62}\.openai\.azure\.com", endpoint.host or "")
        or endpoint.port not in (None, 443)
        or endpoint.userinfo
        or endpoint.query
        or endpoint.fragment
        or endpoint.path not in ("", "/")
        or not api_key
        or any(ord(char) < 33 or ord(char) > 126 for char in api_key)
        or not re.fullmatch(r"20\d{2}-\d{2}-\d{2}(?:-preview)?", api_version)
    ):
        raise ValueError("invalid Azure OpenAI upstream configuration")
    return str(endpoint.copy_with(path="/")).rstrip("/"), api_key, api_version


def _configuration_error() -> func.HttpResponse:
    logger.error("governance bridge configuration invalid")
    return func.HttpResponse(
        json.dumps({"error": "governance_configuration_invalid"}),
        status_code=503,
        mimetype="application/json",
    )


def _validate_request_json(value: object) -> None:
    """Bound nested JSON without recursion before policy checks or forwarding."""
    stack: list[tuple[Iterator[object], int]] = [(iter((value,)), 0)]
    while stack:
        values, depth = stack[-1]
        try:
            node = next(values)
        except StopIteration:
            stack.pop()
            continue
        if depth > MAX_JSON_DEPTH:
            raise ValueError("request JSON is too deeply nested")
        if isinstance(node, dict):
            stack.append((iter(node.values()), depth + 1))
        elif isinstance(node, list):
            stack.append((iter(node), depth + 1))
        elif isinstance(node, float) and not math.isfinite(node):
            raise ValueError("request JSON contains a non-finite number")


@app.route(route="governed/{deployment}/chat/completions", methods=["POST"])
def governed_chat_completions(req: func.HttpRequest) -> func.HttpResponse:
    deployment = req.route_params.get("deployment", "")

    if len(req.get_body()) > MAX_REQUEST_BYTES:
        return func.HttpResponse(
            json.dumps({"error": "request_too_large"}),
            status_code=413,
            mimetype="application/json",
        )

    try:
        body = req.get_json()
        _validate_request_json(body)
    except (ValueError, RecursionError):
        return func.HttpResponse(
            json.dumps({"error": "request body must be valid JSON"}),
            status_code=400,
            mimetype="application/json",
        )

    try:
        broker = _load_broker()
        caller_id, environment = _load_workload()
        signed_card = _load_signed_card()
        endpoint, api_key, api_version = _load_upstream()
    except ValueError:
        return _configuration_error()
    try:
        decision, perm_req = evaluate(
            broker, caller_id=caller_id, deployment=deployment, body=body, environment=environment
        )
    except ValueError as exc:
        return func.HttpResponse(
            json.dumps({"error": "invalid_governed_request", "detail": str(exc)}),
            status_code=400,
            mimetype="application/json",
        )

    try:
        card_result = signed_card.evaluate()
    except Exception:  # noqa: BLE001 - evaluator faults must not reach the upstream
        logger.error("Decision Card evaluation failed")
        failure = PermissionDecision(
            outcome="deny",
            matched_rules=["decision-card-evaluation-error"],
            rationale="Decision Card evaluation unavailable",
        )
        try:
            emit_audit_event(failure, perm_req)
        except Exception:  # noqa: BLE001 - the audit path must not mask the policy failure
            logger.warning("audit emission failed")
        return func.HttpResponse(
            json.dumps(
                {"error": "governance_evaluation_unavailable", "correlation_id": failure.correlation_id}
            ),
            status_code=503,
            mimetype="application/json",
        )
    if card_result.decision.kind != "allow":
        decision = PermissionDecision(
            outcome="deny",
            matched_rules=["decision-card-gate"],
            rationale="Decision Card policy denied this request",
        )

    emit_audit_event(decision, perm_req)

    if decision.outcome == "deny":
        return func.HttpResponse(
            json.dumps(
                {
                    "error": "denied_by_governance",
                    "rationale": decision.rationale,
                    "matched_rules": decision.matched_rules,
                    "decision_card_refs": decision.decision_card_refs,
                    "correlation_id": decision.correlation_id,
                }
            ),
            status_code=403,
            mimetype="application/json",
        )

    if decision.outcome == "require_approval":
        return func.HttpResponse(
            json.dumps(
                {
                    "error": "approval_required",
                    "rationale": decision.rationale,
                    "matched_rules": decision.matched_rules,
                    "correlation_id": decision.correlation_id,
                }
            ),
            status_code=409,
            mimetype="application/json",
        )

    # Allowed — forward to Azure OpenAI.
    upstream = f"{endpoint}/openai/deployments/{deployment}/chat/completions?api-version={api_version}"
    try:
        resp = httpx.post(
            upstream,
            json=body,
            headers={"api-key": api_key, "content-type": "application/json"},
            timeout=60.0,
        )
    except Exception as exc:  # noqa: BLE001
        logger.error("upstream Azure OpenAI call failed: %s", type(exc).__name__)
        return func.HttpResponse(
            json.dumps({"error": "upstream_unreachable", "correlation_id": decision.correlation_id}),
            status_code=502,
            mimetype="application/json",
        )

    return func.HttpResponse(
        resp.content,
        status_code=resp.status_code,
        mimetype=resp.headers.get("content-type", "application/json"),
        headers={"x-kg-correlation-id": decision.correlation_id},
    )


@app.route(route="healthz", methods=["GET"], auth_level=func.AuthLevel.ANONYMOUS)
def healthz(req: func.HttpRequest) -> func.HttpResponse:
    try:
        _load_broker()
        _load_workload()
        signed_card = _load_signed_card()
        _load_upstream()
    except ValueError:
        return _configuration_error()
    try:
        card_result = signed_card.evaluate()
    except Exception:  # noqa: BLE001 - readiness fails closed on evaluator faults
        logger.error("Decision Card evaluation failed")
        return func.HttpResponse(
            json.dumps({"status": "unavailable"}), status_code=503, mimetype="application/json"
        )
    if card_result.decision.kind != "allow":
        return func.HttpResponse(
            json.dumps({"status": "policy_denied"}), status_code=503, mimetype="application/json"
        )
    return func.HttpResponse(
        json.dumps({"status": "ok"}),
        status_code=200,
        mimetype="application/json",
    )
