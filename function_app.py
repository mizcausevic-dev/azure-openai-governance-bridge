"""Azure Functions v2 entry point — the governance proxy in front of Azure OpenAI.

A client POSTs an Azure OpenAI chat-completion payload to
    POST /api/governed/{deployment}/chat/completions
instead of calling Azure OpenAI directly. This function:

  1. Identifies the caller (x-kg-caller-id header) and environment
     (x-kg-environment header, default "production").
  2. Loads the active PolicyBundle(s) from the POLICY_BUNDLES_JSON app setting.
  3. Evaluates the deployment + every declared tool (deny-trumps-allow).
  4. allow      → forwards to AZURE_OPENAI_ENDPOINT, returns the response.
     deny        → 403 with the rationale; nothing forwarded.
     require_approval → 409 with the rationale (caller must obtain approval).
  5. Emits a tool_invocation_* event to audit-stream-py (best-effort).

App settings (environment variables):
  AZURE_OPENAI_ENDPOINT   e.g. https://my-aoai.openai.azure.com
  AZURE_OPENAI_API_KEY    key for the upstream resource
  AZURE_OPENAI_API_VERSION  default 2024-10-21
  POLICY_BUNDLES_JSON     JSON array of PolicyBundle objects
  AUDIT_STREAM_URL        optional; audit-stream-py /events endpoint
  DEFAULT_OUTCOME         'deny' (default) or 'allow'
"""

from __future__ import annotations

import json
import logging
import os

import azure.functions as func
import httpx

from azure_openai_governance_bridge.audit import emit_audit_event
from azure_openai_governance_bridge.bridge import evaluate
from azure_openai_governance_bridge.broker import Broker
from azure_openai_governance_bridge.models import Outcome

logger = logging.getLogger("azure_openai_governance_bridge")

app = func.FunctionApp(http_auth_level=func.AuthLevel.FUNCTION)


def _load_broker() -> Broker:
    raw = os.environ.get("POLICY_BUNDLES_JSON", "[]")
    default_outcome: Outcome = "deny" if os.environ.get("DEFAULT_OUTCOME", "deny") == "deny" else "allow"
    try:
        bundles = json.loads(raw)
    except json.JSONDecodeError:
        logger.error("POLICY_BUNDLES_JSON is not valid JSON; defaulting to empty bundle set")
        bundles = []
    return Broker.from_dicts(bundles, default_outcome=default_outcome)


@app.route(route="governed/{deployment}/chat/completions", methods=["POST"])
def governed_chat_completions(req: func.HttpRequest) -> func.HttpResponse:
    deployment = req.route_params.get("deployment", "")
    caller_id = req.headers.get("x-kg-caller-id", "anonymous")
    environment = req.headers.get("x-kg-environment", "production")

    try:
        body = req.get_json()
    except ValueError:
        return func.HttpResponse(
            json.dumps({"error": "request body must be valid JSON"}),
            status_code=400,
            mimetype="application/json",
        )

    broker = _load_broker()
    decision, perm_req = evaluate(
        broker, caller_id=caller_id, deployment=deployment, body=body, environment=environment
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
    endpoint = os.environ.get("AZURE_OPENAI_ENDPOINT", "").rstrip("/")
    api_key = os.environ.get("AZURE_OPENAI_API_KEY", "")
    api_version = os.environ.get("AZURE_OPENAI_API_VERSION", "2024-10-21")

    if not endpoint or not api_key:
        return func.HttpResponse(
            json.dumps(
                {"error": "bridge_misconfigured", "detail": "AZURE_OPENAI_ENDPOINT / API_KEY not set"}
            ),
            status_code=500,
            mimetype="application/json",
        )

    upstream = f"{endpoint}/openai/deployments/{deployment}/chat/completions?api-version={api_version}"
    try:
        resp = httpx.post(
            upstream,
            json=body,
            headers={"api-key": api_key, "content-type": "application/json"},
            timeout=60.0,
        )
    except Exception as exc:  # noqa: BLE001
        logger.error("upstream Azure OpenAI call failed: %s", exc)
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
    broker = _load_broker()
    return func.HttpResponse(
        json.dumps({"status": "ok", "bundles": broker.bundle_ids}),
        status_code=200,
        mimetype="application/json",
    )
