from __future__ import annotations

import pytest

from azure_openai_governance_bridge import Broker, PermissionRequest, PolicyBundle, PolicyRule
from azure_openai_governance_bridge.audit import derive_tool_names, emit_audit_event
from azure_openai_governance_bridge.bridge import evaluate

BUNDLE = {
    "bundle_id": "acme-aoai-2026",
    "decision_card_url": "https://acme.example/.well-known/decisions/DEC-1.json",
    "rules": [
        {
            "id": "deny-prod-deletes",
            "priority": 100,
            "effect": "deny",
            "tool_name": r"^tool\..*delete.*",
            "when": {"expr": "context.get('environment') == 'production'"},
        },
        {
            "id": "deny-gpt4o-for-untrusted",
            "priority": 90,
            "effect": "deny",
            "tool_name": r"^azure-openai\.gpt-4o$",
            "caller_id": r"^untrusted-.*",
        },
        {
            "id": "allow-known-deployments",
            "priority": 10,
            "effect": "allow",
            "tool_name": r"^azure-openai\..*",
            "caller_id": ".*",
        },
        {
            "id": "allow-tools-baseline",
            "priority": 5,
            "effect": "allow",
            "tool_name": r"^tool\..*",
            "caller_id": ".*",
        },
    ],
}


def make_broker(default="deny"):
    return Broker.from_dicts([BUNDLE], default_outcome=default)


def test_derive_tool_names_deployment_only():
    assert derive_tool_names("gpt-4o", {}) == ["azure-openai.gpt-4o"]


def test_derive_tool_names_with_tools():
    body = {"tools": [{"function": {"name": "delete_record"}}, {"function": {"name": "search"}}]}
    assert derive_tool_names("gpt-4o", body) == [
        "azure-openai.gpt-4o",
        "tool.delete_record",
        "tool.search",
    ]


def test_allow_known_deployment_no_tools():
    broker = make_broker()
    decision, _ = evaluate(broker, caller_id="app-1", deployment="gpt-4o", body={})
    assert decision.outcome == "allow"
    assert decision.matched_rules == ["allow-known-deployments"]


def test_deny_trumps_allow_when_a_tool_is_destructive_in_prod():
    broker = make_broker()
    body = {"tools": [{"function": {"name": "delete_record"}}]}
    decision, req = evaluate(
        broker, caller_id="app-1", deployment="gpt-4o", body=body, environment="production"
    )
    assert decision.outcome == "deny"
    assert decision.matched_rules == ["deny-prod-deletes"]
    assert req.tool_name == "tool.delete_record"


def test_destructive_tool_allowed_in_staging():
    broker = make_broker()
    body = {"tools": [{"function": {"name": "delete_record"}}]}
    decision, _ = evaluate(broker, caller_id="app-1", deployment="gpt-4o", body=body, environment="staging")
    # deny rule is prod-only; deployment allow rule governs.
    assert decision.outcome == "allow"


def test_untrusted_caller_denied_gpt4o():
    broker = make_broker()
    decision, _ = evaluate(broker, caller_id="untrusted-bot", deployment="gpt-4o", body={})
    assert decision.outcome == "deny"
    assert decision.matched_rules == ["deny-gpt4o-for-untrusted"]


def test_default_deny_for_unknown_deployment_under_empty_bundle():
    broker = Broker.from_dicts([], default_outcome="deny")
    decision, _ = evaluate(broker, caller_id="app-1", deployment="mystery", body={})
    assert decision.outcome == "deny"
    assert decision.matched_rules == []


def test_decision_card_ref_propagates():
    broker = make_broker()
    decision, _ = evaluate(broker, caller_id="untrusted-bot", deployment="gpt-4o", body={})
    assert decision.decision_card_refs == ["https://acme.example/.well-known/decisions/DEC-1.json"]


def test_emit_audit_noop_without_url(monkeypatch):
    monkeypatch.delenv("AUDIT_STREAM_URL", raising=False)
    broker = make_broker()
    decision, req = evaluate(broker, caller_id="app-1", deployment="gpt-4o", body={})
    assert emit_audit_event(decision, req) is False


def test_emit_audit_posts_when_url_set():
    broker = make_broker()
    decision, req = evaluate(broker, caller_id="app-1", deployment="gpt-4o", body={})

    posted = {}

    class FakeClient:
        def post(self, url, json, timeout):  # noqa: A002
            posted["url"] = url
            posted["json"] = json

            class R:
                status_code = 200

            return R()

    ok = emit_audit_event(decision, req, audit_stream_url="http://localhost:8093/events", client=FakeClient())
    assert ok is True
    assert posted["url"] == "http://localhost:8093/events"
    assert posted["json"]["kind"] == "tool_invocation_allowed"
    assert posted["json"]["source"] == "azure-openai-governance-bridge"


def test_when_expr_cannot_use_builtins():
    broker = Broker.from_dicts(
        [
            {
                "bundle_id": "b",
                "rules": [{"id": "x", "effect": "deny", "when": {"expr": "open('/etc/passwd')"}}],
            }
        ],
        default_outcome="allow",
    )
    decision = broker.check(PermissionRequest(caller_id="a", tool_name="azure-openai.gpt-4o"))
    assert decision.outcome == "allow"  # eval fails closed → rule skipped → default


def test_invalid_bundle_raises():
    from pydantic import ValidationError

    with pytest.raises(ValidationError):
        PolicyBundle.model_validate({"bundle_id": "x", "rules": "not a list"})


def test_policyrule_defaults():
    r = PolicyRule(id="r", effect="allow")
    assert r.tool_name == ".*"
    assert r.caller_id == ".*"
