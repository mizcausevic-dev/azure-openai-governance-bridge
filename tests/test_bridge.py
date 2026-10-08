from __future__ import annotations

import json

import azure.functions as func
import pytest

from azure_openai_governance_bridge import Broker, PolicyBundle, PolicyRule
from azure_openai_governance_bridge.audit import derive_tool_names, emit_audit_event
from azure_openai_governance_bridge.bridge import evaluate
from function_app import governed_chat_completions, healthz

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
    body = {
        "tools": [
            {"type": "function", "function": {"name": "delete_record"}},
            {"type": "function", "function": {"name": "search"}},
        ]
    }
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
    body = {"tools": [{"type": "function", "function": {"name": "delete_record"}}]}
    decision, req = evaluate(
        broker, caller_id="app-1", deployment="gpt-4o", body=body, environment="production"
    )
    assert decision.outcome == "deny"
    assert decision.matched_rules == ["deny-prod-deletes"]
    assert req.tool_name == "tool.delete_record"


def test_destructive_tool_allowed_in_staging():
    broker = make_broker()
    body = {"tools": [{"type": "function", "function": {"name": "delete_record"}}]}
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
    from pydantic import ValidationError

    with pytest.raises(ValidationError):
        Broker.from_dicts(
            [
                {
                    "bundle_id": "b",
                    "rules": [{"id": "x", "effect": "deny", "when": {"expr": "open('/etc/passwd')"}}],
                }
            ],
            default_outcome="allow",
        )


def test_invalid_bundle_raises():
    from pydantic import ValidationError

    with pytest.raises(ValidationError):
        PolicyBundle.model_validate({"bundle_id": "x", "rules": "not a list"})


def test_policyrule_defaults():
    r = PolicyRule(id="r", effect="allow")
    assert r.tool_name == ".*"
    assert r.caller_id == ".*"


@pytest.mark.parametrize(
    "bad_tools",
    [None, {}, [None], [{"function": {"name": "delete_record"}}], [{"type": "function", "function": {}}]],
)
def test_malformed_tools_never_bypass_gate(bad_tools):
    with pytest.raises(ValueError):
        derive_tool_names("gpt-4o", {"tools": bad_tools})


@pytest.mark.parametrize(
    "bad_body",
    [
        {"functions": [{"name": "delete_record"}]},
        {"function_call": "auto"},
        {"tools": [], "tool_choice": {"type": "function", "function": {"name": "x"}}},
        {"tool_choice": {"type": "function", "function": {"name": "x"}}},
        {"tool_choice": []},
    ],
)
def test_ungoverned_function_declarations_rejected(bad_body):
    with pytest.raises(ValueError):
        derive_tool_names("gpt-4o", bad_body)


def _request(body, *, headers=None):
    return func.HttpRequest(
        method="POST",
        url="http://localhost/api/governed/gpt-4o/chat/completions",
        body=json.dumps(body).encode(),
        headers=headers or {},
        route_params={"deployment": "gpt-4o"},
    )


def test_invalid_config_denies_without_upstream_call(monkeypatch):
    monkeypatch.setenv("GOVERNANCE_CALLER_ID", "app-1")
    monkeypatch.setenv("POLICY_BUNDLES_JSON", "not json")
    monkeypatch.setattr("function_app.httpx.post", lambda *a, **k: pytest.fail("upstream called"))
    assert governed_chat_completions(_request({"messages": []})).status_code == 503
    assert healthz(_request({})).status_code == 503


def test_default_allow_config_denies_without_upstream_call(monkeypatch):
    monkeypatch.setenv("GOVERNANCE_CALLER_ID", "app-1")
    monkeypatch.setenv("DEFAULT_OUTCOME", "allow")
    monkeypatch.setattr("function_app.httpx.post", lambda *a, **k: pytest.fail("upstream called"))
    assert governed_chat_completions(_request({"messages": []})).status_code == 503


def test_unset_server_caller_denies_even_with_caller_header(monkeypatch):
    monkeypatch.delenv("GOVERNANCE_CALLER_ID", raising=False)
    monkeypatch.setenv("POLICY_BUNDLES_JSON", json.dumps([BUNDLE]))
    monkeypatch.setattr("function_app.httpx.post", lambda *a, **k: pytest.fail("upstream called"))
    response = governed_chat_completions(_request({"messages": []}, headers={"x-kg-caller-id": "app-1"}))
    assert response.status_code == 503


def test_headers_cannot_spoof_workload_or_environment(monkeypatch):
    monkeypatch.setenv("GOVERNANCE_CALLER_ID", "app-1")
    monkeypatch.setenv("GOVERNANCE_ENVIRONMENT", "production")
    monkeypatch.setenv("POLICY_BUNDLES_JSON", json.dumps([BUNDLE]))
    monkeypatch.setattr("function_app.httpx.post", lambda *a, **k: pytest.fail("upstream called"))
    body = {"tools": [{"type": "function", "function": {"name": "delete_record"}}]}
    response = governed_chat_completions(
        _request(body, headers={"x-kg-caller-id": "trusted-admin", "x-kg-environment": "staging"})
    )
    assert response.status_code == 403


def test_malformed_tool_request_denies_without_upstream_call(monkeypatch):
    monkeypatch.setenv("GOVERNANCE_CALLER_ID", "app-1")
    monkeypatch.setenv("POLICY_BUNDLES_JSON", json.dumps([BUNDLE]))
    monkeypatch.setattr("function_app.httpx.post", lambda *a, **k: pytest.fail("upstream called"))
    response = governed_chat_completions(_request({"tools": [{"function": {"name": "delete_record"}}]}))
    assert response.status_code == 400


@pytest.mark.parametrize(
    "invalid_rules",
    [
        [{"bundle_id": "bad", "rules": [{"id": "x", "effect": "deny", "tool_name": "("}]}],
        [{"bundle_id": "bad", "rules": [{"id": "x", "effect": "deny", "when": {"expr": "1 + 1"}}]}],
    ],
)
def test_invalid_rules_stop_bridge_before_upstream(monkeypatch, invalid_rules):
    monkeypatch.setenv("GOVERNANCE_CALLER_ID", "app-1")
    monkeypatch.setenv("POLICY_BUNDLES_JSON", json.dumps(invalid_rules))
    monkeypatch.setattr("function_app.httpx.post", lambda *a, **k: pytest.fail("upstream called"))
    assert governed_chat_completions(_request({"messages": []})).status_code == 503


def test_valid_allow_forwards_with_server_identity(monkeypatch):
    monkeypatch.setenv("GOVERNANCE_CALLER_ID", "app-1")
    monkeypatch.setenv("GOVERNANCE_ENVIRONMENT", "production")
    monkeypatch.setenv("POLICY_BUNDLES_JSON", json.dumps([BUNDLE]))
    monkeypatch.setenv("AZURE_OPENAI_ENDPOINT", "https://fixture.openai.azure.com")
    monkeypatch.setenv("AZURE_OPENAI_API_KEY", "fixture-key")
    monkeypatch.delenv("AUDIT_STREAM_URL", raising=False)
    seen = {}

    def fake_post(url, **kwargs):
        seen.update(url=url, **kwargs)

        class Response:
            content = b'{"choices": []}'
            status_code = 200
            headers = {"content-type": "application/json"}

        return Response()

    monkeypatch.setattr("function_app.httpx.post", fake_post)
    response = governed_chat_completions(
        _request(
            {"messages": [{"role": "user", "content": "hi"}]}, headers={"x-kg-caller-id": "untrusted-bot"}
        )
    )
    assert response.status_code == 200
    assert seen["url"].startswith("https://fixture.openai.azure.com/openai/deployments/gpt-4o/")
    assert seen["headers"] == {"api-key": "fixture-key", "content-type": "application/json"}
    assert response.get_body() == b'{"choices": []}'


def test_healthz_does_not_disclose_bundle_ids(monkeypatch):
    monkeypatch.setenv("GOVERNANCE_CALLER_ID", "app-1")
    monkeypatch.setenv("POLICY_BUNDLES_JSON", json.dumps([BUNDLE]))
    response = healthz(_request({}))
    assert response.status_code == 200
    assert response.get_body() == b'{"status": "ok"}'


def test_policy_engine_bundle_contract_is_refused(monkeypatch):
    monkeypatch.setenv("GOVERNANCE_CALLER_ID", "app-1")
    monkeypatch.setenv(
        "POLICY_BUNDLES_JSON",
        json.dumps(
            [
                {
                    "bundle_id": "policy-engine-output",
                    "policies": [{"id": "p", "default_effect": "allow", "rules": []}],
                }
            ]
        ),
    )
    monkeypatch.setattr("function_app.httpx.post", lambda *a, **k: pytest.fail("upstream called"))
    assert governed_chat_completions(_request({"messages": []})).status_code == 503


def test_audit_failure_log_omits_exception_detail(caplog):
    broker = make_broker()
    decision, perm_req = evaluate(broker, caller_id="app-1", deployment="gpt-4o", body={})

    class FailedClient:
        def post(self, *args, **kwargs):
            raise RuntimeError("fixture-secret")

    assert (
        emit_audit_event(
            decision, perm_req, audit_stream_url="https://audit.example/events", client=FailedClient()
        )
        is False
    )
    assert "fixture-secret" not in caplog.text


def test_upstream_failure_log_omits_exception_detail(monkeypatch, caplog):
    monkeypatch.setenv("GOVERNANCE_CALLER_ID", "app-1")
    monkeypatch.setenv("POLICY_BUNDLES_JSON", json.dumps([BUNDLE]))
    monkeypatch.setenv("AZURE_OPENAI_ENDPOINT", "https://fixture.openai.azure.com")
    monkeypatch.setenv("AZURE_OPENAI_API_KEY", "fixture-key")
    monkeypatch.delenv("AUDIT_STREAM_URL", raising=False)

    def fail_post(*args, **kwargs):
        raise RuntimeError("fixture-secret")

    monkeypatch.setattr("function_app.httpx.post", fail_post)
    assert governed_chat_completions(_request({"messages": []})).status_code == 502
    assert "fixture-secret" not in caplog.text
