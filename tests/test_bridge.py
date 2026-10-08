from __future__ import annotations

import base64
import hashlib
import json
from datetime import UTC, datetime

import azure.functions as func
import pytest
import rfc8785
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from azure_openai_governance_bridge import Broker, PolicyBundle, PolicyRule
from azure_openai_governance_bridge.audit import derive_tool_names, emit_audit_event
from azure_openai_governance_bridge.bridge import evaluate
from function_app import MAX_JSON_DEPTH, MAX_REQUEST_BYTES, governed_chat_completions, healthz

_TEST_KEY = Ed25519PrivateKey.from_private_bytes(bytes([7] * 32))
_KEY_URL = "https://buyer.example/.well-known/keys/decision-card"


def _card(**overrides):
    card = {
        "decision_card_version": "0.1",
        "decision_id": "TEST-001",
        "issued_at": "2026-05-14T19:00:00Z",
        "buyer": {"id": "buyer-1", "name": "Test Buyer", "type": "school-district"},
        "decision": {"status": "approved", "effective_until": "2999-01-01T00:00:00Z"},
        "subject": {"vendor_name": "Test Vendor", "vendor_id": "vendor-1"},
        "rationale": "Synthetic test approval.",
    }
    card.update(overrides)
    return card


def _signed_envelope(card):
    fields = {
        "algorithm": "ed25519",
        "hash_profile": "jcs-rfc8785-v1",
        "signed_hash": "sha256:" + hashlib.sha256(rfc8785.dumps(card)).hexdigest(),
        "key_url": _KEY_URL,
        "signed_at": datetime.now(UTC).isoformat(timespec="seconds"),
    }
    signature = _TEST_KEY.sign(b"hash-attestation/v2\x00" + rfc8785.dumps(fields))
    return {"card": card, "attestation": {**fields, "signature": base64.b64encode(signature).decode()}}


def _configure_card(monkeypatch, card=None):
    monkeypatch.setenv("GOVERNANCE_DECISION_CARD_JSON", json.dumps(_signed_envelope(card or _card())))
    monkeypatch.setenv("GOVERNANCE_BUYER_ID", "buyer-1")
    monkeypatch.setenv("GOVERNANCE_BUYER_KEY_URL", _KEY_URL)
    monkeypatch.setenv(
        "GOVERNANCE_BUYER_PUBLIC_KEY_B64",
        base64.b64encode(_TEST_KEY.public_key().public_bytes_raw()).decode(),
    )
    monkeypatch.setenv("GOVERNANCE_VENDOR_ID", "vendor-1")


@pytest.fixture(autouse=True)
def signed_card_environment(monkeypatch):
    _configure_card(monkeypatch)
    monkeypatch.setenv("AZURE_OPENAI_ENDPOINT", "https://fixture.openai.azure.com")
    monkeypatch.setenv("AZURE_OPENAI_API_KEY", "fixture-key")


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
        def post(self, url, json, headers, timeout, follow_redirects):  # noqa: A002
            posted["url"] = url
            posted["json"] = json
            posted["headers"] = headers
            posted["follow_redirects"] = follow_redirects

            class R:
                status_code = 200

            return R()

    ok = emit_audit_event(
        decision,
        req,
        audit_stream_url="http://127.0.0.1:8093",
        audit_stream_token="t" * 32,
        client=FakeClient(),
    )
    assert ok is True
    assert posted["url"] == "http://127.0.0.1:8093/events"
    assert posted["headers"] == {"authorization": "Bearer " + "t" * 32}
    assert posted["follow_redirects"] is False
    assert posted["json"]["kind"] == "tool_invocation_allowed"
    assert posted["json"]["source"] == "azure-openai-governance-bridge"


def test_audit_legacy_events_url_and_unauthorized_response(caplog):
    broker = make_broker()
    decision, req = evaluate(broker, caller_id="app-1", deployment="gpt-4o", body={})
    seen = {}

    class UnauthorizedClient:
        def post(self, url, **kwargs):
            seen["url"] = url
            seen["headers"] = kwargs["headers"]
            seen["follow_redirects"] = kwargs["follow_redirects"]

            class Response:
                status_code = 401

            return Response()

    assert not emit_audit_event(
        decision,
        req,
        audit_stream_url="https://audit.example/events",
        audit_stream_token="s" * 32,
        client=UnauthorizedClient(),
    )
    assert seen["url"] == "https://audit.example/events"
    assert seen["headers"] == {"authorization": "Bearer " + "s" * 32}
    assert seen["follow_redirects"] is False
    assert "s" * 32 not in caplog.text


def test_audit_redirect_is_failed_delivery_without_following():
    broker = make_broker()
    decision, req = evaluate(broker, caller_id="app-1", deployment="gpt-4o", body={})
    observed = {}

    class RedirectClient:
        def post(self, url, **kwargs):
            observed["follow_redirects"] = kwargs["follow_redirects"]

            class Response:
                status_code = 302

            return Response()

    assert not emit_audit_event(
        decision,
        req,
        audit_stream_url="https://audit.example",
        audit_stream_token="s" * 32,
        client=RedirectClient(),
    )
    assert observed["follow_redirects"] is False


def test_audit_configured_without_token_does_not_post(caplog):
    broker = make_broker()
    decision, req = evaluate(broker, caller_id="app-1", deployment="gpt-4o", body={})

    class UnexpectedClient:
        def post(self, *args, **kwargs):
            pytest.fail("audit POST attempted without token")

    assert not emit_audit_event(
        decision,
        req,
        audit_stream_url="https://audit.example",
        audit_stream_token="",
        client=UnexpectedClient(),
    )
    assert "audit-stream token is unavailable" in caplog.text


@pytest.mark.parametrize(
    "url",
    [
        "http://audit.example",
        "http://localhost:8093",
        "https://user:password@audit.example",
        "https://audit.example?token=secret",
        "https://audit.example/#fragment",
    ],
)
def test_audit_rejects_insecure_or_credentialed_url_without_sending_token(url, caplog):
    broker = make_broker()
    decision, req = evaluate(broker, caller_id="app-1", deployment="gpt-4o", body={})

    class UnexpectedClient:
        def post(self, *args, **kwargs):
            pytest.fail("audit POST attempted to unsafe URL")

    assert not emit_audit_event(
        decision,
        req,
        audit_stream_url=url,
        audit_stream_token="s" * 32,
        client=UnexpectedClient(),
    )
    assert "s" * 32 not in caplog.text
    assert "password" not in caplog.text
    assert "secret" not in caplog.text


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


def test_request_over_byte_limit_rejected_before_json_parse(monkeypatch):
    monkeypatch.setattr("function_app.httpx.post", lambda *a, **k: pytest.fail("upstream called"))
    request = func.HttpRequest(
        method="POST",
        url="http://localhost/api/governed/gpt-4o/chat/completions",
        body=b"x" * (MAX_REQUEST_BYTES + 1),
        route_params={"deployment": "gpt-4o"},
    )
    response = governed_chat_completions(request)
    assert response.status_code == 413
    assert json.loads(response.get_body()) == {"error": "request_too_large"}


def test_parser_recursion_error_is_invalid_request_not_server_error(monkeypatch):
    monkeypatch.setattr("function_app.httpx.post", lambda *a, **k: pytest.fail("upstream called"))
    request = func.HttpRequest(
        method="POST",
        url="http://localhost/api/governed/gpt-4o/chat/completions",
        body=b"[" * 2000 + b"0" + b"]" * 2000,
        route_params={"deployment": "gpt-4o"},
    )
    assert governed_chat_completions(request).status_code == 400


def test_parseable_deep_request_rejected_before_policy_or_upstream(monkeypatch):
    monkeypatch.setattr("function_app.httpx.post", lambda *a, **k: pytest.fail("upstream called"))
    nested = 0
    for _ in range(MAX_JSON_DEPTH + 1):
        nested = [nested]
    assert governed_chat_completions(_request({"messages": nested})).status_code == 400


def test_nonfinite_request_value_rejected_before_upstream(monkeypatch):
    monkeypatch.setattr("function_app.httpx.post", lambda *a, **k: pytest.fail("upstream called"))
    assert governed_chat_completions(_request({"messages": [float("inf")]})).status_code == 400


def test_invalid_config_denies_without_upstream_call(monkeypatch):
    monkeypatch.setenv("GOVERNANCE_CALLER_ID", "app-1")
    monkeypatch.setenv("POLICY_BUNDLES_JSON", "not json")
    monkeypatch.setattr("function_app.httpx.post", lambda *a, **k: pytest.fail("upstream called"))
    assert governed_chat_completions(_request({"messages": []})).status_code == 503
    assert healthz(_request({})).status_code == 503


@pytest.mark.parametrize(
    "raw",
    [
        '[{"bundle_id":"b","rules":[],"rules":[]}]',
        '[{"bundle_id":"b","rules":[],"x":NaN}]',
        '[{"bundle_id":"b","rules":[]},{"bundle_id":"b","rules":[]}]',
    ],
)
def test_ambiguous_bridge_rules_fail_closed(monkeypatch, raw):
    monkeypatch.setenv("GOVERNANCE_CALLER_ID", "app-1")
    monkeypatch.setenv("POLICY_BUNDLES_JSON", raw)
    monkeypatch.setattr("function_app.httpx.post", lambda *a, **k: pytest.fail("upstream called"))
    assert governed_chat_completions(_request({"messages": []})).status_code == 503


@pytest.mark.parametrize(
    "endpoint",
    [
        "http://fixture.openai.azure.com",
        "https://user:password@fixture.openai.azure.com",
        "https://fixture.openai.azure.com?token=secret",
        "https://fixture.openai.azure.com/#fragment",
        "https://fixture.openai.azure.com/openai",
        "https://fixture.openai.azure.com:444",
        "https://evil.example",
    ],
)
def test_unsafe_upstream_endpoint_fails_before_forwarding(monkeypatch, endpoint, caplog):
    monkeypatch.setenv("GOVERNANCE_CALLER_ID", "app-1")
    monkeypatch.setenv("POLICY_BUNDLES_JSON", json.dumps([BUNDLE]))
    monkeypatch.setenv("AZURE_OPENAI_ENDPOINT", endpoint)
    monkeypatch.setattr("function_app.httpx.post", lambda *a, **k: pytest.fail("upstream called"))
    assert governed_chat_completions(_request({"messages": []})).status_code == 503
    assert healthz(_request({})).status_code == 503
    assert "password" not in caplog.text
    assert "secret" not in caplog.text


def test_unsafe_api_version_fails_before_forwarding(monkeypatch):
    monkeypatch.setenv("GOVERNANCE_CALLER_ID", "app-1")
    monkeypatch.setenv("POLICY_BUNDLES_JSON", json.dumps([BUNDLE]))
    monkeypatch.setenv("AZURE_OPENAI_API_VERSION", "2024-10-21&extra=1")
    monkeypatch.setattr("function_app.httpx.post", lambda *a, **k: pytest.fail("upstream called"))
    assert governed_chat_completions(_request({"messages": []})).status_code == 503


def test_missing_upstream_key_fails_before_forwarding(monkeypatch):
    monkeypatch.setenv("GOVERNANCE_CALLER_ID", "app-1")
    monkeypatch.setenv("POLICY_BUNDLES_JSON", json.dumps([BUNDLE]))
    monkeypatch.delenv("AZURE_OPENAI_API_KEY")
    monkeypatch.setattr("function_app.httpx.post", lambda *a, **k: pytest.fail("upstream called"))
    assert governed_chat_completions(_request({"messages": []})).status_code == 503


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


def test_policy_regex_timeout_fails_closed_without_upstream(monkeypatch):
    monkeypatch.setenv("GOVERNANCE_CALLER_ID", "app-1")
    monkeypatch.setenv("POLICY_BUNDLES_JSON", json.dumps([BUNDLE]))

    def time_out(*args, **kwargs):
        raise TimeoutError

    monkeypatch.setattr("azure_openai_governance_bridge.broker.regex.fullmatch", time_out)
    monkeypatch.setattr("function_app.httpx.post", lambda *a, **k: pytest.fail("upstream called"))
    assert governed_chat_completions(_request({"messages": []})).status_code == 400


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


def test_missing_signed_card_fails_closed_without_upstream(monkeypatch):
    monkeypatch.setenv("GOVERNANCE_CALLER_ID", "app-1")
    monkeypatch.setenv("POLICY_BUNDLES_JSON", json.dumps([BUNDLE]))
    monkeypatch.delenv("GOVERNANCE_DECISION_CARD_JSON")
    monkeypatch.setattr("function_app.httpx.post", lambda *a, **k: pytest.fail("upstream called"))
    assert governed_chat_completions(_request({"messages": []})).status_code == 503
    assert healthz(_request({})).status_code == 503


def test_tampered_card_or_wrong_buyer_pin_fails_closed(monkeypatch):
    monkeypatch.setenv("GOVERNANCE_CALLER_ID", "app-1")
    monkeypatch.setenv("POLICY_BUNDLES_JSON", json.dumps([BUNDLE]))
    envelope = _signed_envelope(_card())
    envelope["card"]["subject"]["vendor_name"] = "Changed after signing"
    monkeypatch.setenv("GOVERNANCE_DECISION_CARD_JSON", json.dumps(envelope))
    monkeypatch.setattr("function_app.httpx.post", lambda *a, **k: pytest.fail("upstream called"))
    assert governed_chat_completions(_request({"messages": []})).status_code == 503
    _configure_card(monkeypatch)
    monkeypatch.setenv("GOVERNANCE_BUYER_ID", "wrong-buyer")
    assert governed_chat_completions(_request({"messages": []})).status_code == 503


@pytest.mark.parametrize("raw", ['{"card": {}, "card": {}}', '{"card": NaN, "attestation": {}}'])
def test_ambiguous_signed_card_json_fails_closed(monkeypatch, raw):
    monkeypatch.setenv("GOVERNANCE_CALLER_ID", "app-1")
    monkeypatch.setenv("POLICY_BUNDLES_JSON", json.dumps([BUNDLE]))
    monkeypatch.setenv("GOVERNANCE_DECISION_CARD_JSON", raw)
    monkeypatch.setattr("function_app.httpx.post", lambda *a, **k: pytest.fail("upstream called"))
    assert governed_chat_completions(_request({"messages": []})).status_code == 503


def test_expired_signed_card_denies_without_upstream(monkeypatch):
    monkeypatch.setenv("GOVERNANCE_CALLER_ID", "app-1")
    monkeypatch.setenv("POLICY_BUNDLES_JSON", json.dumps([BUNDLE]))
    _configure_card(
        monkeypatch,
        _card(decision={"status": "approved", "effective_until": "2026-01-01T00:00:00Z"}),
    )
    monkeypatch.setattr("function_app.httpx.post", lambda *a, **k: pytest.fail("upstream called"))
    response = governed_chat_completions(_request({"messages": []}))
    assert response.status_code == 403
    assert json.loads(response.get_body())["matched_rules"] == ["decision-card-gate"]
    assert healthz(_request({})).status_code == 503


def test_evaluator_fault_denies_with_sanitized_audit_and_health(monkeypatch, caplog):
    monkeypatch.setenv("GOVERNANCE_CALLER_ID", "app-1")
    monkeypatch.setenv("POLICY_BUNDLES_JSON", json.dumps([BUNDLE]))
    monkeypatch.setattr("function_app.httpx.post", lambda *a, **k: pytest.fail("upstream called"))
    observed = {}

    def fail_evaluation(self):
        raise RuntimeError("fixture-secret")

    def capture_audit(decision, request):
        observed["decision"] = decision
        observed["request"] = request
        return True

    monkeypatch.setattr("azure_openai_governance_bridge.signed_card.SignedCardGate.evaluate", fail_evaluation)
    monkeypatch.setattr("function_app.emit_audit_event", capture_audit)
    response = governed_chat_completions(_request({"messages": []}))
    assert response.status_code == 503
    assert json.loads(response.get_body())["error"] == "governance_evaluation_unavailable"
    assert observed["decision"].outcome == "deny"
    assert observed["decision"].matched_rules == ["decision-card-evaluation-error"]
    assert observed["request"].tool_name == "azure-openai.gpt-4o"
    assert healthz(_request({})).status_code == 503
    assert "fixture-secret" not in caplog.text
    assert b"fixture-secret" not in response.get_body()


def test_evaluator_fault_still_returns_503_if_audit_emitter_fails(monkeypatch, caplog):
    monkeypatch.setenv("GOVERNANCE_CALLER_ID", "app-1")
    monkeypatch.setenv("POLICY_BUNDLES_JSON", json.dumps([BUNDLE]))

    def fail(*args, **kwargs):
        raise RuntimeError("fixture-secret")

    monkeypatch.setattr("azure_openai_governance_bridge.signed_card.SignedCardGate.evaluate", fail)
    monkeypatch.setattr("function_app.emit_audit_event", fail)
    monkeypatch.setattr("function_app.httpx.post", lambda *a, **k: pytest.fail("upstream called"))
    response = governed_chat_completions(_request({"messages": []}))
    assert response.status_code == 503
    assert "fixture-secret" not in caplog.text
    assert b"fixture-secret" not in response.get_body()


def test_conditional_card_ignores_request_assertions_and_denies(monkeypatch):
    monkeypatch.setenv("GOVERNANCE_CALLER_ID", "app-1")
    monkeypatch.setenv("POLICY_BUNDLES_JSON", json.dumps([BUNDLE]))
    _configure_card(
        monkeypatch,
        _card(
            decision={"status": "approved-with-conditions", "effective_until": "2999-01-01T00:00:00Z"},
            conditions=[{"id": "dpa-signed", "description": "DPA is signed"}],
        ),
    )
    monkeypatch.setattr("function_app.httpx.post", lambda *a, **k: pytest.fail("upstream called"))
    response = governed_chat_completions(
        _request(
            {"messages": [], "conditions_satisfied": {"dpa-signed": True}},
            headers={"x-kg-vendor-id": "vendor-1", "x-kg-condition-dpa-signed": "true"},
        )
    )
    assert response.status_code == 403


def test_forged_vendor_header_cannot_change_server_scope(monkeypatch):
    monkeypatch.setenv("GOVERNANCE_CALLER_ID", "app-1")
    monkeypatch.setenv("POLICY_BUNDLES_JSON", json.dumps([BUNDLE]))
    monkeypatch.setenv("GOVERNANCE_VENDOR_ID", "another-vendor")
    monkeypatch.setattr("function_app.httpx.post", lambda *a, **k: pytest.fail("upstream called"))
    response = governed_chat_completions(_request({"messages": []}, headers={"x-kg-vendor-id": "vendor-1"}))
    assert response.status_code == 503


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
            decision,
            perm_req,
            audit_stream_url="https://audit.example/events",
            audit_stream_token="t" * 32,
            client=FailedClient(),
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
