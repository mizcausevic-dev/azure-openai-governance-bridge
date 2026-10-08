# azure-openai-governance-bridge

> Experimental Azure Function that requires both an operator-pinned, signed buyer Decision Card and a locally configured per-tool rule set before forwarding chat-completion requests.

Point your app at the bridge instead of Azure OpenAI directly:

```
POST  https://<your-fn>.azurewebsites.net/api/governed/{deployment}/chat/completions
      x-functions-key: <workload-specific-function-key>
```

The bridge derives the `policy-as-code-engine` `policies[]` bundle from the signed card and evaluates its effective window and vendor/`use` scope on each request. It separately evaluates bridge `rules[]` for the deployment and declared tools. Both gates must allow, and:

- **allow** → forwards to Azure OpenAI, returns the completion verbatim (+ a `x-kg-correlation-id` header)
- **deny** → `403` with the matched rule and any configured Decision Card URL; nothing is forwarded
- **require_approval** → `409`; no approval-token verification exists yet, so an operator must update policy through a separate trusted process before the call can proceed

The bridge attempts one authenticated `tool_invocation_*` POST to [`audit-stream-py`](https://github.com/mizcausevic-dev/audit-stream-py) for the governing decision when both audit URL and token are configured. The sink URL must use HTTPS or numeric loopback HTTP (`127.0.0.1` or `::1`), without embedded credentials, query, or fragment; redirects are not followed. Audit is optional and best-effort: missing or failed delivery does not block forwarding. This is not durable, per-tool, tamper-evident audit evidence.

**Release status:** this repository is a local integration prototype. Do not put it on a production data path until the identity, bundle provenance, audit, network, secrets, deployment, and rollback gates below are closed.

## Why this exists

Azure OpenAI is a REST data path distinct from MCP tool invocation. This prototype shows how a pinned buyer signature and scope check can sit before that path. It does not independently verify buyer authority, live revocation, the Function-key caller, or whether clients can bypass the bridge.

The bridge continues to use its own `rules[]` format for deployment and tool checks. It does **not** accept a bare `policies[]` bundle as evidence of signing: the engine bundle has no embedded attestation. The bridge verifies the card and v2 Ed25519 attestation against an independently pinned buyer ID, key URL, and public key before deriving and evaluating the engine bundle. The operator must separately confirm that the pinned buyer key represents an authorized buyer.

## What gets checked

For each request the bridge derives a list of `tool_name`s and checks every one (deny-trumps-allow across the whole request):

| Derived `tool_name` | From |
| --- | --- |
| `azure-openai.<deployment>` | the route's deployment (e.g. `azure-openai.gpt-4o`) |
| `tool.<name>` | each function-calling tool declared in the request `tools[]` |

So a locally configured rule can restrict a deployment or declared function name before a single token is generated. The bridge checks declarations, not later execution of returned tool calls. It rejects malformed `tools`, undeclared `tool_choice`, and legacy `functions`/`function_call` fields rather than silently skipping them.

The Function adapter rejects request bodies over 1 MiB with HTTP 413 before JSON parsing. The Functions host may still buffer a body before the adapter sees it; add an ingress limit at the deployed boundary. Evaluator faults return 503 without forwarding and emit a sanitized deny event when the audit sink is available. `/healthz` returns 503 when the signed card currently denies or evaluation fails.

## Rule grammar

Similar to `mcp-permission-broker`, with a deliberately restricted condition subset. This [synthetic example](examples/policy-bundle.json) is for local tests:

```json
{
  "id": "deny-destructive-tools-in-prod",
  "priority": 100,
  "effect": "deny",
  "tool_name": "^tool\\..*(delete|drop|purge).*",
  "when": { "expr": "context.get('environment') == 'production'" },
  "because": { "decision_card": "https://district.example/.well-known/decisions/DEC-1.json", "condition_id": "no-destructive-prod-actions" }
}
```

Evaluation order: deny → require_approval → allow → default deny. `when.expr` accepts only `context.get('environment') == 'production'`-style string equality/inequality on `environment` or `deployment`. Unsupported expressions reject the entire configuration before any request is forwarded; Python `eval` is not used. Regex checks have a 20 ms timeout; a timeout rejects the request without forwarding.

`GOVERNANCE_CALLER_ID` and `GOVERNANCE_ENVIRONMENT` are server-side settings. Request headers cannot change them. The Function key is still a shared bearer credential, not per-user or per-tenant authentication. Run one Function app and key per workload until a verified identity integration exists; do not use caller-specific policy rules for multiple callers sharing a key.

`GOVERNANCE_VENDOR_ID` is also fixed by the operator. The card's vendor must match it; the engine action is fixed to `use`. A conditional approval always denies in this version because the bridge has no trusted, expiring condition-assertion channel. Request body fields and headers cannot assert conditions. A buyer withdrawal after configuration is not discovered automatically; the operator must disable the route or update the card. An expired card denies at evaluation time.

The operator-chosen `use` scope is not a buyer-signed permission for every Azure model or function. The per-tool rules and the buyer's actual approval process must separately authorize the specific workload, deployments, and tool declarations.

## Deploy

### Infrastructure (Bicep)

```bash
az bicep build --file infra/main.bicep
```

This checks template syntax only; it does not provision resources. The current Bicep provisions a Consumption-plan Linux Python Function App, storage, and Application Insights. It passes the upstream key, signed card, and audit token into app settings and exposes a public Function endpoint. Do not deploy this template to a production workload until managed secrets, private network boundaries, identity binding, revocation, and audit delivery are designed and verified. Passing raw keys, tokens, or card JSON on the CLI can expose them in shell history.

### Code

```bash
func azure functionapp publish <functionAppName>
```

### App settings

| Setting | Required | Purpose |
| --- | --- | --- |
| `AZURE_OPENAI_ENDPOINT` | yes | HTTPS root URL on `<resource>.openai.azure.com`; no userinfo, nonstandard port, path, query, or fragment; Private Endpoint DNS can resolve that hostname privately |
| `AZURE_OPENAI_API_KEY` | yes | Upstream key; current template uses a direct app setting and is not production-ready |
| `AZURE_OPENAI_API_VERSION` | no (`2024-10-21`) | Date or date-preview version only; malformed values return 503 |
| `POLICY_BUNDLES_JSON` | yes for an allow | JSON array of bridge `rules[]` bundles; empty or unmatched rules default deny; duplicate keys, IDs, and non-finite numbers return 503 |
| `GOVERNANCE_DECISION_CARD_JSON` | yes | JSON `{ "card": ..., "attestation": ... }`; max 128 KiB, duplicate keys and non-finite numbers rejected; missing/invalid config returns 503 |
| `GOVERNANCE_BUYER_ID` | yes | Buyer ID independently pinned by the operator |
| `GOVERNANCE_BUYER_KEY_URL` | yes | Independently pinned HTTPS key URL, compared with signed attestation |
| `GOVERNANCE_BUYER_PUBLIC_KEY_B64` | yes | Base64 Ed25519 public key pinned from buyer authority evidence |
| `GOVERNANCE_VENDOR_ID` | yes | Operator-fixed vendor scope for this one workload |
| `AUDIT_STREAM_URL` | no | Best-effort audit-stream-py base URL or existing `/events` URL |
| `AUDIT_STREAM_TOKEN` | when audit URL set | Separate bearer token, at least 32 visible ASCII characters; failed audit still does not block forwarding |
| `GOVERNANCE_CALLER_ID` | yes | Server-side identity for this one workload; absent returns 503; this is not caller authentication |
| `GOVERNANCE_ENVIRONMENT` | no (`production`) | Server-side production, staging, or development |
| `DEFAULT_OUTCOME` | no (`deny`) | Must be `deny`; any other value returns 503 |

Endpoint validation currently supports the Azure public-cloud `<resource>.openai.azure.com` hostname only. Private DNS may resolve that hostname to a private address. Sovereign-cloud and custom Azure OpenAI domains need a separately reviewed allowlist change before use.

## Local development

```bash
cp local.settings.json.example local.settings.json   # fill in your values, including a real signed card and independently pinned buyer key
pip install -r requirements.txt
func start
```

```bash
# health
curl http://localhost:7071/api/healthz

# a governed call (denied until both signed-card and per-tool gates allow)
curl -X POST http://localhost:7071/api/governed/gpt-4o/chat/completions \
  -H 'content-type: application/json' \
  -d '{"messages":[{"role":"user","content":"hi"}]}'
```

## Testing

```bash
pip install -e ".[dev]"
pytest -v        # broker + bridge orchestration + audit, no Azure runtime needed
ruff check src tests function_app.py
mypy src
```

The core (signed-card verifier/evaluator, broker, bridge orchestration, audit emitter) is tested locally without the Azure Functions host. `function_app.py` is the thin Azure adapter. The synthetic test signing key is never a buyer credential.

## Composes with

| Concern | Repo |
| --- | --- |
| MCP-shaped sibling gate | [`mcp-permission-broker`](https://github.com/mizcausevic-dev/mcp-permission-broker) |
| Signed card conversion and scoped evaluation | [`policy-as-code-engine`](https://github.com/mizcausevic-dev/policy-as-code-engine) v0.2.0; a bare serialized bundle remains untrusted |
| Decision Card schema source | [`ai-procurement-decision-spec`](https://github.com/mizcausevic-dev/ai-procurement-decision-spec); buyer authority and status freshness remain operator responsibilities |
| Optional best-effort event target | [`audit-stream-py`](https://github.com/mizcausevic-dev/audit-stream-py) (delivery and durability not verified) |

## Status

**v0.1.0 prototype** — chat-completions proxy. CI is configured for Python 3.11/3.12/3.13, ruff, mypy, and Bicep build; a green CI run does not prove Azure deployment or runtime enforcement boundaries.

Production release gates: authenticate the requesting workload with a trusted identity and scope; protect the upstream resource from bypass; bind and recheck buyer authority, card status, key rotation, and revocation; add a trusted condition-assertion channel if conditional cards are needed; make audit delivery durable with documented failure behavior; move upstream secrets to a managed credential boundary; perform private staging denial/allowance drills, endpoint and log inspection, and a restore/rollback drill. None of these are demonstrated by local unit tests.

Roadmap: streaming (SSE) passthrough · embeddings + responses endpoints · Key Vault-backed bundle loading · Entra ID caller identity (instead of header-based) · per-deployment rate annotations.

## License

MIT.
