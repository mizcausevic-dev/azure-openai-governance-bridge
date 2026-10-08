# azure-openai-governance-bridge

> Experimental Azure Function that checks a locally configured broker rule set before forwarding chat-completion requests. It does not yet enforce a signed AI Procurement Decision Card or the `policy-as-code-engine` PolicyBundle contract.

Point your app at the bridge instead of Azure OpenAI directly:

```
POST  https://<your-fn>.azurewebsites.net/api/governed/{deployment}/chat/completions
      x-functions-key: <workload-specific-function-key>
```

The bridge evaluates the call against deny-trumps-allow `PolicyBundle`s, and:

- **allow** → forwards to Azure OpenAI, returns the completion verbatim (+ a `x-kg-correlation-id` header)
- **deny** → `403` with the matched rule and any configured Decision Card URL; nothing is forwarded
- **require_approval** → `409`; no approval-token verification exists yet, so an operator must update policy through a separate trusted process before the call can proceed

The bridge attempts one `tool_invocation_*` POST to [`audit-stream-py`](https://github.com/mizcausevic-dev/audit-stream-py) for the governing decision. Audit is optional and best-effort: missing or failed delivery does not block forwarding. This is not durable, per-tool, tamper-evident audit evidence.

**Release status:** this repository is a local integration prototype. Do not put it on a production data path until the identity, bundle provenance, audit, network, secrets, deployment, and rollback gates below are closed.

## Why this exists

Azure OpenAI is a REST data path distinct from MCP tool invocation. This prototype shows how a local rule check can sit before that path. Its current rule format is not a verified enforcement path from a published buyer Decision Card.

This bridge accepts the `mcp-permission-broker`-style `rules[]` JSON shape. The current `policy-as-code-engine` produces a different `policies[]`/typed-matcher contract with signed-card scope and effective windows. Those bundles cannot be loaded here. A verified adapter and runtime attestation checks are required before claiming Decision Card enforcement.

## What gets checked

For each request the bridge derives a list of `tool_name`s and checks every one (deny-trumps-allow across the whole request):

| Derived `tool_name` | From |
| --- | --- |
| `azure-openai.<deployment>` | the route's deployment (e.g. `azure-openai.gpt-4o`) |
| `tool.<name>` | each function-calling tool declared in the request `tools[]` |

So a locally configured rule can restrict a deployment or declared function name before a single token is generated. The bridge checks declarations, not later execution of returned tool calls. It rejects malformed `tools`, undeclared `tool_choice`, and legacy `functions`/`function_call` fields rather than silently skipping them.

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

Evaluation order: deny → require_approval → allow → default deny. `when.expr` accepts only `context.get('environment') == 'production'`-style string equality/inequality on `environment` or `deployment`. Unsupported expressions reject the entire configuration before any request is forwarded; Python `eval` is not used.

`GOVERNANCE_CALLER_ID` and `GOVERNANCE_ENVIRONMENT` are server-side settings. Request headers cannot change them. The Function key is still a shared bearer credential, not per-user or per-tenant authentication. Run one Function app and key per workload until a verified identity integration exists; do not use caller-specific policy rules for multiple callers sharing a key.

## Deploy

### Infrastructure (Bicep)

```bash
az bicep build --file infra/main.bicep
```

This checks template syntax only; it does not provision resources. The current Bicep provisions a Consumption-plan Linux Python Function App, storage, and Application Insights. It passes an Azure OpenAI key into an app setting and exposes a public Function endpoint. Do not deploy this template to a production workload until Key Vault or managed identity, private network boundaries, identity binding, and audit delivery are designed and verified. Passing a raw key on the CLI would also expose it in shell history.

### Code

```bash
func azure functionapp publish <functionAppName>
```

### App settings

| Setting | Required | Purpose |
| --- | --- | --- |
| `AZURE_OPENAI_ENDPOINT` | yes | Upstream Azure OpenAI resource |
| `AZURE_OPENAI_API_KEY` | yes | Upstream key; current template uses a direct app setting and is not production-ready |
| `AZURE_OPENAI_API_VERSION` | no (`2024-10-21`) | API version forwarded upstream |
| `POLICY_BUNDLES_JSON` | no (`[]`) | JSON array of bridge `rules[]` bundles; malformed config returns 503 |
| `AUDIT_STREAM_URL` | no | Best-effort audit-stream-py `/events` endpoint |
| `GOVERNANCE_CALLER_ID` | yes | Server-side identity for this one workload; absent returns 503; this is not caller authentication |
| `GOVERNANCE_ENVIRONMENT` | no (`production`) | Server-side production, staging, or development |
| `DEFAULT_OUTCOME` | no (`deny`) | Must be `deny`; any other value returns 503 |

## Local development

```bash
cp local.settings.json.example local.settings.json   # fill in your values
pip install -r requirements.txt
func start
```

```bash
# health
curl http://localhost:7071/api/healthz

# a governed call (denied by the example bundle if you set POLICY_BUNDLES_JSON)
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

The core (broker, bridge orchestration, audit emitter) is pure Python and fully unit-tested without the Azure Functions host. `function_app.py` is the thin Azure adapter.

## Composes with

| Concern | Repo |
| --- | --- |
| MCP-shaped sibling gate | [`mcp-permission-broker`](https://github.com/mizcausevic-dev/mcp-permission-broker) |
| Future bundle adapter | [`policy-as-code-engine`](https://github.com/mizcausevic-dev/policy-as-code-engine) (current `policies[]` output is incompatible with this bridge's `rules[]` input) |
| Future signed-card input | [`ai-procurement-decision-spec`](https://github.com/mizcausevic-dev/ai-procurement-decision-spec) (not yet verified or enforced here) |
| Optional best-effort event target | [`audit-stream-py`](https://github.com/mizcausevic-dev/audit-stream-py) (delivery and durability not verified) |

## Status

**v0.1.0 prototype** — chat-completions proxy. CI is configured for Python 3.11/3.12/3.13, ruff, mypy, and Bicep build; a green CI run does not prove Azure deployment or runtime enforcement boundaries.

Production release gates: authenticate the requesting workload with a trusted identity and scope; protect the upstream resource from bypass; bind approved bundle version, issuer, signature, scope, and effective window to the workload; make audit delivery durable with documented failure behavior; move upstream secrets to a managed credential boundary; perform private staging denial/allowance drills, endpoint and log inspection, and a restore/rollback drill. None of these are demonstrated by local unit tests.

Roadmap: streaming (SSE) passthrough · embeddings + responses endpoints · Key Vault-backed bundle loading · Entra ID caller identity (instead of header-based) · per-deployment rate annotations.

## License

MIT.
