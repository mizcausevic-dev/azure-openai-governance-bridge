# azure-openai-governance-bridge

> An Azure Function that sits in front of Azure OpenAI and **enforces a buyer's AI Procurement Decision Card at request time** — the Azure-native sibling of [`mcp-permission-broker`](https://github.com/mizcausevic-dev/mcp-permission-broker).

Point your app at the bridge instead of Azure OpenAI directly:

```
POST  https://<your-fn>.azurewebsites.net/api/governed/{deployment}/chat/completions
      x-kg-caller-id: billing-agent-prod
      x-kg-environment: production
```

The bridge evaluates the call against deny-trumps-allow `PolicyBundle`s, and:

- **allow** → forwards to Azure OpenAI, returns the completion verbatim (+ a `x-kg-correlation-id` header)
- **deny** → `403` with the rationale and the Decision Card it traces to; nothing is forwarded
- **require_approval** → `409`; the caller must obtain human approval first

Every decision emits a `tool_invocation_*` event to [`audit-stream-py`](https://github.com/mizcausevic-dev/audit-stream-py), so the Azure data path writes to the same tamper-evident spine as the rest of the [Kinetic Gain Protocol Suite](https://github.com/mizcausevic-dev/kinetic-gain-protocol-suite).

## Why this exists

Enterprises run their AI workloads on Azure OpenAI in enormous volume. The Suite has a *runtime gate for MCP* (`mcp-permission-broker`) but Azure OpenAI is a different data path — direct REST, no MCP. This bridge puts the same governance contract on that path: a school district, hospital, or agency that published an AI Procurement Decision Card can have its conditions enforced on every Azure OpenAI call, not just on MCP tool invocations.

Same `PolicyBundle` shape as `mcp-permission-broker` — a bundle authored for one enforces identically on the other.

## What gets checked

For each request the bridge derives a list of `tool_name`s and checks every one (deny-trumps-allow across the whole request):

| Derived `tool_name` | From |
| --- | --- |
| `azure-openai.<deployment>` | the route's deployment (e.g. `azure-openai.gpt-4o`) |
| `tool.<name>` | each function-calling tool declared in the request `tools[]` |

So a bundle can say "students may only invoke `gpt-4o-mini`," "no destructive tool may run in production," or "PII-lookup tools require human approval" — and the bridge enforces it before a single token is generated.

## Rule grammar

Identical to `mcp-permission-broker`. Example ([`examples/policy-bundle.json`](examples/policy-bundle.json)):

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

Evaluation order: deny → require_approval → allow → configurable default (`deny` for governed posture). The `when.expr` is evaluated with no builtins (fail-closed).

## Deploy

### Infrastructure (Bicep)

```bash
az deployment group create -g my-rg -f infra/main.bicep \
  -p aoaiEndpoint=https://my-aoai.openai.azure.com \
     aoaiApiKey=<key> \
     auditStreamUrl=https://audit.internal/events \
     policyBundlesJson="$(cat examples/policy-bundle.json)"
```

Provisions a Consumption-plan Linux Python Function App, storage, and Application Insights, wired with all bridge app settings. Outputs the Function hostname.

### Code

```bash
func azure functionapp publish <functionAppName>
```

### App settings

| Setting | Required | Purpose |
| --- | --- | --- |
| `AZURE_OPENAI_ENDPOINT` | yes | Upstream Azure OpenAI resource |
| `AZURE_OPENAI_API_KEY` | yes | Upstream key (use Key Vault refs in prod) |
| `AZURE_OPENAI_API_VERSION` | no (`2024-10-21`) | API version forwarded upstream |
| `POLICY_BUNDLES_JSON` | no (`[]`) | JSON array of PolicyBundle objects |
| `AUDIT_STREAM_URL` | no | audit-stream-py `/events` endpoint |
| `DEFAULT_OUTCOME` | no (`deny`) | Outcome when no rule matches |

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
  -H 'x-kg-caller-id: student-123' -H 'content-type: application/json' \
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
| Where bundles come from | [`policy-as-code-engine`](https://github.com/mizcausevic-dev/policy-as-code-engine) (from a Decision Card's conditions) |
| The spec being enforced | [`ai-procurement-decision-spec`](https://github.com/mizcausevic-dev/ai-procurement-decision-spec) |
| The tamper-evident spine | [`audit-stream-py`](https://github.com/mizcausevic-dev/audit-stream-py) |

## Status

**v0.1.0** — chat-completions proxy. Python 3.11/3.12/3.13. CI green (pytest + ruff + mypy strict + bicep build).

Roadmap: streaming (SSE) passthrough · embeddings + responses endpoints · Key Vault-backed bundle loading · Entra ID caller identity (instead of header-based) · per-deployment rate annotations.

## License

MIT.
