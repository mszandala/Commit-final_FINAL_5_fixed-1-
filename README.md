# AI Control Layer

A security layer between users (or apps) and an LLM agent. It checks every prompt, tool call and reply, and masks sensitive data before the model sees it. All controls live in `policy/policy.yaml`, which reloads without a restart.

## Quick start

Set the model in `backend/.env` (copy `backend/.env.example`), **two options:**

- **OpenRouter**: `OPENROUTER_API_KEY=...`
- **Ollama**: `LLM_PROVIDER=ollama`, `OLLAMA_MODEL=gemma4:12b`, `OLLAMA_HOST=http://host.docker.internal:11434`, after `ollama pull gemma4:12b`

Then:

```bash
git lfs pull                           # optional: stock price data (~1.7 GB)
docker compose up -d --build
docker compose run --rm tests          # offline test suite, no key needed
```

UI at http://127.0.0.1:8080, API docs at http://127.0.0.1:8000/docs, proxy at http://127.0.0.1:8000/v1. Details in `DOCKER.md`.

## 1. Solution

Two ways in:

- **Demo app**: chat with a role picker, a security dashboard and a config panel.
- **OpenAI-compatible proxy** (`/v1/chat/completions`): an existing app changes only `base_url` and the API key; the key sets the role.

Both use the same pipeline, split into two zones:

| Zone | Who | Sees |
|---|---|---|
| security | prompt guard, intent classifier, PII judge, refusal judge | raw data (meant to run on local models) |
| chatbot | the model answering the user | placeholders (`<EMAIL_1>`) and pseudonyms (`ID-3fa9c21b07`) only |

<img src="screenshots/2.png" alt="Chat" width="360">

### Configuration

`policy/policy.yaml` is the single config source.

- Changes apply on the next request. A broken file keeps the last valid version (error in `GET /api/v1/policy`).
- Unknown keys are rejected; a control is off only with `enabled: false`.
- Config panel toggles go to `policy.overrides.json`; Reset drops them.

Strictness profiles (`profile:`):

| | strict | balanced (default) | permissive |
|---|---|---|---|
| Max prompt | 2000 chars | 4000 | 8000 |
| Prompt guard | block | block | warn |
| Company policies | block on keyword or topic, fail closed | warn | warn |
| PII threshold | 0.20 | 0.35 | 0.50 |
| Cost per turn | $0.02 | $0.05 | $0.20 |
| Tool steps per turn | 6 | 10 | 15 |
| Spending limit per role | $0.25 | $0.50 | $2.00 |

Roles set allowed tools, visible PII and daily tokens:

```yaml
"bankier":
  id: banker
  allowed_tools: [list_projects, read_project, read_client_records, summarize_client_records, read_bank_campaigns]
  allowed_pii: [SALARY, LOCATION, PROJECT, ORGANIZATION]
  daily_tokens: 50000
```

Analysts see client IDs only as pseudonyms (`pii_policy: {CLIENT-ID: pseudonymize}`).

<img src="screenshots/3.png" alt="Config panel" width="800">

### Controls

| Control | Type | What it does |
|---|---|---|
| Model allowlist | deterministic | Blocks models not in `models.allowed` |
| Prompt length | deterministic | Rejects long prompts before any model sees them |
| Prompt guard | deterministic | Injection and jailbreak patterns (EN, PL), role access to resources |
| Intent classifier | AI | Labels the request: in scope, restricted resource, out of scope, jailbreak |
| Company policies | hybrid | Rules from company documents (NDA, AI policy): keywords, patterns, document fingerprints, semantic classifier. Checks prompt, tool calls, results and reply |
| PII masking | hybrid | Regex + GLiNER; per type allow, redact, block or LLM judge. IDs get HMAC pseudonyms |
| Tool whitelist | deterministic | Tool must be in the role's `allowed_tools`, checked before it runs |
| Tool result scanning | deterministic / hybrid | Masks PII in results, strips paths and stack traces, truncates |
| Code guard | deterministic | AST check before `run_python`: module allowlist, named attack types |
| Executor sandbox | infrastructure | Separate container: no network, read-only, CPU/memory/time limits |
| Output filter | deterministic | Per-role PII policy on the reply; passwords and card numbers always block |
| Refusal detection | AI | Embeddings + LLM judge flag chatbot refusals |
| Budgets | deterministic | Per turn: tokens, cost, tool steps. Per role: daily tokens, USD limit |
| Audit | – | Every stage logged, masked values only |

## 2. Architecture

<img src="screenshots/1.png" alt="Architecture" width="480">

One turn:

1. Model allowlist, prompt length, prompt guard, intent classifier.
2. Company policies on the raw prompt.
3. PII masked; the chatbot gets placeholders.
4. Each tool call: whitelist, budget, company policies. The tool runs locally on unmasked arguments; the result is masked.
5. Reply: company policies and output filter; placeholders become values, labels or pseudonyms per role.
6. Refusal detection, audit log.

### Performance

117 turns, Gemma 4 26B via OpenRouter:

| Spent on | Kind | p50 | p95 |
|---|---|---|---|
| Local checks (regex, whitelists, AST, GLiNER) | deterministic + local model | 185 ms | 1.1 s |
| Intent classifier | LLM | 1.4 s | 2.8 s |
| Refusal judge | LLM | 1.2 s | 2.6 s |
| PII judge | LLM | 1.6 s | 7.5 s |
| Company policy classifier | LLM | 2.5 s | 13.2 s |
| **Worst-case total, security layer** | | **6.9 s** | **27.2 s** |
| Chatbot (external) | LLM | 3.7 s | 15.7 s |

Worst case assumes every control fires; judges run only when needed, so the real average was 5.3 s per turn. Rule checks stay under 2 ms at p95; local time is mostly GLiNER. LLM controls take nearly all the time and 35% of spend, so each can be turned off or moved to a local model (`SECURITY_MODEL`).

## 3. Reporting

<img src="screenshots/4.png" alt="Dashboard" width="800">

<img src="screenshots/5.png" alt="Logs" width="800">

<img src="screenshots/6.png" alt="Report" width="800">

Tabs: **Logs** (each turn with its check trace), **Dashboard** (metrics), **Report** (printable summary of a period), **Tests** (live scenarios).

Metrics (`GET /api/v1/metrics?sinceMinutes=N`):

- decisions (allowed, redacted, refused, blocked), block and intervention rates
- blocks and warnings per control
- attack types (prompt injection, code execution, deserialization, ...)
- turns per role
- tokens and cost, chatbot vs security
- budget use per role
- latency per turn (avg, p50, p95, p99, max), per control and per zone

Audit export: `GET /api/v1/audit/export` (JSONL or CSV). `AUDIT_SINK=stdout` streams events as JSON lines.

## 4. Testing

**Offline suite**: 440 pytest tests on a mock model, no key or network needed.

```bash
docker compose run --rm tests
# or: cd backend && python -m pytest tests
```

Includes 96 self-written cases in `backend/tests/datasets/`, modelled on PINT, HackAPrompt, InjecAgent, Garak and OWASP LLM Top 10 (sources in `TEST_SUITE_DATASOURCES.md`):

| Dataset | Cases | Blocked / allowed |
|---|---|---|
| input guardrails | 44 | 29 / 15 |
| output guardrails | 30 | 22 / 8 |
| budget and resources | 10 | 7 / 3 |
| historical attacks | 12 | 9 / 3 |

**Live scenarios**: 32 real turns through the layer and model, from the Tests tab or `python -m live_tests [group]`. Some of them:

| Scenario | Expected |
|---|---|
| Banker reads a client record | allowed |
| HR / basic employee asks for the same record | blocked |
| Analyst reads clients | allowed, IDs pseudonymized |
| Prompt injection (EN, PL), DAN, admin impersonation, base64 payload | blocked |
| Code execution: list server files | blocked |
| Card number in the prompt | never reaches the model |
| E-mail in the prompt | masked for the model, restored for the user |
| Prompt length limit 40 chars | blocked |
| Turn budget 1 token | stopped |
| Control on vs off (masking, code guard, output filter, company policies) | side by side |

<img src="screenshots/7.png" alt="Tests" width="800">

`eval_masking.py` and `eval_refusals.py` measure leaks and over-redaction on the datasets.

## 5. Implementation

```
backend/
  api/         REST API for the UI: chat, logs, metrics, export, tests
  proxy/       OpenAI-compatible proxy, API keys, sessions
  core/        turn stages, policy model, PII handling
  security/    guards, classifiers, masking, code guard, budgets, company policies
  tools/       demo agent tools (HR, banking, markets, projects, code)
  live_tests/  live scenario runner
  tests/       pytest suite and datasets
frontend/      React + Vite
policy/        policy.yaml
```

Stack: Python, FastAPI, GLiNER, sentence-transformers, SQLite, React. LLM: OpenRouter or Ollama.

### Plugging into an existing agent

Point the OpenAI client at the proxy:

```python
from openai import OpenAI

client = OpenAI(base_url="http://127.0.0.1:8000/v1", api_key="sk-demo-hr")
reply = client.chat.completions.create(
    model="google/gemma-4-26b-a4b-it",
    messages=[{"role": "user", "content": "What is the average salary in Sales?"}],
)
print(reply.model_extra["x_security"]["decision"])   # pass | redact | refuse | block
```

The response includes the decision, check trace and policy version (`x_security`, `X-Security-Decision`, `X-Policy-Version`). New key: `python -m proxy new-key <name> <role>`; the policy stores only its SHA-256.

Containers run as non-root, read-only, with `cap_drop: ALL` and resource limits.

### Limitations

- In the demo both zones call OpenRouter; in production the security zone should run on local models.
- The proxy doesn't support streaming yet.
