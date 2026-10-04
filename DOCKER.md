# Running with Docker

Compose launches three services: **backend** (demo application API, admin panel, metrics, and OpenAI-compatible proxy, single process), **frontend** (nginx with the UI that proxies `/api` and `/v1` to the backend), and **executor** (isolated container that executes code from the `run_python` tool). The LLM runs at the provider (default: OpenRouter); PII detection and refusal detection models are packaged inside the image, so the container requires no internet access other than outbound LLM API calls.

## Requirements

- Docker Desktop in **Linux containers** mode (Windows: WSL 2) or Docker Engine with the Compose plugin.
- `git lfs pull`: Stock market data in `backend/data/stock_market` is tracked in Git LFS.
- Model provider API key in `backend/.env` (see `backend/.env.example`), e.g. `OPENROUTER_API_KEY=...`. Compose loads it on startup (`.dockerignore` excludes `.env` from the image).

## Startup

```bash
docker compose up -d --build
```

| URL | Description |
|---|---|
| http://127.0.0.1:8080 | Web UI (chat, dashboard, configuration) |
| http://127.0.0.1:8000/docs | API Documentation (OpenAPI / Swagger) |
| http://127.0.0.1:8000/v1 | OpenAI-compatible proxy (`base_url` for external apps) |

Ports are bound to `127.0.0.1` by default. If ports 8000 or 8080 are already occupied:
`API_PORT=18000 UI_PORT=18080 docker compose up -d --build` (or set them in `.env`).

```bash
docker compose ps                  # Check status and health of services
docker compose logs -f backend     # View backend logs
docker compose down                # Stop services (persists the `state` volume)
docker compose down -v             # Stop and remove state volume (audit logs, DBs, overrides)
```

## Proxy for External Applications

Applications only need to change `base_url` and the API key; the key determines the role (configured in `clients` section of `policy/policy.yaml`).
Demo keys: `sk-demo-basic-user`, `sk-demo-hr`, `sk-demo-banker`, `sk-demo-admin`.
Generate custom key: `python -m proxy new-key name "role"` outputs the key and policy snippet.

```python
from openai import OpenAI

client = OpenAI(base_url="http://127.0.0.1:8000/v1", api_key="sk-demo-hr")
reply = client.chat.completions.create(
    model="google/gemma-4-26b-a4b-it",
    messages=[{"role": "user", "content": "Hello, how can you help me?"}],
)
print(reply.choices[0].message.content)
print(reply.model_extra["x_security"]["decision"])      # pass | redact | refuse | block
```

The response includes an `x_security` object (decision, control trail, policy version) and headers `X-Session-Id`, `X-Security-Decision`, `X-Policy-Version`. Subsequent requests in the same conversation are linked via `X-Session-Id`.

## Live Policy Reload

`policy/policy.yaml` is the single source of truth and is mounted into the container as **read-only**.
Edits on the host apply on the next request without needing a restart. If an invalid syntax is introduced, the server continues with the last known valid configuration (`GET /api/v1/policy` reports state and any syntax errors). Dashboard overrides are saved to `/state/policy.overrides.json` in the volume and take precedence until reset.

## Test Suite Execution

```bash
docker compose run --rm tests
```

Runs the entire test suite (allowed/blocked scenarios, budgets, injection attacks, proxy) inside the container without external network or API key dependencies (using mock LLM).

## State, Logs & Metrics

- `state` volume: audit logs, conversation and spending DBs, policy overrides.
- `AUDIT_SINK=stdout` in `backend/.env` logs audit events as JSON lines (`docker compose logs backend`).
- Export and metrics: `GET /api/v1/audit/export` (JSONL or CSV), `GET /api/v1/metrics`.

## Code Execution Sandbox (executor)

The `run_python` tool does not execute untrusted code directly in the backend. The backend statically analyzes code (`code_guard`) and then dispatches it over a Unix socket to the `executor` container, which:
- Operates with `network_mode: none` (no internet).
- Has no access to application data or secrets.
- Has a read-only root filesystem, process limit (32), memory limit (512 MB), and CPU limit (1 core).
- Re-verifies and executes each script in an isolated subprocess with timeouts (3 s), memory limit (256 MB), and stdout/stderr cap (8 KB).
Infinite loops are terminated without hanging the backend. When run locally without Docker (`PYTHON_EXECUTOR_SOCKET` unset), `run_python` executes locally after static analysis.

## Hardening

Containers run as non-root (uid 10001 in backend), with read-only root filesystems, `cap_drop: ALL`, `no-new-privileges`, and resource limits. Only `/state` and `/tmp` are writable. Tool data directories are mounted read-only.
