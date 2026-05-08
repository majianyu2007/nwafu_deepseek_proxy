# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project overview

Transparent reverse proxy that bypasses Wisedu CAS authentication for NWAFU's Open WebUI instance. The proxy handles CAS session management and header injection, then forwards **all requests** to the upstream. Visiting `http://localhost:8000/` shows the full Open WebUI interface, proxied from `deepseek.nwafu.edu.cn`.

## Commands

```bash
# Run the server
python server.py

# Docker
docker compose up -d       # start
docker compose down        # stop

# Verify connectivity
python list_models.py      # list available models
python test_api.py          # streaming chat test (auto-selects first chat model)
python test_api.py <model>  # test with a specific model
```

No test suite, linter, or type-checker is configured. `test_api.py` serves as the manual end-to-end smoke test.

## Architecture

**`server.py`** (~1300 lines) — the main application.  
**`utils/model_monitor.py`** — optional model change monitor (enabled via `MONITOR_ENABLED=true`).

### Auth state machine

The old `_login_ok: bool` is replaced by `AuthState` enum with 5 states:

| State | Meaning | Triggers Login? |
|-------|---------|-----------------|
| `OK` | Session valid | No |
| `SUSPECT` | Anomaly detected (network error, upstream 502, etc.) | **No** |
| `EXPIRED` | Definitive CAS redirect confirmed | Yes, through protections |
| `LOGIN_BACKOFF` | Consecutive login failures, waiting | No (exponential backoff) |
| `CIRCUIT_OPEN` | Too many failures, account protection | **No** (15 min – 6 hour hard block) |

Key principle: only definitive CAS login page redirects (`authserver.nwafu.edu.cn/authserver/login`) can trigger a re-login. Everything else (network errors, 502s, non-CAS redirects, HTML error pages) transitions to SUSPECT, which does NOT trigger login.

### Login protection layers (innermost to outermost)

1. **Failure classification** — `_classify_login_failure()` distinguishes account_locked (6h circuit), captcha (2h), password_error (1h), rate_limited (6h), maintenance (15min), unknown (15min)
2. **Circuit breaker** — 3 consecutive failures → `CIRCUIT_OPEN` for 15min–6h, returns 503 with `Retry-After` header
3. **Exponential backoff** — `5s → 20s → 80s → 5min → 15min` (with jitter)
4. **Rate limiting** — max 6 login attempts per hour, persisted to `.data/login_state.json`
5. **Single-flight lock** — `asyncio.Lock` + double-check pattern in `ensure_login()`, at most 1 real CAS login across concurrent requests

### CAS detection (strict)

`_is_cas_login_url()` requires **exact host match** (`authserver.nwafu.edu.cn`) and path prefix match (`/authserver/login`). No substring matching. For 401/403 HTML responses, body is sampled (first 4KB) to check for CAS form fields (`execution` + `pwdEncryptSalt`). Streaming endpoints are never body-sampled.

### Full reverse proxy

All routes (including `/`) proxy to upstream. Origin/Referer headers are rewritten to `TARGET_BASE`. Location headers in responses are rewritten from `TARGET_BASE` to `localhost:{port}`. SSE/streaming uses 5-minute timeout.

### `force_relogin()` is locked down

Only ONE call site is allowed: `_proxy_request()` when `_check_auth_failure()` confirms a definitive CAS redirect. `check_and_refresh()` (keepalive) never calls it. The model monitor never calls it. All paths must pass through the protection layers in `ensure_login()`.

### Model monitor (`utils/model_monitor.py`)

Optional. Enable with `MONITOR_ENABLED=true`. Polls `/v1/models` at configurable interval (default 10 min). Only polls when auth state is `OK` — skips in SUSPECT, BACKOFF, CIRCUIT_OPEN, EXPIRED states. Notifies via Telegram, Webhook, or SSE. Monitor page at `/monitor`.

## Configuration

Copy `.env.example` to `.env`. Required: `NWAFU_USERNAME`, `NWAFU_PASSWORD`, `OPENWEBUI_API_KEY`. Optional: `PROXY_PORT`, `TARGET_HOST`, `AUTH_SERVER`, `CORS_ORIGINS`, `MONITOR_ENABLED`, `MONITOR_POLL_INTERVAL`, `TELEGRAM_BOT_TOKEN`, `TELEGRAM_CHAT_ID`, `WEBHOOK_URLS`, `WEBHOOK_SECRET`, `NOTIFY_PROXY`.

Clients can use any placeholder API key (e.g., `sk-any`) — the proxy injects the real key.

## Dependencies

`fastapi`, `uvicorn`, `httpx`, `pycryptodome`, `python-dotenv` — see `requirements.txt`. HTML parsing for CAS pages uses stdlib regex only.

## Key files

| File | Purpose |
|------|---------|
| `server.py` | Main application: auth, proxy, routes |
| `utils/model_monitor.py` | Optional model change monitor |
| `static/monitor.html` | Monitor dashboard (only if MONITOR_ENABLED) |
| `list_models.py` | CLI utility to list available models |
| `test_api.py` | Manual E2E streaming chat test |
| `.data/` | Persistent state directory (login rate limit, circuit state) |
