# NWAFU DeepSeek Proxy - Agent Instructions

## Project Type
Python FastAPI transparent reverse proxy that bypasses Wisedu CAS authentication for NWAFU's Open WebUI instance. All requests are forwarded to the upstream as-is; the proxy only handles CAS session management and header injection.

## Core Commands

**Start server:**
```bash
python server.py
```

**Docker deployment:**
```bash
docker compose up -d    # Start
docker compose down     # Stop
```

**Verify models:**
```bash
python list_models.py
```

**Test API endpoint:**
```bash
python test_api.py                  # Auto-select first chat model
python test_api.py Qwen3-235B-A22B  # Specific model
```

## Environment Setup

1. Copy config template:
   ```bash
   cp .env.example .env
   ```

2. Required env vars in `.env`:
   - `NWAFU_USERNAME` - Student ID
   - `NWAFU_PASSWORD` - Auth password (wrap in quotes if contains `#`)
   - `OPENWEBUI_API_KEY` - From Open WebUI Settings / Account / API Keys

3. Optional:
   - `TOTP_SECRET` - TOTP authenticator secret (Base32) for auto-completing 2FA (required since 2026-05-12)
   - `MONITOR_ENABLED=true` - Enable model change monitoring
   - `MONITOR_POLL_INTERVAL` - Poll interval in seconds (default 600, min 300)

4. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```

## Architecture Facts

**Entry points:**
- `server.py` - Main FastAPI application (~1300 lines, full reverse proxy)
- `utils/model_monitor.py` - Optional model change monitor (enabled via `MONITOR_ENABLED=true`)
- `list_models.py` - Model listing utility
- `test_api.py` - End-to-end connectivity test

**Core flow:**
1. Client -> `localhost:8000/*` -> FastAPI proxy
2. Proxy authenticates via CAS (AES-CBC password encryption + TOTP 2FA)
3. Transparently forwards ALL requests to `deepseek.nwafu.edu.cn` with valid session cookie + Bearer token
4. Visiting `localhost:8000/` shows the full Open WebUI interface

**Auth state machine (replaces old `_login_ok` bool):**
- `OK` — Session valid, normal operation
- `SUSPECT` — Anomaly detected (network error, upstream issue), does NOT trigger login
- `EXPIRED` — Definitive CAS redirect confirmed, needs re-login
- `LOGIN_BACKOFF` — Consecutive failures, waiting with exponential backoff
- `CIRCUIT_OPEN` — Too many failures, account protection active (15 min – 6 hours)

Only a definitive CAS login page redirect (exact host `authserver.nwafu.edu.cn`) can trigger re-login. All other errors → SUSPECT.

**Login safety layers:**
1. Failure classification (account lock → 6h circuit, captcha → 2h, password error → 1h)
2. Circuit breaker (3 consecutive failures → CIRCUIT_OPEN)
3. Exponential backoff (5s → 20s → 80s → 5min → 15min, with jitter)
4. Rate limiting (max 6 logins/hour, persisted to `.data/login_state.json`)
5. Single-flight lock (at most 1 real CAS login across concurrent requests)

**Model monitor (optional):**
- Only polls when auth state is OK
- Never triggers CAS login
- Notifies via Telegram / Webhook / SSE
- Dashboard at `/monitor`

## Dependencies (requirements.txt)
- fastapi, uvicorn, httpx - Core HTTP/server
- pycryptodome - AES encryption
- python-dotenv - Environment loading
- pyotp - TOTP code generation for 2FA
- HTML parsing for CAS login uses stdlib regex only

## Testing Notes
- API Key in requests can be arbitrary value (e.g., `sk-any`) - proxy replaces with real key
- Stream responses use 5-minute timeout; non-stream use 60-second timeout
- Visit `http://localhost:8000/health` for health check (includes auth_state field)

## Network Requirements
Must be able to reach:
- `authserver.nwafu.edu.cn` - CAS authentication
- `deepseek.nwafu.edu.cn` - Target Open WebUI instance

Requires campus network or VPN.
