# NWAFU DeepSeek Proxy — Agent Instructions

## Scope and entry points

Python/FastAPI reverse proxy for NWAFU Open WebUI. `main` is the Python implementation; `rust-rewrite` is separate. Preserve existing upstream HTTP, SSE and WebSocket behavior when editing.

- Run: `python server.py` or `python -m nwafu_proxy`
- Factory: `nwafu_proxy.app.create_app(settings, manager)`
- Docker: `docker compose up -d`
- Offline tests: `python -m unittest discover -s tests -v`
- Lint: `ruff check nwafu_proxy server.py tests utils/model_monitor.py utils/fido2_auth.py`
- Format: `ruff format --check nwafu_proxy server.py tests utils/model_monitor.py utils/fido2_auth.py`
- Install runtime: `pip install -r requirements.txt`; development: `pip install -r requirements-dev.txt`
- Manual campus smoke tests: `python utils/list_models.py`, `python utils/test_api.py [model]`

See `docs/architecture.md` for module responsibilities and compatibility details. Keep runtime code in `nwafu_proxy/`; keep `server.py` as a small compatibility entry point. Avoid import-time environment loading, authentication and global session instances. Pass Settings and AuthSessionManager explicitly. Register local routes before proxy catch-all.

## Configuration

Copy `.env.example` to `.env`. Required: `NWAFU_USERNAME`, `NWAFU_PASSWORD`; API access uses `OPENWEBUI_API_KEY`. Optional TOTP, FIDO2 and monitoring options are described in README. Never commit credentials, exported vaults, cookies, or `.data/*.json`.

Default persistent data stays at root `.data/`. Tests use temporary directories and mocked HTTP transports; never require real campus credentials or authenticate during ordinary unit tests. Campus end-to-end checks require connectivity to the configured target and university authentication services.

## Account protection invariants

- `OK`: valid session; `SUSPECT`: ambiguous upstream/network issue; `EXPIRED`: confirmed authentication failure; `LOGIN_BACKOFF` / `CIRCUIT_OPEN`: protected waiting periods.
- Only confirmed authentication redirects/login forms may trigger recovery. Network errors and ordinary upstream errors must not cause login storms.
- Preserve the login lock, hourly rate limit, minimum login interval, exponential backoff and failure-specific circuit durations.
- Cookie restoration shares the login lock. Service restart must not erase login limits or active circuits.
- `force_relogin` has one runtime call site, in HTTP proxy authentication recovery, and must honor all active protection windows.
- Health checks and model monitoring never call `ensure_login` or `force_relogin`. Monitoring uses the existing client only in OK state.
- Keepalive may recover confirmed authentication expiry through `ensure_login`, but never calls `force_relogin`; network failures only mark SUSPECT and never clear a circuit/backoff.
- Streaming auth checks do not consume response bodies. Browser `/api/*` requests retain cookie-based identity; real API-key injection is limited to `/v1/`, `/openai/`, `/ollama/`.
- Preserve cancellation and cleanup for HTTP streams, WebSocket relay tasks, monitoring and keepalive.

## Change discipline

Cover meaningful auth, routing and streaming changes with offline regression tests. Update Docker COPY entries if runtime assets move. Update architecture documentation when module boundaries or compatibility change. Do not claim campus integration works based only on mocked tests.
