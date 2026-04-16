# NWAFU DeepSeek Proxy - Agent Instructions

## Project Type
Python FastAPI transparent reverse proxy that bypasses Wisedu CAS authentication for NWAFU's Open WebUI instance. All `/v1/*` requests are forwarded to the upstream as-is; the proxy only handles CAS session management and header injection.

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

3. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```

## Architecture Facts

**Entry points:**
- `server.py` - Main FastAPI application (~550 lines, pure transparent proxy)
- `list_models.py` - Model listing utility
- `test_api.py` - End-to-end connectivity test

**Core flow:**
1. Client -> `localhost:8000/v1/*` -> FastAPI proxy
2. Proxy authenticates via CAS (AES-CBC password encryption)
3. Transparently forwards ALL requests to `deepseek.nwafu.edu.cn` with valid session cookie + Bearer token

**Design principle:** The proxy is a transparent pass-through. It does NOT interpret, transform, or add business logic to any API endpoint. Every `/v1/*` path (chat, embeddings, rerank, models, audio, images, etc.) is forwarded identically to the upstream.

**Key technical details:**
- Password encryption: AES-CBC with PKCS7 padding, 64-char random prefix
- CAS flow: GET login page -> extract `execution`/`salt` -> POST encrypted password -> follow 302 chain
- Cookie keepalive: 5-minute heartbeat via HEAD request, 25-minute TTL threshold
- Auth detection: 302 redirect to authserver, 401/403 with non-JSON body, or 200 with HTML content-type
- Streaming: auto-detected via `stream: true` in request body, uses 5-minute read timeout
- Auto-relogin on auth failure detection, with retry

**API endpoints (all transparently proxied):**
- `/v1/models` - List available models
- `/v1/chat/completions` - Chat (streaming supported)
- `/v1/embeddings` - Vector embeddings
- `/v1/rerank` - Document re-ranking (if supported by upstream)
- `/v1/*` - Any other endpoint the upstream exposes

## Dependencies (requirements.txt)
- fastapi, uvicorn, httpx - Core HTTP/server
- pycryptodome - AES encryption
- beautifulsoup4, lxml - HTML parsing for CAS login
- python-dotenv - Environment loading

## Testing Notes
- API Key in requests can be arbitrary value (e.g., `sk-any`) - proxy replaces with real key
- All endpoints are transparent proxies; behavior depends entirely on the upstream
- Stream responses use 5-minute timeout; non-stream use 60-second timeout

## Network Requirements
Must be able to reach:
- `authserver.nwafu.edu.cn` - CAS authentication
- `deepseek.nwafu.edu.cn` - Target Open WebUI instance

Requires campus network or VPN.
