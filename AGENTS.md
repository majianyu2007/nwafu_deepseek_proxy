# NWAFU DeepSeek Proxy - Agent Instructions

## Project Type

Rust Axum transparent reverse proxy for NWAFU's Open WebUI instance. The proxy performs Wisedu CAS login, maintains the upstream session cookie, injects the Open WebUI API key, and forwards all HTTP/WebSocket paths to the upstream.

## Core Commands

**Start server:**
```bash
cargo run --release
```

**Build binary:**
```bash
cargo build --release
```

**Docker deployment:**
```bash
docker compose up -d
docker compose down
```

**Verify models:**
```bash
curl http://localhost:8000/v1/models -H 'Authorization: Bearer sk-local'
```

## Environment Setup

1. Copy config template:
   ```bash
   cp .env.example .env
   ```

2. Required env vars in `.env`:
   - `NWAFU_USERNAME` - Student ID
   - `NWAFU_PASSWORD` - Auth password
   - `OPENWEBUI_API_KEY` - From Open WebUI Settings / Account / API Keys

3. Optional env vars:
   - `PROXY_PORT` - Listen port, default `8000`
   - `TARGET_HOST` - Open WebUI host, default `deepseek.nwafu.edu.cn`
   - `AUTH_SERVER` - CAS server, default `https://authserver.nwafu.edu.cn`

## Architecture Facts

**Entry points:**
- `src/main.rs` - Main Axum application
- `Cargo.toml` / `Cargo.lock` - Rust package metadata and locked dependencies
- `Dockerfile` - Multi-stage Rust container build
- `.github/workflows/release.yml` - GitHub Release binary build workflow

**Core flow:**
1. Client -> `localhost:8000/*` -> Axum proxy
2. Proxy authenticates via CAS using AES-CBC password encryption
3. Proxy forwards requests to `deepseek.nwafu.edu.cn` with valid session cookie and Bearer token
4. Visiting `localhost:8000/` shows the proxied Open WebUI interface

**Current Rust implementation:**
- Handles CAS login form parsing and redirect following
- Maintains a `reqwest` cookie jar for upstream CAS session cookies
- Proxies all HTTP paths, including `/`
- Proxies `/ws/*` WebSocket paths
- Rewrites upstream `Location` headers and textual absolute URLs to local proxy origin
- Provides `/health`
- Uses login rate limiting, backoff, circuit protection, and login-after-reject suppression

## Dependencies

- `axum`, `tokio` - HTTP server/runtime
- `reqwest` - HTTP client and cookie jar
- `tokio-tungstenite` - WebSocket upstream client
- `aes`, `cbc`, `base64` - CAS password encryption
- `dotenvy` - Environment loading
- `regex` - CAS login form parsing

## Network Requirements

Must be able to reach:
- `authserver.nwafu.edu.cn`
- `deepseek.nwafu.edu.cn`

Requires campus network or VPN.
