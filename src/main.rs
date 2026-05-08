use std::{
    collections::VecDeque,
    net::SocketAddr,
    sync::Arc,
    time::{Duration, Instant},
};

use aes::Aes128;
use anyhow::{anyhow, Context, Result};
use axum::{
    body::{to_bytes, Body},
    extract::{
        ws::{Message, WebSocket, WebSocketUpgrade},
        State,
    },
    http::{header, HeaderMap, HeaderName, HeaderValue, Request, Response, StatusCode, Uri},
    response::IntoResponse,
    routing::get,
    Json, Router,
};
use base64::{engine::general_purpose, Engine as _};
use cbc::cipher::{block_padding::Pkcs7, BlockEncryptMut, KeyIvInit};
use futures_util::{SinkExt, StreamExt};
use rand::{seq::SliceRandom, thread_rng};
use regex::Regex;
use reqwest::{
    cookie::{CookieStore, Jar},
    redirect::Policy,
    Client,
};
use serde::Serialize;
use tokio::{net::TcpListener, sync::Mutex, task::JoinSet};
use tokio_tungstenite::{connect_async_tls_with_config, tungstenite::client::IntoClientRequest};
use tracing::{debug, error, info, warn};
use url::{form_urlencoded::byte_serialize, Url};

type Aes128CbcEnc = cbc::Encryptor<Aes128>;

const COOKIE_TTL: Duration = Duration::from_secs(25 * 60);
const LOGIN_STICKY_WINDOW: Duration = Duration::from_secs(30);
const MAX_LOGIN_ATTEMPTS_PER_HOUR: usize = 6;
const LOGIN_WINDOW: Duration = Duration::from_secs(3600);
const MAX_LOGIN_REDIRECTS: usize = 10;
const BODY_LIMIT: usize = 64 * 1024 * 1024;
const REWRITE_LIMIT: usize = 5 * 1024 * 1024;
const AES_CHARS: &[u8] = b"ABCDEFGHJKMNPQRSTWXYZabcdefhijkmnprstwxyz2345678";

#[derive(Clone)]
struct Settings {
    username: String,
    password: String,
    proxy_port: u16,
    target_host: String,
    target_base: String,
    openwebui_api_key: String,
    auth_server: String,
}

impl Settings {
    fn load() -> Result<Self> {
        dotenvy::dotenv().ok();
        let username = env("NWAFU_USERNAME", "");
        let password = env("NWAFU_PASSWORD", "");
        if username.is_empty() || password.is_empty() {
            return Err(anyhow!("missing NWAFU_USERNAME or NWAFU_PASSWORD"));
        }
        let proxy_port = env("PROXY_PORT", "8000")
            .parse()
            .context("invalid PROXY_PORT")?;
        let target_host = env("TARGET_HOST", "deepseek.nwafu.edu.cn");
        let auth_server = env("AUTH_SERVER", "https://authserver.nwafu.edu.cn");
        Ok(Self {
            username,
            password,
            proxy_port,
            target_base: format!("https://{target_host}"),
            target_host,
            openwebui_api_key: env("OPENWEBUI_API_KEY", ""),
            auth_server: auth_server.trim_end_matches('/').to_string(),
        })
    }
}

fn env(key: &str, default: &str) -> String {
    std::env::var(key)
        .unwrap_or_else(|_| default.to_string())
        .trim()
        .to_string()
}

#[derive(Clone)]
struct AppState {
    settings: Arc<Settings>,
    auth: Arc<AuthManager>,
}

struct AuthManager {
    settings: Arc<Settings>,
    client: Client,
    cookie_jar: Arc<Jar>,
    state: Mutex<AuthState>,
}

#[derive(Default)]
struct AuthState {
    last_login: Option<Instant>,
    last_login_ok: Option<Instant>,
    login_attempts: VecDeque<Instant>,
    consecutive_failures: usize,
    backoff_until: Option<Instant>,
    circuit_until: Option<Instant>,
    login_then_rejected: bool,
}

impl AuthManager {
    fn new(settings: Arc<Settings>) -> Result<Self> {
        let cookie_jar = Arc::new(Jar::default());
        let client = Client::builder()
            .cookie_provider(cookie_jar.clone())
            .redirect(Policy::none())
            .user_agent("Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36")
            .timeout(Duration::from_secs(60))
            .build()
            .context("failed to create HTTP client")?;
        Ok(Self {
            settings,
            client,
            cookie_jar,
            state: Mutex::new(AuthState::default()),
        })
    }

    async fn ensure_login(&self) -> Result<()> {
        {
            let state = self.state.lock().await;
            if state.last_login.is_some_and(|t| t.elapsed() < COOKIE_TTL) {
                return Ok(());
            }
        }

        let mut state = self.state.lock().await;
        if state.last_login.is_some_and(|t| t.elapsed() < COOKIE_TTL) {
            return Ok(());
        }
        if let Some(until) = state.circuit_until {
            if Instant::now() < until {
                return Err(anyhow!("login circuit is open"));
            }
            state.circuit_until = None;
        }
        if let Some(until) = state.backoff_until {
            if Instant::now() < until {
                return Err(anyhow!("login backoff is active"));
            }
            state.backoff_until = None;
        }
        prune_attempts(&mut state.login_attempts, LOGIN_WINDOW);
        if state.login_attempts.len() >= MAX_LOGIN_ATTEMPTS_PER_HOUR {
            return Err(anyhow!("login rate limit exceeded"));
        }
        state.login_attempts.push_back(Instant::now());
        drop(state);

        match self.do_login().await {
            Ok(()) => {
                let mut state = self.state.lock().await;
                state.last_login = Some(Instant::now());
                state.last_login_ok = Some(Instant::now());
                state.consecutive_failures = 0;
                state.backoff_until = None;
                state.circuit_until = None;
                state.login_then_rejected = false;
                info!("event=login_result outcome=success");
                Ok(())
            }
            Err(err) => {
                let mut state = self.state.lock().await;
                state.consecutive_failures += 1;
                let delay = backoff_delay(state.consecutive_failures);
                state.backoff_until = Some(Instant::now() + delay);
                if state.consecutive_failures >= 3 {
                    state.circuit_until = Some(Instant::now() + Duration::from_secs(15 * 60));
                }
                Err(err)
            }
        }
    }

    async fn do_login(&self) -> Result<()> {
        info!("event=login_start target={}", self.settings.target_base);
        let service = format!(
            "{}/.auth/login/cas/callback?return_to={}/",
            self.settings.target_base, self.settings.target_base
        );
        let encoded: String = byte_serialize(service.as_bytes()).collect();
        let login_url = format!(
            "{}/authserver/login?service={encoded}",
            self.settings.auth_server
        );

        let resp = self.client.get(&login_url).send().await?;
        if is_redirect(resp.status()) {
            let location = location(&resp)?;
            self.follow_redirects(location).await?;
            return Ok(());
        }
        let html = resp.text().await?;
        let (execution, salt) = parse_login_form(&html)?;
        let encrypted = encrypt_password(&self.settings.password, &salt)?;
        let params = [
            ("username", self.settings.username.as_str()),
            ("password", encrypted.as_str()),
            ("captcha", ""),
            ("rememberMe", "false"),
            ("_eventId", "submit"),
            ("cllt", "userNameLogin"),
            ("lt", ""),
            ("execution", execution.as_str()),
        ];
        let resp = self.client.post(&login_url).form(&params).send().await?;
        if !is_redirect(resp.status()) {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            return Err(anyhow!(
                "authserver login failed: status={status} body={}",
                trim_log(&body)
            ));
        }
        let location = location(&resp)?;
        self.follow_redirects(location).await
    }

    async fn follow_redirects(&self, initial_location: String) -> Result<()> {
        let mut current = Url::parse(&initial_location)?;
        for idx in 0..MAX_LOGIN_REDIRECTS {
            info!("event=login_redirect step={} url={}", idx + 1, current);
            let resp = self.client.get(current.clone()).send().await?;
            if !is_redirect(resp.status()) {
                info!(
                    "event=login_redirect_done status={} url={}",
                    resp.status(),
                    resp.url()
                );
                return Ok(());
            }
            let next = location(&resp)?;
            current = resp.url().join(&next)?;
        }
        Err(anyhow!("login redirect limit exceeded"))
    }

    async fn recent_login_rejected(&self) -> bool {
        let mut state = self.state.lock().await;
        if !state.login_then_rejected
            && state
                .last_login_ok
                .is_some_and(|t| t.elapsed() < LOGIN_STICKY_WINDOW)
        {
            state.login_then_rejected = true;
            warn!("event=login_rejected_after_success action=suppress_relogin");
        }
        state.login_then_rejected
    }

    fn cookie_header(&self, url: &Url) -> Option<String> {
        self.cookie_jar
            .cookies(url)
            .and_then(|v| v.to_str().ok().map(ToString::to_string))
    }
}

fn prune_attempts(attempts: &mut VecDeque<Instant>, window: Duration) {
    while attempts.front().is_some_and(|t| t.elapsed() > window) {
        attempts.pop_front();
    }
}

fn backoff_delay(failures: usize) -> Duration {
    let secs = match failures {
        0 | 1 => 5,
        2 => 20,
        3 => 80,
        4 => 300,
        _ => 900,
    };
    Duration::from_secs(secs)
}

fn is_redirect(status: reqwest::StatusCode) -> bool {
    matches!(status.as_u16(), 301 | 302 | 303 | 307 | 308)
}

fn location(resp: &reqwest::Response) -> Result<String> {
    Ok(resp
        .headers()
        .get(reqwest::header::LOCATION)
        .ok_or_else(|| anyhow!("redirect response missing Location"))?
        .to_str()?
        .to_string())
}

async fn health(State(state): State<AppState>) -> impl IntoResponse {
    #[derive(Serialize)]
    struct Health {
        status: &'static str,
        service: &'static str,
        target: String,
        api_base: String,
    }
    Json(Health {
        status: "ok",
        service: "NWAFU DeepSeek Proxy",
        target: state.settings.target_base.clone(),
        api_base: format!("http://localhost:{}/v1", state.settings.proxy_port),
    })
}

async fn proxy_handler(State(state): State<AppState>, req: Request<Body>) -> impl IntoResponse {
    match proxy_http(state, req).await {
        Ok(resp) => resp,
        Err(err) => json_error(StatusCode::BAD_GATEWAY, "proxy_error", &err.to_string()),
    }
}

async fn proxy_http(state: AppState, req: Request<Body>) -> Result<Response<Body>> {
    state.auth.ensure_login().await?;
    let uri = req.uri().clone();
    let target_url = build_target_url(&state.settings, &uri)?;
    let method = req.method().clone();
    let headers = req.headers().clone();
    let body = to_bytes(req.into_body(), BODY_LIMIT)
        .await
        .context("failed to read request body")?;

    let mut upstream = state.auth.client.request(method, target_url.clone());
    upstream = upstream.header(reqwest::header::HOST, state.settings.target_host.as_str());
    if !state.settings.openwebui_api_key.is_empty() {
        upstream = upstream.bearer_auth(&state.settings.openwebui_api_key);
    }
    for (name, value) in headers.iter() {
        if should_skip_request_header(name) {
            continue;
        }
        let mut value = value.clone();
        if name == header::ORIGIN || name == header::REFERER {
            value = HeaderValue::from_str(&state.settings.target_base)?;
        }
        upstream = upstream.header(name, value);
    }
    let resp = upstream.body(body).send().await?;
    if is_auth_redirect(&resp) {
        if state.auth.recent_login_rejected().await {
            return Ok(json_error(
                StatusCode::BAD_GATEWAY,
                "upstream_auth_session_rejected",
                "upstream authentication session was not accepted",
            ));
        }
        return Ok(json_error(
            StatusCode::UNAUTHORIZED,
            "auth_expired",
            "authentication expired",
        ));
    }

    response_from_reqwest(resp, &state.settings).await
}

fn build_target_url(settings: &Settings, uri: &Uri) -> Result<Url> {
    let path = uri.path_and_query().map(|v| v.as_str()).unwrap_or("/");
    Url::parse(&format!("{}{}", settings.target_base, path)).context("invalid target URL")
}

fn should_skip_request_header(name: &HeaderName) -> bool {
    matches!(
        name.as_str().to_ascii_lowercase().as_str(),
        "host"
            | "connection"
            | "keep-alive"
            | "transfer-encoding"
            | "te"
            | "trailer"
            | "upgrade"
            | "proxy-authorization"
            | "proxy-authenticate"
            | "content-length"
            | "authorization"
            | "accept-encoding"
            | "cookie"
    )
}

fn should_skip_response_header(name: &reqwest::header::HeaderName) -> bool {
    matches!(
        name.as_str().to_ascii_lowercase().as_str(),
        "content-length"
            | "transfer-encoding"
            | "content-encoding"
            | "strict-transport-security"
            | "content-security-policy"
            | "content-security-policy-report-only"
    )
}

fn is_auth_redirect(resp: &reqwest::Response) -> bool {
    if !is_redirect(resp.status()) {
        return false;
    }
    let Some(location) = resp.headers().get(reqwest::header::LOCATION) else {
        return false;
    };
    let Ok(location) = location.to_str() else {
        return false;
    };
    if let Ok(url) = Url::parse(location) {
        return url.host_str() == Some("authserver.nwafu.edu.cn")
            && url.path().starts_with("/authserver/login")
            || url.path().starts_with("/.auth/login/cas");
    }
    location.starts_with("/.auth/login/cas")
}

async fn response_from_reqwest(
    resp: reqwest::Response,
    settings: &Settings,
) -> Result<Response<Body>> {
    let status = StatusCode::from_u16(resp.status().as_u16())?;
    let content_type = resp
        .headers()
        .get(reqwest::header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string();
    let mut builder = Response::builder().status(status);
    for (name, value) in resp.headers() {
        if should_skip_response_header(name) {
            continue;
        }
        let name = HeaderName::from_bytes(name.as_str().as_bytes())?;
        let mut value = HeaderValue::from_bytes(value.as_bytes())?;
        if name == header::LOCATION {
            if let Ok(text) = value.to_str() {
                let local = format!("http://localhost:{}", settings.proxy_port);
                value = HeaderValue::from_str(&text.replace(&settings.target_base, &local))?;
            }
        }
        builder = builder.header(name, value);
    }
    let bytes = resp.bytes().await?;
    let body = if should_rewrite_body(&content_type) && bytes.len() <= REWRITE_LIMIT {
        let local = format!("http://localhost:{}", settings.proxy_port);
        let target_origin = format!("https://{}", settings.target_host);
        let body = replace_bytes(&bytes, settings.target_base.as_bytes(), local.as_bytes());
        let body = replace_bytes(&body, target_origin.as_bytes(), local.as_bytes());
        replace_bytes(
            &body,
            format!("https://localhost:{}", settings.proxy_port).as_bytes(),
            local.as_bytes(),
        )
    } else {
        bytes.to_vec()
    };
    Ok(builder.body(Body::from(body))?)
}

fn should_rewrite_body(content_type: &str) -> bool {
    let content_type = content_type.to_ascii_lowercase();
    [
        "text/html",
        "text/css",
        "application/json",
        "application/manifest+json",
        "text/javascript",
        "application/javascript",
    ]
    .iter()
    .any(|v| content_type.contains(v))
}

fn replace_bytes(input: &[u8], from: &[u8], to: &[u8]) -> Vec<u8> {
    if from.is_empty() {
        return input.to_vec();
    }
    let mut out = Vec::with_capacity(input.len());
    let mut start = 0;
    while let Some(pos) = input[start..].windows(from.len()).position(|w| w == from) {
        let abs = start + pos;
        out.extend_from_slice(&input[start..abs]);
        out.extend_from_slice(to);
        start = abs + from.len();
    }
    out.extend_from_slice(&input[start..]);
    out
}

async fn ws_handler(
    State(state): State<AppState>,
    ws: WebSocketUpgrade,
    uri: Uri,
    headers: HeaderMap,
) -> impl IntoResponse {
    ws.on_upgrade(move |socket| proxy_ws(state, socket, uri, headers))
}

async fn proxy_ws(state: AppState, client_ws: WebSocket, uri: Uri, headers: HeaderMap) {
    if let Err(err) = state.auth.ensure_login().await {
        warn!("event=ws_auth_failed error={}", err);
        return;
    }
    let target = match build_ws_url(&state.settings, &uri) {
        Ok(url) => url,
        Err(err) => {
            warn!("event=ws_url_error error={}", err);
            return;
        }
    };
    let mut request = match target.as_str().into_client_request() {
        Ok(req) => req,
        Err(err) => {
            warn!("event=ws_request_error error={}", err);
            return;
        }
    };
    request.headers_mut().insert(
        "Origin",
        HeaderValue::from_str(&state.settings.target_base).unwrap(),
    );
    if !state.settings.openwebui_api_key.is_empty() {
        let value = format!("Bearer {}", state.settings.openwebui_api_key);
        request
            .headers_mut()
            .insert("Authorization", HeaderValue::from_str(&value).unwrap());
    }
    if let Ok(url) = Url::parse(&target) {
        if let Some(cookie) = state.auth.cookie_header(&url) {
            if let Ok(value) = HeaderValue::from_str(&cookie) {
                request.headers_mut().insert("Cookie", value);
            }
        }
    }
    if let Some(protocol) = headers.get(header::SEC_WEBSOCKET_PROTOCOL) {
        request
            .headers_mut()
            .insert(header::SEC_WEBSOCKET_PROTOCOL, protocol.clone());
    }

    let Ok((upstream_ws, _)) = connect_async_tls_with_config(request, None, false, None).await
    else {
        warn!("event=ws_upstream_rejected path={}", uri.path());
        return;
    };
    let (mut client_tx, mut client_rx) = client_ws.split();
    let (mut upstream_tx, mut upstream_rx) = upstream_ws.split();
    let mut tasks = JoinSet::new();

    tasks.spawn(async move {
        while let Some(Ok(message)) = client_rx.next().await {
            let out = match message {
                Message::Text(v) => {
                    tokio_tungstenite::tungstenite::Message::Text(v.to_string().into())
                }
                Message::Binary(v) => tokio_tungstenite::tungstenite::Message::Binary(v),
                Message::Ping(v) => tokio_tungstenite::tungstenite::Message::Ping(v),
                Message::Pong(v) => tokio_tungstenite::tungstenite::Message::Pong(v),
                Message::Close(_) => break,
            };
            if upstream_tx.send(out).await.is_err() {
                break;
            }
        }
    });
    tasks.spawn(async move {
        while let Some(Ok(message)) = upstream_rx.next().await {
            let out = match message {
                tokio_tungstenite::tungstenite::Message::Text(v) => {
                    Message::Text(v.to_string().into())
                }
                tokio_tungstenite::tungstenite::Message::Binary(v) => Message::Binary(v),
                tokio_tungstenite::tungstenite::Message::Ping(v) => Message::Ping(v),
                tokio_tungstenite::tungstenite::Message::Pong(v) => Message::Pong(v),
                tokio_tungstenite::tungstenite::Message::Close(_) => break,
                _ => continue,
            };
            if client_tx.send(out).await.is_err() {
                break;
            }
        }
    });
    tasks.join_next().await;
    tasks.abort_all();
    debug!("event=ws_proxy_close path={}", uri.path());
}

fn build_ws_url(settings: &Settings, uri: &Uri) -> Result<String> {
    let path = uri.path_and_query().map(|v| v.as_str()).unwrap_or("/");
    Ok(format!("wss://{}{}", settings.target_host, path))
}

fn json_error(status: StatusCode, typ: &str, message: &str) -> Response<Body> {
    let body = serde_json::json!({"type": typ, "error": message}).to_string();
    Response::builder()
        .status(status)
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(body))
        .unwrap()
}

fn parse_login_form(html: &str) -> Result<(String, String)> {
    let execution = extract_input_value(html, "execution")?;
    let salt = extract_input_value(html, "pwdEncryptSalt")?;
    Ok((execution, salt))
}

fn extract_input_value(html: &str, id: &str) -> Result<String> {
    let tag_re = Regex::new(&format!(
        r#"<input\b[^>]*\bid=["']{}["'][^>]*>"#,
        regex::escape(id)
    ))?;
    let value_re = Regex::new(r#"\bvalue=["']([^"']*)["']"#)?;
    let tag = tag_re
        .find(html)
        .ok_or_else(|| anyhow!("login form field not found: {id}"))?
        .as_str();
    Ok(value_re
        .captures(tag)
        .and_then(|c| c.get(1))
        .map(|m| m.as_str().to_string())
        .unwrap_or_default())
}

fn encrypt_password(password: &str, salt: &str) -> Result<String> {
    let random_prefix = random_string(64);
    let random_iv = random_string(16);
    let plaintext = format!("{random_prefix}{password}");
    let encrypted = Aes128CbcEnc::new_from_slices(salt.trim().as_bytes(), random_iv.as_bytes())?
        .encrypt_padded_vec_mut::<Pkcs7>(plaintext.as_bytes());
    Ok(general_purpose::STANDARD.encode(encrypted))
}

fn random_string(len: usize) -> String {
    let mut rng = thread_rng();
    (0..len)
        .map(|_| *AES_CHARS.choose(&mut rng).unwrap() as char)
        .collect()
}

fn trim_log(text: &str) -> String {
    text.chars()
        .take(300)
        .collect::<String>()
        .replace('\n', " ")
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::from_default_env().add_directive("info".parse()?),
        )
        .init();

    let settings = Arc::new(Settings::load()?);
    let auth = Arc::new(AuthManager::new(settings.clone())?);
    let state = AppState {
        settings: settings.clone(),
        auth,
    };

    if settings.openwebui_api_key.is_empty() {
        warn!("OPENWEBUI_API_KEY is not configured");
    }
    if let Err(err) = state.auth.ensure_login().await {
        warn!("event=initial_login_failed error={}", err);
    }

    let app = Router::new()
        .route("/health", get(health))
        .route("/ws/{*path}", get(ws_handler))
        .fallback(proxy_handler)
        .with_state(state);
    let addr = SocketAddr::from(([0, 0, 0, 0], settings.proxy_port));
    info!(
        "event=server_start listen=http://localhost:{} upstream={}",
        settings.proxy_port, settings.target_base
    );
    let listener = TcpListener::bind(addr).await?;
    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal())
        .await?;
    Ok(())
}

async fn shutdown_signal() {
    let ctrl_c = async {
        if let Err(err) = tokio::signal::ctrl_c().await {
            error!("failed to listen for ctrl_c: {}", err);
        }
    };
    #[cfg(unix)]
    let terminate = async {
        let mut signal = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
            .expect("failed to install SIGTERM handler");
        signal.recv().await;
    };
    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();
    tokio::select! {
        _ = ctrl_c => {},
        _ = terminate => {},
    }
    info!("event=shutdown_start");
}
