use std::{
    collections::VecDeque,
    net::SocketAddr,
    sync::Arc,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
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
use data_encoding::BASE32_NOPAD;
use futures_util::{SinkExt, StreamExt};
use hmac::{Hmac, Mac};
use rand::{seq::SliceRandom, thread_rng};
use regex::Regex;
use reqwest::{
    cookie::{CookieStore, Jar},
    redirect::Policy,
    Client,
};
use serde::Serialize;
use sha1::Sha1;
use tokio::{net::TcpListener, sync::Mutex, task::JoinSet};
use tokio_tungstenite::{connect_async_tls_with_config, tungstenite::client::IntoClientRequest};
use tracing::{debug, error, info, warn};
use url::{form_urlencoded::byte_serialize, Url};

type HmacSha1 = Hmac<Sha1>;

type Aes128CbcEnc = cbc::Encryptor<Aes128>;

const COOKIE_TTL: Duration = Duration::from_secs(25 * 60);
const KEEPALIVE_INTERVAL: Duration = Duration::from_secs(5 * 60);
const LOGIN_STICKY_WINDOW: Duration = Duration::from_secs(30);
const LOGIN_MIN_INTERVAL: Duration = Duration::from_secs(60);
const FORCE_RELOGIN_THROTTLE: Duration = Duration::from_secs(10);
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
    totp_secret: String,
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
        let totp_secret = env("TOTP_SECRET", "");
        Ok(Self {
            username,
            password,
            proxy_port,
            target_base: format!("https://{target_host}"),
            target_host,
            openwebui_api_key: env("OPENWEBUI_API_KEY", ""),
            auth_server: auth_server.trim_end_matches('/').to_string(),
            totp_secret,
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
    last_login_attempt_time: Option<Instant>,
    last_force_relogin_time: Option<Instant>,
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
        // 登录最小间隔
        if let Some(last) = state.last_login_attempt_time {
            let since = last.elapsed();
            if since < LOGIN_MIN_INTERVAL {
                let remaining = LOGIN_MIN_INTERVAL - since;
                return Err(anyhow!(
                    "login cooldown active, {:.0}s remaining",
                    remaining.as_secs_f64()
                ));
            }
        }
        state.login_attempts.push_back(Instant::now());
        state.last_login_attempt_time = Some(Instant::now());
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
                let msg = err.to_string();
                let delay = if msg.contains("2FA") || msg.contains("TOTP") {
                    Duration::from_secs(30) // 2FA failures use short backoff
                } else {
                    backoff_delay(state.consecutive_failures)
                };
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
            info!("event=tgc_reuse following redirect chain");
            self.handle_login_redirect(&location).await?;
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
        self.handle_login_redirect(&location).await
    }

    async fn handle_login_redirect(&self, initial_location: &str) -> Result<()> {
        let (final_url, _) = self.follow_redirects(initial_location).await?;

        // 检测二次验证
        if final_url.contains("/reAuthLoginView.do") {
            let service_url = Url::parse(&final_url)
                .ok()
                .and_then(|u| {
                    u.query_pairs()
                        .find(|(k, _)| k == "service")
                        .map(|(_, v)| v.to_string())
                })
                .unwrap_or_else(|| {
                    format!(
                        "{}/.auth/login/cas/callback?return_to={}/",
                        self.settings.target_base, self.settings.target_base
                    )
                });
            info!("event=2fa_detected url={}", final_url);
            self.complete_2fa(&service_url).await?;
        }

        self.validate_session().await?;
        info!("event=login_complete");
        Ok(())
    }

    async fn follow_redirects(
        &self,
        initial_location: &str,
    ) -> Result<(String, Option<reqwest::Response>)> {
        let mut current = Url::parse(initial_location)?;
        let mut last_resp = None;
        for idx in 0..MAX_LOGIN_REDIRECTS {
            info!("event=login_redirect step={} url={}", idx + 1, current);
            let resp = self.client.get(current.clone()).send().await?;
            if !is_redirect(resp.status()) {
                info!(
                    "event=login_redirect_done status={} url={}",
                    resp.status(),
                    resp.url()
                );
                last_resp = Some(resp);
                break;
            }
            let next = location(&resp)?;
            current = resp.url().join(&next)?;
        }
        Ok((current.to_string(), last_resp))
    }

    async fn complete_2fa(&self, service_url: &str) -> Result<()> {
        info!("event=2fa_start service={}", service_url);

        // Step 1: 切换到安全令牌 (reAuthType=10)
        let change_body = [
            ("isMultifactor", "true"),
            ("reAuthType", "10"),
            ("service", service_url),
        ];
        let change_resp = self
            .client
            .post(format!(
                "{}/authserver/reAuthCheck/changeReAuthType.do",
                self.settings.auth_server
            ))
            .form(&change_body)
            .send()
            .await?;
        if change_resp.status() != reqwest::StatusCode::OK {
            return Err(anyhow!("2FA: switch to TOTP failed, HTTP {}", change_resp.status()));
        }
        let change_data: serde_json::Value = change_resp.json().await.unwrap_or_default();
        if change_data.get("code").and_then(|v| v.as_str()) != Some("1") {
            return Err(anyhow!(
                "2FA: switch to TOTP rejected: {}",
                change_data.get("message").and_then(|v| v.as_str()).unwrap_or("?")
            ));
        }
        info!("event=2fa_switch reAuthType=10");

        // Step 2: 生成 TOTP 码
        let totp_secret = self.settings.totp_secret.trim();
        if totp_secret.is_empty() {
            return Err(anyhow!("2FA: TOTP_SECRET not configured"));
        }
        let secret = if totp_secret.starts_with("otpauth://") {
            // 从 otpauth URL 提取 secret 参数
            Url::parse(totp_secret)
                .ok()
                .and_then(|u| {
                    u.query_pairs()
                        .find(|(k, _)| k == "secret")
                        .map(|(_, v)| v.to_string())
                })
                .unwrap_or_else(|| totp_secret.to_string())
        } else {
            totp_secret.replace(char::is_whitespace, "")
        };
        let secret_bytes = BASE32_NOPAD
            .decode(secret.to_ascii_uppercase().as_bytes())
            .map_err(|e| anyhow!("2FA: invalid base32 secret: {e}"))?;

        if secret_bytes.len() < 10 {
            return Err(anyhow!(
                "2FA: decoded TOTP secret too short ({} bytes), check TOTP_SECRET value",
                secret_bytes.len()
            ));
        }
        info!(
            "event=2fa_totp_generated secret_len={} first_byte={:02x}",
            secret_bytes.len(),
            secret_bytes[0]
        );

        let otp_code = generate_totp(&secret_bytes);

        // Step 3: 提交二次验证 (最多重试一次 TOTP 码)
        let submit_body = [
            ("service", service_url.to_string()),
            ("reAuthType", "10".to_string()),
            ("isMultifactor", "true".to_string()),
            ("password", String::new()),
            ("dynamicCode", String::new()),
            ("uuid", String::new()),
            ("answer1", String::new()),
            ("answer2", String::new()),
            ("otpCode", otp_code.to_string()),
            ("skipTmpReAuth", "true".to_string()),
        ];
        let submit = || async {
            self.client
                .post(format!(
                    "{}/authserver/reAuthCheck/reAuthSubmit.do",
                    self.settings.auth_server
                ))
                .form(&submit_body)
                .send()
                .await
        };

        let mut resp = submit().await?;
        if resp.status() != reqwest::StatusCode::OK {
            return Err(anyhow!("2FA: submit failed, HTTP {}", resp.status()));
        }
        let data: serde_json::Value = resp.json().await.unwrap_or_default();
        let code = data.get("code").and_then(|v| v.as_str()).unwrap_or("");

        if code != "reAuth_success" {
            // 重试一次
            warn!("event=2fa_retry reason=first code rejected, retrying in 2s");
            tokio::time::sleep(Duration::from_secs(2)).await;
            let new_code = generate_totp(&secret_bytes);
            let mut retry_body = submit_body;
            retry_body[8].1 = new_code.to_string();
            resp = self
                .client
                .post(format!(
                    "{}/authserver/reAuthCheck/reAuthSubmit.do",
                    self.settings.auth_server
                ))
                .form(&retry_body)
                .send()
                .await?;
            if resp.status() != reqwest::StatusCode::OK {
                return Err(anyhow!("2FA: retry submit failed, HTTP {}", resp.status()));
            }
            let retry_data: serde_json::Value = resp.json().await.unwrap_or_default();
            if retry_data.get("code").and_then(|v| v.as_str()) != Some("reAuth_success") {
                let msg = retry_data
                    .get("msg")
                    .and_then(|v| v.as_str())
                    .unwrap_or("unknown");
                return Err(anyhow!("2FA TOTP failed after retry: {msg}"));
            }
        }

        info!("event=2fa_success");

        // Step 4: 跟随重定向回到目标服务
        self.follow_redirects(service_url).await?;
        info!("event=2fa_complete");
        Ok(())
    }

    async fn validate_session(&self) -> Result<()> {
        let resp = self
            .client
            .head(format!("{}/api/config", self.settings.target_base))
            .header(reqwest::header::HOST, &self.settings.target_host)
            .bearer_auth(&self.settings.openwebui_api_key)
            .send()
            .await?;
        if is_redirect(resp.status()) {
            if let Ok(loc) = location(&resp) {
                if is_cas_login_url(&loc) {
                    return Err(anyhow!(
                        "session validation failed: redirected to CAS login"
                    ));
                }
            }
        }
        info!("event=session_validated status={}", resp.status());
        Ok(())
    }

    async fn force_relogin(&self) -> Result<()> {
        let now = Instant::now();
        {
            let mut state = self.state.lock().await;
            if let Some(last) = state.last_force_relogin_time {
                if last.elapsed() < FORCE_RELOGIN_THROTTLE {
                    warn!("event=force_relogin outcome=throttled");
                    return if state.last_login.is_some() {
                        Ok(())
                    } else {
                        Err(anyhow!("login throttled"))
                    };
                }
            }
            state.last_force_relogin_time = Some(now);
        }
        warn!("event=force_relogin requested");
        self.ensure_login().await
    }

    async fn check_and_refresh(&self) {
        let state = self.state.lock().await;
        if state.circuit_until.is_some() {
            return;
        }
        drop(state);

        let resp = match self
            .client
            .head(format!("{}/api/config", self.settings.target_base))
            .header(reqwest::header::HOST, &self.settings.target_host)
            .bearer_auth(&self.settings.openwebui_api_key)
            .send()
            .await
        {
            Ok(r) => r,
            Err(e) => {
                warn!("event=keepalive error=network {}", e);
                return;
            }
        };

        if is_redirect(resp.status()) {
            if let Ok(loc) = location(&resp) {
                if is_cas_login_url(&loc) {
                    warn!("event=keepalive result=cas_redirect");
                    if let Err(e) = self.ensure_login().await {
                        warn!("event=keepalive relogin_failed: {e}");
                    }
                    return;
                }
            }
        }

        if resp.status().as_u16() >= 400 {
            warn!("event=keepalive result=upstream_error status={}", resp.status());
        } else {
            debug!("event=keepalive ok");
        }
    }

    async fn start_keepalive(self: Arc<Self>) {
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(KEEPALIVE_INTERVAL).await;
                self.check_and_refresh().await;
            }
        });
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
        status: String,
        service: &'static str,
        target: String,
        api_base: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        note: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        auth_state: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        latency_ms: Option<u64>,
        #[serde(skip_serializing_if = "Option::is_none")]
        upstream_status: Option<u16>,
    }

    let state_guard = state.auth.state.lock().await;
    let circuit = state_guard.circuit_until.is_some_and(|t| Instant::now() < t);
    let backoff = state_guard.backoff_until.is_some_and(|t| Instant::now() < t);
    let logged_in = state_guard.last_login.is_some_and(|t| t.elapsed() < COOKIE_TTL);
    let consecutive = state_guard.consecutive_failures;
    let last_ok_ago = state_guard
        .last_login_ok
        .map(|t| t.elapsed().as_secs())
        .unwrap_or(0);
    drop(state_guard);

    let t0 = Instant::now();
    let probe = state
        .auth
        .client
        .head(format!("{}/api/config", state.settings.target_base))
        .header(
            reqwest::header::HOST,
            &state.settings.target_host,
        )
        .bearer_auth(&state.settings.openwebui_api_key)
        .send()
        .await;

    let latency = t0.elapsed().as_millis() as u64;

    let (status, note, upstream_status) = match probe {
        Ok(resp) if resp.status().is_success() => {
            ("healthy".into(), Some("proxy normal, session valid".into()), Some(resp.status().as_u16()))
        }
        Ok(resp) if is_redirect(resp.status()) => {
            let is_cas = resp
                .headers()
                .get(reqwest::header::LOCATION)
                .and_then(|v| v.to_str().ok())
                .map(|loc| is_cas_login_url(loc))
                .unwrap_or(false);
            if is_cas {
                ("unhealthy".into(), Some("session expired, re-login needed".into()), Some(resp.status().as_u16()))
            } else {
                ("degraded".into(), Some("upstream redirect detected".into()), Some(resp.status().as_u16()))
            }
        }
        Ok(resp) => {
            ("degraded".into(), Some(format!("upstream status {}", resp.status())), Some(resp.status().as_u16()))
        }
        Err(e) => {
            ("degraded".into(), Some(format!("probe failed: {e}")), None)
        }
    };

    Json(Health {
        status: if circuit || backoff {
            "degraded".into()
        } else if !logged_in {
            "starting".into()
        } else {
            status
        },
        service: "NWAFU DeepSeek Proxy",
        target: state.settings.target_base.clone(),
        api_base: format!("http://localhost:{}/v1", state.settings.proxy_port),
        note: Some(format!(
            "circuit={} backoff={} logged_in={} consecutive_failures={} last_ok={last_ok_ago}s | {}",
            if circuit { "open" } else { "ok" },
            if backoff { "active" } else { "ok" },
            logged_in,
            consecutive,
            note.unwrap_or_default()
        )),
        auth_state: Some(if circuit {
            "circuit_open"
        } else if backoff {
            "backoff"
        } else if logged_in {
            "ok"
        } else {
            "expired"
        }.into()),
        latency_ms: Some(latency),
        upstream_status,
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
        let _ = state.auth.force_relogin().await;
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
    is_cas_login_url(location)
}

fn is_cas_login_url(url_str: &str) -> bool {
    if url_str.is_empty() {
        return false;
    }
    if url_str.starts_with("/.auth/login/cas") {
        return true;
    }
    if let Ok(url) = Url::parse(url_str) {
        return url.host_str() == Some("authserver.nwafu.edu.cn")
            && url.path().starts_with("/authserver/login");
    }
    false
}

fn generate_totp(secret: &[u8]) -> u32 {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let counter = (now / 30).to_be_bytes();
    let mut mac = HmacSha1::new_from_slice(secret).expect("HMAC can take key of any size");
    mac.update(&counter);
    let result = mac.finalize().into_bytes();
    let offset = (result[19] & 0xf) as usize;
    let code = u32::from_be_bytes(result[offset..offset + 4].try_into().unwrap()) & 0x7fff_ffff;
    code % 1_000_000
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

async fn proxy_ws(state: AppState, mut client_ws: WebSocket, uri: Uri, headers: HeaderMap) {
    if let Err(err) = state.auth.ensure_login().await {
        warn!("event=ws_auth_failed error={}", err);
        let _ = client_ws
            .send(Message::Close(Some(axum::extract::ws::CloseFrame {
                code: 1013,
                reason: "auth failed".into(),
            })))
            .await;
        return;
    }
    let target = match build_ws_url(&state.settings, &uri) {
        Ok(url) => url,
        Err(err) => {
            warn!("event=ws_url_error error={}", err);
            let _ = client_ws.close().await;
            return;
        }
    };
    let mut request = match target.as_str().into_client_request() {
        Ok(req) => req,
        Err(err) => {
            warn!("event=ws_request_error error={}", err);
            let _ = client_ws.close().await;
            return;
        }
    };
    // Origin / User-Agent
    request.headers_mut().insert(
        "Origin",
        HeaderValue::from_str(&state.settings.target_base).unwrap(),
    );
    request.headers_mut().insert(
        "User-Agent",
        HeaderValue::from_static(
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
        ),
    );
    // API Key
    if !state.settings.openwebui_api_key.is_empty() {
        let value = format!("Bearer {}", state.settings.openwebui_api_key);
        request
            .headers_mut()
            .insert("Authorization", HeaderValue::from_str(&value).unwrap());
    }
    // Session cookies
    if let Ok(url) = Url::parse(&target) {
        if let Some(cookie) = state.auth.cookie_header(&url) {
            info!("event=ws_cookie len={}", cookie.len());
            if let Ok(value) = HeaderValue::from_str(&cookie) {
                request.headers_mut().insert("Cookie", value);
            }
        } else {
            warn!("event=ws_no_cookie url={}", target);
        }
    }
    // Subprotocols
    if let Some(protocol) = headers.get(header::SEC_WEBSOCKET_PROTOCOL) {
        request
            .headers_mut()
            .insert(header::SEC_WEBSOCKET_PROTOCOL, protocol.clone());
    }
    // Forward non-hop-by-hop headers from client
    for (name, value) in headers.iter() {
        let name_lower = name.as_str().to_ascii_lowercase();
        if matches!(
            name_lower.as_str(),
            "host" | "connection" | "upgrade" | "sec-websocket-key"
                | "sec-websocket-version" | "sec-websocket-extensions"
                | "sec-websocket-protocol" | "origin" | "user-agent"
                | "authorization" | "cookie" | "content-length"
        ) {
            continue; // already handled or hop-by-hop
        }
        // Only forward if not already set
        if !request.headers().contains_key(name) {
            request.headers_mut().insert(name.clone(), value.clone());
        }
    }

    info!(
        "event=ws_connect path={} headers=[{}]",
        uri.path(),
        request
            .headers()
            .iter()
            .map(|(k, _)| k.as_str())
            .collect::<Vec<_>>()
            .join(", ")
    );

    let upstream_ws = match connect_async_tls_with_config(request, None, false, None).await {
        Ok((ws, resp)) => {
            info!(
                "event=ws_connected path={} status={}",
                uri.path(),
                resp.status()
            );
            ws
        }
        Err(err) => {
            warn!("event=ws_upstream_rejected path={} error={}", uri.path(), err);
            let _ = client_ws
                .send(Message::Close(Some(axum::extract::ws::CloseFrame {
                    code: 1011,
                    reason: format!("upstream: {err}").into(),
                })))
                .await;
            return;
        }
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

    // Start background keepalive
    state.auth.clone().start_keepalive().await;
    info!("event=keepalive_started interval={:?}", KEEPALIVE_INTERVAL);

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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_totp_against_known_value() {
        // RFC 6238 test vector: secret = "12345678901234567890" (base32: GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ)
        // At time=59, T0=0, step=30, SHA1:
        // HMAC-SHA1 result: 0x75a48a19d4cbe100644e8ac1397eea747a2d33ab (per RFC 6238 Appendix B)
        // So we construct counter = 59/30 = 1
        // Then verify our function produces the expected TOTP code
        
        let secret = b"12345678901234567890";  // 20 bytes raw ASCII
        // We need to test at a specific time. But we can't control SystemTime in a simple test.
        // Let's just verify the internal logic with known values.
        
        use hmac::Mac;
        
        // Test at counter=1 (time=30 to 59)
        let counter = 1u64.to_be_bytes();
        let mut mac = HmacSha1::new_from_slice(secret).unwrap();
        mac.update(&counter);
        let result = mac.finalize().into_bytes();
        
        // Expected HMAC per RFC 6238: 75a48a19d4cbe100644e8ac1397eea747a2d33ab
        let expected_hmac: [u8; 20] = [
            0x75, 0xa4, 0x8a, 0x19, 0xd4, 0xcb, 0xe1, 0x00,
            0x64, 0x4e, 0x8a, 0xc1, 0x39, 0x7e, 0xea, 0x74,
            0x7a, 0x2d, 0x33, 0xab,
        ];
        assert_eq!(&result[..], &expected_hmac[..], "HMAC-SHA1 mismatch");
        
        let offset = (result[19] & 0xf) as usize;
        let code = u32::from_be_bytes(result[offset..offset + 4].try_into().unwrap()) & 0x7fff_ffff;
        let totp = code % 1_000_000;
        println!("TOTP = {:06}", totp);
        
        // TOTP at time=59 (counter=1), 6 digits, SHA1 → 287082
        assert_eq!(totp, 287082, "TOTP for counter=1, 6-digit should be 287082");
    }
}
