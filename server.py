"""
nwafu_deepseek_proxy - 校园统一认证 Open WebUI 透明反向代理

自动处理金智教育 (Wisedu) AuthServer CAS 认证流程,
在本地暴露与源站完全一致的 API 端点, 供第三方客户端直接调用。
所有请求无差别透传到源站, 代理仅负责会话维护与请求头注入。

详见 README.md
"""

import asyncio
import base64
import enum
import json
import logging
import os
import random
import re
import secrets
import sys
import time
from contextlib import asynccontextmanager
from contextvars import ContextVar
from dataclasses import dataclass
from typing import Optional
from urllib.parse import urljoin, urlparse, quote, parse_qs

import httpx
import pyotp
import websockets
from websockets.asyncio.client import connect as websocket_connect
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from fastapi import FastAPI, Request, Response, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, StreamingResponse, JSONResponse
from dotenv import load_dotenv
import uvicorn

# ============================================================
# 配置与日志
# ============================================================

load_dotenv(override=False)

request_id_ctx: ContextVar[str] = ContextVar("request_id", default="-")

_DATA_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), ".data")
_PERSIST_FILE = os.path.join(_DATA_DIR, "login_state.json")


class _RequestIDFilter(logging.Filter):
    def filter(self, record: logging.LogRecord) -> bool:
        record.request_id = request_id_ctx.get()
        return True


logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] [%(request_id)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger("proxy")

_request_id_filter = _RequestIDFilter()
_root_logger = logging.getLogger()
for _h in _root_logger.handlers:
    _h.addFilter(_request_id_filter)

for _name in ("uvicorn", "uvicorn.error", "uvicorn.access"):
    _l = logging.getLogger(_name)
    _l.handlers.clear()
    _l.propagate = True

# ---- 时间常量 ----

COOKIE_TTL_SECONDS = 25 * 60
KEEPALIVE_INTERVAL_SECONDS = 5 * 60
KEEPALIVE_JITTER_SECONDS = 30
MAX_LOGIN_REDIRECTS = 10
PROXY_MAX_RETRIES = 2
NETWORK_RETRY_ATTEMPTS = 3

# 登录频率限制
MAX_LOGINS_PER_HOUR = 6
LOGIN_WINDOW_SECONDS = 3600

# 退避
LOGIN_BACKOFF_BASE = 5
LOGIN_BACKOFF_MULTIPLIER = 4
LOGIN_BACKOFF_MAX_NORMAL = 900       # 15 min
LOGIN_BACKOFF_MAX_CRITICAL = 14400   # 4 hours

# 熔断
CIRCUIT_NORMAL_DURATION = 900        # 15 min
CIRCUIT_CRITICAL_DURATION = 21600    # 6 hours
CIRCUIT_CAPTCHA_DURATION = 7200      # 2 hours
CIRCUIT_PASSWORD_ERROR_DURATION = 3600  # 1 hour
MAX_CONSECUTIVE_FAILURES = 3

# Body 采样上限（用于 CAS 登录页识别）
BODY_SAMPLE_MAX_BYTES = 4096

STREAM_TIMEOUT = httpx.Timeout(300.0, connect=15.0)
DEFAULT_TIMEOUT = httpx.Timeout(60.0, connect=15.0)
DEGRADED_TIMEOUT = httpx.Timeout(8.0, connect=5.0)     # 上游异常时快速失败
DEGRADED_WINDOW = 120     # 2 分钟内
DEGRADED_THRESHOLD = 2    # 出现 2 次失败即进入降级模式
LOGIN_STICKY_WINDOW = 30  # 登录成功后短时间内仍被拒绝，视为会话建立异常
LOGIN_MIN_INTERVAL = 60     # 两次登录之间的最小间隔（防止登录风暴）
FORCE_RELOGIN_THROTTLE = 10  # force_relogin 限流窗口（秒）
RESPONSE_REWRITE_MAX_BYTES = 5 * 1024 * 1024

_RETRIABLE_NET_ERRORS = (
    httpx.ConnectError,
    httpx.NetworkError,
    httpx.ReadError,
    httpx.RemoteProtocolError,
)

_LOGIN_ERROR_MESSAGES = {
    "FAIL_UPNOTMATCH": "密码错误或账户不存在",
    "CAPTCHA_NOTMATCH": "需要输入验证码，账号可能被临时限制",
    "LOCK": "账户已被锁定",
}

# ---- HTML 解析工具 (仅用于 CAS 登录页) ----

_RE_INPUT_BY_ID = lambda name: re.compile(
    rf'<input\b[^>]*\bid=["\']{re.escape(name)}["\'][^>]*>', re.I
)
_RE_VALUE_ATTR = re.compile(r'\bvalue=["\']([^"\']*)["\']', re.I)
_RE_ERROR_TIP = re.compile(
    r'id=["\']formErrorTip["\'][^>]*>.*?<span[^>]*>([^<]+)</span>',
    re.S | re.I,
)
_RE_CAS_FORM_FIELDS = re.compile(
    r'<input\b[^>]*\bid=["\'](?:execution|pwdEncryptSalt)["\'][^>]*>', re.I
)


def _extract_input_value(html: str, input_id: str) -> str | None:
    tag_match = _RE_INPUT_BY_ID(input_id).search(html)
    if not tag_match:
        return None
    val = _RE_VALUE_ATTR.search(tag_match.group(0))
    return val.group(1) if val else ""


def _parse_login_form(html: str) -> tuple[str, str]:
    execution = _extract_input_value(html, "execution")
    salt = _extract_input_value(html, "pwdEncryptSalt")
    if execution is None or salt is None:
        raise RuntimeError("登录页结构变更：无法提取 execution/pwdEncryptSalt")
    return execution, salt


def _extract_error_text(html: str) -> str | None:
    m = _RE_ERROR_TIP.search(html)
    return m.group(1).strip() if m else None


def _sample_contains_cas_fields(body_bytes: bytes) -> bool:
    """检查前 N 字节中是否包含 CAS 登录表单特征字段"""
    sample = body_bytes[:BODY_SAMPLE_MAX_BYTES].decode("utf-8", errors="ignore")
    found = set()
    for m in _RE_CAS_FORM_FIELDS.finditer(sample):
        tag = m.group(0).lower()
        if 'id="execution"' in tag or "id='execution'" in tag:
            found.add("execution")
        if 'id="pwdencryptsalt"' in tag or "id='pwdencryptsalt'" in tag:
            found.add("pwdEncryptSalt")
    return "execution" in found and "pwdEncryptSalt" in found


# ---- 流式端点识别 ----

_STREAMING_PATH_PREFIXES = (
    "/api/chat/completions",
    "/v1/chat/completions",
    "/ollama",
    "/openai",
)


def _is_streaming_path(path: str) -> bool:
    return any(path.startswith(p) for p in _STREAMING_PATH_PREFIXES)


def _needs_long_timeout(path: str) -> bool:
    return _is_streaming_path(path)


# ============================================================
# 配置
# ============================================================


@dataclass(frozen=True)
class Settings:
    username: str
    password: str
    proxy_port: int
    target_host: str
    openwebui_api_key: str
    auth_server: str
    cors_origins: list[str]
    # 模型监控（可选）
    monitor_enabled: bool
    monitor_poll_interval: int
    telegram_bot_token: str
    telegram_chat_id: str
    webhook_urls: list[str]
    webhook_secret: str
    notify_proxy: str
    totp_secret: str

    @property
    def target_base(self) -> str:
        return f"https://{self.target_host}"


def load_settings() -> Settings:
    username = os.getenv("NWAFU_USERNAME", "").strip()
    password = os.getenv("NWAFU_PASSWORD", "")
    proxy_port = int(os.getenv("PROXY_PORT", "8000"))
    target_host = os.getenv("TARGET_HOST", "deepseek.nwafu.edu.cn").strip()
    openwebui_api_key = os.getenv("OPENWEBUI_API_KEY", "").strip()
    auth_server = os.getenv("AUTH_SERVER", "https://authserver.nwafu.edu.cn").strip()
    cors_raw = os.getenv("CORS_ORIGINS", "").strip()
    cors_origins = ["*"] if not cors_raw else [p.strip() for p in cors_raw.split(",") if p.strip()]

    monitor_enabled = os.getenv("MONITOR_ENABLED", "false").strip().lower() == "true"
    monitor_poll_interval = int(os.getenv("MONITOR_POLL_INTERVAL", "600"))
    if monitor_poll_interval < 300:
        logger.warning("MONITOR_POLL_INTERVAL=%d 过短，已调整为 600s", monitor_poll_interval)
        monitor_poll_interval = 600
    telegram_bot_token = os.getenv("TELEGRAM_BOT_TOKEN", "").strip()
    telegram_chat_id = os.getenv("TELEGRAM_CHAT_ID", "").strip()
    webhook_urls_raw = os.getenv("WEBHOOK_URLS", "").strip()
    webhook_urls = [u.strip() for u in webhook_urls_raw.split(",") if u.strip()] if webhook_urls_raw else []
    webhook_secret = os.getenv("WEBHOOK_SECRET", "").strip()
    notify_proxy = os.getenv("NOTIFY_PROXY", "").strip()
    totp_secret = os.getenv("TOTP_SECRET", "").strip()

    if not username or not password:
        raise SystemExit("缺少必填环境变量：NWAFU_USERNAME / NWAFU_PASSWORD（请在 .env 中配置）")

    if not openwebui_api_key:
        logger.warning("未配置 OPENWEBUI_API_KEY：上游可能返回 401/403（请在 .env 中配置）")

    return Settings(
        username=username,
        password=password,
        proxy_port=proxy_port,
        target_host=target_host,
        openwebui_api_key=openwebui_api_key,
        auth_server=auth_server,
        cors_origins=cors_origins,
        monitor_enabled=monitor_enabled,
        monitor_poll_interval=monitor_poll_interval,
        telegram_bot_token=telegram_bot_token,
        telegram_chat_id=telegram_chat_id,
        webhook_urls=webhook_urls,
        webhook_secret=webhook_secret,
        notify_proxy=notify_proxy,
        totp_secret=totp_secret,
    )


settings = load_settings()

USERNAME = settings.username
PASSWORD = settings.password
PROXY_PORT = settings.proxy_port
TARGET_HOST = settings.target_host
OPENWEBUI_API_KEY = settings.openwebui_api_key
AUTH_SERVER = settings.auth_server
TARGET_BASE = settings.target_base
TOTP_SECRET = settings.totp_secret

# ============================================================
# 金智 AuthServer AES 加密（对齐前端 encrypt.js）
# ============================================================

AES_CHARS = "ABCDEFGHJKMNPQRSTWXYZabcdefhijkmnprstwxyz2345678"


def _random_string(length: int) -> str:
    return "".join(secrets.choice(AES_CHARS) for _ in range(length))


def encrypt_password(password: str, salt: str) -> str:
    if not salt:
        return password
    random_prefix = _random_string(64)
    random_iv = _random_string(16)
    data = (random_prefix + password).encode("utf-8")
    key = salt.strip().encode("utf-8")
    iv = random_iv.encode("utf-8")
    cipher = AES.new(key, AES.MODE_CBC, iv)
    encrypted = cipher.encrypt(pad(data, AES.block_size))
    return base64.b64encode(encrypted).decode("utf-8")


# ============================================================
# 认证状态机
# ============================================================


class AuthState(enum.Enum):
    OK = "ok"                  # 会话有效，正常运作
    SUSPECT = "suspect"        # 检测到异常但不确定是认证过期，不触发登录
    EXPIRED = "expired"        # 明确检测到 CAS 重定向，需要重新登录
    LOGIN_BACKOFF = "backoff"  # 登录失败，等待退避
    CIRCUIT_OPEN = "circuit_open"  # 熔断开启，保护账号


class CriticalLoginError(Exception):
    """高危登录失败（账号锁定/验证码/密码错误），需要更长熔断"""
    def __init__(self, message: str, circuit_duration: int = CIRCUIT_CRITICAL_DURATION):
        super().__init__(message)
        self.circuit_duration = circuit_duration


class CircuitOpenError(Exception):
    """熔断开启中，拒绝登录"""
    def __init__(self, message: str, retry_after: int = 0):
        super().__init__(message)
        self.retry_after = retry_after


class UpstreamUnavailableError(Exception):
    """上游暂不可达（用于向客户端返回 503）"""


class TwoFactorError(Exception):
    """二次验证失败（TOTP 码错误/过期等），使用较短退避"""

    def __init__(self, message: str):
        super().__init__(message)


# ============================================================
# AuthServer 会话管理器
# ============================================================


class AuthSessionManager:
    """
    管理与 AuthServer 及目标站之间的完整会话生命周期:

    安全保护层级（由外到内）：
    1. 状态机 — 区分"上游异常"与"认证过期"
    2. 单飞锁 — 并发请求最多触发一次真实 CAS 登录
    3. 频率限制 — 每小时最多 N 次登录尝试（支持文件持久化）
    4. 指数退避 — 每次失败后退避时间翻倍
    5. 熔断器 — 连续失败达阈值后长时间停止登录
    6. 失败分类 — 高危错误（锁定/验证码）使用更长熔断
    """

    def __init__(self):
        self._client: Optional[httpx.AsyncClient] = None
        self._login_lock = asyncio.Lock()     # 单飞登录锁
        self._state: AuthState = AuthState.OK
        self._last_login_time: float = 0
        self._cookie_ttl: float = float(COOKIE_TTL_SECONDS)
        self._keepalive_task: Optional[asyncio.Task[None]] = None

        # 频率限制 & 退避
        self._login_attempt_times: list[float] = []
        self._consecutive_failures: int = 0
        self._backoff_until: float = 0
        self._circuit_until: float = 0
        self._circuit_duration: float = 0

        # 上游降级检测（与认证状态机独立）
        self._recent_proxy_failures: list[float] = []  # 最近代理请求失败的时间戳
        self._last_login_ok_time: float = 0           # 最近一次成功登录的时间
        self._login_then_rejected: bool = False        # 登录成功后仍被拒绝
        self._last_login_attempt_time: float = 0       # 最近一次登录尝试的时间
        self._last_force_relogin_time: float = 0       # 最近一次 force_relogin 的时间

        # 从文件恢复持久化状态
        self._load_persisted_state()

    # ---- 持久化 ----

    def _load_persisted_state(self):
        try:
            with open(_PERSIST_FILE, "r") as f:
                data = json.load(f)
        except (FileNotFoundError, json.JSONDecodeError):
            return

        now = time.time()
        self._login_attempt_times = [t for t in data.get("attempts", []) if now - t < LOGIN_WINDOW_SECONDS]
        self._consecutive_failures = data.get("consecutive_failures", 0)
        circuit_remaining = data.get("circuit_remaining", 0)
        circuit_duration = data.get("circuit_duration", 0)
        if circuit_remaining > 0:
            self._state = AuthState.CIRCUIT_OPEN
            self._circuit_until = time.monotonic() + circuit_remaining
            self._circuit_duration = circuit_duration
            logger.info(
                "event=state_restored state=circuit_open consecutive_failures=%d remaining=%ds",
                self._consecutive_failures, circuit_remaining,
            )
        elif self._consecutive_failures > 0:
            logger.info(
                "event=state_restored consecutive_failures=%d (circuit expired)",
                self._consecutive_failures,
            )

    def _save_persisted_state(self):
        circuit_remaining = 0
        if self._state == AuthState.CIRCUIT_OPEN:
            circuit_remaining = max(0, self._circuit_until - time.monotonic())
        data = {
            "attempts": self._login_attempt_times,
            "consecutive_failures": self._consecutive_failures,
            "circuit_remaining": int(circuit_remaining),
            "circuit_duration": int(self._circuit_duration) if self._state == AuthState.CIRCUIT_OPEN else 0,
        }
        try:
            os.makedirs(_DATA_DIR, exist_ok=True)
            with open(_PERSIST_FILE, "w") as f:
                json.dump(data, f)
        except Exception as e:
            logger.warning("event=persist_failed error=%s", e)

    # ---- 状态管理 ----

    @property
    def state(self) -> AuthState:
        return self._state

    @property
    def login_ok(self) -> bool:
        return self._state == AuthState.OK

    def _transition(self, new_state: AuthState, reason: str):
        old = self._state
        if old == new_state:
            return
        self._state = new_state
        logger.info(
            "event=auth_state_change old_state=%s new_state=%s reason=%s",
            old.value, new_state.value, reason,
        )
        self._save_persisted_state()

    # ---- 频率限制 ----

    def _check_rate_limit(self) -> bool:
        """检查是否超过每小时登录次数限制，返回 True 表示允许"""
        now = time.time()
        self._login_attempt_times = [t for t in self._login_attempt_times if now - t < LOGIN_WINDOW_SECONDS]
        if len(self._login_attempt_times) >= MAX_LOGINS_PER_HOUR:
            logger.warning(
                "event=login_attempt outcome=denied reason=rate_limited "
                "attempts=%d/%dh window=%ds",
                len(self._login_attempt_times), MAX_LOGINS_PER_HOUR, LOGIN_WINDOW_SECONDS,
            )
            return False
        return True

    def _record_login_attempt(self):
        self._login_attempt_times.append(time.time())
        self._save_persisted_state()

    # ---- 退避时间计算 ----

    def _compute_backoff(self, is_critical: bool = False) -> float:
        max_delay = LOGIN_BACKOFF_MAX_CRITICAL if is_critical else LOGIN_BACKOFF_MAX_NORMAL
        raw = min(
            LOGIN_BACKOFF_BASE * (LOGIN_BACKOFF_MULTIPLIER ** max(0, self._consecutive_failures - 1)),
            max_delay,
        )
        jitter = raw * (0.75 + random.random() * 0.5)
        return jitter

    # ---- 熔断 ----

    # ---- 上游降级检测 ----

    def _record_proxy_failure(self):
        """记录一次代理请求失败（超时或网络错误），用于降级检测"""
        self._recent_proxy_failures.append(time.monotonic())

    def is_degraded(self) -> bool:
        """检查上游是否处于降级状态（最近有多个请求失败）"""
        now = time.monotonic()
        self._recent_proxy_failures = [t for t in self._recent_proxy_failures if now - t < DEGRADED_WINDOW]
        return len(self._recent_proxy_failures) >= DEGRADED_THRESHOLD

    def recent_login_rejected(self) -> bool:
        """
        检查登录成功后的短窗口内是否仍被认证中间件拒绝。
        返回 True 时不再立即重试登录，避免形成 CAS 登录风暴。
        """
        if not self._login_then_rejected:
            now = time.monotonic()
            if self._last_login_ok_time > 0 and (now - self._last_login_ok_time) < LOGIN_STICKY_WINDOW:
                self._login_then_rejected = True
                logger.warning(
                    "event=login_rejected_after_success seconds_since_login=%.1f "
                    "action=suppress_immediate_relogin",
                    now - self._last_login_ok_time,
                )
        return self._login_then_rejected

    # ---- 熔断 ----

    def _open_circuit(self, duration: float, reason: str):
        self._circuit_duration = duration
        self._circuit_until = time.monotonic() + duration
        self._transition(AuthState.CIRCUIT_OPEN, f"circuit_open:{reason}")
        logger.warning(
            "event=circuit state=open duration=%ds reason=%s consecutive_failures=%d",
            int(duration), reason, self._consecutive_failures,
        )
        self._save_persisted_state()

    def _check_or_raise_circuit(self) -> None:
        """检查熔断状态，若熔断已过期则解除，否则抛出 CircuitOpenError"""
        if self._state != AuthState.CIRCUIT_OPEN:
            return
        remaining = self._circuit_until - time.monotonic()
        if remaining <= 0:
            self._transition(AuthState.EXPIRED, "circuit_expired")
            logger.info("event=circuit state=closed")
            self._save_persisted_state()
            return
        msg = "Login temporarily disabled to protect the campus account. Please retry later."
        raise CircuitOpenError(msg, retry_after=int(remaining))

    def _check_circuit(self) -> bool:
        """检查熔断是否已过期，返回 True 表示熔断已解除（供外部只读使用）"""
        if self._state != AuthState.CIRCUIT_OPEN:
            return True
        if time.monotonic() >= self._circuit_until:
            self._transition(AuthState.EXPIRED, "circuit_expired")
            logger.info("event=circuit state=closed")
            self._save_persisted_state()
            return True
        return False

    # ---- 主入口：确保已登录 ----

    async def ensure_login(self) -> httpx.AsyncClient:
        """
        双重检查 + 单飞锁模式：
        1. 快速路径：状态 OK 且 TTL 有效 → 直接返回
        2. 熔断开启时有旧 client → 返回旧 client
        3. 否则通过 login_lock 排队，只允许一个真实登录
        """
        now = time.monotonic()

        # 快速路径：无锁检查
        if self._state == AuthState.OK and self._client is not None and (now - self._last_login_time) <= self._cookie_ttl:
            return self._client

        # 熔断期间：若有旧 client 则继续使用（session 可能仍有效）
        try:
            self._check_or_raise_circuit()
        except CircuitOpenError:
            if self._client is not None:
                return self._client
            raise

        # SUSPECT 状态：不触发登录，继续使用旧 client
        if self._state == AuthState.SUSPECT and self._client is not None:
            return self._client

        # 进入单飞登录锁
        async with self._login_lock:
            # 双重检查：排队期间可能已被其他请求修复
            now2 = time.monotonic()
            if self._state == AuthState.OK and self._client is not None and (now2 - self._last_login_time) <= self._cookie_ttl:
                return self._client

            # 再次检查熔断
            try:
                self._check_or_raise_circuit()
            except CircuitOpenError:
                if self._client is not None:
                    return self._client
                raise

            # SUSPECT 复用旧 client（双重检查）
            if self._state == AuthState.SUSPECT and self._client is not None:
                return self._client

            # 检查退避
            if self._state == AuthState.LOGIN_BACKOFF:
                if time.monotonic() < self._backoff_until:
                    remaining = int(self._backoff_until - time.monotonic())
                    logger.info(
                        "event=login_attempt outcome=denied reason=backoff remaining=%ds",
                        remaining,
                    )
                    if self._client is not None:
                        return self._client
                    raise UpstreamUnavailableError(
                        f"登录退避中（剩余 {remaining}s），请稍后重试"
                    )
                else:
                    self._transition(AuthState.EXPIRED, "backoff_expired")

            # 频率限制检查
            if not self._check_rate_limit():
                if self._client is not None:
                    return self._client
                raise UpstreamUnavailableError("登录频率过高，请稍后重试")

            # 登录最小间隔检查（防止登录风暴）
            now3 = time.monotonic()
            since_last_attempt = now3 - self._last_login_attempt_time
            if self._last_login_attempt_time > 0 and since_last_attempt < LOGIN_MIN_INTERVAL:
                remaining = int(LOGIN_MIN_INTERVAL - since_last_attempt)
                logger.warning(
                    "event=login_attempt outcome=denied reason=cooldown remaining=%ds "
                    "last_attempt=%.1fs_ago",
                    remaining, since_last_attempt,
                )
                if self._client is not None:
                    return self._client
                raise UpstreamUnavailableError(
                    f"登录间隔过短（剩余 {remaining}s），请稍后重试"
                )

            # 真正执行登录
            return await self._do_login_with_protections()

    async def _do_login_with_protections(self) -> httpx.AsyncClient:
        """在 login_lock 持有下执行登录，记录结果并更新状态"""
        logger.info(
            "event=login_attempt outcome=allowed state=%s consecutive_failures=%d",
            self._state.value, self._consecutive_failures,
        )
        self._last_login_attempt_time = time.monotonic()
        self._record_login_attempt()

        try:
            await self._do_login()
            # 登录成功
            self._consecutive_failures = 0
            self._backoff_until = 0
            self._transition(AuthState.OK, "login_success")
            self._last_login_time = time.monotonic()
            self._last_login_ok_time = time.monotonic()
            self._login_then_rejected = False
            logger.info("event=login_result outcome=success")
            self._save_persisted_state()
            return self._client  # type: ignore[return-value]
        except TwoFactorError as e:
            self._consecutive_failures += 1
            # 2FA 失败使用固定短退避（30s），不触发熔断
            self._backoff_until = time.monotonic() + 30
            self._transition(AuthState.LOGIN_BACKOFF, f"2fa_failed:{e}")
            logger.error(
                "event=login_result outcome=failure type=2fa error=%s failures=%d",
                e, self._consecutive_failures,
            )
            if self._consecutive_failures >= MAX_CONSECUTIVE_FAILURES:
                self._open_circuit(CIRCUIT_NORMAL_DURATION, f"consecutive_failures={self._consecutive_failures}")
            self._save_persisted_state()
            raise
        except CriticalLoginError as e:
            self._consecutive_failures += 1
            logger.error("event=login_result outcome=failure type=critical error=%s", e)
            self._open_circuit(e.circuit_duration, str(e))
            raise
        except Exception as e:
            self._consecutive_failures += 1
            backoff = self._compute_backoff(is_critical=False)
            self._backoff_until = time.monotonic() + backoff
            self._transition(AuthState.LOGIN_BACKOFF, f"login_failed:{e}")
            logger.error(
                "event=login_result outcome=failure type=normal error=%s backoff=%.1fs failures=%d",
                e, backoff, self._consecutive_failures,
            )
            if self._consecutive_failures >= MAX_CONSECUTIVE_FAILURES:
                self._open_circuit(CIRCUIT_NORMAL_DURATION, f"consecutive_failures={self._consecutive_failures}")
            self._save_persisted_state()
            raise

    async def force_relogin(self):
        """
        仅在明确检测到 CAS session 失效时调用。
        调用者必须已经确认响应是真实的 CAS 登录页重定向。
        此方法仍需通过 ensure_login() 的所有保护层级。

        限流：10 秒内重复调用 force_relogin 会被忽略。
        """
        now = time.monotonic()
        since_last = now - self._last_force_relogin_time
        if self._last_force_relogin_time > 0 and since_last < FORCE_RELOGIN_THROTTLE:
            logger.warning(
                "event=force_relogin outcome=throttled "
                "since_last=%.1fs throttle=%ds — 忽略重复请求",
                since_last, FORCE_RELOGIN_THROTTLE,
            )
            if self._client is not None:
                return self._client
            raise UpstreamUnavailableError("登录请求过于频繁，请稍后重试")

        self._last_force_relogin_time = now
        logger.warning("event=force_relogin requested — 检测到明确的 CAS 会话失效")
        self._transition(AuthState.EXPIRED, "force_relogin:definitive_cas_redirect")
        self._last_login_time = 0
        try:
            return await self.ensure_login()
        except (CircuitOpenError, UpstreamUnavailableError):
            raise
        except Exception as e:
            logger.error("event=force_relogin failed: %s", e)
            raise

    # ---- HTTP Client ----

    async def _create_client(self) -> httpx.AsyncClient:
        return httpx.AsyncClient(
            timeout=DEFAULT_TIMEOUT,
            follow_redirects=True,
            trust_env=False,
            limits=httpx.Limits(max_connections=30, max_keepalive_connections=15),
            headers={
                "User-Agent": (
                    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) "
                    "AppleWebKit/537.36 (KHTML, like Gecko) "
                    "Chrome/124.0.0.0 Safari/537.36"
                ),
                "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                "Accept-Language": "zh-CN,zh;q=0.9,en;q=0.8",
            },
        )

    # ---- 网络重试 ----

    async def _retry_request(self, method: str, url: str, *, follow_redirects: bool = False, **kwargs) -> httpx.Response:
        assert self._client is not None
        last_exc: Optional[Exception] = None
        for attempt in range(NETWORK_RETRY_ATTEMPTS):
            try:
                return await self._client.request(method, url, follow_redirects=follow_redirects, **kwargs)
            except _RETRIABLE_NET_ERRORS as e:
                last_exc = e
                if attempt < NETWORK_RETRY_ATTEMPTS - 1:
                    logger.warning("event=network_retry method=%s url=%s error=%s attempt=%d",
                                   method, str(url)[:60], e, attempt + 1)
                    await asyncio.sleep(1.0 * (2 ** attempt))
                    continue
                raise
        assert last_exc is not None
        raise last_exc

    # ---- CAS 登录流程 ----

    async def _fetch_login_page(self, login_url: str) -> httpx.Response:
        logger.info("请求登录页：GET %s...", login_url[:80])
        return await self._retry_request("GET", login_url, follow_redirects=False)

    async def _submit_login_form(self, login_url: str, login_data: dict) -> httpx.Response:
        logger.info("提交登录表单：POST /authserver/login")
        return await self._retry_request("POST", login_url, data=login_data, follow_redirects=False)

    def _classify_login_failure(self, resp: httpx.Response) -> tuple[str, str, int]:
        """
        分类登录失败原因。返回 (message, failure_type, circuit_duration)。

        failure_type: "account_locked" | "captcha" | "password_error" | "rate_limited" | "maintenance" | "unknown"
        """
        html_text = ""
        # 尝试 JSON 响应
        try:
            data = resp.json()
            code = data.get("resultCode", "")
            if code == "LOCK":
                return ("账户已被锁定，请手动解锁后重启代理", "account_locked", CIRCUIT_CRITICAL_DURATION)
            if code == "CAPTCHA_NOTMATCH":
                return ("需要验证码，账号可能被临时限制", "captcha", CIRCUIT_CAPTCHA_DURATION)
            if code == "FAIL_UPNOTMATCH":
                return ("密码错误或账户不存在，请检查 .env 配置", "password_error", CIRCUIT_PASSWORD_ERROR_DURATION)
            if code:
                return (f"AuthServer 错误: {code}", "unknown", CIRCUIT_NORMAL_DURATION)
        except Exception:
            html_text = resp.text[:2000]

        # 检查 HTML 响应中的高危信号
        if html_text:
            if "锁定" in html_text or "LOCK" in html_text:
                return ("账户可能已被锁定，请手动检查", "account_locked", CIRCUIT_CRITICAL_DURATION)
            if "频繁" in html_text or "操作过于频繁" in html_text:
                return ("CAS 提示操作过于频繁，账号可能被临时限制", "rate_limited", CIRCUIT_CRITICAL_DURATION)
            if "验证码" in html_text or "captcha" in html_text.lower():
                return ("需要验证码，账号可能被临时限制", "captcha", CIRCUIT_CAPTCHA_DURATION)
            if "维护" in html_text or "maintenance" in html_text.lower():
                return ("CAS 系统可能正在维护", "maintenance", CIRCUIT_NORMAL_DURATION)

        # 尝试从 HTML 中提取错误提示
        err_text = _extract_error_text(html_text) if html_text else None
        if err_text:
            return (f"AuthServer 登录失败: {err_text}", "unknown", CIRCUIT_NORMAL_DURATION)

        return ("AuthServer 登录失败: 未知错误", "unknown", CIRCUIT_NORMAL_DURATION)

    async def _do_login(self):
        """执行完整的金智 AuthServer 登录流程"""
        logger.info("event=login_start target=%s", TARGET_BASE)

        if self._client:
            try:
                await self._client.aclose()
            except Exception:
                pass

        self._client = await self._create_client()

        try:
            # Step 1: 获取登录页并提取表单参数
            service_url = (
                f"{TARGET_BASE}/.auth/login/cas/callback"
                f"?return_to={TARGET_BASE}/"
            )
            encoded_service = quote(service_url, safe="")
            login_url = f"{AUTH_SERVER}/authserver/login?service={encoded_service}"

            resp = await self._fetch_login_page(login_url)

            if resp.status_code in (301, 302, 307, 308):
                location = resp.headers.get("location", "")
                logger.info("检测到有效 TGC，跟随重定向完成会话建立")
                await self._handle_login_redirect(location)
                return

            execution, salt = _parse_login_form(resp.text)

            logger.info("解析表单参数成功：salt=%s**** execution=%s...", salt[:4], execution[:20])

            # Step 2: 加密密码
            encrypted_pwd = encrypt_password(PASSWORD, salt)

            # Step 3: 提交登录表单
            login_data = {
                "username": USERNAME,
                "password": encrypted_pwd,
                "captcha": "",
                "rememberMe": "false",
                "_eventId": "submit",
                "cllt": "userNameLogin",
                "lt": "",
                "execution": execution,
            }

            resp = await self._submit_login_form(login_url, login_data)

            # Step 4: 处理登录结果
            if resp.status_code in (301, 302, 307, 308):
                location = resp.headers.get("location", "")
                logger.info("登录表单提交成功，跟随重定向链：%s...", location[:80])
                await self._handle_login_redirect(location)
            else:
                msg, failure_type, circuit_dur = self._classify_login_failure(resp)
                if failure_type in ("account_locked", "captcha", "password_error", "rate_limited"):
                    raise CriticalLoginError(msg, circuit_dur)
                raise RuntimeError(msg)

        except CriticalLoginError:
            raise
        except Exception as e:
            logger.error("event=login_error error=%s", e)
            raise

    async def _follow_cas_redirect(self, location: str) -> tuple[str, Optional[httpx.Response]]:
        """跟随 CAS 重定向链。返回 (final_url, last_response)。"""
        max_redirects = MAX_LOGIN_REDIRECTS
        current_url = location
        last_resp = None
        for i in range(max_redirects):
            if not current_url:
                break
            logger.info("跟随重定向[%d/%d]：%s...", i + 1, max_redirects, current_url[:80])
            last_resp = await self._retry_request("GET", current_url, follow_redirects=False)
            if last_resp.status_code in (301, 302, 307, 308):
                current_url = last_resp.headers.get("location", "")
                if current_url and not current_url.startswith("http"):
                    current_url = urljoin(str(last_resp.url), current_url)
            else:
                logger.info("重定向链结束：url=%s status=%d", last_resp.url, last_resp.status_code)
                break
        return (str(last_resp.url) if last_resp else location, last_resp)

    async def _handle_login_redirect(self, location: str):
        """统一处理登录后的重定向链：跟随重定向 → 检测 2FA → 验证会话"""
        final_url, _last_resp = await self._follow_cas_redirect(location)

        # 检测二次验证跳转（TGC 复用和新登录都会触发）
        if self._RE_AUTH_VIEW.search(final_url):
            logger.info("event=2fa_detected url=%s", final_url[:80])
            parsed = urlparse(final_url)
            params = parse_qs(parsed.query)
            service_url = (
                params.get("service", [None])[0]
                or quote(f"{TARGET_BASE}/.auth/login/cas/callback?return_to={TARGET_BASE}/")
            )
            await self._complete_2fa(service_url)

        # 登录后验证：确保会话确实可用
        await self._validate_session()

        logger.info("认证完成，会话 Cookie 已就绪")

    async def _validate_session(self):
        """登录后快速验证会话是否有效。失败时抛出异常避免虚假 OK 状态。"""
        try:
            headers = {"Host": TARGET_HOST}
            if OPENWEBUI_API_KEY:
                headers["Authorization"] = f"Bearer {OPENWEBUI_API_KEY}"

            resp = await self._client.head(
                f"{TARGET_BASE}/api/config",
                headers=headers,
                follow_redirects=False,
            )

            if resp.status_code in (301, 302, 307):
                location = resp.headers.get("location", "")
                if _is_cas_login_url(location):
                    raise RuntimeError(
                        f"会话验证失败：登录后仍被重定向到 CAS 登录页 location={location[:80]}"
                    )
            logger.info("event=session_validated status=%d", resp.status_code)
        except _RETRIABLE_NET_ERRORS as e:
            logger.warning("event=session_validation_skipped reason=network_error error=%s", e)
        except httpx.HTTPStatusError as e:
            logger.warning("event=session_validation_http_error status=%d", e.response.status_code)
        except RuntimeError:
            raise

    # ---- 二次验证 (2FA / TOTP) ----

    _RE_AUTH_VIEW = re.compile(r"/authserver/reAuthCheck/reAuthLoginView\.do", re.I)

    async def _complete_2fa(self, service_url: str):
        """通过 TOTP 安全令牌完成二次验证。完成后跟随重定向链回到目标服务。"""
        logger.info("event=2fa_start service=%s", service_url[:60])

        # Step 1: 切换到安全令牌 (reAuthType=10)
        change_body = {
            "isMultifactor": "true",
            "reAuthType": "10",
            "service": service_url,
        }
        change_resp = await self._retry_request(
            "POST",
            f"{AUTH_SERVER}/authserver/reAuthCheck/changeReAuthType.do",
            data=change_body,
            headers={"Content-Type": "application/x-www-form-urlencoded;charset=utf-8"},
        )
        if change_resp.status_code != 200:
            raise RuntimeError(f"切换二次验证方式失败：HTTP {change_resp.status_code}")
        try:
            change_data = change_resp.json()
        except Exception:
            change_data = {}
        if change_data.get("code") != "1":
            raise RuntimeError(f"切换二次验证方式被拒绝：{change_data.get('message', change_resp.text[:200])}")
        logger.info("event=2fa_switch reAuthType=10 name=%s",
                    change_data.get("data", {}).get("reAuthTypeName", "?"))

        # Step 2: 生成 TOTP 码
        if not TOTP_SECRET:
            raise RuntimeError(
                "检测到二次验证要求，但未配置 TOTP_SECRET。"
                "请从认证器 APP 中获取 TOTP 密钥并填入 .env 文件"
            )
        # 兼容多种 secret 格式：纯 base32、otpauth:// URL、含空格的
        secret = TOTP_SECRET.strip()
        if secret.startswith("otpauth://"):
            # 从 otpauth URL 中提取 secret 参数
            _q = urlparse(secret).query
            _params = parse_qs(_q)
            secret = _params.get("secret", [secret])[0]
        # 移除可能混入的空格和换行
        secret = re.sub(r"\s+", "", secret)
        totp = pyotp.TOTP(secret)
        otp_code = totp.now()
        logger.info("event=2fa_totp_generated code=%s****", otp_code[:2])

        # Step 3: 提交二次验证
        submit_body = {
            "service": service_url,
            "reAuthType": "10",
            "isMultifactor": "true",
            "password": "",
            "dynamicCode": "",
            "uuid": "",
            "answer1": "",
            "answer2": "",
            "otpCode": otp_code,
            "skipTmpReAuth": "true",
        }
        submit_resp = await self._retry_request(
            "POST",
            f"{AUTH_SERVER}/authserver/reAuthCheck/reAuthSubmit.do",
            data=submit_body,
            headers={"Content-Type": "application/x-www-form-urlencoded;charset=utf-8"},
        )
        if submit_resp.status_code != 200:
            raise RuntimeError(f"二次验证提交失败：HTTP {submit_resp.status_code}")

        submit_data = {}
        try:
            submit_data = submit_resp.json()
        except Exception:
            pass

        if submit_data.get("code") != "reAuth_success":
            msg = submit_data.get("msg", submit_resp.text[:200])
            # 如果 TOTP 码被拒，等 2s 后用新码重试一次（处理时钟漂移/码过期）
            if self._consecutive_failures == 0 and ("code" in msg.lower() or "fail" in msg.lower() or "error" in msg.lower()):
                logger.warning("event=2fa_retry reason=TOTP码被拒，等2s后用新码重试 msg=%s", msg)
                await asyncio.sleep(2)
                new_code = pyotp.TOTP(secret).now()
                submit_body["otpCode"] = new_code
                logger.info("event=2fa_retry new_code=%s****", new_code[:2])
                retry_resp = await self._retry_request(
                    "POST",
                    f"{AUTH_SERVER}/authserver/reAuthCheck/reAuthSubmit.do",
                    data=submit_body,
                    headers={"Content-Type": "application/x-www-form-urlencoded;charset=utf-8"},
                )
                try:
                    retry_data = retry_resp.json()
                except Exception:
                    retry_data = {}
                if retry_data.get("code") == "reAuth_success":
                    logger.info("event=2fa_success_after_retry")
                    await self._follow_cas_redirect(service_url)
                    logger.info("event=2fa_complete")
                    return
                msg = retry_data.get("msg", retry_resp.text[:200])
            raise TwoFactorError(f"二次验证失败：{msg}")

        logger.info("event=2fa_success")

        # Step 4: 二次验证成功后跟随重定向
        # reAuthSubmit 成功后浏览器会通过 JS 跳转到 service URL，
        # 我们需要模拟：直接请求 service URL
        await self._follow_cas_redirect(service_url)
        logger.info("event=2fa_complete")

    # ---- 保活 ----

    async def check_and_refresh(self):
        """
        保活检查：轻量 HEAD 请求验证 Cookie 是否还有效。

        安全规则：
        - 网络异常 → 状态转 SUSPECT，不触发登录
        - 非 CAS 的 302/401/403 → 状态转 SUSPECT，不触发登录
        - 只有明确 CAS 重定向才转 EXPIRED
        - 熔断期间跳过检查
        """
        if not self._client or self._state == AuthState.CIRCUIT_OPEN:
            return

        try:
            headers = {"Host": TARGET_HOST}
            if OPENWEBUI_API_KEY:
                headers["Authorization"] = f"Bearer {OPENWEBUI_API_KEY}"

            resp = await self._client.head(
                f"{TARGET_BASE}/api/config",
                headers=headers,
                follow_redirects=False,
            )

            # 只对明确的 CAS 重定向触发登录
            if resp.status_code in (301, 302, 307):
                location = resp.headers.get("location", "")
                if _is_cas_login_url(location):
                    logger.warning("event=keepalive result=cas_redirect location=%s", location[:80])
                    self._transition(AuthState.EXPIRED, "keepalive:definitive_cas_redirect")
                    try:
                        await self.ensure_login()
                    except (CircuitOpenError, UpstreamUnavailableError):
                        pass
                    return

            # 其他非 2xx 响应：标记 SUSPECT
            if resp.status_code >= 400:
                logger.info("event=keepalive result=upstream_error status=%d", resp.status_code)
                self._transition(AuthState.SUSPECT, f"keepalive:upstream_status_{resp.status_code}")
            else:
                self._last_login_time = time.monotonic()
                if self._state == AuthState.SUSPECT:
                    self._transition(AuthState.OK, "keepalive:recovered")
                logger.debug("保活检查通过")

        except Exception as e:
            logger.warning("event=keepalive result=network_error error=%s", e)
            self._transition(AuthState.SUSPECT, "keepalive:network_error")

    async def start_keepalive(self):
        async def _keepalive_loop():
            while True:
                jitter = random.randint(-KEEPALIVE_JITTER_SECONDS, KEEPALIVE_JITTER_SECONDS)
                interval = KEEPALIVE_INTERVAL_SECONDS + jitter
                await asyncio.sleep(interval)
                try:
                    await self.check_and_refresh()
                except Exception as e:
                    logger.error("保活任务异常：%s", e)

        self._keepalive_task = asyncio.create_task(_keepalive_loop())
        logger.info("后台保活任务已启动（间隔：~5 分钟，含 ±30s 抖动）")

    async def stop_keepalive(self):
        if self._keepalive_task:
            self._keepalive_task.cancel()
            try:
                await self._keepalive_task
            except asyncio.CancelledError:
                pass

    async def close(self):
        await self.stop_keepalive()
        if self._client:
            try:
                await asyncio.wait_for(self._client.aclose(), timeout=2.0)
            except asyncio.TimeoutError:
                pass


# ---- 全局会话管理器 ----

session_mgr = AuthSessionManager()


# ============================================================
# 认证检测（严格版）
# ============================================================


def _is_cas_login_url(url: str) -> bool:
    """
    严格检查 URL 是否是 CAS 登录重定向。
    支持两种场景：
    (a) 直接重定向到 authserver.nwafu.edu.cn/authserver/login
    (b) Open WebUI 内部 auth 重定向 /.auth/login/cas（说明 session 已失效）
    """
    if not url:
        return False
    try:
        parsed = urlparse(url)
    except Exception:
        return False
    # 直接 CAS 登录页重定向
    if parsed.hostname == "authserver.nwafu.edu.cn" and parsed.path.startswith("/authserver/login"):
        return True
    # Open WebUI 内部 auth 重定向 — session 失效，Open WebUI 正尝试发起 CAS 流程
    if parsed.path.startswith("/.auth/login/cas"):
        return True
    return False


def _is_cas_login_redirect(resp: httpx.Response) -> bool:
    """检查响应是否是 CAS 登录页重定向（精确匹配 host）"""
    if resp.status_code not in (301, 302, 307):
        return False
    location = resp.headers.get("location", "")
    return _is_cas_login_url(location)


async def _is_cas_login_html(resp: httpx.Response) -> bool:
    """
    检查 401/403 HTML 响应是否真的是 CAS 登录页。
    必须满足：(a) Content-Type 为 text/html (b) body 前 4KB 包含 execution 和 pwdEncryptSalt 字段。
    """
    if resp.status_code not in (401, 403):
        return False
    content_type = resp.headers.get("content-type", "")
    if "text/html" not in content_type:
        return False
    try:
        body_sample = await resp.aread()
        # 将读取的 body 暂存以便调用方重建响应
        resp._sampled_body = body_sample  # type: ignore[attr-defined]
        return _sample_contains_cas_fields(body_sample)
    except Exception:
        return False


async def _check_auth_failure(resp: httpx.Response, is_streaming: bool) -> bool:
    """
    综合判断上游响应是否表明 CAS 会话已失效。

    对非流式响应：先检查重定向 URL，再检查 HTML body。
    对流式响应：只检查重定向 URL（不读取 body）。
    """
    # 检查 302 重定向 URL
    if _is_cas_login_redirect(resp):
        logger.info("event=auth_detection result=definitive_cas state=redirect url=%s",
                     resp.headers.get("location", "")[:80])
        return True

    # 对流式接口不读取 body
    if is_streaming:
        return False

    # 检查 HTML body 是否包含 CAS 登录表单
    if await _is_cas_login_html(resp):
        logger.info("event=auth_detection result=definitive_cas state=html_body")
        return True

    return False


# ============================================================
# 透明反向代理 —— 核心引擎
# ============================================================


HOP_BY_HOP_HEADERS = frozenset({
    "host", "connection", "keep-alive", "transfer-encoding",
    "te", "trailer", "upgrade", "proxy-authorization",
    "proxy-authenticate", "content-length",
    "authorization", "accept-encoding",
    # 客户端 Cookie 属于本地代理域名，不能覆盖服务端维护的上游 CAS Cookie。
    "cookie",
})

STRIP_RESPONSE_HEADERS = frozenset({
    "content-length", "transfer-encoding", "content-encoding",
    # 上游安全策略不应直接应用到本地代理域名。
    "strict-transport-security",
    "content-security-policy", "content-security-policy-report-only",
})

REWRITE_REQUEST_HEADERS = frozenset({
    "origin", "referer",
})

REWRITE_RESPONSE_HEADERS = frozenset({
    "location",
})

_AUTH_EXPIRED = object()


async def _read_request_body(request: Request) -> tuple[bytes, bool]:
    body = await request.body()
    is_stream = False
    if body:
        try:
            body_json = json.loads(body)
            is_stream = bool(body_json.get("stream", False))
        except (json.JSONDecodeError, UnicodeDecodeError, TypeError):
            pass
    return body, is_stream


def _build_target_url(request: Request, target_path: str) -> str:
    target_url = f"{TARGET_BASE}{target_path}"
    if request.url.query:
        target_url += f"?{request.url.query}"
    return target_url


def _needs_api_key(path: str) -> bool:
    return (
        path.startswith("/v1/")
        or path.startswith("/openai/")
        or path.startswith("/ollama/")
    )


def _build_forward_headers(request: Request, target_path: str) -> dict[str, str]:
    headers = {}
    for k, v in request.headers.items():
        kl = k.lower()
        if kl in HOP_BY_HOP_HEADERS:
            continue
        if kl in REWRITE_REQUEST_HEADERS and TARGET_BASE:
            # 将客户端 Origin/Referer 替换为上游地址
            headers[k] = TARGET_BASE
        else:
            headers[k] = v
    headers["Host"] = TARGET_HOST
    # 浏览器内的 OpenWebUI /api/* 请求依赖 CAS session cookie 和同一条
    # Socket.IO 会话接收异步任务结果。强行注入 API key 可能让任务归属到
    # token auth 上，而页面的 websocket 仍归属 cookie session，导致 WebUI
    # 只拿到 task_id 但迟迟收不到回复。
    if OPENWEBUI_API_KEY and _needs_api_key(target_path):
        headers["Authorization"] = f"Bearer {OPENWEBUI_API_KEY}"
    return headers


def _strip_response_headers(headers: httpx.Headers) -> dict[str, str]:
    return {k: v for k, v in headers.items() if k.lower() not in STRIP_RESPONSE_HEADERS}


def _rewrite_response_header_value(name: str, value: str) -> str:
    """将上游域名替换为本地位址（用于 Location 等头）"""
    if name.lower() in REWRITE_RESPONSE_HEADERS and TARGET_BASE in value:
        local_base = f"http://localhost:{PROXY_PORT}"
        return value.replace(TARGET_BASE, local_base)
    return value


def _should_rewrite_body(content_type: str, is_stream: bool) -> bool:
    if is_stream:
        return False
    content_type = content_type.lower()
    return any(
        marker in content_type
        for marker in (
            "text/html",
            "text/css",
            "application/json",
            "application/manifest+json",
            "text/javascript",
            "application/javascript",
        )
    )


async def _rewrite_response_body(resp: httpx.Response, content_type: str, is_stream: bool) -> bytes | None:
    if not _should_rewrite_body(content_type, is_stream=is_stream):
        return None
    content_length = resp.headers.get("content-length")
    if content_length:
        try:
            if int(content_length) > RESPONSE_REWRITE_MAX_BYTES:
                return None
        except ValueError:
            return None
    try:
        body = await resp.aread()
    except httpx.HTTPError:
        return None
    if len(body) > RESPONSE_REWRITE_MAX_BYTES:
        return body

    local_base = f"http://localhost:{PROXY_PORT}"
    local_https_base = f"https://localhost:{PROXY_PORT}"
    target_origin = f"https://{TARGET_HOST}"
    rewritten = body.replace(TARGET_BASE.encode("utf-8"), local_base.encode("utf-8"))
    rewritten = rewritten.replace(target_origin.encode("utf-8"), local_base.encode("utf-8"))
    rewritten = rewritten.replace(local_https_base.encode("utf-8"), local_base.encode("utf-8"))
    return rewritten


async def _forward(
    client: httpx.AsyncClient,
    *,
    method: str,
    url: str,
    headers: dict[str, str],
    body: bytes,
    is_stream: bool,
    long_timeout: bool,
    force_timeout: Optional[httpx.Timeout] = None,
) -> Response | object:
    if force_timeout is not None:
        timeout = force_timeout
    elif is_stream or long_timeout:
        timeout = STREAM_TIMEOUT
    else:
        timeout = DEFAULT_TIMEOUT

    req = client.build_request(
        method=method,
        url=url,
        headers=headers,
        content=body,
        timeout=timeout,
    )
    resp = await client.send(req, stream=True, follow_redirects=False)

    # 认证检测（不破坏流式响应）
    if await _check_auth_failure(resp, is_stream):
        await resp.aclose()
        return _AUTH_EXPIRED

    resp_headers = _strip_response_headers(resp.headers)
    # 重写 Location 等响应头
    resp_headers = {
        k: _rewrite_response_header_value(k, v)
        for k, v in resp_headers.items()
    }
    media_type = resp.headers.get("content-type", "text/event-stream" if is_stream else None)
    response_is_sse = "text/event-stream" in (media_type or "").lower()
    if response_is_sse or long_timeout:
        resp_headers.setdefault("Cache-Control", "no-cache")
        resp_headers.setdefault("X-Accel-Buffering", "no")
    logger.info(
        "event=upstream_headers status=%d content_type=%s request_stream=%s long_timeout=%s",
        resp.status_code,
        media_type or "",
        "true" if is_stream else "false",
        "true" if long_timeout else "false",
    )

    # 模型/生成类端点必须尽快把上游字节交给客户端。即使不是标准
    # text/event-stream，也不能为了 URL 重写而先读完整响应，否则前端/API
    # 会表现为长时间没有任何内容返回。
    should_buffer_for_rewrite = not long_timeout or (
        long_timeout and not response_is_sse and "application/json" in (media_type or "").lower()
    )
    rewritten_body = None
    if should_buffer_for_rewrite:
        rewritten_body = await _rewrite_response_body(resp, media_type or "", response_is_sse)
        if long_timeout and not response_is_sse and rewritten_body is not None:
            preview = rewritten_body[:500].decode("utf-8", errors="replace").replace("\n", "\\n")
            logger.warning(
                "event=model_non_sse_response status=%d content_type=%s body_preview=%s",
                resp.status_code,
                media_type or "",
                preview,
            )
    if rewritten_body is not None:
        await resp.aclose()
        return Response(
            content=rewritten_body,
            status_code=resp.status_code,
            headers=resp_headers,
            media_type=media_type,
        )

    # 如果 CAS 检测读取过 body，httpx 响应流已经被消费，直接返回采样内容。
    sampled_body = getattr(resp, "_sampled_body", None)
    if sampled_body is not None:
        await resp.aclose()
        return Response(
            content=sampled_body,
            status_code=resp.status_code,
            headers=resp_headers,
            media_type=media_type,
        )

    async def stream_generator():
        try:
            async for chunk in resp.aiter_bytes():
                yield chunk
        except (httpx.ReadError, httpx.RemoteProtocolError, httpx.TransportError) as e:
            if is_stream:
                logger.error("流式响应中断：%s", e)
                error_payload = json.dumps({"error": "upstream connection lost"}, ensure_ascii=False)
                yield f"data: {error_payload}\n\n".encode("utf-8")
        finally:
            await resp.aclose()

    return StreamingResponse(
        stream_generator(),
        status_code=resp.status_code,
        headers=resp_headers,
        media_type=media_type,
    )


async def _proxy_request(request: Request, target_path: str) -> Response:
    t0 = time.monotonic()
    body, is_stream = await _read_request_body(request)

    # 对话/生成类端点可能很慢，但不一定是 SSE。是否流式只由请求体
    # stream=true 或上游 Content-Type 决定，避免把普通 JSON 响应误当成流。
    long_timeout = _needs_long_timeout(target_path)

    # 上游降级模式：最近多个请求失败时使用短超时，避免客户端长时间等待
    degraded = session_mgr.is_degraded()

    for attempt in range(PROXY_MAX_RETRIES):
        try:
            client = await session_mgr.ensure_login()
        except CircuitOpenError as e:
            logger.warning("event=proxy_blocked reason=circuit_open path=%s", target_path)
            return _circuit_error_response(e.retry_after)
        except UpstreamUnavailableError as e:
            logger.warning("event=proxy_blocked reason=upstream_unavailable path=%s error=%s", target_path, e)
            return _error_response(503, str(e), error_type="upstream_unavailable")
        except _RETRIABLE_NET_ERRORS as e:
            logger.warning("登录阶段网络异常：%s", e)
            return _error_response(503, "上游暂时不可达，请稍后重试", error_type="upstream_unreachable")
        except Exception as e:
            logger.error("登录失败：%s", e)
            return _error_response(503, "登录失败，请稍后重试", error_type="login_failed")

        target_url = _build_target_url(request, target_path)
        headers = _build_forward_headers(request, target_path)

        # 降级模式下使用短超时，避免客户端长时间挂起
        req_timeout = DEGRADED_TIMEOUT if degraded else None

        try:
            result = await _forward(
                client,
                method=request.method,
                url=target_url,
                headers=headers,
                body=body,
                is_stream=is_stream,
                long_timeout=long_timeout,
                force_timeout=req_timeout,
            )

            if result is _AUTH_EXPIRED:
                # 登录后立即被认证中间件拒绝时，抑制连续重登以保护账号。
                if session_mgr.recent_login_rejected():
                    logger.warning(
                        "event=auth_session_not_accepted path=%s action=suppress_relogin",
                        target_path,
                    )
                    return _error_response(502, "上游认证会话未被接受", error_type="upstream_auth_session_rejected")

                if attempt < PROXY_MAX_RETRIES - 1:
                    logger.warning("event=proxy_auth_expired path=%s attempt=%d", target_path, attempt + 1)
                    try:
                        await session_mgr.force_relogin()
                    except (CircuitOpenError, UpstreamUnavailableError):
                        pass
                    await asyncio.sleep(1)
                    continue
                return _error_response(401, "认证失败, 请检查账号密码", error_type="auth_failed")

            elapsed = int((time.monotonic() - t0) * 1000)
            status_code = getattr(result, "status_code", 0)
            # 上游返回 5xx：清除降级（说明上游可达，只是内部错误）
            if status_code >= 500:
                if degraded:
                    session_mgr._recent_proxy_failures.clear()
                if session_mgr._login_then_rejected:
                    session_mgr._login_then_rejected = False
                logger.warning(
                    "event=upstream_error method=%s path=%s status=%d ms=%d",
                    request.method, target_path, status_code, elapsed,
                )
            else:
                # 2xx/3xx/4xx：上游正常，清除降级状态
                if degraded:
                    session_mgr._recent_proxy_failures.clear()
                if session_mgr._login_then_rejected:
                    session_mgr._login_then_rejected = False
                    logger.info("event=upstream_recovered — 上游恢复正常")
                if session_mgr.state == AuthState.SUSPECT:
                    session_mgr._transition(AuthState.OK, "proxy:recovered")
            logger.info(
                "event=proxy_response method=%s path=%s status=%s stream=%s ms=%d",
                request.method,
                target_path,
                status_code,
                "true" if is_stream else "false",
                elapsed,
            )
            return result

        except httpx.TimeoutException:
            elapsed = int((time.monotonic() - t0) * 1000)
            session_mgr._record_proxy_failure()
            session_mgr._transition(AuthState.SUSPECT, "proxy:upstream_timeout")
            if degraded:
                logger.warning("上游请求超时（降级模式，ms=%d, url=%s）", elapsed, target_url[:100])
            else:
                logger.error("上游请求超时（ms=%d, url=%s）", elapsed, target_url[:100])
            if attempt < PROXY_MAX_RETRIES - 1:
                await asyncio.sleep(1)
                degraded = True  # 重试时强制降级
                continue
            return _error_response(504, "上游请求超时", error_type="upstream_timeout")

        except _RETRIABLE_NET_ERRORS as e:
            elapsed = int((time.monotonic() - t0) * 1000)
            session_mgr._record_proxy_failure()
            session_mgr._transition(AuthState.SUSPECT, "proxy:network_error")
            logger.warning("上游网络异常：%s（ms=%d, url=%s）", e, elapsed, target_url[:100])
            if attempt < PROXY_MAX_RETRIES - 1:
                await asyncio.sleep(0.5 * (2 ** attempt))
                degraded = True  # 重试时强制降级
                continue
            return _error_response(503, "上游暂时不可达，请稍后重试", error_type="upstream_unreachable")

        except Exception:
            elapsed = int((time.monotonic() - t0) * 1000)
            logger.exception("代理异常（ms=%d）", elapsed)
            return _error_response(502, "代理异常", error_type="proxy_error")

    return _error_response(502, "代理请求失败", error_type="proxy_exhausted")


def _error_response(status_code: int, message: str, *, error_type: str | None = None) -> Response:
    body: dict = {"error": message}
    if error_type:
        body["type"] = error_type
    return Response(content=json.dumps(body, ensure_ascii=False), status_code=status_code, media_type="application/json")


def _circuit_error_response(retry_after: int) -> Response:
    body = json.dumps({
        "error": "auth_circuit_open",
        "message": "Login temporarily disabled to protect the campus account. Please retry later.",
    }, ensure_ascii=False)
    return Response(
        content=body,
        status_code=503,
        media_type="application/json",
        headers={"Retry-After": str(retry_after)},
    )


# ============================================================
# WebSocket 代理
# ============================================================


def _get_cookie_header(client: httpx.AsyncClient, target_url: str) -> str:
    """从 httpx client 的 cookie jar 中提取目标域名的 Cookie 头"""
    try:
        parsed = urlparse(target_url)
        if not parsed.hostname:
            return ""
        # httpx cookies 使用标准 http.cookiejar
        jar = client.cookies.jar
        cookies_for_domain = []
        for cookie in jar:
            domain = cookie.domain.lstrip(".")
            if parsed.hostname == domain or parsed.hostname.endswith(f".{domain}"):
                cookies_for_domain.append(f"{cookie.name}={cookie.value}")
        return "; ".join(cookies_for_domain)
    except Exception:
        return ""


async def _proxy_websocket(client_ws: WebSocket, target_path: str):
    """双向代理 WebSocket 连接"""
    t0 = time.monotonic()
    await client_ws.accept()

    try:
        http_client = await session_mgr.ensure_login()
    except CircuitOpenError as e:
        await client_ws.close(code=1013, reason="Auth circuit open")
        return
    except Exception as e:
        logger.warning("WebSocket 登录失败：%s", e)
        await client_ws.close(code=1013, reason="Login failed")
        return

    # 构建上游 WebSocket URL
    ws_scheme = "wss"
    target_url = f"{ws_scheme}://{TARGET_HOST}{target_path}"
    if client_ws.url.query:
        target_url += f"?{client_ws.url.query}"

    # 准备上游请求头。Host / Origin / User-Agent 属于 WebSocket 握手头，
    # 交给 websockets 通过专用参数生成，避免重复头导致上游返回 400。
    extra_headers = {}

    cookie_str = _get_cookie_header(http_client, target_url)
    if cookie_str:
        extra_headers["Cookie"] = cookie_str
        logger.info("event=ws_cookie_present len=%d", len(cookie_str))
    else:
        logger.warning("event=ws_no_cookie url=%s", target_url)

    # 转发客户端非逐跳头
    _ws_skip_headers = {
        "host", "connection", "upgrade", "sec-websocket-key",
        "sec-websocket-version", "sec-websocket-extensions",
        "sec-websocket-protocol", "origin", "user-agent",
        "authorization", "cookie", "content-length",
    }
    for name, value in client_ws.headers.items():
        if name.lower() not in _ws_skip_headers and name not in extra_headers:
            extra_headers[name] = value

    subprotocol_header = client_ws.headers.get("sec-websocket-protocol", "")
    subprotocols = [p.strip() for p in subprotocol_header.split(",") if p.strip()] or None

    logger.info(
        "event=ws_proxy_connect path=%s headers=%s",
        target_path,
        list(extra_headers.keys()),
    )

    try:
        async with websocket_connect(
            target_url,
            origin=TARGET_BASE,
            additional_headers=extra_headers,
            subprotocols=subprotocols,
            user_agent_header="Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36",
            proxy=None,
            close_timeout=3,
            ping_interval=None,  # 让上游管理 ping
        ) as upstream_ws:

            async def client_to_upstream():
                try:
                    while True:
                        data = await client_ws.receive()
                        if data["type"] == "websocket.receive":
                            if "text" in data:
                                logger.debug("event=ws_frame direction=client_to_upstream type=text len=%d", len(data["text"]))
                                await upstream_ws.send(data["text"])
                            elif "bytes" in data:
                                logger.debug("event=ws_frame direction=client_to_upstream type=bytes len=%d", len(data["bytes"]))
                                await upstream_ws.send(data["bytes"])
                        elif data["type"] == "websocket.disconnect":
                            break
                except asyncio.CancelledError:
                    raise
                except WebSocketDisconnect:
                    pass
                except websockets.exceptions.ConnectionClosed:
                    pass
                except Exception as e:
                    logger.debug("WS client→upstream 关闭：%s", e)

            async def upstream_to_client():
                try:
                    async for message in upstream_ws:
                        if isinstance(message, str):
                            logger.debug("event=ws_frame direction=upstream_to_client type=text len=%d", len(message))
                            await client_ws.send_text(message)
                        elif isinstance(message, bytes):
                            logger.debug("event=ws_frame direction=upstream_to_client type=bytes len=%d", len(message))
                            await client_ws.send_bytes(message)
                except asyncio.CancelledError:
                    raise
                except websockets.exceptions.ConnectionClosed:
                    pass
                except WebSocketDisconnect:
                    pass
                except Exception as e:
                    logger.debug("WS upstream→client 关闭：%s", e)

            tasks = [
                asyncio.create_task(client_to_upstream()),
                asyncio.create_task(upstream_to_client()),
            ]
            try:
                done, pending = await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)
                for task in pending:
                    task.cancel()
                await asyncio.gather(*pending, return_exceptions=True)
                for task in done:
                    exc = task.exception()
                    if exc is not None:
                        raise exc
            finally:
                for task in tasks:
                    if not task.done():
                        task.cancel()
                await asyncio.gather(*tasks, return_exceptions=True)

    except asyncio.CancelledError:
        logger.debug("event=ws_proxy_cancelled path=%s", target_path)
    except websockets.exceptions.InvalidStatus as e:
        logger.warning("WS 上游拒绝（status=%d）：%s", e.response.status_code, target_path[:80])
        await client_ws.close(code=1013, reason="Upstream rejected WebSocket")
    except Exception as e:
        logger.warning("WebSocket 代理异常：%s（path=%s）", e, target_path[:80])
        try:
            await client_ws.close(code=1011, reason="Proxy error")
        except Exception:
            pass

    elapsed = int((time.monotonic() - t0) * 1000)
    logger.info("event=ws_proxy_close path=%s ms=%d", target_path, elapsed)


# ============================================================
# FastAPI 应用
# ============================================================


def create_app(_settings: Settings, manager: AuthSessionManager) -> FastAPI:
    @asynccontextmanager
    async def _lifespan(_app: FastAPI):
        logger.info("服务启动：target=%s user=%s", TARGET_BASE, USERNAME)

        try:
            # 启动登录不受频率限制（服务重启是有意操作，不是登录风暴）
            manager._login_attempt_times.clear()
            manager._save_persisted_state()
            await manager.ensure_login()
            logger.info("初始登录成功")
        except Exception as e:
            logger.error("初始登录失败：%s（服务将继续启动；后续请求会触发重试）", e)

        await manager.start_keepalive()

        # 模型监控（可选）
        monitor = None
        if _settings.monitor_enabled:
            try:
                from utils.model_monitor import create_monitor, register_monitor_routes
                monitor = create_monitor(_settings, lambda: manager.state == AuthState.OK)
                register_monitor_routes(_app, monitor)
                await monitor.start()
                logger.info("模型监控已启用（间隔 %ds）", _settings.monitor_poll_interval)
            except Exception as e:
                logger.error("模型监控启动失败：%s", e)

        yield

        logger.info("服务关闭中")
        if monitor:
            await monitor.stop()
        await manager.close()

    _app = FastAPI(
        title="NWAFU DeepSeek Proxy",
        description="本地透明代理网关, 自动处理校园认证, 无差别转发所有请求",
        lifespan=_lifespan,
    )

    @_app.middleware("http")
    async def request_id_middleware(request: Request, call_next):
        rid = secrets.token_hex(4)
        token = request_id_ctx.set(rid)
        t0 = time.monotonic()
        response: Optional[Response] = None
        try:
            response = await call_next(request)
            return response
        except Exception:
            logger.exception("event=http_error method=%s path=%s", request.method, request.url.path)
            raise
        finally:
            request_id_ctx.reset(token)
            if response is not None:
                response.headers["X-Request-ID"] = rid
                elapsed_ms = int((time.monotonic() - t0) * 1000)
                logger.info(
                    "event=http method=%s path=%s status=%d ms=%d",
                    request.method,
                    request.url.path,
                    response.status_code,
                    elapsed_ms,
                )

    _app.add_middleware(
        CORSMiddleware,
        allow_origins=_settings.cors_origins,
        allow_credentials=False,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    @_app.get("/health")
    async def health(response: Response):
        """健康检查：报告认证状态、上游可达性和会话有效性。

        不会触发登录，仅使用已有 client 做轻量验证。
        """
        now = time.time()
        now_mono = time.monotonic()

        state = manager.state
        state_value = state.value

        # 基础信息
        result = {
            "service": "NWAFU DeepSeek Proxy",
            "target": TARGET_BASE,
            "api_base": f"http://localhost:{PROXY_PORT}/v1",
            "auth_state": state_value,
        }

        # 熔断信息
        if state == AuthState.CIRCUIT_OPEN:
            remaining = int(max(0, manager._circuit_until - now_mono))
            result["status"] = "degraded"
            result["circuit_remaining_seconds"] = remaining
            result["note"] = "登录已熔断，请稍后重试"
            response.headers["Retry-After"] = str(remaining)
            response.status_code = 503
            return result

        # 退避信息
        if state == AuthState.LOGIN_BACKOFF:
            remaining = int(max(0, manager._backoff_until - now_mono))
            result["status"] = "degraded"
            result["backoff_remaining_seconds"] = remaining
            result["note"] = "登录退避中"
            response.headers["Retry-After"] = str(remaining)
            return result

        # 统计信息
        last_ok_ago = int(now_mono - manager._last_login_ok_time) if manager._last_login_ok_time > 0 else -1
        last_attempt_ago = int(now_mono - manager._last_login_attempt_time) if manager._last_login_attempt_time > 0 else -1
        result["last_login_ok_seconds_ago"] = last_ok_ago
        result["consecutive_failures"] = manager._consecutive_failures

        recent_failures = [t for t in manager._login_attempt_times if t > now - LOGIN_WINDOW_SECONDS]
        result["login_attempts_last_hour"] = len(recent_failures)

        # 会话验证：若状态 OK 且有 client，做一次实际探测
        client = manager._client
        if state == AuthState.OK and client is not None:
            t0 = time.monotonic()
            try:
                headers = {"Host": TARGET_HOST}
                if OPENWEBUI_API_KEY:
                    headers["Authorization"] = f"Bearer {OPENWEBUI_API_KEY}"

                probe = await client.head(
                    f"{TARGET_BASE}/api/config",
                    headers=headers,
                    follow_redirects=False,
                )
                latency_ms = int((time.monotonic() - t0) * 1000)

                if probe.status_code in (301, 302, 307):
                    location = probe.headers.get("location", "")
                    if _is_cas_login_url(location):
                        result["status"] = "unhealthy"
                        result["note"] = "会话已过期，需要重新登录"
                        result["latency_ms"] = latency_ms
                        response.status_code = 503
                        return result

                result["status"] = "healthy"
                result["upstream_status"] = probe.status_code
                result["latency_ms"] = latency_ms
                result["note"] = "代理运行正常，会话有效"
                return result
            except Exception as e:
                result["status"] = "degraded"
                result["note"] = f"上游探测失败: {type(e).__name__}"
                result["latency_ms"] = int((time.monotonic() - t0) * 1000)
                return result

        if state == AuthState.SUSPECT:
            result["status"] = "degraded"
            result["note"] = "认证状态异常，正在等待恢复"
            return result

        if state == AuthState.EXPIRED:
            result["status"] = "degraded"
            result["note"] = "会话已过期，需要重新登录"
            return result

        result["status"] = "ok"
        result["note"] = "代理已启动，会话尚未建立"
        return result

    return _app


app = create_app(settings, session_mgr)


# ============================================================
# 注册代理路由
# ============================================================


_PROXY_METHODS = ["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS", "HEAD"]

# 特定前缀路由（先注册，优先匹配）
_PROXY_PREFIXES = ("v1", "api", "ollama", "openai")


def _register_proxy_routes(app: FastAPI) -> None:
    # HTTP 路由
    for prefix in _PROXY_PREFIXES:
        @app.api_route(f"/{prefix}/{{path:path}}", methods=_PROXY_METHODS)
        async def _handler(request: Request, path: str, _prefix: str = prefix):
            return await _proxy_request(request, f"/{_prefix}/{path}")

    @app.api_route("/", methods=_PROXY_METHODS)
    async def _root_handler(request: Request):
        return await _proxy_request(request, "/")

    @app.api_route("/{path:path}", methods=_PROXY_METHODS)
    async def _catchall_handler(request: Request, path: str):
        return await _proxy_request(request, f"/{path}")

    # WebSocket 路由（与 HTTP 路径共存，FastAPI 根据 Upgrade 头区分）
    for prefix in _PROXY_PREFIXES:
        @app.websocket(f"/{prefix}/{{path:path}}")
        async def _ws_handler(ws: WebSocket, path: str, _prefix: str = prefix):
            await _proxy_websocket(ws, f"/{_prefix}/{path}")

    @app.websocket("/{path:path}")
    async def _ws_catchall_handler(ws: WebSocket, path: str):
        await _proxy_websocket(ws, f"/{path}")


_register_proxy_routes(app)


# ============================================================
# 入口
# ============================================================

if __name__ == "__main__":
    api_key_hint = "已配置" if OPENWEBUI_API_KEY else "未配置"
    monitor_hint = "已启用" if settings.monitor_enabled else "未启用"
    logger.info(
        "\n  NWAFU DeepSeek Proxy (transparent reverse proxy)\n"
        "  ------------------------------------------------\n"
        "  Listen:     http://localhost:%s\n"
        "  Upstream:   %s\n"
        "  AuthServer: %s\n"
        "  User:       %s\n"
        "  WebUI Key:  %s\n"
        "  Monitor:    %s\n\n"
        "  Note:\n"
        "    - 代理透明转发所有请求到源站\n"
        "    - 客户端 API Key 可使用占位值（代理会注入真实 Open WebUI Key）\n"
        "    - 访问 http://localhost:%s 直接使用 Open WebUI\n",
        PROXY_PORT,
        TARGET_BASE,
        AUTH_SERVER,
        USERNAME,
        api_key_hint,
        monitor_hint,
        PROXY_PORT,
    )

    uvicorn.run(
        app,
        host="0.0.0.0",
        port=PROXY_PORT,
        log_level="info",
        access_log=False,
        log_config=None,
        timeout_graceful_shutdown=2,
    )
