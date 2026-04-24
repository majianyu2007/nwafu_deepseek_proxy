"""
nwafu_deepseek_proxy - 校园统一认证 Open WebUI 透明反向代理

自动处理金智教育 (Wisedu) AuthServer CAS 认证流程,
在本地暴露与源站完全一致的 API 端点, 供第三方客户端直接调用。
所有 /v1/* 请求无差别透传到源站, 代理仅负责会话维护与请求头注入。

详见 README.md
"""

import asyncio
import base64
import json
import logging
import os
import re
import secrets
import sys
import time
from contextlib import asynccontextmanager
from contextvars import ContextVar
from dataclasses import dataclass
from typing import Optional
from urllib.parse import urljoin, quote

import httpx
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from fastapi import FastAPI, Request, Response
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import HTMLResponse, StreamingResponse
import uvicorn

# ============================================================
# 配置与日志
# ============================================================

def _load_dotenv(path: str = ".env") -> None:
    """极简 dotenv（兼容 export 前缀与引号包裹）。"""
    try:
        with open(path, "r", encoding="utf-8") as f:
            for raw in f:
                line = raw.strip()
                if not line or line.startswith("#"):
                    continue
                if line.startswith("export "):
                    line = line[len("export "):].lstrip()
                if "=" not in line:
                    continue
                key, _, value = line.partition("=")
                key = key.strip()
                value = value.strip()
                if len(value) >= 2 and value[0] == value[-1] and value[0] in ("'", '"'):
                    value = value[1:-1]
                os.environ.setdefault(key, value)
    except FileNotFoundError:
        return


_load_dotenv()

request_id_ctx: ContextVar[str] = ContextVar("request_id", default="-")


class _RequestIDFilter(logging.Filter):
    def filter(self, record: logging.LogRecord) -> bool:  # noqa: A003 - logging 约定
        record.request_id = request_id_ctx.get()
        return True


logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] [%(request_id)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger("proxy")

_request_id_filter = _RequestIDFilter()
# 给 handler 加 Filter，确保包括 httpx/uvicorn 等所有日志都有 request_id 字段
_root_logger = logging.getLogger()
for _h in _root_logger.handlers:
    _h.addFilter(_request_id_filter)

# 统一 uvicorn 的日志风格：清空其默认 handler，交由 root formatter 输出
for _name in ("uvicorn", "uvicorn.error", "uvicorn.access"):
    _l = logging.getLogger(_name)
    _l.handlers.clear()
    _l.propagate = True

COOKIE_TTL_SECONDS = 25 * 60
LOGIN_COOLDOWN_SECONDS = 5.0
KEEPALIVE_INTERVAL_SECONDS = 5 * 60
MAX_LOGIN_REDIRECTS = 10
PROXY_MAX_RETRIES = 2
NETWORK_RETRY_ATTEMPTS = 3

STREAM_TIMEOUT = httpx.Timeout(300.0, connect=15.0)
DEFAULT_TIMEOUT = httpx.Timeout(60.0, connect=15.0)

_RETRIABLE_NET_ERRORS = (
    httpx.ConnectError,
    httpx.NetworkError,
    httpx.ReadError,
    httpx.RemoteProtocolError,
)

_LOGIN_ERROR_MESSAGES = {
    "FAIL_UPNOTMATCH": "密码错误或账户不存在",
    "CAPTCHA_NOTMATCH": "需要输入验证码 (账号可能被临时锁定, 请稍后再试)",
    "LOCK": "账户已被锁定",
}


_RE_INPUT_BY_ID = lambda name: re.compile(  # noqa: E731 - 保持局部工具形态
    rf'<input\b[^>]*\bid=["\']{re.escape(name)}["\'][^>]*>', re.I
)
_RE_VALUE_ATTR = re.compile(r'\bvalue=["\']([^"\']*)["\']', re.I)
_RE_ERROR_TIP = re.compile(
    r'id=["\']formErrorTip["\'][^>]*>.*?<span[^>]*>([^<]+)</span>',
    re.S | re.I,
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


@dataclass(frozen=True)
class Settings:
    username: str
    password: str
    proxy_port: int
    target_host: str
    openwebui_api_key: str
    auth_server: str
    cors_origins: list[str]

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
    )


settings = load_settings()

USERNAME = settings.username
PASSWORD = settings.password
PROXY_PORT = settings.proxy_port
TARGET_HOST = settings.target_host
OPENWEBUI_API_KEY = settings.openwebui_api_key
AUTH_SERVER = settings.auth_server

TARGET_BASE = settings.target_base


# ============================================================
# 金智 AuthServer AES 加密（对齐前端 encrypt.js）
# ============================================================

AES_CHARS = "ABCDEFGHJKMNPQRSTWXYZabcdefhijkmnprstwxyz2345678"


def _random_string(length: int) -> str:
    # 这里虽然主要用于前缀与 IV，但仍使用 secrets 生成更稳妥
    return "".join(secrets.choice(AES_CHARS) for _ in range(length))


def encrypt_password(password: str, salt: str) -> str:
    """
    对齐 encrypt.js 中 encryptAES / getAesString：
    - 明文：randomString(64) + password
    - key：salt（UTF-8）
    - iv：randomString(16)
    - AES-CBC + PKCS7 padding，输出 Base64
    """
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
# AuthServer 会话管理器
# ============================================================


class UpstreamUnavailableError(Exception):
    """上游暂不可用（用于登录冷却/抖动期间的降级响应）"""


class AuthSessionManager:
    """
    管理与 AuthServer 及目标站之间的完整会话生命周期:
    - 自动登录 / Cookie 持久化
    - 定期保活 / 过期主动刷新
    - asyncio.Lock 保证并发安全
    """

    def __init__(self):
        self._client: Optional[httpx.AsyncClient] = None
        self._lock = asyncio.Lock()
        self._last_login_time: float = 0
        self._login_ok: bool = False
        self._cookie_ttl: float = float(COOKIE_TTL_SECONDS)
        self._keepalive_task: Optional[asyncio.Task[None]] = None
        self._login_inflight: Optional[asyncio.Future[httpx.AsyncClient]] = None
        self._last_login_failure: float = 0
        self._login_cooldown: float = float(LOGIN_COOLDOWN_SECONDS)

    @property
    def login_ok(self) -> bool:
        return self._login_ok

    async def _create_client(self) -> httpx.AsyncClient:
        return httpx.AsyncClient(
            timeout=DEFAULT_TIMEOUT,
            follow_redirects=True,
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

    async def ensure_login(self) -> httpx.AsyncClient:
        """确保已登录且 Cookie 有效, 返回可用的 client"""
        now = time.monotonic()
        if self._login_ok and self._client is not None and (now - self._last_login_time) <= self._cookie_ttl:
            return self._client
        return await self._login_once(reason="ensure_login")

    async def force_relogin(self):
        """强制重新登录 (当检测到认证失效时调用)"""
        logger.warning("会话可能已失效，准备重新登录")
        self._login_ok = False
        await self._login_once(reason="force_relogin")

    async def _login_once(self, *, reason: str) -> httpx.AsyncClient:
        """
        登录去重 + 失败冷却：
        - 并发情况下仅允许一个登录在途，其余 await 同一个 future
        - 最近一次登录失败后短时间内直接拒绝，避免登录风暴
        """
        async with self._lock:
            now = time.monotonic()
            if self._login_ok and self._client is not None and (now - self._last_login_time) <= self._cookie_ttl:
                return self._client

            if self._login_inflight is not None and not self._login_inflight.done():
                fut = self._login_inflight
            else:
                since_fail = now - self._last_login_failure
                if since_fail < self._login_cooldown:
                    raise UpstreamUnavailableError(
                        f"登录冷却中（原因={reason}，剩余 {self._login_cooldown - since_fail:.1f}s）"
                    )

                loop = asyncio.get_running_loop()
                fut = loop.create_future()
                self._login_inflight = fut
                asyncio.create_task(self._run_login(fut))

        return await fut

    async def _run_login(self, fut: asyncio.Future[httpx.AsyncClient]):
        try:
            await self._do_login()
            fut.set_result(self._client)
        except Exception as e:
            self._last_login_failure = time.monotonic()
            if not fut.done():
                fut.set_exception(e)
        finally:
            async with self._lock:
                if self._login_inflight is fut:
                    self._login_inflight = None

    async def _retry_request(self, method: str, url: str, *, follow_redirects: bool = False, **kwargs) -> httpx.Response:
        assert self._client is not None
        last_exc: Optional[Exception] = None
        for attempt in range(NETWORK_RETRY_ATTEMPTS):
            try:
                return await self._client.request(method, url, follow_redirects=follow_redirects, **kwargs)
            except _RETRIABLE_NET_ERRORS as e:
                last_exc = e
                if attempt < NETWORK_RETRY_ATTEMPTS - 1:
                    logger.warning("网络异常（%s %s）：%s，准备重试", method, str(url)[:60], e)
                    await asyncio.sleep(1.0 * (2 ** attempt))
                    continue
                raise
        assert last_exc is not None
        raise last_exc

    async def _fetch_login_page(self, login_url: str) -> httpx.Response:
        logger.info("请求登录页：GET %s...", login_url[:80])
        return await self._retry_request("GET", login_url, follow_redirects=False)

    async def _submit_login_form(self, login_url: str, login_data: dict) -> httpx.Response:
        logger.info("提交登录表单：POST /authserver/login")
        return await self._retry_request("POST", login_url, data=login_data, follow_redirects=False)

    def _extract_login_error(self, resp: httpx.Response) -> str:
        try:
            data = resp.json()
            code = data.get("resultCode", "")
            return _LOGIN_ERROR_MESSAGES.get(code, f"错误码: {code}")
        except Exception:
            text = _extract_error_text(resp.text)
            return text or "未知错误"

    async def _do_login(self):
        """执行完整的金智 AuthServer 登录流程"""
        logger.info("开始统一身份认证登录（AuthServer CAS）")

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

            if resp.status_code in (301, 302):
                location = resp.headers.get("location", "")
                logger.info("检测到有效 TGC，跟随重定向完成会话建立")
                await self._follow_cas_redirect(location)
                self._login_ok = True
                self._last_login_time = time.monotonic()
                logger.info("登录成功（复用 TGC）")
                return

            execution, salt = _parse_login_form(resp.text)

            logger.info("解析表单参数成功：salt=%s**** execution=%s...", salt[:4], execution[:20])

            # Step 2: 加密密码（与前端实现对齐）
            encrypted_pwd = encrypt_password(PASSWORD, salt)
            logger.info("密码加密完成（AES-CBC），cipher_len=%d", len(encrypted_pwd))

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
            if resp.status_code in (301, 302):
                location = resp.headers.get("location", "")
                logger.info("登录表单提交成功，跟随重定向链：%s...", location[:80])
                await self._follow_cas_redirect(location)
                self._login_ok = True
                self._last_login_time = time.monotonic()
                logger.info("认证完成，会话 Cookie 已就绪")
            else:
                raise RuntimeError(f"AuthServer 登录失败: {self._extract_login_error(resp)}")

        except Exception as e:
            self._login_ok = False
            logger.error("登录失败：%s", e)
            raise

    async def _follow_cas_redirect(self, location: str):
        """
        手动跟随 CAS 重定向链, 确保拿到目标站点的所有 Cookie。
        authserver 到 cas callback（携带 ST ticket）再到目标站主页
        """
        max_redirects = MAX_LOGIN_REDIRECTS
        current_url = location

        for i in range(max_redirects):
            if not current_url:
                break

            logger.info("跟随重定向[%d/%d]：%s...", i + 1, max_redirects, current_url[:80])
            resp = await self._retry_request("GET", current_url, follow_redirects=False)

            if resp.status_code in (301, 302):
                current_url = resp.headers.get("location", "")
                if current_url and not current_url.startswith("http"):
                    current_url = urljoin(str(resp.url), current_url)
            else:
                logger.info("重定向链结束：url=%s status=%d", resp.url, resp.status_code)
                break

    async def check_and_refresh(self):
        """保活检查: 轻量 HEAD 请求验证 Cookie 是否还有效"""
        if not self._client or not self._login_ok:
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
            if resp.status_code in (301, 302, 401, 403):
                logger.warning("保活检查失败（status=%d），准备重新登录", resp.status_code)
                await self.force_relogin()
            else:
                self._last_login_time = time.monotonic()
                logger.debug("保活检查通过")
        except Exception as e:
            logger.warning("保活检查异常：%s（标记需重登）", e)
            self._login_ok = False

    async def start_keepalive(self):
        """启动后台保活定时器"""
        async def _keepalive_loop():
            while True:
                await asyncio.sleep(KEEPALIVE_INTERVAL_SECONDS)
                try:
                    await self.check_and_refresh()
                except Exception as e:
                    logger.error("保活任务异常：%s", e)

        self._keepalive_task = asyncio.create_task(_keepalive_loop())
        logger.info("后台保活任务已启动（间隔：5 分钟）")

    async def stop_keepalive(self):
        if self._keepalive_task:
            self._keepalive_task.cancel()
            try:
                await self._keepalive_task
            except asyncio.CancelledError:
                pass
            except Exception as e:
                logger.debug("keepalive_task 退出异常：%s", e)

    async def close(self):
        await self.stop_keepalive()
        if self._client:
            try:
                await asyncio.wait_for(self._client.aclose(), timeout=2.0)
            except asyncio.TimeoutError:
                pass


# ============================================================
# 全局会话管理器实例
# ============================================================

session_mgr = AuthSessionManager()


# ============================================================
# FastAPI 应用
# ============================================================

def create_app(_settings: Settings, manager: AuthSessionManager) -> FastAPI:
    static_dir = os.path.join(os.path.dirname(__file__), "static")
    index_html_path = os.path.join(static_dir, "index.html")

    @asynccontextmanager
    async def _lifespan(_app: FastAPI):
        logger.info("服务启动：target=%s user=%s", TARGET_BASE, USERNAME)

        try:
            await manager.ensure_login()
            logger.info("初始登录成功")
        except Exception as e:
            logger.error("初始登录失败：%s", e)
            logger.error("服务将继续启动；后续请求会触发重试登录")

        await manager.start_keepalive()

        yield

        logger.info("服务关闭中")
        await manager.close()

    _app = FastAPI(
        title="NWAFU DeepSeek Proxy",
        description="本地透明代理网关, 自动处理校园认证, 无差别转发所有 API 请求",
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
        # 注意：allow_origins="*" 与 allow_credentials=True 在浏览器端不兼容
        allow_credentials=False,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    _app.mount("/static", StaticFiles(directory=static_dir, html=True), name="static")

    @_app.get("/")
    async def root():
        try:
            with open(index_html_path, "r", encoding="utf-8") as f:
                return HTMLResponse(content=f.read())
        except FileNotFoundError:
            return HTMLResponse(
                content="缺少静态页面：static/index.html（请确认你已创建 static/ 目录）",
                status_code=500,
            )

    @_app.get("/health")
    async def health():
        return {
            "status": "ok",
            "service": "NWAFU DeepSeek Proxy",
            "target": TARGET_BASE,
            "login_ok": manager.login_ok,
            "api_base": f"http://localhost:{PROXY_PORT}/v1",
            "ui": "/",
            "note": "所有 /v1/* 路径透明转发到源站，与源站 API 保持一致",
        }

    return _app


app = create_app(settings, session_mgr)


# ============================================================
# 认证检测
# ============================================================


def _is_login_redirect(resp: httpx.Response) -> bool:
    if resp.status_code in (301, 302, 307):
        location = resp.headers.get("location", "")
        location_l = location.lower()
        if "authserver" in location_l or "/login" in location_l:
            return True
    return False


def _is_html_unauthorized(resp: httpx.Response) -> bool:
    if resp.status_code not in (401, 403):
        return False
    content_type = resp.headers.get("content-type", "")
    # Open WebUI 在 API Key 无效、模型不存在等情况也可能返回 401/403，
    # 但 body 是 JSON；CAS 失效通常返回 HTML。
    return "application/json" not in content_type


def _is_auth_redirect(resp: httpx.Response) -> bool:
    """
    判断上游响应是否表明 CAS 会话已失效。
    需要与"上游正常业务错误"区分: Open WebUI 在 API Key 无效或
    模型不存在时也会返回 401/403, 但 body 是 JSON。
    """
    return _is_login_redirect(resp) or _is_html_unauthorized(resp)


# ============================================================
# 透明反向代理 —— 核心引擎
# ============================================================


HOP_BY_HOP_HEADERS = frozenset({
    "host", "connection", "keep-alive", "transfer-encoding",
    "te", "trailer", "upgrade", "proxy-authorization",
    "proxy-authenticate", "content-length",
    # 注意：这里刻意丢弃客户端 Authorization，并在后续注入真实 OPENWEBUI_API_KEY。
    "authorization", "accept-encoding",
})

STRIP_RESPONSE_HEADERS = frozenset({
    "content-length", "transfer-encoding", "content-encoding",
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


def _build_forward_headers(request: Request) -> dict[str, str]:
    headers = {k: v for k, v in request.headers.items() if k.lower() not in HOP_BY_HOP_HEADERS}
    headers["Host"] = TARGET_HOST
    if OPENWEBUI_API_KEY:
        headers["Authorization"] = f"Bearer {OPENWEBUI_API_KEY}"
    return headers


def _strip_response_headers(headers: httpx.Headers) -> dict[str, str]:
    return {k: v for k, v in headers.items() if k.lower() not in STRIP_RESPONSE_HEADERS}


async def _forward(
    client: httpx.AsyncClient,
    *,
    method: str,
    url: str,
    headers: dict[str, str],
    body: bytes,
    is_stream: bool,
) -> Response | object:
    req = client.build_request(
        method=method,
        url=url,
        headers=headers,
        content=body,
        timeout=STREAM_TIMEOUT if is_stream else DEFAULT_TIMEOUT,
    )
    resp = await client.send(req, stream=True, follow_redirects=False)

    if _is_auth_redirect(resp):
        await resp.aclose()
        return _AUTH_EXPIRED

    resp_headers = _strip_response_headers(resp.headers)
    media_type = resp.headers.get("content-type", "text/event-stream" if is_stream else None)

    async def stream_generator():
        try:
            async for chunk in resp.aiter_bytes():
                yield chunk
        except (httpx.ReadError, httpx.RemoteProtocolError, httpx.TransportError) as e:
            # 仅对 SSE 流式请求提供“最后一条 data:”兜底，避免客户端永远 hang。
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
    """
    核心代理逻辑: 透明转发任何请求到源站。
    - 注入 CAS Cookie (通过 httpx client 的 cookie jar)
    - 注入 Authorization Bearer (Open WebUI API Key)
    - 自动检测流式请求并使用长超时
    - Cookie 失效时自动重登并重试
    """
    t0 = time.monotonic()
    body, is_stream = await _read_request_body(request)

    for attempt in range(PROXY_MAX_RETRIES):
        # 先确保已登录。登录失败应返回干净的 503，而不是抛出到 ASGI
        try:
            client = await session_mgr.ensure_login()
        except UpstreamUnavailableError as e:
            logger.warning("登录被冷却拒绝：%s", e)
            return _error_response(503, "上游暂时不可达，请稍后重试", error_type="login_cooldown")
        except _RETRIABLE_NET_ERRORS as e:
            logger.warning("登录阶段网络异常：%s", e)
            return _error_response(503, "上游暂时不可达，请稍后重试", error_type="upstream_unreachable")
        except Exception as e:
            logger.error("登录失败：%s", e)
            return _error_response(503, "登录失败，请稍后重试", error_type="login_failed")

        target_url = _build_target_url(request, target_path)
        headers = _build_forward_headers(request)

        try:
            result = await _forward(
                client,
                method=request.method,
                url=target_url,
                headers=headers,
                body=body,
                is_stream=is_stream,
            )

            if result is _AUTH_EXPIRED:
                if attempt < PROXY_MAX_RETRIES - 1:
                    logger.warning("认证失效，准备重新登录并重试")
                    await session_mgr.force_relogin()
                    await asyncio.sleep(1)
                    continue
                return _error_response(401, "认证失败, 请检查账号密码", error_type="auth_failed")

            elapsed = int((time.monotonic() - t0) * 1000)
            logger.info(
                "event=proxy_response method=%s path=%s status=%s stream=%s ms=%d",
                request.method,
                target_path,
                getattr(result, "status_code", "-"),
                "true" if is_stream else "false",
                elapsed,
            )
            return result

        except httpx.TimeoutException:
            elapsed = int((time.monotonic() - t0) * 1000)
            logger.error("上游请求超时（ms=%d）", elapsed)
            if attempt < PROXY_MAX_RETRIES - 1:
                await asyncio.sleep(1)
                continue
            return _error_response(504, "上游请求超时", error_type="upstream_timeout")

        except _RETRIABLE_NET_ERRORS as e:
            # 网络错误：不动 session，不触发重登；仅对该请求做退避重试
            elapsed = int((time.monotonic() - t0) * 1000)
            logger.warning(
                "上游网络抖动：%s（ms=%d）",
                e,
                elapsed,
            )
            if attempt < PROXY_MAX_RETRIES - 1:
                await asyncio.sleep(0.5 * (2 ** attempt))
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


# ============================================================
# 注册代理路由 —— 所有路径无差别转发
# ============================================================


_PROXY_METHODS = ["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS", "HEAD"]
_PROXY_PREFIXES = ("v1", "api", "ollama", "openai")


def _register_proxy_routes(app: FastAPI) -> None:
    for prefix in _PROXY_PREFIXES:
        _mount_proxy_prefix(app, prefix)


def _mount_proxy_prefix(app: FastAPI, prefix: str) -> None:
    @app.api_route(f"/{prefix}/{{path:path}}", methods=_PROXY_METHODS)
    async def _handler(request: Request, path: str):  # noqa: ANN001 - FastAPI 注入
        return await _proxy_request(request, f"/{prefix}/{path}")


_register_proxy_routes(app)


# ============================================================
# 入口
# ============================================================

if __name__ == "__main__":
    api_key_hint = "已配置" if OPENWEBUI_API_KEY else "未配置"
    logger.info(
        "\n  NWAFU DeepSeek Proxy (transparent reverse proxy)\n"
        "  ------------------------------------------------\n"
        "  Listen:     http://localhost:%s/v1\n"
        "  Upstream:   %s\n"
        "  AuthServer: %s\n"
        "  User:       %s\n"
        "  WebUI Key:  %s\n\n"
        "  Note:\n"
        "    - 代理透明转发所有 /v1/* 请求到源站\n"
        "    - 客户端 API Key 可填任意值（代理会注入真实 Open WebUI Key）\n",
        PROXY_PORT,
        TARGET_BASE,
        AUTH_SERVER,
        USERNAME,
        api_key_hint,
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
