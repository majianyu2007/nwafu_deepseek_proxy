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
import random
import secrets
import sys
import time
from contextlib import asynccontextmanager
from typing import Optional
from urllib.parse import urljoin, quote

import httpx
from bs4 import BeautifulSoup
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from dotenv import load_dotenv
from fastapi import FastAPI, Request, Response
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import HTMLResponse, StreamingResponse
import uvicorn

# ============================================================
# 配置与日志
# ============================================================

load_dotenv()

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger("proxy")

USERNAME = os.getenv("NWAFU_USERNAME", "")
PASSWORD = os.getenv("NWAFU_PASSWORD", "")
PROXY_PORT = int(os.getenv("PROXY_PORT", "8000"))
TARGET_HOST = os.getenv("TARGET_HOST", "deepseek.nwafu.edu.cn")
OPENWEBUI_API_KEY = os.getenv("OPENWEBUI_API_KEY", "")
AUTH_SERVER = os.getenv("AUTH_SERVER", "https://authserver.nwafu.edu.cn")

TARGET_BASE = f"https://{TARGET_HOST}"

STREAM_TIMEOUT = httpx.Timeout(300.0, connect=15.0)
DEFAULT_TIMEOUT = httpx.Timeout(60.0, connect=15.0)

if not USERNAME or not PASSWORD:
    logger.error("缺少必填环境变量：NWAFU_USERNAME / NWAFU_PASSWORD（请在 .env 中配置）")
    sys.exit(1)

if not OPENWEBUI_API_KEY:
    logger.warning("未配置 OPENWEBUI_API_KEY：上游可能返回 401/403（请在 .env 中配置）")


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
        self._cookie_ttl: float = 25 * 60
        self._keepalive_task: Optional[asyncio.Task] = None

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
        async with self._lock:
            now = time.monotonic()
            needs_login = (
                not self._login_ok
                or self._client is None
                or (now - self._last_login_time) > self._cookie_ttl
            )
            if needs_login:
                await self._do_login()
            return self._client

    async def force_relogin(self):
        """强制重新登录 (当检测到认证失效时调用)"""
        async with self._lock:
            logger.warning("会话可能已失效，准备重新登录")
            self._login_ok = False
            await self._do_login()

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

            logger.info("请求登录页：GET %s...", login_url[:80])
            resp = await self._client.get(login_url, follow_redirects=False)

            if resp.status_code in (301, 302):
                location = resp.headers.get("location", "")
                logger.info("检测到有效 TGC，跟随重定向完成会话建立")
                await self._follow_cas_redirect(location)
                self._login_ok = True
                self._last_login_time = time.monotonic()
                logger.info("登录成功（复用 TGC）")
                return

            html = resp.text
            soup = BeautifulSoup(html, "lxml")

            execution_input = soup.find("input", {"id": "execution"})
            if not execution_input:
                raise RuntimeError("无法提取 execution 参数, 登录页结构可能已变更")
            execution = execution_input.get("value", "")

            salt_input = soup.find("input", {"id": "pwdEncryptSalt"})
            if not salt_input:
                raise RuntimeError("无法提取 pwdEncryptSalt, 登录页结构可能已变更")
            salt = salt_input.get("value", "")

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

            logger.info("提交登录表单：POST /authserver/login")
            resp = await self._client.post(
                login_url,
                data=login_data,
                follow_redirects=False,
            )

            # Step 4: 处理登录结果
            if resp.status_code in (301, 302):
                location = resp.headers.get("location", "")
                logger.info("登录表单提交成功，跟随重定向链：%s...", location[:80])
                await self._follow_cas_redirect(location)
                self._login_ok = True
                self._last_login_time = time.monotonic()
                logger.info("认证完成，会话 Cookie 已就绪")
            else:
                error_msg = "未知错误"
                try:
                    data = resp.json()
                    code = data.get("resultCode", "")
                    if code == "FAIL_UPNOTMATCH":
                        error_msg = "密码错误或账户不存在"
                    elif code == "CAPTCHA_NOTMATCH":
                        error_msg = "需要输入验证码 (账号可能被临时锁定, 请稍后再试)"
                    elif code == "LOCK":
                        error_msg = "账户已被锁定"
                    else:
                        error_msg = f"错误码: {code}"
                except Exception:
                    error_soup = BeautifulSoup(resp.text, "lxml")
                    error_tip = error_soup.find(id="formErrorTip")
                    if error_tip:
                        span = error_tip.find("span")
                        if span:
                            error_msg = span.get_text(strip=True)

                raise RuntimeError(f"AuthServer 登录失败: {error_msg}")

        except Exception as e:
            self._login_ok = False
            logger.error("登录失败：%s", e)
            raise

    async def _follow_cas_redirect(self, location: str):
        """
        手动跟随 CAS 重定向链, 确保拿到目标站点的所有 Cookie。
        authserver 到 cas callback（携带 ST ticket）再到目标站主页
        """
        max_redirects = 10
        current_url = location

        for i in range(max_redirects):
            if not current_url:
                break

            logger.info("跟随重定向[%d/%d]：%s...", i + 1, max_redirects, current_url[:80])
            resp = await self._client.get(current_url, follow_redirects=False)

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
                await asyncio.sleep(5 * 60)
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


@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info("服务启动：target=%s user=%s", TARGET_BASE, USERNAME)

    try:
        await session_mgr.ensure_login()
        logger.info("初始登录成功")
    except Exception as e:
        logger.error("初始登录失败：%s", e)
        logger.error("服务将继续启动；后续请求会触发重试登录")

    await session_mgr.start_keepalive()

    yield

    logger.info("服务关闭中")
    await session_mgr.close()


app = FastAPI(
    title="NWAFU DeepSeek Proxy",
    description="本地透明代理网关, 自动处理校园认证, 无差别转发所有 API 请求",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    # 注意：allow_origins="*" 与 allow_credentials=True 在浏览器端不兼容
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)

STATIC_DIR = os.path.join(os.path.dirname(__file__), "static")
INDEX_HTML_PATH = os.path.join(STATIC_DIR, "index.html")
app.mount("/static", StaticFiles(directory=STATIC_DIR, html=True), name="static")


# ============================================================
# 健康检查
# ============================================================


@app.get("/")
async def root():
    try:
        with open(INDEX_HTML_PATH, "r", encoding="utf-8") as f:
            return HTMLResponse(content=f.read())
    except FileNotFoundError:
        return HTMLResponse(
            content="缺少静态页面：static/index.html（请确认你已创建 static/ 目录）",
            status_code=500,
        )


@app.get("/health")
async def health():
    return {
        "status": "ok",
        "service": "NWAFU DeepSeek Proxy",
        "target": TARGET_BASE,
        "login_ok": session_mgr.login_ok,
        "api_base": f"http://localhost:{PROXY_PORT}/v1",
        "ui": "/",
        "note": "所有 /v1/* 路径透明转发到源站，与源站 API 保持一致",
    }


# ============================================================
# 认证检测
# ============================================================


def _is_auth_redirect(resp: httpx.Response, *, is_stream: bool = False) -> bool:
    """
    判断上游响应是否表明 CAS 会话已失效。
    需要与"上游正常业务错误"区分: Open WebUI 在 API Key 无效或
    模型不存在时也会返回 401/403, 但 body 是 JSON。
    """
    if resp.status_code in (301, 302, 307):
        location = resp.headers.get("location", "")
        if "authserver" in location.lower() or "/login" in location.lower():
            return True

    content_type = resp.headers.get("content-type", "")

    if resp.status_code in (401, 403):
        if "application/json" in content_type:
            return False
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
})

STRIP_RESPONSE_HEADERS = frozenset({
    "content-length", "transfer-encoding", "content-encoding",
})


async def _proxy_request(request: Request, target_path: str) -> Response:
    """
    核心代理逻辑: 透明转发任何请求到源站。
    - 注入 CAS Cookie (通过 httpx client 的 cookie jar)
    - 注入 Authorization Bearer (Open WebUI API Key)
    - 自动检测流式请求并使用长超时
    - Cookie 失效时自动重登并重试
    """
    max_retries = 2
    t0 = time.monotonic()

    body = await request.body()

    is_stream = False
    if body:
        try:
            body_json = json.loads(body)
            is_stream = body_json.get("stream", False)
        except (json.JSONDecodeError, UnicodeDecodeError):
            pass

    for attempt in range(max_retries):
        client = await session_mgr.ensure_login()

        target_url = f"{TARGET_BASE}{target_path}"
        if request.url.query:
            target_url += f"?{request.url.query}"

        headers = {
            k: v for k, v in request.headers.items()
            if k.lower() not in HOP_BY_HOP_HEADERS
        }
        headers["Host"] = TARGET_HOST
        if OPENWEBUI_API_KEY:
            headers["Authorization"] = f"Bearer {OPENWEBUI_API_KEY}"

        try:
            if is_stream:
                req = client.build_request(
                    method=request.method,
                    url=target_url,
                    headers=headers,
                    content=body,
                    timeout=STREAM_TIMEOUT,
                )
                resp = await client.send(req, stream=True, follow_redirects=False)

                if _is_auth_redirect(resp, is_stream=True):
                    await resp.aclose()
                    if attempt < max_retries - 1:
                        logger.warning("[%s %s] 认证失效（stream），准备重新登录并重试", request.method, target_path)
                        await session_mgr.force_relogin()
                        await asyncio.sleep(1)
                        continue
                    return _error_response(401, "认证失败, 请检查账号密码")

                elapsed = int((time.monotonic() - t0) * 1000)
                logger.info(
                    "event=proxy_response method=%s path=%s status=%d stream=true connect_ms=%d",
                    request.method,
                    target_path,
                    resp.status_code,
                    elapsed,
                )

                async def stream_generator():
                    try:
                        async for chunk in resp.aiter_bytes():
                            yield chunk
                    except (httpx.ReadError, httpx.RemoteProtocolError, httpx.TransportError) as e:
                        logger.error("[%s %s] 流式响应中断：%s", request.method, target_path, e)
                        error_payload = json.dumps({"error": "upstream connection lost"})
                        yield f"data: {error_payload}\n\n".encode("utf-8")
                    finally:
                        await resp.aclose()

                resp_headers = {
                    k: v for k, v in resp.headers.items()
                    if k.lower() not in STRIP_RESPONSE_HEADERS
                }

                return StreamingResponse(
                    stream_generator(),
                    status_code=resp.status_code,
                    headers=resp_headers,
                    media_type=resp.headers.get("content-type", "text/event-stream"),
                )

            else:
                resp = await client.request(
                    method=request.method,
                    url=target_url,
                    headers=headers,
                    content=body,
                    follow_redirects=False,
                    timeout=DEFAULT_TIMEOUT,
                )

                if _is_auth_redirect(resp, is_stream=False):
                    if attempt < max_retries - 1:
                        logger.warning("[%s %s] 认证失效，准备重新登录并重试", request.method, target_path)
                        await session_mgr.force_relogin()
                        await asyncio.sleep(1)
                        continue
                    return _error_response(401, "认证失败, 请检查账号密码")

                elapsed = int((time.monotonic() - t0) * 1000)
                logger.info(
                    "event=proxy_response method=%s path=%s status=%d stream=false bytes=%d ms=%d",
                    request.method,
                    target_path,
                    resp.status_code,
                    len(resp.content),
                    elapsed,
                )

                resp_headers = {
                    k: v for k, v in resp.headers.items()
                    if k.lower() not in STRIP_RESPONSE_HEADERS
                }

                return Response(
                    content=resp.content,
                    status_code=resp.status_code,
                    headers=resp_headers,
                    media_type=resp.headers.get("content-type"),
                )

        except httpx.TimeoutException:
            elapsed = int((time.monotonic() - t0) * 1000)
            logger.error("[%s %s] 上游请求超时（ms=%d）", request.method, target_path, elapsed)
            if attempt < max_retries - 1:
                await asyncio.sleep(1)
                continue
            return _error_response(504, "上游请求超时")

        except Exception as e:
            elapsed = int((time.monotonic() - t0) * 1000)
            logger.error("[%s %s] 代理异常：%s（ms=%d）", request.method, target_path, e, elapsed)
            if attempt < max_retries - 1:
                await session_mgr.force_relogin()
                await asyncio.sleep(1)
                continue
            return _error_response(502, str(e))

    return _error_response(502, "代理请求失败")


def _error_response(status_code: int, message: str) -> Response:
    return Response(
        content=json.dumps({"error": message}),
        status_code=status_code,
        media_type="application/json",
    )


# ============================================================
# 注册代理路由 —— 所有路径无差别转发
# ============================================================


@app.get("/v1")
@app.get("/v1/")
async def v1_index():
    """直接访问 /v1 时返回友好提示而非走代理"""
    return {
        "message": "NWAFU DeepSeek Proxy — /v1 API 端点",
        "endpoints": {
            "models": "/v1/models",
            "chat": "/v1/chat/completions",
            "embeddings": "/v1/embeddings",
        },
        "ui": "/",
        "note": "客户端 API Key 可填任意值，代理会自动替换",
    }


@app.get("/v1/chat/completions")
async def proxy_v1_chat_get():
    """显式拦截对聊天 API 的非规范 GET 测试，返回更标准友好的错误"""
    return _error_response(405, "Method Not Allowed. Please use POST for /v1/chat/completions.")


@app.api_route("/v1/{path:path}", methods=["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS"])
async def proxy_v1(request: Request, path: str):
    if path == "chat/completions" and request.method == "GET":
        return _error_response(405, "Method Not Allowed. Please use POST for /v1/chat/completions.")
    return await _proxy_request(request, f"/v1/{path}")


@app.api_route("/api/{path:path}", methods=["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS"])
async def proxy_api(request: Request, path: str):
    return await _proxy_request(request, f"/api/{path}")


@app.api_route("/ollama/{path:path}", methods=["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS"])
async def proxy_ollama(request: Request, path: str):
    return await _proxy_request(request, f"/ollama/{path}")


@app.api_route("/openai/{path:path}", methods=["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS"])
async def proxy_openai(request: Request, path: str):
    return await _proxy_request(request, f"/openai/{path}")


# ============================================================
# 入口
# ============================================================

if __name__ == "__main__":
    api_key_hint = "已配置" if OPENWEBUI_API_KEY else "未配置"
    print(f"""
  NWAFU DeepSeek Proxy (transparent reverse proxy)
  ------------------------------------------------
  Listen:     http://localhost:{PROXY_PORT}/v1
  Upstream:   {TARGET_BASE}
  AuthServer: {AUTH_SERVER}
  User:       {USERNAME}
  WebUI Key:  {api_key_hint}

  Note:
    - 代理透明转发所有 /v1/* 请求到源站
    - 客户端 API Key 可填任意值（代理会注入真实 Open WebUI Key）
""")

    uvicorn.run(
        app,
        host="0.0.0.0",
        port=PROXY_PORT,
        log_level="info",
        timeout_graceful_shutdown=2,
    )
