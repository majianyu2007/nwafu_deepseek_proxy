"""
nwafu_deepseek_proxy - 校园统一认证 Open WebUI 代理

自动处理金智教育 (Wisedu) AuthServer CAS 认证流程,
在本地暴露 OpenAI 兼容的 API 端点, 供第三方客户端直接调用。
支持 chat / completions / embeddings / rerank 等全部 OpenAI 兼容接口。

详见 README.md
"""

import asyncio
import base64
import json
import logging
import os
import random
import sys
import time
from contextlib import asynccontextmanager
from typing import Any, Dict, List, Optional
from urllib.parse import urljoin, quote

import httpx
from bs4 import BeautifulSoup
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from dotenv import load_dotenv
from fastapi import FastAPI, Request, Response
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, StreamingResponse
from pydantic import BaseModel, Field
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

if not USERNAME or not PASSWORD:
    logger.error("请在 .env 文件中配置 NWAFU_USERNAME 和 NWAFU_PASSWORD")
    sys.exit(1)

if not OPENWEBUI_API_KEY:
    logger.warning("⚠️  未配置 OPENWEBUI_API_KEY, Open WebUI 的 API 调用可能会失败")
    logger.warning("   请在 Open WebUI 个人设置中获取 API Key 并填入 .env 文件")


# ============================================================
# 金智 AuthServer AES 加密 —— 完美还原 encrypt.js
# ============================================================

# 与 encrypt.js 中 $aes_chars 完全一致
AES_CHARS = "ABCDEFGHJKMNPQRSTWXYZabcdefhijkmnprstwxyz2345678"


def _random_string(length: int) -> str:
    """生成与 JS 端 randomString() 完全一致的随机字符串"""
    return "".join(random.choice(AES_CHARS) for _ in range(length))


def encrypt_password(password: str, salt: str) -> str:
    """
    完美还原 encrypt.js 中 encryptAES / getAesString 的加密流程:
    1. 生成 64 位随机前缀 + 原始密码 作为明文
    2. 使用 salt 作为 AES key (UTF-8 编码)
    3. 使用随机 16 位字符串作为 IV
    4. AES-CBC 模式, PKCS7 填充
    5. 返回 Base64 编码的密文
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
# AuthServer 会话管理器 —— Cookie 保活加强
# ============================================================


class AuthSessionManager:
    """
    管理与 AuthServer 及 DeepSeek 之间的完整会话生命周期:
    - 自动登录
    - Cookie 持久化
    - 定期保活 / 过期自动刷新
    - 线程安全
    """

    def __init__(self):
        self._client: Optional[httpx.AsyncClient] = None
        self._lock = asyncio.Lock()
        self._last_login_time: float = 0
        self._login_ok: bool = False
        # Cookie 有效期阈值 (秒), 超过此时间主动刷新
        self._cookie_ttl: float = 25 * 60  # 25 分钟
        self._keepalive_task: Optional[asyncio.Task] = None

    async def _create_client(self) -> httpx.AsyncClient:
        """创建一个干净的 httpx 客户端 (保持 Cookie Jar)"""
        return httpx.AsyncClient(
            timeout=httpx.Timeout(30.0, connect=15.0),
            follow_redirects=True,
            limits=httpx.Limits(max_connections=20, max_keepalive_connections=10),
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
            now = time.time()
            needs_login = (
                not self._login_ok
                or self._client is None
                or (now - self._last_login_time) > self._cookie_ttl
            )
            if needs_login:
                await self._do_login()
            return self._client

    async def force_relogin(self):
        """强制重新登录 (当检测到 302 / 401 / 403 时调用)"""
        async with self._lock:
            logger.warning("🔄 检测到 Cookie 失效, 强制重新登录...")
            self._login_ok = False
            await self._do_login()

    async def _do_login(self):
        """执行完整的金智 AuthServer 登录流程"""
        logger.info("🔐 开始金智 AuthServer 统一身份认证登录...")

        # 关闭旧客户端
        if self._client:
            try:
                await self._client.aclose()
            except Exception:
                pass

        self._client = await self._create_client()

        try:
            # ============ Step 1: 获取登录页, 提取表单参数 ============
            service_url = (
                f"{TARGET_BASE}/.auth/login/cas/callback"
                f"?return_to={TARGET_BASE}/"
            )
            # service 参数必须 URL 编码
            encoded_service = quote(service_url, safe="")
            login_url = f"{AUTH_SERVER}/authserver/login?service={encoded_service}"

            logger.info(f"  → GET {login_url[:80]}...")
            resp = await self._client.get(login_url, follow_redirects=False)

            # 如果已经有有效的 TGC, 会直接 302 到 service
            if resp.status_code in (301, 302):
                location = resp.headers.get("location", "")
                logger.info(f"  ✅ TGC 仍然有效, 直接跟随重定向...")
                await self._follow_cas_redirect(location)
                self._login_ok = True
                self._last_login_time = time.time()
                logger.info("  ✅ 使用已有 TGC 登录成功!")
                return

            html = resp.text
            soup = BeautifulSoup(html, "lxml")

            # 提取 execution
            execution_input = soup.find("input", {"id": "execution"})
            if not execution_input:
                raise RuntimeError("无法提取 execution 参数, 登录页结构可能已变更")
            execution = execution_input.get("value", "")

            # 提取 pwdEncryptSalt
            salt_input = soup.find("input", {"id": "pwdEncryptSalt"})
            if not salt_input:
                raise RuntimeError("无法提取 pwdEncryptSalt, 登录页结构可能已变更")
            salt = salt_input.get("value", "")

            logger.info(f"  → 提取到 salt: {salt[:4]}**** , execution: {execution[:20]}...")

            # ============ Step 2: 加密密码 ============
            encrypted_pwd = encrypt_password(PASSWORD, salt)
            logger.info(f"  → 密码已加密 (AES-CBC), 长度: {len(encrypted_pwd)}")

            # ============ Step 3: 提交登录表单 ============
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

            logger.info("  → POST /authserver/login ...")
            # 注意: POST URL 必须也带上 service 参数, 否则 CAS 不知道登录后重定向到哪
            resp = await self._client.post(
                login_url,
                data=login_data,
                follow_redirects=False,
            )

            # ============ Step 4: 处理登录结果 ============
            if resp.status_code in (301, 302):
                # 登录成功, 跟随重定向链获取目标站 Cookie
                location = resp.headers.get("location", "")
                logger.info(f"  ✅ 登录成功! 跟随重定向到: {location[:80]}...")
                await self._follow_cas_redirect(location)
                self._login_ok = True
                self._last_login_time = time.time()
                logger.info("  ✅ 全部认证完成, Cookie 已就绪!")
            else:
                # 登录失败, 尝试解析错误信息
                error_msg = "未知错误"
                try:
                    # 尝试 JSON 响应 (doLogin 接口)
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
                    # HTML 响应, 从中提取错误
                    error_soup = BeautifulSoup(resp.text, "lxml")
                    error_tip = error_soup.find(id="formErrorTip")
                    if error_tip:
                        span = error_tip.find("span")
                        if span:
                            error_msg = span.get_text(strip=True)

                raise RuntimeError(f"AuthServer 登录失败: {error_msg}")

        except Exception as e:
            self._login_ok = False
            logger.error(f"  ❌ 登录失败: {e}")
            raise

    async def _follow_cas_redirect(self, location: str):
        """
        手动跟随 CAS 重定向链, 确保拿到目标站点的所有 Cookie。
        这个过程通常是:
        authserver -> cas callback (带 ST ticket) -> deepseek 主页
        """
        max_redirects = 10
        current_url = location

        for i in range(max_redirects):
            if not current_url:
                break

            logger.info(f"  → 重定向 [{i+1}]: {current_url[:80]}...")
            resp = await self._client.get(current_url, follow_redirects=False)

            if resp.status_code in (301, 302):
                current_url = resp.headers.get("location", "")
                # 处理相对路径
                if current_url and not current_url.startswith("http"):
                    current_url = urljoin(str(resp.url), current_url)
            else:
                # 最终落地页
                logger.info(f"  → 最终落地页: {resp.url} (状态码: {resp.status_code})")
                break

    async def check_and_refresh(self):
        """保活检查: 发一个轻量请求验证 Cookie 是否还有效"""
        if not self._client or not self._login_ok:
            return

        try:
            resp = await self._client.get(
                f"{TARGET_BASE}/api/models",
                follow_redirects=False,
            )
            if resp.status_code in (301, 302, 401, 403):
                logger.warning("🔄 保活检查发现 Cookie 已过期")
                self._login_ok = False
            else:
                self._last_login_time = time.time()
                logger.debug("💓 保活检查通过")
        except Exception as e:
            logger.warning(f"💔 保活检查异常: {e}")
            self._login_ok = False

    async def start_keepalive(self):
        """启动后台保活定时器"""
        async def _keepalive_loop():
            while True:
                await asyncio.sleep(5 * 60)  # 每 5 分钟检查一次
                try:
                    await self.check_and_refresh()
                except Exception as e:
                    logger.error(f"保活任务异常: {e}")

        self._keepalive_task = asyncio.create_task(_keepalive_loop())
        logger.info("💓 后台保活任务已启动 (每 5 分钟)")

    async def stop_keepalive(self):
        """停止后台保活"""
        if self._keepalive_task:
            self._keepalive_task.cancel()
            try:
                await self._keepalive_task
            except asyncio.CancelledError:
                pass

    async def close(self):
        """清理资源"""
        await self.stop_keepalive()
        if self._client:
            await self._client.aclose()


# ============================================================
# 全局会话管理器实例
# ============================================================

session_mgr = AuthSessionManager()


# ============================================================
# FastAPI 应用
# ============================================================


@asynccontextmanager
async def lifespan(app: FastAPI):
    """应用生命周期管理"""
    logger.info("=" * 60)
    logger.info("🚀 NWAFU DeepSeek Proxy Server 启动中...")
    logger.info(f"   目标: {TARGET_BASE}")
    logger.info(f"   用户: {USERNAME}")
    logger.info("=" * 60)

    # 启动时先执行一次登录
    try:
        await session_mgr.ensure_login()
        logger.info("✅ 初始登录成功!")
    except Exception as e:
        logger.error(f"❌ 初始登录失败: {e}")
        logger.error("   服务仍会启动, 后续请求时会重试登录")

    # 启动保活
    await session_mgr.start_keepalive()

    yield

    # 清理
    logger.info("🛑 正在关闭...")
    await session_mgr.close()


app = FastAPI(
    title="NWAFU DeepSeek Proxy",
    description="本地代理网关, 自动处理校园认证, 兼容 OpenAI API",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ============================================================
# 健康检查路由
# ============================================================


@app.get("/")
async def root():
    return {
        "service": "NWAFU DeepSeek Proxy",
        "status": "running",
        "target": TARGET_BASE,
        "login_ok": session_mgr._login_ok,
        "usage": {
            "api_base": f"http://localhost:{PROXY_PORT}/v1",
            "models_endpoint": f"http://localhost:{PROXY_PORT}/v1/models",
            "chat_endpoint": f"http://localhost:{PROXY_PORT}/v1/chat/completions",
            "embeddings_endpoint": f"http://localhost:{PROXY_PORT}/v1/embeddings",
            "rerank_endpoint": f"http://localhost:{PROXY_PORT}/v1/rerank",
        },
    }


@app.get("/health")
async def health():
    return {"status": "ok", "login_ok": session_mgr._login_ok}


# ============================================================
# 通用反向代理 —— 核心路由
# ============================================================



async def _proxy_request(request: Request, target_path: str) -> Response:
    """
    核心代理逻辑:
    1. 使用已认证的 session 转发请求
    2. 检测到 Cookie 过期时自动重新登录并重试
    3. 支持 SSE 流式响应
    """
    max_retries = 2

    for attempt in range(max_retries):
        client = await session_mgr.ensure_login()

        # 构建目标 URL
        target_url = f"{TARGET_BASE}{target_path}"
        if request.url.query:
            target_url += f"?{request.url.query}"

        # 构建请求头 (过滤掉 hop-by-hop 头)
        skip_headers = {
            "host", "connection", "keep-alive", "transfer-encoding",
            "te", "trailer", "upgrade", "proxy-authorization",
            "proxy-authenticate", "content-length",
            "authorization",  # 移除客户端发来的 auth, 由我们注入正确的
        }
        headers = {
            k: v for k, v in request.headers.items()
            if k.lower() not in skip_headers
        }
        headers["Host"] = TARGET_HOST

        # 注入 Open WebUI API Key (关键: CAS Cookie 通过中间件, Bearer Token 通过 Open WebUI)
        if OPENWEBUI_API_KEY:
            headers["Authorization"] = f"Bearer {OPENWEBUI_API_KEY}"

        # 读取请求体
        body = await request.body()

        try:
            # 检查是否需要流式传输
            is_stream = False
            if body:
                try:
                    body_json = json.loads(body)
                    is_stream = body_json.get("stream", False)
                except (json.JSONDecodeError, UnicodeDecodeError):
                    pass

            if is_stream:
                # SSE 流式响应
                req = client.build_request(
                    method=request.method,
                    url=target_url,
                    headers=headers,
                    content=body,
                )
                resp = await client.send(req, stream=True)

                # 检查是否被重定向到登录页
                if _is_auth_redirect(resp):
                    await resp.aclose()
                    if attempt < max_retries - 1:
                        logger.warning("🔄 流式请求被认证拦截, 重新登录...")
                        await session_mgr.force_relogin()
                        continue
                    return Response(
                        content=json.dumps({"error": "认证失败, 请检查账号密码"}),
                        status_code=401,
                        media_type="application/json",
                    )

                async def stream_generator():
                    try:
                        async for chunk in resp.aiter_bytes():
                            yield chunk
                    finally:
                        await resp.aclose()

                # 转发响应头
                resp_headers = dict(resp.headers)
                for h in ["content-length", "transfer-encoding", "content-encoding"]:
                    resp_headers.pop(h, None)

                return StreamingResponse(
                    stream_generator(),
                    status_code=resp.status_code,
                    headers=resp_headers,
                    media_type=resp.headers.get("content-type", "text/event-stream"),
                )

            else:
                # 普通请求
                resp = await client.request(
                    method=request.method,
                    url=target_url,
                    headers=headers,
                    content=body,
                    follow_redirects=False,
                )

                # 检查是否被重定向到登录页
                if _is_auth_redirect(resp):
                    if attempt < max_retries - 1:
                        logger.warning("🔄 请求被认证拦截, 重新登录...")
                        await session_mgr.force_relogin()
                        continue
                    return Response(
                        content=json.dumps({"error": "认证失败, 请检查账号密码"}),
                        status_code=401,
                        media_type="application/json",
                    )

                # 转发响应
                resp_headers = dict(resp.headers)
                for h in ["content-length", "transfer-encoding", "content-encoding"]:
                    resp_headers.pop(h, None)

                return Response(
                    content=resp.content,
                    status_code=resp.status_code,
                    headers=resp_headers,
                    media_type=resp.headers.get("content-type"),
                )

        except httpx.TimeoutException:
            logger.error(f"⏰ 请求超时: {target_url}")
            if attempt < max_retries - 1:
                continue
            return Response(
                content=json.dumps({"error": "请求超时"}),
                status_code=504,
                media_type="application/json",
            )
        except Exception as e:
            logger.error(f"❌ 代理请求异常: {e}")
            if attempt < max_retries - 1:
                await session_mgr.force_relogin()
                continue
            return Response(
                content=json.dumps({"error": str(e)}),
                status_code=502,
                media_type="application/json",
            )

    return Response(
        content=json.dumps({"error": "代理请求失败"}),
        status_code=502,
        media_type="application/json",
    )


def _is_auth_redirect(resp: httpx.Response) -> bool:
    """检测响应是否是 AuthServer 的认证重定向"""
    if resp.status_code in (301, 302):
        location = resp.headers.get("location", "")
        if "authserver" in location.lower() or "/login" in location.lower():
            return True
    # 有些情况下会返回 200 但内容是登录页 (仅对非流式响应检查)
    if resp.status_code == 200 and not resp.stream:
        content_type = resp.headers.get("content-type", "")
        if "text/html" in content_type:
            # API 应该返回 JSON, 如果返回 HTML 大概率是登录页
            return True
    return False


# ============================================================
# Rerank 模型支持 —— Jina / Cohere 兼容的 /v1/rerank 端点
# ============================================================


class RerankRequest(BaseModel):
    """标准 Jina / Cohere 兼容的 rerank 请求体"""
    model: str = Field(default="", description="Rerank 模型 ID, 留空则自动选择")
    query: str = Field(..., description="查询文本")
    documents: List[Any] = Field(..., description="待排序的文档列表 (字符串或字典)")
    top_n: Optional[int] = Field(default=None, description="返回前 N 个结果")
    return_documents: Optional[bool] = Field(default=True, description="是否在结果中包含文档内容")


class RerankResult(BaseModel):
    index: int
    relevance_score: float
    document: Optional[Dict[str, str]] = None


class RerankResponse(BaseModel):
    id: str = ""
    results: List[RerankResult] = []
    meta: Optional[Dict[str, Any]] = None


# 缓存已发现的 rerank 模型 ID
_rerank_model_cache: List[str] = []
_rerank_cache_time: float = 0
_RERANK_CACHE_TTL: float = 300  # 5 分钟缓存


async def _discover_rerank_models() -> List[str]:
    """从上游 /v1/models 自动发现 rerank 模型"""
    global _rerank_model_cache, _rerank_cache_time

    now = time.time()
    if _rerank_model_cache and (now - _rerank_cache_time) < _RERANK_CACHE_TTL:
        return _rerank_model_cache

    try:
        client = await session_mgr.ensure_login()
        headers = {"Host": TARGET_HOST}
        if OPENWEBUI_API_KEY:
            headers["Authorization"] = f"Bearer {OPENWEBUI_API_KEY}"

        resp = await client.get(
            f"{TARGET_BASE}/v1/models",
            headers=headers,
            follow_redirects=False,
        )

        if resp.status_code == 200:
            models = resp.json().get("data", [])
            rerank_ids = [
                m["id"] for m in models
                if "rerank" in m.get("id", "").lower()
            ]
            _rerank_model_cache = rerank_ids
            _rerank_cache_time = now
            if rerank_ids:
                logger.info(f"🔍 发现 {len(rerank_ids)} 个 rerank 模型: {rerank_ids}")
            else:
                logger.warning("⚠️  未发现 rerank 模型")
            return rerank_ids
    except Exception as e:
        logger.error(f"❌ 查询 rerank 模型失败: {e}")

    return _rerank_model_cache


def _extract_document_text(doc: Any) -> str:
    """从文档中提取纯文本 (支持字符串和 {text: ...} 格式)"""
    if isinstance(doc, str):
        return doc
    if isinstance(doc, dict):
        return doc.get("text", str(doc))
    return str(doc)


async def _rerank_via_upstream_api(
    client: httpx.AsyncClient,
    model: str,
    query: str,
    documents: List[str],
    top_n: Optional[int],
) -> tuple[Optional[List[dict]], str]:
    """
    策略 1: 直接转发到上游的 /api/v1/retrieval/rerank
    (Open WebUI 内部 RAG 接口, 部分版本可能可用)
    """
    headers = {"Host": TARGET_HOST, "Content-Type": "application/json"}
    if OPENWEBUI_API_KEY:
        headers["Authorization"] = f"Bearer {OPENWEBUI_API_KEY}"

    # 尝试 Jina/Cohere 标准格式的上游端点
    for endpoint in ["/v1/rerank", "/api/v1/retrieval/rerank"]:
        try:
            payload = {
                "model": model,
                "query": query,
                "documents": documents,
            }
            if top_n is not None:
                payload["top_n"] = top_n

            resp = await client.post(
                f"{TARGET_BASE}{endpoint}",
                headers=headers,
                json=payload,
                follow_redirects=False,
            )

            if _is_auth_redirect(resp):
                logger.debug(f"  → {endpoint} 被认证拦截")
                continue

            if resp.status_code == 200:
                data = resp.json()
                results = data.get("results", data.get("data", []))
                if results:
                    logger.info(f"  ✅ 上游 {endpoint} 返回 {len(results)} 条结果")
                    return results, model

            logger.debug(f"  → {endpoint} 返回 {resp.status_code}, 尝试下一个端点")

        except Exception as e:
            logger.debug(f"  → {endpoint} 调用异常: {e}")
            continue

    return None, model


async def _rerank_via_embeddings(
    client: httpx.AsyncClient,
    model: str,
    query: str,
    documents: List[str],
    top_n: Optional[int],
) -> tuple[Optional[List[dict]], str]:
    """
    策略 2: 使用 embeddings API 计算余弦相似度进行 rerank
    将 query 和 documents 一起发送给 embeddings API, 然后计算相似度
    """
    headers = {"Host": TARGET_HOST, "Content-Type": "application/json"}
    if OPENWEBUI_API_KEY:
        headers["Authorization"] = f"Bearer {OPENWEBUI_API_KEY}"

    try:
        # 找一个 embedding 模型
        resp = await client.get(
            f"{TARGET_BASE}/v1/models",
            headers={"Host": TARGET_HOST, **({
                "Authorization": f"Bearer {OPENWEBUI_API_KEY}"
            } if OPENWEBUI_API_KEY else {})},
            follow_redirects=False,
        )

        embed_model = None
        if resp.status_code == 200:
            models = resp.json().get("data", [])
            for m in models:
                mid = m.get("id", "").lower()
                is_embedding = any(kw in mid for kw in ["embed", "bge-m", "m3", "nomic", "minilm"])
                if is_embedding and "rerank" not in mid:
                    embed_model = m["id"]
                    break

        if not embed_model:
            logger.warning("⚠️  未找到 embedding 模型, 无法使用 embeddings 回退策略")
            return None, model

        # 将 query + documents 合并成一次 embedding 调用
        all_texts = [query] + documents
        resp = await client.post(
            f"{TARGET_BASE}/v1/embeddings",
            headers=headers,
            json={"model": embed_model, "input": all_texts},
            follow_redirects=False,
        )

        if resp.status_code != 200:
            logger.warning(f"⚠️  embeddings API 返回 {resp.status_code}")
            return None, model

        emb_data = resp.json().get("data", [])
        if len(emb_data) < 2:
            return None, model

        # 按 index 排序确保顺序正确
        emb_data.sort(key=lambda x: x.get("index", 0))
        query_vec = emb_data[0]["embedding"]
        doc_vecs = [d["embedding"] for d in emb_data[1:]]

        # 计算余弦相似度
        import math

        def cosine_sim(a, b):
            dot = sum(x * y for x, y in zip(a, b))
            norm_a = math.sqrt(sum(x * x for x in a))
            norm_b = math.sqrt(sum(x * x for x in b))
            if norm_a == 0 or norm_b == 0:
                return 0.0
            return dot / (norm_a * norm_b)

        scores = []
        for i, doc_vec in enumerate(doc_vecs):
            score = cosine_sim(query_vec, doc_vec)
            # 归一化到 [0, 1] 范围 (余弦相似度范围为 [-1, 1])
            normalized_score = (score + 1.0) / 2.0
            scores.append({"index": i, "relevance_score": round(normalized_score, 6)})

        # 按分数降序排列
        scores.sort(key=lambda x: x["relevance_score"], reverse=True)

        if top_n is not None:
            scores = scores[:top_n]

        logger.info(f"  ✅ embeddings 回退: 使用 {embed_model} 计算了 {len(scores)} 条相似度")
        return scores, embed_model

    except Exception as e:
        logger.error(f"❌ embeddings 回退失败: {e}")
        return None, model


@app.post("/v1/rerank")
async def rerank(request: Request):
    """
    Jina / Cohere 兼容的 Rerank API 端点

    请求格式:
    {
        "model": "bge-reranker-v2-m3",  // 可选, 留空自动选择
        "query": "搜索内容",
        "documents": ["文档1", "文档2", ...],
        "top_n": 3,                      // 可选
        "return_documents": true          // 可选
    }
    """
    try:
        body = await request.json()
    except Exception:
        return JSONResponse(
            status_code=400,
            content={"error": "无效的 JSON 请求体"},
        )

    try:
        req = RerankRequest(**body)
    except Exception as e:
        return JSONResponse(
            status_code=400,
            content={"error": f"请求参数错误: {e}"},
        )

    if not req.documents:
        return JSONResponse(
            status_code=400,
            content={"error": "documents 不能为空"},
        )

    # 提取文档纯文本
    doc_texts = [_extract_document_text(d) for d in req.documents]

    # 确定使用的模型
    model = req.model
    if not model:
        available = await _discover_rerank_models()
        if available:
            model = available[0]
            logger.info(f"🎯 自动选择 rerank 模型: {model}")
        else:
            model = ""  # 留空, 让回退策略处理

    logger.info(
        f"📊 Rerank 请求: model={model}, query={req.query[:50]}..., "
        f"docs={len(doc_texts)}, top_n={req.top_n}"
    )

    max_retries = 2
    for attempt in range(max_retries):
        client = await session_mgr.ensure_login()

        actual_model_used = model
        
        # 策略 1: 尝试上游 rerank API
        results, actual_model_used = await _rerank_via_upstream_api(
            client, model, req.query, doc_texts, req.top_n
        )

        # 策略 2: embeddings 回退
        if results is None:
            logger.info("  ℹ️  上游 rerank 不可用, 尝试 embeddings 回退...")
            results, actual_model_used = await _rerank_via_embeddings(
                client, model, req.query, doc_texts, req.top_n
            )

        if results is not None:
            # 构造标准响应
            response_results = []
            for r in results:
                item = RerankResult(
                    index=r["index"],
                    relevance_score=r["relevance_score"],
                )
                if req.return_documents:
                    idx = r["index"]
                    if 0 <= idx < len(doc_texts):
                        item.document = {"text": doc_texts[idx]}
                response_results.append(item)

            resp = RerankResponse(
                id=f"rerank-{int(time.time())}",
                results=response_results,
                meta={
                    "model": actual_model_used,
                    "query": req.query,
                    "total_docs": len(doc_texts),
                },
            )

            return JSONResponse(content=resp.model_dump())

        # 如果两个策略都失败, 尝试重新登录
        if attempt < max_retries - 1:
            logger.warning("🔄 rerank 请求失败, 尝试重新登录...")
            await session_mgr.force_relogin()

    return JSONResponse(
        status_code=502,
        content={"error": "Rerank 请求失败: 上游 API 不可用且无可用回退策略"},
    )


# ============================================================
# 注册代理路由
# ============================================================


@app.api_route("/v1/{path:path}", methods=["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS"])
async def proxy_v1(request: Request, path: str):
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
  NWAFU DeepSeek Proxy
  {'=' * 40}
  API Base:    http://localhost:{PROXY_PORT}/v1
  Target:      {TARGET_BASE}
  AuthServer:  {AUTH_SERVER}
  User:        {USERNAME}
  WebUI Key:   {api_key_hint}
  {'=' * 40}
  支持端点:
    - /v1/chat/completions  (对话)
    - /v1/embeddings        (向量嵌入)
    - /v1/rerank            (重排序)
    - /v1/models            (模型列表)
  {'=' * 40}
  客户端配置: API URL = http://localhost:{PROXY_PORT}/v1, API Key = 任意值
""")

    uvicorn.run(
        app,
        host="0.0.0.0",
        port=PROXY_PORT,
        log_level="info",
    )
