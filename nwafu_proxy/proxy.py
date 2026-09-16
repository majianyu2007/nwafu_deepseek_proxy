import asyncio
import json
import time
from typing import Optional

import httpx
from fastapi import Request, Response
from fastapi.responses import StreamingResponse

from nwafu_proxy.auth.detection import _check_auth_failure
from nwafu_proxy.auth.session import AuthSessionManager
from nwafu_proxy.auth.state import (
    CircuitOpenError,
    CriticalLoginError,
    UpstreamUnavailableError,
)
from nwafu_proxy.config import Settings
from nwafu_proxy.constants import (
    _RETRIABLE_NET_ERRORS,
    DEFAULT_TIMEOUT,
    DEGRADED_TIMEOUT,
    PROXY_MAX_RETRIES,
    RESPONSE_REWRITE_MAX_BYTES,
    STREAM_TIMEOUT,
)
from nwafu_proxy.logging import logger

HOP_BY_HOP_HEADERS = frozenset(
    {
        "host",
        "connection",
        "keep-alive",
        "transfer-encoding",
        "te",
        "trailer",
        "upgrade",
        "proxy-authorization",
        "proxy-authenticate",
        "content-length",
        "authorization",
        "accept-encoding",
        # 客户端 Cookie 属于本地代理域名，不能覆盖服务端维护的上游 CAS Cookie。
        "cookie",
    }
)

STRIP_RESPONSE_HEADERS = frozenset(
    {
        "content-length",
        "transfer-encoding",
        "content-encoding",
        # 上游安全策略不应直接应用到本地代理域名。
        "strict-transport-security",
        "content-security-policy",
        "content-security-policy-report-only",
    }
)

REWRITE_REQUEST_HEADERS = frozenset(
    {
        "origin",
        "referer",
    }
)

REWRITE_RESPONSE_HEADERS = frozenset(
    {
        "location",
    }
)

_AUTH_EXPIRED = object()


_STREAMING_PATH_PREFIXES = ("/api/chat/completions", "/v1/chat/completions", "/ollama", "/openai")
_STATIC_RESOURCE_SUFFIXES = (
    ".map",
    ".css",
    ".js",
    ".woff2",
    ".woff",
    ".ttf",
    ".eot",
    ".ico",
    ".png",
    ".jpg",
    ".jpeg",
    ".gif",
    ".svg",
    ".webp",
    ".woff2.map",
    ".js.map",
    ".css.map",
)


def _is_streaming_path(path: str) -> bool:
    return any(path.startswith(p) for p in _STREAMING_PATH_PREFIXES)


def _is_auth_irrelevant_path(path: str) -> bool:
    """判断路径是否无需触发重新登录。

    静态资源（.map, .css, .js, 图片等）的认证重定向不应触发完整的
    CAS 重新登录流程，避免并发请求造成登录风暴。
    """
    return any(path.endswith(suffix) for suffix in _STATIC_RESOURCE_SUFFIXES)


def _needs_long_timeout(path: str) -> bool:
    return _is_streaming_path(path)


async def _read_request_body(request: Request) -> tuple[bytes, bool]:
    body = await request.body()
    is_stream = False
    if body:
        try:
            body_json = json.loads(body)
            is_stream = isinstance(body_json, dict) and bool(body_json.get("stream", False))
        except (json.JSONDecodeError, UnicodeDecodeError, TypeError):
            pass
    return body, is_stream


def _needs_api_key(path: str) -> bool:
    return path.startswith("/v1/") or path.startswith("/openai/") or path.startswith("/ollama/")


def _strip_response_headers(headers: httpx.Headers) -> dict[str, str]:
    return {k: v for k, v in headers.items() if k.lower() not in STRIP_RESPONSE_HEADERS}


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


def _error_response(status_code: int, message: str, *, error_type: str | None = None) -> Response:
    body: dict = {"error": message}
    if error_type:
        body["type"] = error_type
    return Response(
        content=json.dumps(body, ensure_ascii=False),
        status_code=status_code,
        media_type="application/json",
    )


def _circuit_error_response(retry_after: int) -> Response:
    body = json.dumps(
        {
            "error": "auth_circuit_open",
            "message": "Login temporarily disabled to protect the campus account. Please retry later.",
        },
        ensure_ascii=False,
    )
    return Response(
        content=body,
        status_code=503,
        media_type="application/json",
        headers={"Retry-After": str(retry_after)},
    )


class ReverseProxy:
    """HTTP forwarding bound to one configuration and authentication session."""

    def __init__(self, settings: Settings, manager: AuthSessionManager):
        self.settings = settings
        self.manager = manager

    def _build_target_url(self, request: Request, target_path: str) -> str:
        target_url = f"{self.settings.target_base}{target_path}"
        if request.url.query:
            target_url += f"?{request.url.query}"
        return target_url

    def _build_forward_headers(self, request: Request, target_path: str) -> dict[str, str]:
        headers = {}
        for k, v in request.headers.items():
            kl = k.lower()
            if kl in HOP_BY_HOP_HEADERS:
                continue
            if kl in REWRITE_REQUEST_HEADERS and self.settings.target_base:
                # 将客户端 Origin/Referer 替换为上游地址
                headers[k] = self.settings.target_base
            else:
                headers[k] = v
        headers["Host"] = self.settings.target_host
        # 浏览器内的 OpenWebUI /api/* 请求依赖 CAS session cookie 和同一条
        # Socket.IO 会话接收异步任务结果。强行注入 API key 可能让任务归属到
        # token auth 上，而页面的 websocket 仍归属 cookie session，导致 WebUI
        # 只拿到 task_id 但迟迟收不到回复。
        if self.settings.openwebui_api_key and _needs_api_key(target_path):
            headers["Authorization"] = f"Bearer {self.settings.openwebui_api_key}"
        return headers

    def _rewrite_response_header_value(self, name: str, value: str) -> str:
        """将上游域名替换为本地位址（用于 Location 等头）"""
        if name.lower() in REWRITE_RESPONSE_HEADERS and self.settings.target_base in value:
            local_base = f"http://localhost:{self.settings.proxy_port}"
            return value.replace(self.settings.target_base, local_base)
        return value

    async def _rewrite_response_body(
        self, resp: httpx.Response, content_type: str, is_stream: bool
    ) -> bytes | None:
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

        local_base = f"http://localhost:{self.settings.proxy_port}"
        local_https_base = f"https://localhost:{self.settings.proxy_port}"
        target_origin = f"https://{self.settings.target_host}"
        rewritten = body.replace(
            self.settings.target_base.encode("utf-8"), local_base.encode("utf-8")
        )
        rewritten = rewritten.replace(target_origin.encode("utf-8"), local_base.encode("utf-8"))
        rewritten = rewritten.replace(local_https_base.encode("utf-8"), local_base.encode("utf-8"))
        return rewritten

    async def _forward(
        self,
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
            k: self._rewrite_response_header_value(k, v) for k, v in resp_headers.items()
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
            long_timeout
            and not response_is_sse
            and "application/json" in (media_type or "").lower()
        )
        rewritten_body = None
        if should_buffer_for_rewrite:
            rewritten_body = await self._rewrite_response_body(
                resp, media_type or "", response_is_sse
            )
            if long_timeout and not response_is_sse and rewritten_body is not None:
                preview = (
                    rewritten_body[:500].decode("utf-8", errors="replace").replace("\n", "\\n")
                )
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
                    error_payload = json.dumps(
                        {"error": "upstream connection lost"}, ensure_ascii=False
                    )
                    yield f"data: {error_payload}\n\n".encode("utf-8")
            finally:
                await resp.aclose()

        return StreamingResponse(
            stream_generator(),
            status_code=resp.status_code,
            headers=resp_headers,
            media_type=media_type,
        )

    async def handle(self, request: Request, target_path: str) -> Response:
        t0 = time.monotonic()
        body, is_stream = await _read_request_body(request)

        # 对话/生成类端点可能很慢，但不一定是 SSE。是否流式只由请求体
        # stream=true 或上游 Content-Type 决定，避免把普通 JSON 响应误当成流。
        long_timeout = _needs_long_timeout(target_path)

        # 上游降级模式：最近多个请求失败时使用短超时，避免客户端长时间等待
        degraded = self.manager.is_degraded()

        for attempt in range(PROXY_MAX_RETRIES):
            try:
                client = await self.manager.ensure_login()
            except CircuitOpenError as e:
                logger.warning("event=proxy_blocked reason=circuit_open path=%s", target_path)
                return _circuit_error_response(e.retry_after)
            except UpstreamUnavailableError as e:
                logger.warning(
                    "event=proxy_blocked reason=upstream_unavailable path=%s error=%s",
                    target_path,
                    e,
                )
                return _error_response(503, str(e), error_type="upstream_unavailable")
            except _RETRIABLE_NET_ERRORS as e:
                logger.warning("登录阶段网络异常：%s", e)
                return _error_response(
                    503, "上游暂时不可达，请稍后重试", error_type="upstream_unreachable"
                )
            except Exception as e:
                logger.error("登录失败：%s", e)
                return _error_response(503, "登录失败，请稍后重试", error_type="login_failed")

            target_url = self._build_target_url(request, target_path)
            headers = self._build_forward_headers(request, target_path)

            # 降级模式下使用短超时，避免客户端长时间挂起
            req_timeout = DEGRADED_TIMEOUT if degraded else None

            try:
                result = await self._forward(
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
                    # 静态资源（.map, .css, .js 等）遇到认证重定向时，
                    # 不触发重新登录，直接返回 502。客户端刷新页面时会重新
                    # 通过完整页面请求完成认证。
                    if _is_auth_irrelevant_path(target_path):
                        return _error_response(
                            502, "静态资源认证过期，请刷新页面", error_type="static_auth_expired"
                        )

                    # 登录后立即被认证中间件拒绝时，抑制连续重登以保护账号。
                    if self.manager.recent_login_rejected():
                        logger.warning(
                            "event=auth_session_not_accepted path=%s action=suppress_relogin",
                            target_path,
                        )
                        return _error_response(
                            502, "上游认证会话未被接受", error_type="upstream_auth_session_rejected"
                        )

                    if attempt < PROXY_MAX_RETRIES - 1:
                        logger.warning(
                            "event=proxy_auth_expired path=%s attempt=%d", target_path, attempt + 1
                        )
                        try:
                            await self.manager.force_relogin()
                        except (CircuitOpenError, UpstreamUnavailableError, CriticalLoginError):
                            pass
                        await asyncio.sleep(1)
                        continue
                    return _error_response(
                        401, "认证失败, 请检查账号密码", error_type="auth_failed"
                    )

                elapsed = int((time.monotonic() - t0) * 1000)
                status_code = getattr(result, "status_code", 0)
                self.manager.record_proxy_response(status_code)
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
                self.manager.record_proxy_failure("proxy:upstream_timeout")
                if degraded:
                    logger.warning(
                        "上游请求超时（降级模式，ms=%d, url=%s）", elapsed, target_url[:100]
                    )
                else:
                    logger.error("上游请求超时（ms=%d, url=%s）", elapsed, target_url[:100])
                if attempt < PROXY_MAX_RETRIES - 1:
                    await asyncio.sleep(1)
                    degraded = True  # 重试时强制降级
                    continue
                return _error_response(504, "上游请求超时", error_type="upstream_timeout")

            except _RETRIABLE_NET_ERRORS as e:
                elapsed = int((time.monotonic() - t0) * 1000)
                self.manager.record_proxy_failure("proxy:network_error")
                logger.warning("上游网络异常：%s（ms=%d, url=%s）", e, elapsed, target_url[:100])
                if attempt < PROXY_MAX_RETRIES - 1:
                    await asyncio.sleep(0.5 * (2**attempt))
                    degraded = True  # 重试时强制降级
                    continue
                return _error_response(
                    503, "上游暂时不可达，请稍后重试", error_type="upstream_unreachable"
                )

            except Exception:
                elapsed = int((time.monotonic() - t0) * 1000)
                logger.exception("代理异常（ms=%d）", elapsed)
                return _error_response(502, "代理异常", error_type="proxy_error")

        return _error_response(502, "代理请求失败", error_type="proxy_exhausted")
