import asyncio
import time
from urllib.parse import urlparse

import httpx
import websockets
from fastapi import WebSocket, WebSocketDisconnect
from websockets.asyncio.client import connect as websocket_connect

from nwafu_proxy.auth.session import AuthSessionManager
from nwafu_proxy.auth.state import CircuitOpenError
from nwafu_proxy.config import Settings
from nwafu_proxy.logging import logger


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


class WebSocketProxy:
    """Bidirectional websocket forwarding using the same authenticated session."""

    def __init__(self, settings: Settings, manager: AuthSessionManager):
        self.settings = settings
        self.manager = manager

    async def handle(self, client_ws: WebSocket, target_path: str):
        """双向代理 WebSocket 连接"""
        t0 = time.monotonic()
        await client_ws.accept()

        try:
            http_client = await self.manager.ensure_login()
        except CircuitOpenError:
            await client_ws.close(code=1013, reason="Auth circuit open")
            return
        except Exception as e:
            logger.warning("WebSocket 登录失败：%s", e)
            await client_ws.close(code=1013, reason="Login failed")
            return

        # 构建上游 WebSocket URL
        ws_scheme = "wss"
        target_url = f"{ws_scheme}://{self.settings.target_host}{target_path}"
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
            "host",
            "connection",
            "upgrade",
            "sec-websocket-key",
            "sec-websocket-version",
            "sec-websocket-extensions",
            "sec-websocket-protocol",
            "origin",
            "user-agent",
            "authorization",
            "cookie",
            "content-length",
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
                origin=self.settings.target_base,
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
                                    logger.debug(
                                        "event=ws_frame direction=client_to_upstream type=text len=%d",
                                        len(data["text"]),
                                    )
                                    await upstream_ws.send(data["text"])
                                elif "bytes" in data:
                                    logger.debug(
                                        "event=ws_frame direction=client_to_upstream type=bytes len=%d",
                                        len(data["bytes"]),
                                    )
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
                                logger.debug(
                                    "event=ws_frame direction=upstream_to_client type=text len=%d",
                                    len(message),
                                )
                                await client_ws.send_text(message)
                            elif isinstance(message, bytes):
                                logger.debug(
                                    "event=ws_frame direction=upstream_to_client type=bytes len=%d",
                                    len(message),
                                )
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
