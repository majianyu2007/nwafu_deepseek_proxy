"""Offline regression tests: no campus credentials or network required."""

import asyncio
import os
import tempfile
import time
import unittest
from dataclasses import replace
from pathlib import Path
from unittest.mock import AsyncMock, patch

import httpx
from starlette.requests import Request

from nwafu_proxy.auth.detection import _check_auth_failure
from nwafu_proxy.auth.session import AuthSessionManager
from nwafu_proxy.auth.state import AuthState, CircuitOpenError, CriticalLoginError
from nwafu_proxy.config import load_settings
from nwafu_proxy.proxy import ReverseProxy


def settings_for(data_dir):
    with (
        patch.dict(
            os.environ,
            {
                "NWAFU_USERNAME": "test-user",
                "NWAFU_PASSWORD": "test-password",
                "OPENWEBUI_API_KEY": "test-key",
            },
            clear=True,
        ),
        patch("nwafu_proxy.config.load_dotenv"),
    ):
        return replace(load_settings(), data_dir=Path(data_dir))


def request(path, body=b"", headers=()):
    async def receive():
        return {"type": "http.request", "body": body, "more_body": False}

    return Request(
        {
            "type": "http",
            "http_version": "1.1",
            "method": "POST",
            "scheme": "http",
            "path": path,
            "raw_path": path.encode(),
            "query_string": b"q=one%20two",
            "headers": list(headers),
            "server": ("localhost", 8000),
            "client": ("127.0.0.1", 1),
        },
        receive,
    )


class TrackingStream(httpx.AsyncByteStream):
    def __init__(self):
        self.reads = 0
        self.closed = False

    async def __aiter__(self):
        for chunk in (b"data: first\n\n", b"data: second\n\n"):
            self.reads += 1
            yield chunk

    async def aclose(self):
        self.closed = True


class Contracts(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.settings = settings_for(self.temp.name)
        self.manager = AuthSessionManager(self.settings)
        self.proxy = ReverseProxy(self.settings, self.manager)
        self.addAsyncCleanup(self.manager.close)

    async def test_auth_redirect_detection(self):
        for url in (
            "https://authserver.nwafu.edu.cn/authserver/login?service=x",
            "https://vouch.nwafu.edu.cn/login",
            "/.auth/login/cas",
        ):
            self.assertTrue(
                await _check_auth_failure(httpx.Response(302, headers={"location": url}), False)
            )
        for url in ("https://authserver.nwafu.edu.cn.evil.test/authserver/login", "/other"):
            self.assertFalse(
                await _check_auth_failure(httpx.Response(302, headers={"location": url}), False)
            )

    async def test_api_errors_do_not_trigger_auth(self):
        for status in (401, 403, 502, 503):
            self.assertFalse(
                await _check_auth_failure(httpx.Response(status, json={"error": "failed"}), False)
            )

    async def test_stream_auth_detection_does_not_read_body(self):
        stream = TrackingStream()
        response = httpx.Response(403, headers={"content-type": "text/html"}, stream=stream)
        self.assertFalse(await _check_auth_failure(response, True))
        self.assertEqual(stream.reads, 0)
        await response.aclose()

    async def test_api_key_and_cookie_boundaries(self):
        req = request(
            "/v1/models", headers=[(b"authorization", b"Bearer caller"), (b"cookie", b"local=1")]
        )
        headers = self.proxy._build_forward_headers(req, "/v1/models")
        self.assertEqual(headers["Authorization"], "Bearer test-key")
        self.assertNotIn("cookie", headers)
        self.assertNotIn(
            "Authorization", self.proxy._build_forward_headers(req, "/api/chat/completions")
        )

    async def test_query_and_response_url_rewrite(self):
        self.assertEqual(
            self.proxy._build_target_url(request("/v1/models"), "/v1/models"),
            "https://deepseek.nwafu.edu.cn/v1/models?q=one%20two",
        )
        self.assertEqual(
            self.proxy._rewrite_response_header_value(
                "location", "https://deepseek.nwafu.edu.cn/chat"
            ),
            "http://localhost:8000/chat",
        )

    async def test_sse_forwarding_is_lazy_and_closes_upstream(self):
        stream = TrackingStream()
        async with httpx.AsyncClient(
            transport=httpx.MockTransport(
                lambda req: httpx.Response(
                    200, headers={"content-type": "text/event-stream"}, stream=stream
                )
            )
        ) as client:
            response = await self.proxy._forward(
                client,
                method="POST",
                url="https://example.test/chat",
                headers={},
                body=b"{}",
                is_stream=True,
                long_timeout=True,
            )
            self.assertEqual(stream.reads, 0)
            self.assertEqual(await anext(response.body_iterator), b"data: first\n\n")
            self.assertEqual(stream.reads, 1)
            await response.body_iterator.aclose()
            self.assertTrue(stream.closed)

    async def test_suspect_reuses_session_without_login(self):
        self.manager.auth.client = httpx.AsyncClient(trust_env=False)
        self.manager._state = AuthState.SUSPECT
        with patch.object(self.manager.auth, "login", new_callable=AsyncMock) as login:
            self.assertIs(await self.manager.ensure_login(), self.manager.auth.client)
            login.assert_not_awaited()

    async def test_circuit_blocks_login_without_session(self):
        self.manager._state = AuthState.CIRCUIT_OPEN
        self.manager._circuit_until = time.monotonic() + 600
        with patch.object(self.manager.auth, "login", new_callable=AsyncMock) as login:
            with self.assertRaises(CircuitOpenError):
                await self.manager.ensure_login()
            login.assert_not_awaited()

    async def test_concurrent_requests_share_one_login(self):
        async def login(*args):
            await asyncio.sleep(0)
            self.manager.auth.client = httpx.AsyncClient(trust_env=False)

        with patch.object(self.manager.auth, "login", side_effect=login) as mocked:
            clients = await asyncio.gather(*(self.manager.ensure_login() for _ in range(8)))
            self.assertEqual(mocked.await_count, 1)
            self.assertTrue(all(c is clients[0] for c in clients))

    async def test_password_error_opens_circuit(self):
        with patch.object(
            self.manager.auth, "login", side_effect=CriticalLoginError("bad credentials", 3600)
        ):
            with self.assertRaises(CriticalLoginError):
                await self.manager.ensure_login()
        self.assertEqual(self.manager.state, AuthState.CIRCUIT_OPEN)
        self.assertGreater(self.manager._circuit_until - time.monotonic(), 3500)


if __name__ == "__main__":
    unittest.main()
