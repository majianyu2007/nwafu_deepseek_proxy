"""Integration tests exercise isolated apps with simulated upstream responses."""

import asyncio
import os
import subprocess
import sys
import tempfile
import time
import unittest
from contextlib import asynccontextmanager
from dataclasses import replace
from pathlib import Path
from unittest.mock import AsyncMock, patch

import httpx
from starlette.datastructures import URL
from test_contracts import request, settings_for

from nwafu_proxy.app import create_app
from nwafu_proxy.auth.session import AuthSessionManager
from nwafu_proxy.auth.state import (
    AuthState,
    CircuitOpenError,
    TwoFactorError,
    UpstreamUnavailableError,
)
from nwafu_proxy.auth.storage import SessionStore
from nwafu_proxy.proxy import ReverseProxy, _read_request_body
from nwafu_proxy.websocket import WebSocketProxy


class ApplicationTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.settings = settings_for(self.temp.name)
        self.manager = AuthSessionManager(self.settings)
        self.addAsyncCleanup(self.manager.close)

    def upstream(self, handler):
        client = httpx.AsyncClient(transport=httpx.MockTransport(handler), trust_env=False)
        self.manager.auth.client = client
        self.manager._last_login_time = time.monotonic()
        return client

    async def test_two_apps_keep_settings_and_sessions_separate(self):
        first_requests, second_requests = [], []

        def reply(calls):
            def handler(req):
                calls.append(req)
                return httpx.Response(200, json={"url": str(req.url)})

            return handler

        self.upstream(reply(first_requests))
        other_settings = replace(
            self.settings,
            target_host="second.test",
            proxy_port=8999,
            openwebui_api_key="second-key",
            data_dir=Path(self.temp.name) / "second",
        )
        other = AuthSessionManager(other_settings)
        other.auth.client = httpx.AsyncClient(
            transport=httpx.MockTransport(reply(second_requests)), trust_env=False
        )
        other._last_login_time = time.monotonic()
        self.addAsyncCleanup(other.close)
        for settings, manager, calls in (
            (self.settings, self.manager, first_requests),
            (other_settings, other, second_requests),
        ):
            app = create_app(settings, manager)
            async with httpx.AsyncClient(
                transport=httpx.ASGITransport(app), base_url="http://local"
            ) as client:
                response = await client.get("/v1/models?q=a%20b&_prefix=wrong")
                self.assertEqual(response.status_code, 200)
                self.assertIn("X-Request-ID", response.headers)
                self.assertEqual(calls[-1].url.host, settings.target_host)
                self.assertEqual(calls[-1].url.path, "/v1/models")
                self.assertEqual(
                    calls[-1].headers["authorization"], f"Bearer {settings.openwebui_api_key}"
                )
                self.assertIn(
                    f"http://localhost:{settings.proxy_port}/v1/models", response.json()["url"]
                )
                calls.clear()
                response = await client.get("/totp")
                self.assertIn("无需输入", response.text)
                self.assertFalse(calls)

    async def test_health_auth_redirect_never_logs_in(self):
        self.upstream(
            lambda req: httpx.Response(
                302, headers={"location": "https://vouch.nwafu.edu.cn/login"}
            )
        )
        app = create_app(self.settings, self.manager)
        with (
            patch.object(self.manager, "force_relogin", new_callable=AsyncMock) as force,
            patch.object(self.manager, "ensure_login", new_callable=AsyncMock) as ensure,
        ):
            async with httpx.AsyncClient(
                transport=httpx.ASGITransport(app), base_url="http://local"
            ) as client:
                response = await client.get("/health")
            await asyncio.sleep(0)
            self.assertEqual(response.status_code, 503)
            self.assertEqual(response.json()["status"], "unhealthy")
            force.assert_not_awaited()
            ensure.assert_not_awaited()

    async def test_health_upstream_error_is_not_healthy(self):
        self.upstream(lambda req: httpx.Response(503))
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(create_app(self.settings, self.manager)),
            base_url="http://local",
        ) as client:
            response = await client.get("/health")
        self.assertEqual(response.status_code, 503)
        self.assertEqual(response.json()["status"], "degraded")

    async def test_lifespan_retains_circuit_and_closes_resources(self):
        self.manager._consecutive_failures = 3
        self.manager._open_circuit(600, "test")
        restored = AuthSessionManager(self.settings)
        with patch.object(restored.auth, "login", new_callable=AsyncMock) as login:
            app = create_app(self.settings, restored)
            async with app.router.lifespan_context(app):
                self.assertEqual(restored.state, AuthState.CIRCUIT_OPEN)
                self.assertEqual(restored._consecutive_failures, 3)
                self.assertGreater(restored.diagnostics()["circuit_remaining_seconds"], 500)
                self.assertIsNotNone(restored._keepalive_task)
            login.assert_not_awaited()
            self.assertTrue(restored._keepalive_task.done())

    async def test_force_relogin_cannot_clear_active_circuit_or_backoff(self):
        with patch.object(self.manager.auth, "login", new_callable=AsyncMock) as login:
            self.manager._state = AuthState.CIRCUIT_OPEN
            self.manager._circuit_until = time.monotonic() + 600
            with self.assertRaises(CircuitOpenError):
                await self.manager.force_relogin()
            self.assertEqual(self.manager.state, AuthState.CIRCUIT_OPEN)
            self.manager._state = AuthState.LOGIN_BACKOFF
            self.manager._backoff_until = time.monotonic() + 60
            with self.assertRaises(UpstreamUnavailableError):
                await self.manager.force_relogin()
            self.assertEqual(self.manager.state, AuthState.LOGIN_BACKOFF)
            login.assert_not_awaited()

    async def test_cookie_restore_is_single_flight(self):
        async def restore():
            await asyncio.sleep(0)
            self.upstream(lambda req: httpx.Response(200))
            return True

        with (
            patch.object(self.manager, "_restore_session", side_effect=restore) as restore_mock,
            patch.object(self.manager.auth, "login", new_callable=AsyncMock) as login,
        ):
            clients = await asyncio.gather(*(self.manager.ensure_login() for _ in range(8)))
            self.assertTrue(all(client is clients[0] for client in clients))
            self.assertEqual(restore_mock.await_count, 1)
            login.assert_not_awaited()

    async def test_cookie_restore_keeps_active_circuit(self):
        store = SessionStore(self.settings.data_dir)
        store._write(
            "cookies.json",
            [
                {
                    "Name": "CASTGC",
                    "Value": "test-cookie",
                    "Domain": "authserver.nwafu.edu.cn",
                    "Path": "/",
                }
            ],
        )
        self.manager._state = AuthState.CIRCUIT_OPEN
        self.manager._circuit_until = time.monotonic() + 600
        client = httpx.AsyncClient(
            transport=httpx.MockTransport(lambda req: httpx.Response(200)), trust_env=False
        )
        with (
            patch.object(self.manager.auth, "create_client", return_value=client),
            patch.object(self.manager.auth, "login", new_callable=AsyncMock) as login,
        ):
            self.assertIs(await self.manager.ensure_login(), client)
            self.assertEqual(self.manager.state, AuthState.CIRCUIT_OPEN)
            self.assertEqual(client.cookies.get("CASTGC"), "test-cookie")
            login.assert_not_awaited()

    async def test_monitor_uses_existing_session_and_never_relogs(self):
        self.upstream(
            lambda req: httpx.Response(
                302, headers={"location": "https://vouch.nwafu.edu.cn/login"}
            )
        )
        settings = replace(self.settings, monitor_enabled=True)
        self.manager.settings = settings
        app = create_app(settings, self.manager)
        with (
            patch.object(self.manager, "ensure_login", new_callable=AsyncMock) as ensure,
            patch.object(self.manager, "force_relogin", new_callable=AsyncMock) as force,
        ):
            await app.state.monitor.poll_once()
            ensure.assert_not_awaited()
            force.assert_not_awaited()
        self.assertFalse(app.state.monitor.status["last_poll_ok"])
        self.manager._state = AuthState.SUSPECT
        with patch.object(app.state.monitor, "fetch_models", new_callable=AsyncMock) as fetch:
            await app.state.monitor.poll_once()
            fetch.assert_not_awaited()

    async def test_totp_form_submission_and_assets(self):
        self.manager.auth._totp_pending = True
        app = create_app(self.settings, self.manager)
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app), base_url="http://local"
        ) as client:
            page = await client.get("/totp")
            self.assertIn("输入 TOTP 安全令牌", page.text)
            self.assertNotIn("{{remaining}}", page.text)
            self.assertIn('pattern="[0-9]{6}"', page.text)
            self.assertEqual((await client.post("/totp", data={"code": "abc"})).status_code, 400)
            response = await client.post("/totp", data={"code": "123456"})
        self.assertEqual(response.status_code, 200)
        self.assertEqual(self.manager.auth._totp_code, "123456")
        self.assertTrue(self.manager.auth._totp_ready.is_set())

    async def test_non_object_json_request_is_forwardable(self):
        for body in (b"[]", b"null", b"123", b'"text"'):
            actual, streaming = await _read_request_body(request("/api/test", body))
            self.assertEqual(actual, body)
            self.assertFalse(streaming)

    async def test_static_auth_redirect_does_not_relogin(self):
        self.upstream(
            lambda req: httpx.Response(
                302, headers={"location": "https://vouch.nwafu.edu.cn/login"}
            )
        )
        proxy = ReverseProxy(self.settings, self.manager)
        with patch.object(self.manager, "force_relogin", new_callable=AsyncMock) as force:
            response = await proxy.handle(request("/assets/main.js"), "/assets/main.js")
            self.assertEqual(response.status_code, 502)
            force.assert_not_awaited()

    async def test_upstream_network_error_preserves_login_protection(self):
        for state in (AuthState.CIRCUIT_OPEN, AuthState.LOGIN_BACKOFF):
            self.manager._state = state
            self.manager.record_proxy_failure("test")
            self.assertEqual(self.manager.state, state)

    async def test_cas_relative_redirect_navigation(self):
        seen = []

        def handler(req):
            seen.append(str(req.url))
            if req.url.path == "/":
                return httpx.Response(200)
            if req.url.path == "/api/config":
                return httpx.Response(302, headers={"location": "/start"})
            if req.url.path == "/start":
                return httpx.Response(
                    302,
                    headers={
                        "location": "https://authserver.nwafu.edu.cn/authserver/login?service=test"
                    },
                )
            return httpx.Response(200, text='<input id="execution" value="abc">')

        self.upstream(handler)
        url, response = await self.manager.auth._navigate_to_login_page()
        self.assertEqual(url, seen[-1])
        self.assertEqual(response.status_code, 200)
        self.assertEqual(len(seen), 4)
        self.assertEqual(seen[2], "https://deepseek.nwafu.edu.cn/start")

    async def test_manual_totp_rejection_raises_two_factor_error(self):
        auth = self.manager.auth
        responses = [
            httpx.Response(200, json={"code": "1"}),
            httpx.Response(200, json={"code": "failed", "msg": "code error"}),
        ]
        with patch.object(auth, "_retry_request", side_effect=responses):
            task = asyncio.create_task(auth._complete_2fa("https://deepseek.nwafu.edu.cn/"))
            for _ in range(10):
                if auth.totp_pending:
                    break
                await asyncio.sleep(0)
            self.assertTrue(auth.submit_totp("123456"))
            with self.assertRaises(TwoFactorError):
                await task
        self.assertFalse(auth.totp_pending)

    async def test_password_login_flow_establishes_cookie_session(self):
        from urllib.parse import parse_qs

        posted = []

        def handler(req):
            if req.method == "POST":
                posted.append(parse_qs(req.content.decode()))
                return httpx.Response(
                    302, headers={"location": self.settings.target_base + "/callback"}
                )
            if req.url.path == "/callback":
                return httpx.Response(200, headers={"set-cookie": "session=authenticated; Path=/"})
            if req.url.path == "/api/config" and req.method == "HEAD":
                self.assertIn("session=authenticated", req.headers.get("cookie", ""))
                return httpx.Response(200)
            if req.url.host == "authserver.nwafu.edu.cn":
                return httpx.Response(
                    200,
                    text='<input id="execution" value="ticket"><input id="pwdEncryptSalt" value="1234567890abcdef">',
                )
            return httpx.Response(
                302, headers={"location": "https://authserver.nwafu.edu.cn/authserver/login"}
            )

        client = httpx.AsyncClient(transport=httpx.MockTransport(handler), trust_env=False)
        with patch.object(self.manager.auth, "create_client", return_value=client):
            self.assertIs(await self.manager.ensure_login(), client)
        self.assertEqual(posted[0]["username"], ["test-user"])
        self.assertNotEqual(posted[0]["password"], ["test-password"])
        self.assertEqual(self.manager.state, AuthState.OK)
        self.assertTrue((self.settings.data_dir / "cookies.json").is_file())

    async def test_keepalive_network_error_does_not_login(self):
        def handler(req):
            raise httpx.ConnectError("offline", request=req)

        self.upstream(handler)
        with patch.object(self.manager.auth, "login", new_callable=AsyncMock) as login:
            await self.manager.check_and_refresh()
            self.assertEqual(self.manager.state, AuthState.SUSPECT)
            login.assert_not_awaited()

    async def test_lifespan_exception_closes_session(self):
        client = self.upstream(lambda req: httpx.Response(200))
        app = create_app(self.settings, self.manager)
        with self.assertRaisesRegex(RuntimeError, "test failure"):
            async with app.router.lifespan_context(app):
                raise RuntimeError("test failure")
        self.assertTrue(client.is_closed)
        self.assertTrue(self.manager._keepalive_task.done())

    async def test_websocket_relays_text_bytes_and_uses_instance_headers(self):
        client = self.upstream(lambda req: httpx.Response(200))
        client.cookies.set("session", "upstream", domain=self.settings.target_host)
        queue = asyncio.Queue()
        disconnected = asyncio.Event()
        messages = iter(
            [
                {"type": "websocket.receive", "text": "hello"},
                {"type": "websocket.receive", "bytes": b"bytes"},
            ]
        )

        async def receive():
            try:
                return next(messages)
            except StopIteration:
                await disconnected.wait()
                return {"type": "websocket.disconnect"}

        delivered = []

        async def deliver(message):
            delivered.append(message)
            if len(delivered) == 2:
                disconnected.set()

        ws = AsyncMock()
        ws.url = URL("http://local/ws?transport=websocket")
        ws.headers = {
            "cookie": "local=wrong",
            "authorization": "Bearer wrong",
            "user-agent": "local-agent",
        }
        ws.receive.side_effect = receive
        ws.send_text.side_effect = deliver
        ws.send_bytes.side_effect = deliver

        class Upstream:
            async def send(self, message):
                await queue.put(message)

            def __aiter__(self):
                return self

            async def __anext__(self):
                return await queue.get()

        captured = {}

        @asynccontextmanager
        async def connect(url, **kwargs):
            captured.update(url=url, **kwargs)
            yield Upstream()

        with patch("nwafu_proxy.websocket.websocket_connect", side_effect=connect):
            await asyncio.wait_for(WebSocketProxy(self.settings, self.manager).handle(ws, "/ws"), 1)
        self.assertEqual(delivered, ["hello", b"bytes"])
        self.assertEqual(captured["url"], "wss://deepseek.nwafu.edu.cn/ws?transport=websocket")
        self.assertEqual(captured["additional_headers"]["Cookie"], "session=upstream")
        self.assertNotIn("authorization", captured["additional_headers"])
        self.assertEqual(captured["origin"], self.settings.target_base)


class StorageAndImportTests(unittest.TestCase):
    def test_circuit_elapsed_time_survives_restart(self):
        with tempfile.TemporaryDirectory() as tmp:
            settings = settings_for(tmp)
            store = SessionStore(settings.data_dir)
            store.save_state(
                {
                    "saved_at": time.time() - 120,
                    "circuit_remaining": 600,
                    "attempts": [],
                    "consecutive_failures": 3,
                }
            )
            manager = AuthSessionManager(settings)
            self.assertGreater(manager.diagnostics()["circuit_remaining_seconds"], 470)
            self.assertLess(manager.diagnostics()["circuit_remaining_seconds"], 481)

    def test_import_requires_no_credentials_or_files(self):
        env = {k: v for k, v in os.environ.items() if not k.startswith(("NWAFU_", "OPENWEBUI_"))}
        result = subprocess.run(
            [
                sys.executable,
                "-c",
                'import server; import nwafu_proxy.app; assert "app" not in vars(server)',
            ],
            env=env,
            capture_output=True,
            text=True,
        )
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_legacy_and_cli_entry_points_build_app(self):
        import server
        from nwafu_proxy import cli

        with tempfile.TemporaryDirectory() as tmp:
            settings = settings_for(tmp)
            app = create_app(settings)
            with (
                patch.object(cli, "configure_logging"),
                patch.object(cli, "load_settings", return_value=settings),
                patch.object(cli, "create_app", return_value=app),
                patch.object(cli.uvicorn, "run") as run,
            ):
                cli.main()
                self.assertIs(run.call_args.args[0], app)
            with (
                patch("nwafu_proxy.logging.configure_logging"),
                patch.object(server, "create_app", return_value=app),
            ):
                try:
                    self.assertIs(server.app, app)
                finally:
                    vars(server).pop("app", None)
