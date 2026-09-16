import secrets
import time
from contextlib import asynccontextmanager
from typing import Optional

from fastapi import FastAPI, Request, Response
from fastapi.middleware.cors import CORSMiddleware

from nwafu_proxy.auth.session import AuthSessionManager
from nwafu_proxy.auth.state import AuthState
from nwafu_proxy.config import Settings, load_settings
from nwafu_proxy.logging import logger, request_id_ctx
from nwafu_proxy.proxy import ReverseProxy
from nwafu_proxy.routes.health import register_health_routes
from nwafu_proxy.routes.proxy import register_proxy_routes
from nwafu_proxy.routes.totp import register_totp_routes
from nwafu_proxy.websocket import WebSocketProxy


def create_app(
    _settings: Settings | None = None, manager: AuthSessionManager | None = None
) -> FastAPI:
    """Construct an isolated app; network activity starts only inside lifespan."""
    _settings = _settings or (manager.settings if manager else load_settings())
    manager = manager or AuthSessionManager(_settings)
    if manager.settings != _settings:
        raise ValueError("manager and app must use the same settings")
    monitor = None

    @asynccontextmanager
    async def _lifespan(_app: FastAPI):
        logger.info("服务启动：target=%s user=%s", _settings.target_base, _settings.username)

        try:
            try:
                await manager.ensure_login()
                logger.info("初始登录成功")
            except Exception as e:
                logger.error("初始登录失败：%s（服务将继续启动；后续请求会触发重试）", e)

            await manager.start_keepalive()

            if monitor:
                await monitor.start()
                logger.info("模型监控已启用（间隔 %ds）", _settings.monitor_poll_interval)

            yield
        finally:
            logger.info("服务关闭中")
            try:
                if monitor:
                    await monitor.stop()
            finally:
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

            request_id_ctx.reset(token)

    _app.add_middleware(
        CORSMiddleware,
        allow_origins=_settings.cors_origins,
        allow_credentials=False,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    register_totp_routes(_app, manager)
    register_health_routes(_app, _settings, manager)

    # 本地监控路由必须先于代理 catch-all 注册
    if _settings.monitor_enabled:
        try:
            from nwafu_proxy.monitor import create_monitor, register_monitor_routes

            monitor = create_monitor(
                _settings, lambda: manager.state == AuthState.OK, fetch_models=manager.fetch_models
            )
            register_monitor_routes(_app, monitor)
            n_routes = len(_app.routes)
            monitor_routes = [
                r.path for r in _app.routes if "monitor" in str(getattr(r, "path", ""))
            ]
            logger.info("模型监控路由已注册（共 %d 条路由, monitor=%s）", n_routes, monitor_routes)
        except Exception as e:
            logger.error("模型监控初始化失败：%s", e)

    _app.state.settings = _settings
    _app.state.session = manager
    _app.state.monitor = monitor
    register_proxy_routes(
        _app, ReverseProxy(_settings, manager), WebSocketProxy(_settings, manager)
    )
    return _app
