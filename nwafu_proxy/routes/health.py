import time

from fastapi import FastAPI, Response

from nwafu_proxy.auth.detection import _is_cas_login_url, _is_vouch_login_url
from nwafu_proxy.auth.session import AuthSessionManager
from nwafu_proxy.auth.state import AuthState
from nwafu_proxy.config import Settings


def register_health_routes(app: FastAPI, settings: Settings, manager: AuthSessionManager) -> None:
    @app.get("/health")
    async def health(response: Response):
        """健康检查：报告认证状态、上游可达性和会话有效性。

        不会触发登录，仅使用已有 client 做轻量验证。
        """
        diagnostics = manager.diagnostics()

        state = manager.state
        state_value = state.value

        # 基础信息
        result = {
            "service": "NWAFU DeepSeek Proxy",
            "target": settings.target_base,
            "api_base": f"http://localhost:{settings.proxy_port}/v1",
            "auth_state": state_value,
        }

        # 熔断信息
        if state == AuthState.CIRCUIT_OPEN:
            remaining = diagnostics["circuit_remaining_seconds"]
            result["status"] = "degraded"
            result["circuit_remaining_seconds"] = remaining
            result["note"] = "登录已熔断，请稍后重试"
            response.headers["Retry-After"] = str(remaining)
            response.status_code = 503
            return result

        # 退避信息
        if state == AuthState.LOGIN_BACKOFF:
            remaining = diagnostics["backoff_remaining_seconds"]
            result["status"] = "degraded"
            result["backoff_remaining_seconds"] = remaining
            result["note"] = "登录退避中"
            response.headers["Retry-After"] = str(remaining)
            return result

        for key in (
            "last_login_ok_seconds_ago",
            "consecutive_failures",
            "login_attempts_last_hour",
        ):
            result[key] = diagnostics[key]

        # 会话验证：若 client 存在，始终做实际探测（含 SUSPECT 状态）
        client = manager.client
        if client is not None:
            t0 = time.monotonic()
            try:
                headers = {"Host": settings.target_host}
                if settings.openwebui_api_key:
                    headers["Authorization"] = f"Bearer {settings.openwebui_api_key}"

                probe = await client.head(
                    f"{settings.target_base}/api/config",
                    headers=headers,
                    follow_redirects=False,
                )
                latency_ms = int((time.monotonic() - t0) * 1000)

                if probe.status_code in (301, 302, 307):
                    location = probe.headers.get("location", "")
                    if _is_cas_login_url(location) or _is_vouch_login_url(location):
                        result["status"] = "unhealthy"
                        result["note"] = "会话已过期，需要重新登录"
                        result["latency_ms"] = latency_ms
                        response.status_code = 503
                        return result

                if probe.status_code >= 400:
                    result.update(
                        status="degraded",
                        upstream_status=probe.status_code,
                        latency_ms=latency_ms,
                        note="上游返回错误",
                    )
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

        if state == AuthState.EXPIRED:
            result["status"] = "degraded"
            result["note"] = "会话已过期，需要重新登录"
            return result

        result["status"] = "ok"
        result["note"] = "代理已启动，会话尚未建立"
        return result
