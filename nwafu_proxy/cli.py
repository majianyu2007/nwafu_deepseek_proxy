"""Command-line entry point."""

import uvicorn

from .app import create_app
from .config import load_settings
from .logging import configure_logging, logger


def main() -> None:
    configure_logging()
    settings = load_settings()
    app = create_app(settings)
    api_key_hint = "已配置" if settings.openwebui_api_key else "未配置"
    monitor_hint = "已启用" if settings.monitor_enabled else "未启用"
    fido2_hint = "已启用" if settings.fido2_enabled else "未启用"
    logger.info(
        "\n  NWAFU DeepSeek Proxy (transparent reverse proxy)\n"
        "  ------------------------------------------------\n"
        "  Listen:     http://localhost:%s\n"
        "  Upstream:   %s\n"
        "  AuthServer: %s\n"
        "  User:       %s\n"
        "  WebUI Key:  %s\n"
        "  Monitor:    %s\n"
        "  FIDO2:      %s\n\n"
        "  Note:\n"
        "    - 代理透明转发所有请求到源站\n"
        "    - 客户端 API Key 可使用占位值（代理会注入真实 Open WebUI Key）\n"
        "    - 访问 http://localhost:%s 直接使用 Open WebUI\n",
        settings.proxy_port,
        settings.target_base,
        settings.auth_server,
        settings.username,
        api_key_hint,
        monitor_hint,
        fido2_hint,
        settings.proxy_port,
    )

    uvicorn.run(
        app,
        host="0.0.0.0",
        port=settings.proxy_port,
        log_level="info",
        access_log=False,
        log_config=None,
        timeout_graceful_shutdown=2,
    )
