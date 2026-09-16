import os
from dataclasses import dataclass
from pathlib import Path

from dotenv import load_dotenv

from nwafu_proxy.logging import logger


@dataclass(frozen=True)
class Settings:
    username: str
    password: str
    proxy_port: int
    target_host: str
    openwebui_api_key: str
    auth_server: str
    cors_origins: list[str]
    # 模型监控（可选）
    monitor_enabled: bool
    monitor_poll_interval: int
    telegram_bot_token: str
    telegram_chat_id: str
    webhook_urls: list[str]
    webhook_secret: str
    notify_proxy: str
    totp_secret: str

    data_dir: Path = Path(__file__).resolve().parent.parent / ".data"
    fido2_enabled: bool = False
    totp_auto_enabled: bool = True

    @property
    def target_base(self) -> str:
        return f"https://{self.target_host}"


def load_settings() -> Settings:
    """Load environment only when the application is explicitly constructed."""
    load_dotenv(override=False)
    username = os.getenv("NWAFU_USERNAME", "").strip()
    password = os.getenv("NWAFU_PASSWORD", "")
    proxy_port = int(os.getenv("PROXY_PORT", "8000"))
    target_host = os.getenv("TARGET_HOST", "deepseek.nwafu.edu.cn").strip()
    openwebui_api_key = os.getenv("OPENWEBUI_API_KEY", "").strip()
    auth_server = os.getenv("AUTH_SERVER", "https://authserver.nwafu.edu.cn").strip()
    cors_raw = os.getenv("CORS_ORIGINS", "").strip()
    cors_origins = ["*"] if not cors_raw else [p.strip() for p in cors_raw.split(",") if p.strip()]

    monitor_enabled = os.getenv("MONITOR_ENABLED", "false").strip().lower() == "true"
    monitor_poll_interval = int(os.getenv("MONITOR_POLL_INTERVAL", "600"))
    if monitor_poll_interval < 300:
        logger.warning("MONITOR_POLL_INTERVAL=%d 过短，已调整为 600s", monitor_poll_interval)
        monitor_poll_interval = 600
    telegram_bot_token = os.getenv("TELEGRAM_BOT_TOKEN", "").strip()
    telegram_chat_id = os.getenv("TELEGRAM_CHAT_ID", "").strip()
    webhook_urls_raw = os.getenv("WEBHOOK_URLS", "").strip()
    webhook_urls = (
        [u.strip() for u in webhook_urls_raw.split(",") if u.strip()] if webhook_urls_raw else []
    )
    webhook_secret = os.getenv("WEBHOOK_SECRET", "").strip()
    notify_proxy = os.getenv("NOTIFY_PROXY", "").strip()
    totp_secret = os.getenv("TOTP_SECRET", "").strip()

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
        monitor_enabled=monitor_enabled,
        monitor_poll_interval=monitor_poll_interval,
        telegram_bot_token=telegram_bot_token,
        telegram_chat_id=telegram_chat_id,
        webhook_urls=webhook_urls,
        webhook_secret=webhook_secret,
        notify_proxy=notify_proxy,
        totp_secret=totp_secret,
        fido2_enabled=os.getenv("FIDO2_ENABLED", "false").strip().lower() == "true",
        totp_auto_enabled=os.getenv("TOTP_AUTO_ENABLED", "true").strip().lower() == "true",
    )
