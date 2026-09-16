from urllib.parse import urlparse

import httpx

from nwafu_proxy.logging import logger

from .forms import _sample_contains_cas_fields


def _is_cas_login_url(url: str) -> bool:
    """
    严格检查 URL 是否是 CAS 登录重定向。
    支持两种场景：
    (a) 直接重定向到 authserver.nwafu.edu.cn/authserver/login
    (b) Open WebUI 内部 auth 重定向 /.auth/login/cas（说明 session 已失效）
    """
    if not url:
        return False
    try:
        parsed = urlparse(url)
    except Exception:
        return False
    # 直接 CAS 登录页重定向
    if parsed.hostname == "authserver.nwafu.edu.cn" and parsed.path.startswith("/authserver/login"):
        return True
    # Open WebUI 内部 auth 重定向 — session 失效，Open WebUI 正尝试发起 CAS 流程
    if parsed.path.startswith("/.auth/login/cas"):
        return True
    return False


def _is_vouch_login_url(url: str) -> bool:
    """检查 URL 是否是 Vouch Proxy 登录重定向（上游已切换到 Vouch + CAS OIDC 流程）。"""
    if not url:
        return False
    try:
        parsed = urlparse(url)
    except Exception:
        return False
    return parsed.hostname == "vouch.nwafu.edu.cn" and parsed.path.startswith("/login")


def _is_auth_redirect(resp: httpx.Response) -> bool:
    """检查响应是否是认证重定向（CAS 登录页 或 Vouch Proxy）。"""
    if resp.status_code not in (301, 302, 307):
        return False
    location = resp.headers.get("location", "")
    return _is_cas_login_url(location) or _is_vouch_login_url(location)


def _is_cas_login_redirect(resp: httpx.Response) -> bool:
    """检查响应是否是 CAS 登录页重定向（精确匹配 host）"""
    if resp.status_code not in (301, 302, 307):
        return False
    location = resp.headers.get("location", "")
    return _is_cas_login_url(location)


async def _is_cas_login_html(resp: httpx.Response) -> bool:
    """
    检查 401/403 HTML 响应是否真的是 CAS 登录页。
    必须满足：(a) Content-Type 为 text/html (b) body 前 4KB 包含 execution 和 pwdEncryptSalt 字段。
    """
    if resp.status_code not in (401, 403):
        return False
    content_type = resp.headers.get("content-type", "")
    if "text/html" not in content_type:
        return False
    try:
        body_sample = await resp.aread()
        # 将读取的 body 暂存以便调用方重建响应
        resp._sampled_body = body_sample  # type: ignore[attr-defined]
        return _sample_contains_cas_fields(body_sample)
    except Exception:
        return False


async def _check_auth_failure(resp: httpx.Response, is_streaming: bool) -> bool:
    """
    综合判断上游响应是否表明 CAS 会话已失效。

    对非流式响应：先检查重定向 URL，再检查 HTML body。
    对流式响应：只检查重定向 URL（不读取 body）。
    """
    # 检查 302 重定向 URL
    if _is_auth_redirect(resp):
        logger.info(
            "event=auth_detection result=definitive_cas state=redirect url=%s",
            resp.headers.get("location", "")[:80],
        )
        return True

    # 对流式接口不读取 body
    if is_streaming:
        return False

    # 检查 HTML body 是否包含 CAS 登录表单
    if await _is_cas_login_html(resp):
        logger.info("event=auth_detection result=definitive_cas state=html_body")
        return True

    return False
