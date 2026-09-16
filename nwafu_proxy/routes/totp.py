"""Local TOTP form backed by the application's own authenticator."""

from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse

from nwafu_proxy.auth.session import AuthSessionManager

_STATIC_DIR = Path(__file__).resolve().parents[2] / "static"


def register_totp_routes(app: FastAPI, manager: AuthSessionManager) -> None:
    @app.get("/totp")
    async def totp_page():
        if not manager.auth.totp_pending:
            return HTMLResponse((_STATIC_DIR / "totp_idle.html").read_text(encoding="utf-8"))
        html = (_STATIC_DIR / "totp.html").read_text(encoding="utf-8")
        return HTMLResponse(html.replace("{{remaining}}", str(manager.auth.totp_remaining or 30)))

    @app.post("/totp")
    async def totp_submit(request: Request):
        if not manager.auth.totp_pending:
            return HTMLResponse(
                "<html><body><h3>无需提交</h3><p>当前没有等待中的二次验证。</p></body></html>"
            )
        form = await request.form()
        code = form.get("code", "")
        if not isinstance(code, str) or len(code) != 6 or not code.isascii() or not code.isdigit():
            return HTMLResponse("请输入 6 位数字验证码", status_code=400)
        if manager.auth.submit_totp(code):
            return HTMLResponse(
                "<html><head><meta charset='utf-8'></head><body><h3>TOTP 已提交</h3><p>代理正在继续登录，请稍候。</p></body></html>"
            )
        return HTMLResponse("<html><body><h3>提交失败</h3><p>请重试。</p></body></html>")
