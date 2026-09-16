import asyncio
import base64
import json
import re
import secrets
import time
from typing import Optional
from urllib.parse import parse_qs, quote, urljoin, urlparse

import httpx
import pyotp
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad

from nwafu_proxy.config import Settings
from nwafu_proxy.constants import (
    _RETRIABLE_NET_ERRORS,
    CIRCUIT_CAPTCHA_DURATION,
    CIRCUIT_CRITICAL_DURATION,
    CIRCUIT_NORMAL_DURATION,
    CIRCUIT_PASSWORD_ERROR_DURATION,
    DEFAULT_TIMEOUT,
    MAX_LOGIN_REDIRECTS,
    NETWORK_RETRY_ATTEMPTS,
)
from nwafu_proxy.logging import logger

from .detection import _is_cas_login_url
from .forms import _extract_error_text, _parse_login_form
from .state import CriticalLoginError, TwoFactorError

AES_CHARS = "ABCDEFGHJKMNPQRSTWXYZabcdefhijkmnprstwxyz2345678"


def _random_string(length: int) -> str:
    return "".join(secrets.choice(AES_CHARS) for _ in range(length))


def encrypt_password(password: str, salt: str) -> str:
    if not salt:
        return password
    random_prefix = _random_string(64)
    random_iv = _random_string(16)
    data = (random_prefix + password).encode("utf-8")
    key = salt.strip().encode("utf-8")
    iv = random_iv.encode("utf-8")
    cipher = AES.new(key, AES.MODE_CBC, iv)
    encrypted = cipher.encrypt(pad(data, AES.block_size))
    return base64.b64encode(encrypted).decode("utf-8")


def _totp_window_remaining_seconds() -> int:
    return 30 - (int(time.time()) % 30)


async def _wait_for_stable_totp_window() -> None:
    remaining = _totp_window_remaining_seconds()
    if remaining <= 3:
        await asyncio.sleep(remaining + 1)


async def _wait_for_next_totp_window() -> None:
    await asyncio.sleep(_totp_window_remaining_seconds() + 1)


class CasAuthenticator:
    """CAS/Vouch protocol client. Login frequency and retry policy live in session.py."""

    def __init__(self, settings: Settings):
        self.settings = settings
        self.client: httpx.AsyncClient | None = None
        self._consecutive_failures = 0
        self._totp_pending = False
        self._totp_code: str | None = None
        self._totp_ready = asyncio.Event()

    async def create_client(self) -> httpx.AsyncClient:
        return httpx.AsyncClient(
            timeout=DEFAULT_TIMEOUT,
            follow_redirects=True,
            trust_env=False,
            limits=httpx.Limits(max_connections=30, max_keepalive_connections=15),
            headers={
                "User-Agent": (
                    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) "
                    "AppleWebKit/537.36 (KHTML, like Gecko) "
                    "Chrome/124.0.0.0 Safari/537.36"
                ),
                "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                "Accept-Language": "zh-CN,zh;q=0.9,en;q=0.8",
            },
        )

    # ---- 网络重试 ----

    async def _retry_request(
        self, method: str, url: str, *, follow_redirects: bool = False, **kwargs
    ) -> httpx.Response:
        assert self.client is not None
        last_exc: Optional[Exception] = None
        for attempt in range(NETWORK_RETRY_ATTEMPTS):
            try:
                return await self.client.request(
                    method, url, follow_redirects=follow_redirects, **kwargs
                )
            except _RETRIABLE_NET_ERRORS as e:
                last_exc = e
                if attempt < NETWORK_RETRY_ATTEMPTS - 1:
                    logger.warning(
                        "event=network_retry method=%s url=%s error=%s attempt=%d",
                        method,
                        str(url)[:60],
                        e,
                        attempt + 1,
                    )
                    await asyncio.sleep(1.0 * (2**attempt))
                    continue
                raise
        assert last_exc is not None
        raise last_exc

    # ---- CAS 登录流程 ----

    async def _fetch_login_page(self, login_url: str) -> httpx.Response:
        logger.info("请求登录页：GET %s...", login_url[:80])
        return await self._retry_request("GET", login_url, follow_redirects=False)

    async def _submit_login_form(self, login_url: str, login_data: dict) -> httpx.Response:
        logger.info("提交登录表单：POST /authserver/login")
        return await self._retry_request("POST", login_url, data=login_data, follow_redirects=False)

    def _classify_login_failure(self, resp: httpx.Response) -> tuple[str, str, int]:
        """
        分类登录失败原因。返回 (message, failure_type, circuit_duration)。

        failure_type: "account_locked" | "captcha" | "password_error" | "rate_limited" | "maintenance" | "unknown"
        """
        html_text = ""
        # 尝试 JSON 响应
        try:
            data = resp.json()
            code = data.get("resultCode", "")
            if code == "LOCK":
                return (
                    "账户已被锁定，请手动解锁后重启代理",
                    "account_locked",
                    CIRCUIT_CRITICAL_DURATION,
                )
            if code == "CAPTCHA_NOTMATCH":
                return ("需要验证码，账号可能被临时限制", "captcha", CIRCUIT_CAPTCHA_DURATION)
            if code == "FAIL_UPNOTMATCH":
                return (
                    "密码错误或账户不存在，请检查 .env 配置",
                    "password_error",
                    CIRCUIT_PASSWORD_ERROR_DURATION,
                )
            if code:
                return (f"AuthServer 错误: {code}", "unknown", CIRCUIT_NORMAL_DURATION)
        except Exception:
            html_text = resp.text[:2000]

        # 检查 HTML 响应中的高危信号
        if html_text:
            if "锁定" in html_text or "LOCK" in html_text:
                return ("账户可能已被锁定，请手动检查", "account_locked", CIRCUIT_CRITICAL_DURATION)
            if "频繁" in html_text or "操作过于频繁" in html_text:
                return (
                    "CAS 提示操作过于频繁，账号可能被临时限制",
                    "rate_limited",
                    CIRCUIT_CRITICAL_DURATION,
                )
            if "验证码" in html_text or "captcha" in html_text.lower():
                return ("需要验证码，账号可能被临时限制", "captcha", CIRCUIT_CAPTCHA_DURATION)
            if "维护" in html_text or "maintenance" in html_text.lower():
                return ("CAS 系统可能正在维护", "maintenance", CIRCUIT_NORMAL_DURATION)

        # 尝试从 HTML 中提取错误提示
        err_text = _extract_error_text(html_text) if html_text else None
        if err_text:
            return (f"AuthServer 登录失败: {err_text}", "unknown", CIRCUIT_NORMAL_DURATION)

        return ("AuthServer 登录失败: 未知错误", "unknown", CIRCUIT_NORMAL_DURATION)

    async def _try_fido2_login(self, login_page_html: str, login_url: str) -> bool:
        """
        尝试 FIDO2/WebAuthn passkey 登录。成功返回 True。

        FIDO2 登录在 Vouch + CAS OIDC 流程下：
        1. 使用 _navigate_to_login_page 返回的登录页（含 OIDC service）完成 passkey 认证
        2. 跟随重定向链完成 Vouch → deepseek 会话建立
        """
        if not self.settings.fido2_enabled:
            return False

        try:
            from utils.fido2_auth import build_webauthn_assertion, load_credential
        except ImportError:
            logger.warning("event=fido2_skip reason=import_failed")
            return False

        cred = load_credential(self.settings.data_dir / "fido2_credential.json")
        if not cred:
            logger.info("event=fido2_skip reason=no_credential_file")
            return False
        if "keyValue" not in cred:
            logger.warning("event=fido2_skip reason=missing_keyValue")
            return False
        if "deviceBindingId" not in cred:
            logger.warning(
                "event=fido2_skip reason=missing_deviceBindingId note=需要 --device-id 参数"
            )
            return False

        logger.info("event=fido2_attempt")

        try:
            # 使用 Vouch 流程获取的登录页中的 execution token
            m = re.search(r'name="execution"[^>]*value="([^"]+)"', login_page_html)
            if not m:
                logger.warning("event=fido2_error detail=no_execution")
                return False
            execution = m.group(1)

            # POST /startAssertion
            resp = await self.client.post(
                f"{self.settings.auth_server}/authserver/startAssertion",
                json={
                    "userId": base64.b64encode(self.settings.username.encode()).decode(),
                    "id": cred["deviceBindingId"],
                },
                headers={"Content-Type": "application/json;charset=utf-8"},
            )
            data = resp.json()
            if not data.get("result", {}).get("success"):
                logger.warning("event=fido2_start_assertion_failed response=%s", data)
                return False

            req = data["result"]["request"]
            opts = req["publicKeyCredentialRequestOptions"]

            # Build & sign assertion
            assertion = build_webauthn_assertion(
                cred,
                opts["challenge"],
                opts["rpId"],
                self.settings.auth_server,
            )
            response_json = json.dumps(
                {"requestId": req["requestId"], "credential": assertion, "sessionToken": None},
                separators=(",", ":"),
            )
            logger.info("event=fido2_assertion_built")

            # 提交 FIDO2 表单到 Vouch 流程获取的 login_url（含 OIDC service 参数）
            form = {
                "username": base64.b64encode(self.settings.username.encode()).decode(),
                "responseJson": response_json,
                "_eventId": "submit",
                "cllt": "fidoLogin",
                "dllt": "generalLogin",
                "lt": "",
                "rememberMe": "true",
                "execution": execution,
            }
            resp = await self._retry_request(
                "POST",
                login_url,
                data=form,
                follow_redirects=False,
            )
            post_status = resp.status_code
            logger.info("event=fido2_form_submit status=%d", post_status)

            if post_status not in (301, 302, 307, 308):
                err_text = _extract_error_text(resp.text)
                logger.warning(
                    "event=fido2_login_failed status=%d error=%s",
                    post_status,
                    err_text or "unknown",
                )
                return False

            # 跟随重定向链完成 Vouch → deepseek 会话建立
            location = resp.headers.get("location", "")
            await self._handle_login_redirect(location)

            logger.info("event=fido2_login_success")
            return True

        except Exception as e:
            logger.warning("event=fido2_login_error error=%s", e)
            return False

    async def _navigate_to_login_page(self) -> tuple[str, "httpx.Response"]:
        """通过 Vouch → CAS OIDC 链导航到实际 CAS 登录页。返回 (login_url, response)。"""
        # 先尝试访问首页；如果首页不重定向（SPA 返回 200），则用 API 路径触发 Vouch
        vouch_entry = self.settings.target_base
        resp = await self._retry_request("GET", vouch_entry, follow_redirects=False)
        if resp.status_code not in (301, 302, 307, 308):
            # 首页没有重定向（Vouch 可能只保护 API 路径），改用 /api/config
            logger.info("首页未重定向 (status=%d)，尝试 /api/config 触发 Vouch", resp.status_code)
            vouch_entry = f"{self.settings.target_base}/api/config"
            resp = await self._retry_request("GET", vouch_entry, follow_redirects=False)
        if resp.status_code not in (301, 302, 307, 308):
            raise RuntimeError(f"上游未返回预期的认证重定向 (status={resp.status_code})")

        # 动态跟随重定向链直到到达登录页（非重定向响应）
        current_url = resp.headers.get("location", "")
        if not current_url:
            raise RuntimeError("上游重定向缺少 Location 头")
        if not current_url.startswith("http"):
            current_url = urljoin(str(resp.url), current_url)

        max_hops = 10
        for hop in range(max_hops):
            resp = await self._retry_request("GET", current_url, follow_redirects=False)
            if resp.status_code not in (301, 302, 307, 308):
                # 到达最终页面（登录页）
                break
            next_url = resp.headers.get("location", "")
            if not next_url:
                raise RuntimeError(f"重定向链中缺少 Location 头 (hop={hop + 1})")
            if not next_url.startswith("http"):
                next_url = urljoin(str(resp.url), next_url)
            current_url = next_url
        else:
            raise RuntimeError(f"重定向链过长（超过 {max_hops} 跳）")

        login_url = str(current_url)
        logger.info("到达登录页：%s (经过 %d 跳重定向)", login_url[:80], hop + 1)

        return login_url, resp

    async def login(self, consecutive_failures: int = 0):
        """执行完整的金智 AuthServer 登录流程。优先尝试 FIDO2 passkey 登录。"""
        self._consecutive_failures = consecutive_failures
        logger.info("event=login_start target=%s", self.settings.target_base)

        if self.client:
            try:
                await self.client.aclose()
            except Exception:
                pass

        self.client = await self.create_client()

        try:
            # Step 1: 通过 Vouch → CAS OIDC 链获取登录页
            login_url, resp = await self._navigate_to_login_page()

            if resp.status_code in (301, 302, 307, 308):
                location = resp.headers.get("location", "")
                logger.info("检测到有效 TGC，跟随重定向完成会话建立")
                await self._handle_login_redirect(location)
                return

            execution, salt = _parse_login_form(resp.text)

            logger.info("解析表单参数成功：salt=%s**** execution=%s...", salt[:4], execution[:20])

            # Step 2: 尝试 FIDO2 passkey 登录（优先级高于密码登录）
            try:
                if await self._try_fido2_login(resp.text, login_url):
                    return
            except Exception as e:
                logger.warning("event=fido2_login_fallback reason=%s", e)

            # Step 3: 加密密码
            encrypted_pwd = encrypt_password(self.settings.password, salt)

            # Step 4: 提交登录表单
            login_data = {
                "username": self.settings.username,
                "password": encrypted_pwd,
                "captcha": "",
                "rememberMe": "true",
                "_eventId": "submit",
                "cllt": "userNameLogin",
                "lt": "",
                "execution": execution,
            }

            resp = await self._submit_login_form(login_url, login_data)

            # Step 4: 处理登录结果
            if resp.status_code in (301, 302, 307, 308):
                location = resp.headers.get("location", "")
                logger.info("登录表单提交成功，跟随重定向链：%s...", location[:80])
                await self._handle_login_redirect(location)
            else:
                msg, failure_type, circuit_dur = self._classify_login_failure(resp)
                if failure_type in ("account_locked", "captcha", "password_error", "rate_limited"):
                    raise CriticalLoginError(msg, circuit_dur)
                raise RuntimeError(msg)

        except CriticalLoginError:
            raise
        except Exception as e:
            logger.error("event=login_error error=%s", e)
            raise

    async def _follow_cas_redirect(self, location: str) -> tuple[str, Optional[httpx.Response]]:
        """跟随 CAS 重定向链。返回 (final_url, last_response)。"""
        max_redirects = MAX_LOGIN_REDIRECTS
        current_url = location
        last_resp = None
        for i in range(max_redirects):
            if not current_url:
                break
            logger.info("跟随重定向[%d/%d]：%s...", i + 1, max_redirects, current_url[:80])
            last_resp = await self._retry_request("GET", current_url, follow_redirects=False)
            if last_resp.status_code in (301, 302, 307, 308):
                current_url = last_resp.headers.get("location", "")
                if current_url and not current_url.startswith("http"):
                    current_url = urljoin(str(last_resp.url), current_url)
            else:
                logger.info("重定向链结束：url=%s status=%d", last_resp.url, last_resp.status_code)
                break
        return (str(last_resp.url) if last_resp else location, last_resp)

    async def _handle_login_redirect(self, location: str):
        """统一处理登录后的重定向链：跟随重定向 → 检测 2FA → 验证会话"""
        final_url, _last_resp = await self._follow_cas_redirect(location)

        # 检测二次验证跳转（TGC 复用和新登录都会触发）
        if self._RE_AUTH_VIEW.search(final_url):
            logger.info("event=2fa_detected url=%s", final_url[:80])
            parsed = urlparse(final_url)
            params = parse_qs(parsed.query)
            service_url = params.get("service", [None])[0] or quote(f"{self.settings.target_base}/")
            await self._complete_2fa(service_url)

        # 登录后验证：确保会话确实可用
        await self._validate_session()

        logger.info("认证完成，会话 Cookie 已就绪")

    async def _validate_session(self):
        """登录后快速验证会话是否有效。失败时抛出异常避免虚假 OK 状态。"""
        try:
            headers = {"Host": self.settings.target_host}
            if self.settings.openwebui_api_key:
                headers["Authorization"] = f"Bearer {self.settings.openwebui_api_key}"

            resp = await self.client.head(
                f"{self.settings.target_base}/api/config",
                headers=headers,
                follow_redirects=False,
            )

            if resp.status_code in (301, 302, 307):
                location = resp.headers.get("location", "")
                if _is_cas_login_url(location):
                    raise RuntimeError(
                        f"会话验证失败：登录后仍被重定向到 CAS 登录页 location={location[:80]}"
                    )
            logger.info("event=session_validated status=%d", resp.status_code)
        except _RETRIABLE_NET_ERRORS as e:
            logger.warning("event=session_validation_skipped reason=network_error error=%s", e)
        except httpx.HTTPStatusError as e:
            logger.warning("event=session_validation_http_error status=%d", e.response.status_code)
        except RuntimeError:
            raise

    # ---- 二次验证 (2FA / TOTP) ----

    _RE_AUTH_VIEW = re.compile(r"/authserver/reAuthCheck/reAuthLoginView\.do", re.I)

    async def _complete_2fa(self, service_url: str):
        """通过 TOTP 安全令牌完成二次验证。完成后跟随重定向链回到目标服务。"""
        logger.info("event=2fa_start service=%s", service_url[:60])

        # Step 1: 切换到安全令牌 (reAuthType=10)
        change_body = {
            "isMultifactor": "true",
            "reAuthType": "10",
            "service": service_url,
        }
        change_resp = await self._retry_request(
            "POST",
            f"{self.settings.auth_server}/authserver/reAuthCheck/changeReAuthType.do",
            data=change_body,
            headers={"Content-Type": "application/x-www-form-urlencoded;charset=utf-8"},
        )
        if change_resp.status_code != 200:
            raise RuntimeError(f"切换二次验证方式失败：HTTP {change_resp.status_code}")
        try:
            change_data = change_resp.json()
        except Exception:
            change_data = {}
        if change_data.get("code") != "1":
            raise RuntimeError(
                f"切换二次验证方式被拒绝：{change_data.get('message', change_resp.text[:200])}"
            )
        logger.info(
            "event=2fa_switch reAuthType=10 name=%s",
            change_data.get("data", {}).get("reAuthTypeName", "?"),
        )

        # Step 2: 生成 TOTP 码
        auto_enabled = self.settings.totp_auto_enabled
        secret = self.settings.totp_secret.strip() if self.settings.totp_secret else ""

        # 兼容多种格式
        if secret.startswith("otpauth://"):
            _q = urlparse(secret).query
            _params = parse_qs(_q)
            secret = re.sub(r"\s+", "", _params.get("secret", [secret])[0])
        else:
            secret = re.sub(r"\s+", "", secret)

        totp = pyotp.TOTP(secret) if secret else None

        if totp and auto_enabled:
            # 自动模式：生成 TOTP 码
            await _wait_for_stable_totp_window()
            otp_code = totp.now()
            logger.info(
                "event=2fa_totp_generated code=%s**** window_remaining=%ds",
                otp_code[:2],
                _totp_window_remaining_seconds(),
            )
        else:
            # 手动模式：等待用户通过 /totp 页面提交
            if not secret:
                logger.warning(
                    "event=2fa_manual_wait note=TOTP_SECRET未配置，"
                    "请在浏览器访问 http://localhost:%d/totp 输入TOTP码",
                    self.settings.proxy_port,
                )
            else:
                logger.warning(
                    "event=2fa_manual_wait note=TOTP_AUTO_ENABLED=false，"
                    "请在浏览器访问 http://localhost:%d/totp 输入TOTP码",
                    self.settings.proxy_port,
                )
            self._totp_code = None
            self._totp_ready.clear()
            self._totp_pending = True

            try:
                await asyncio.wait_for(self._totp_ready.wait(), timeout=300)
                otp_code = self._totp_code
                if not otp_code or not otp_code.strip():
                    raise RuntimeError("未收到 TOTP 码")
                otp_code = otp_code.strip()
            except asyncio.TimeoutError:
                raise RuntimeError("等待 TOTP 输入超时（5 分钟）")
            finally:
                self._totp_pending = False

        # Step 3: 提交二次验证
        submit_body = {
            "service": service_url,
            "reAuthType": "10",
            "isMultifactor": "true",
            "password": "",
            "dynamicCode": "",
            "uuid": "",
            "answer1": "",
            "answer2": "",
            "otpCode": otp_code,
            "skipTmpReAuth": "true",
        }
        submit_resp = await self._retry_request(
            "POST",
            f"{self.settings.auth_server}/authserver/reAuthCheck/reAuthSubmit.do",
            data=submit_body,
            headers={"Content-Type": "application/x-www-form-urlencoded;charset=utf-8"},
        )
        if submit_resp.status_code != 200:
            raise RuntimeError(f"二次验证提交失败：HTTP {submit_resp.status_code}")

        submit_data = {}
        try:
            submit_data = submit_resp.json()
        except Exception:
            pass

        if submit_data.get("code") != "reAuth_success":
            msg = submit_data.get("msg", submit_resp.text[:200])
            # 如果 TOTP 码被拒，等待下一个时间窗后用新码重试一次。
            if (
                totp
                and auto_enabled
                and self._consecutive_failures == 0
                and ("code" in msg.lower() or "fail" in msg.lower() or "error" in msg.lower())
            ):
                logger.warning(
                    "event=2fa_retry reason=TOTP码被拒，等待下一个时间窗后用新码重试 msg=%s", msg
                )
                await _wait_for_next_totp_window()
                await _wait_for_stable_totp_window()
                new_code = totp.now()
                submit_body["otpCode"] = new_code
                logger.info(
                    "event=2fa_retry new_code=%s**** window_remaining=%ds",
                    new_code[:2],
                    _totp_window_remaining_seconds(),
                )
                retry_resp = await self._retry_request(
                    "POST",
                    f"{self.settings.auth_server}/authserver/reAuthCheck/reAuthSubmit.do",
                    data=submit_body,
                    headers={"Content-Type": "application/x-www-form-urlencoded;charset=utf-8"},
                )
                try:
                    retry_data = retry_resp.json()
                except Exception:
                    retry_data = {}
                if retry_data.get("code") == "reAuth_success":
                    logger.info("event=2fa_success_after_retry")
                    await self._follow_cas_redirect(service_url)
                    logger.info("event=2fa_complete")
                    return
                msg = retry_data.get("msg", retry_resp.text[:200])
            raise TwoFactorError(f"二次验证失败：{msg}")

        logger.info("event=2fa_success")

        # Step 4: 二次验证成功后跟随重定向
        # reAuthSubmit 成功后浏览器会通过 JS 跳转到 service URL，
        # 我们需要模拟：直接请求 service URL
        await self._follow_cas_redirect(service_url)
        logger.info("event=2fa_complete")

    def submit_totp(self, code: str) -> bool:
        """接收用户提交的 TOTP 码。成功返回 True。"""
        if not self._totp_pending:
            return False
        self._totp_code = code.strip()
        self._totp_ready.set()
        logger.info("event=totp_code_submitted")
        return True

    @property
    def totp_pending(self) -> bool:
        return self._totp_pending

    @property
    def totp_remaining(self) -> int | None:
        """当前 TOTP 窗口剩余秒数（供前端显示）"""
        if not self._totp_pending:
            return None
        return 30 - (int(time.time()) % 30)
