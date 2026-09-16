import asyncio
import random
import time
from typing import Optional

import httpx

from nwafu_proxy.config import Settings
from nwafu_proxy.constants import (
    CIRCUIT_NORMAL_DURATION,
    COOKIE_TTL_SECONDS,
    DEGRADED_THRESHOLD,
    DEGRADED_WINDOW,
    FORCE_RELOGIN_THROTTLE,
    KEEPALIVE_INTERVAL_SECONDS,
    KEEPALIVE_JITTER_SECONDS,
    LOGIN_BACKOFF_BASE,
    LOGIN_BACKOFF_MAX_CRITICAL,
    LOGIN_BACKOFF_MAX_NORMAL,
    LOGIN_BACKOFF_MULTIPLIER,
    LOGIN_MIN_INTERVAL,
    LOGIN_STICKY_WINDOW,
    LOGIN_WINDOW_SECONDS,
    MAX_CONSECUTIVE_FAILURES,
    MAX_LOGINS_PER_HOUR,
)
from nwafu_proxy.logging import logger

from .cas import CasAuthenticator
from .detection import _is_auth_redirect
from .state import (
    AuthState,
    CircuitOpenError,
    CriticalLoginError,
    TwoFactorError,
    UpstreamUnavailableError,
)
from .storage import SessionStore


class AuthSessionManager:
    """
    管理与 AuthServer 及目标站之间的完整会话生命周期:

    安全保护层级（由外到内）：
    1. 状态机 — 区分"上游异常"与"认证过期"
    2. 单飞锁 — 并发请求最多触发一次真实 CAS 登录
    3. 频率限制 — 每小时最多 N 次登录尝试（支持文件持久化）
    4. 指数退避 — 每次失败后退避时间翻倍
    5. 熔断器 — 连续失败达阈值后长时间停止登录
    6. 失败分类 — 高危错误（锁定/验证码）使用更长熔断
    """

    def __init__(self, settings: Settings):
        self.settings = settings
        self.auth = CasAuthenticator(settings)
        self.store = SessionStore(settings.data_dir)
        self._restore_attempted = False
        self._login_lock = asyncio.Lock()  # 单飞登录锁
        self._state: AuthState = AuthState.OK
        self._last_login_time: float = 0
        self._cookie_ttl: float = float(COOKIE_TTL_SECONDS)
        self._keepalive_task: Optional[asyncio.Task[None]] = None

        # 频率限制 & 退避
        self._login_attempt_times: list[float] = []
        self._consecutive_failures: int = 0
        self._backoff_until: float = 0
        self._circuit_until: float = 0
        self._circuit_duration: float = 0

        # 上游降级检测（与认证状态机独立）
        self._recent_proxy_failures: list[float] = []  # 最近代理请求失败的时间戳
        self._last_login_ok_time: float = 0  # 最近一次成功登录的时间
        self._login_then_rejected: bool = False  # 登录成功后仍被拒绝
        self._last_login_attempt_time: float = 0  # 最近一次登录尝试的时间
        self._last_force_relogin_time: float = 0  # 最近一次 force_relogin 的时间

        # 从文件恢复持久化状态
        self._load_persisted_state()

    # ---- 持久化 ----

    def _load_persisted_state(self):
        data = self.store.load_state()
        now = time.time()
        self._login_attempt_times = [
            t for t in data.get("attempts", []) if now - t < LOGIN_WINDOW_SECONDS
        ]
        self._consecutive_failures = data.get("consecutive_failures", 0)
        elapsed = max(0, now - data.get("saved_at", now))
        circuit_remaining = max(0, data.get("circuit_remaining", 0) - elapsed)
        circuit_duration = data.get("circuit_duration", 0)
        if circuit_remaining > 0:
            self._state = AuthState.CIRCUIT_OPEN
            self._circuit_until = time.monotonic() + circuit_remaining
            self._circuit_duration = circuit_duration
            logger.info(
                "event=state_restored state=circuit_open consecutive_failures=%d remaining=%ds",
                self._consecutive_failures,
                circuit_remaining,
            )
        elif self._consecutive_failures > 0:
            logger.info(
                "event=state_restored consecutive_failures=%d (circuit expired)",
                self._consecutive_failures,
            )

    def _save_persisted_state(self):
        circuit_remaining = 0
        if self._state == AuthState.CIRCUIT_OPEN:
            circuit_remaining = max(0, self._circuit_until - time.monotonic())
        data = {
            "saved_at": time.time(),
            "attempts": self._login_attempt_times,
            "consecutive_failures": self._consecutive_failures,
            "circuit_remaining": int(circuit_remaining),
            "circuit_duration": int(self._circuit_duration)
            if self._state == AuthState.CIRCUIT_OPEN
            else 0,
        }
        self.store.save_state(data)

    # ---- Cookie 持久化 ----

    def _save_cookies(self):
        if self.auth.client:
            self.store.save_cookies(self.auth.client.cookies)

    async def _restore_session(self) -> bool:
        """从文件恢复 Cookie 并快速验证是否仍然有效。成功返回 True 并设置 OK 状态。

        支持两种 JSON 格式：
        1. 代理自动导出的格式：{"cookies": [...], "saved_at": 1234567890}
        2. 浏览器导出的纯数组格式：[{"name": "TGC", "value": "...", "domain": "..."}, ...]
        兼容常见 cookie 字段名的大小写差异（domain/Domain, path/Path）。
        """
        normalized, saved_at = self.store.load_cookies()
        if not normalized:
            return False

        age_hint = ""
        if saved_at:
            age_days = (time.time() - saved_at) / 86400
            age_hint = f" saved_ago={age_days:.1f}d"

        if self.auth.client:
            try:
                await self.auth.client.aclose()
            except Exception:
                pass
        self.auth.client = await self.auth.create_client()
        for c in normalized:
            self.auth.client.cookies.set(c["name"], c["value"], c["domain"], c["path"])
        logger.info("event=cookie_restore count=%d%s", len(normalized), age_hint)

        try:
            headers = {"Host": self.settings.target_host}
            if self.settings.openwebui_api_key:
                headers["Authorization"] = f"Bearer {self.settings.openwebui_api_key}"
            resp = await self.auth.client.head(
                f"{self.settings.target_base}/api/config",
                headers=headers,
                follow_redirects=False,
            )
            if resp.status_code in (301, 302, 307):
                if _is_auth_redirect(resp):
                    logger.info("event=cookie_restore result=session_expired")
                    await self.auth.client.aclose()
                    self.auth.client = None
                    return False
            logger.info("event=cookie_restore result=valid status=%d", resp.status_code)
            self._last_login_time = time.monotonic()
            self._last_login_ok_time = time.monotonic()
            if self._state not in (AuthState.CIRCUIT_OPEN, AuthState.LOGIN_BACKOFF):
                self._state = AuthState.OK
            self._save_persisted_state()
            return True
        except Exception as e:
            logger.warning("event=cookie_restore result=validation_error error=%s", e)
            await self.auth.client.aclose()
            self.auth.client = None
            return False

    # ---- 状态管理 ----

    @property
    def state(self) -> AuthState:
        return self._state

    @property
    def login_ok(self) -> bool:
        return self._state == AuthState.OK

    def _transition(self, new_state: AuthState, reason: str):
        old = self._state
        if old == new_state:
            return
        self._state = new_state
        logger.info(
            "event=auth_state_change old_state=%s new_state=%s reason=%s",
            old.value,
            new_state.value,
            reason,
        )
        self._save_persisted_state()

    # ---- 频率限制 ----

    def _check_rate_limit(self) -> bool:
        """检查是否超过每小时登录次数限制，返回 True 表示允许"""
        now = time.time()
        self._login_attempt_times = [
            t for t in self._login_attempt_times if now - t < LOGIN_WINDOW_SECONDS
        ]
        if len(self._login_attempt_times) >= MAX_LOGINS_PER_HOUR:
            logger.warning(
                "event=login_attempt outcome=denied reason=rate_limited attempts=%d/%dh window=%ds",
                len(self._login_attempt_times),
                MAX_LOGINS_PER_HOUR,
                LOGIN_WINDOW_SECONDS,
            )
            return False
        return True

    def _record_login_attempt(self):
        self._login_attempt_times.append(time.time())
        self._save_persisted_state()

    # ---- 退避时间计算 ----

    def _compute_backoff(self, is_critical: bool = False) -> float:
        max_delay = LOGIN_BACKOFF_MAX_CRITICAL if is_critical else LOGIN_BACKOFF_MAX_NORMAL
        raw = min(
            LOGIN_BACKOFF_BASE
            * (LOGIN_BACKOFF_MULTIPLIER ** max(0, self._consecutive_failures - 1)),
            max_delay,
        )
        jitter = raw * (0.75 + random.random() * 0.5)
        return jitter

    # ---- 熔断 ----

    # ---- 上游降级检测 ----

    def _record_proxy_failure(self):
        """记录一次代理请求失败（超时或网络错误），用于降级检测"""
        self._recent_proxy_failures.append(time.monotonic())

    def is_degraded(self) -> bool:
        """检查上游是否处于降级状态（最近有多个请求失败）"""
        now = time.monotonic()
        self._recent_proxy_failures = [
            t for t in self._recent_proxy_failures if now - t < DEGRADED_WINDOW
        ]
        return len(self._recent_proxy_failures) >= DEGRADED_THRESHOLD

    def recent_login_rejected(self) -> bool:
        """
        检查登录成功后的短窗口内是否仍被认证中间件拒绝。
        返回 True 时不再立即重试登录，避免形成 CAS 登录风暴。
        """
        if not self._login_then_rejected:
            now = time.monotonic()
            if (
                self._last_login_ok_time > 0
                and (now - self._last_login_ok_time) < LOGIN_STICKY_WINDOW
            ):
                self._login_then_rejected = True
                logger.warning(
                    "event=login_rejected_after_success seconds_since_login=%.1f "
                    "action=suppress_immediate_relogin",
                    now - self._last_login_ok_time,
                )
        return self._login_then_rejected

    # ---- 熔断 ----

    def _open_circuit(self, duration: float, reason: str):
        self._circuit_duration = duration
        self._circuit_until = time.monotonic() + duration
        self._transition(AuthState.CIRCUIT_OPEN, f"circuit_open:{reason}")
        logger.warning(
            "event=circuit state=open duration=%ds reason=%s consecutive_failures=%d",
            int(duration),
            reason,
            self._consecutive_failures,
        )
        self._save_persisted_state()

    def _check_or_raise_circuit(self) -> None:
        """检查熔断状态，若熔断已过期则解除，否则抛出 CircuitOpenError"""
        if self._state != AuthState.CIRCUIT_OPEN:
            return
        remaining = self._circuit_until - time.monotonic()
        if remaining <= 0:
            self._transition(AuthState.EXPIRED, "circuit_expired")
            logger.info("event=circuit state=closed")
            self._save_persisted_state()
            return
        msg = "Login temporarily disabled to protect the campus account. Please retry later."
        raise CircuitOpenError(msg, retry_after=int(remaining))

    def _check_circuit(self) -> bool:
        """检查熔断是否已过期，返回 True 表示熔断已解除（供外部只读使用）"""
        if self._state != AuthState.CIRCUIT_OPEN:
            return True
        if time.monotonic() >= self._circuit_until:
            self._transition(AuthState.EXPIRED, "circuit_expired")
            logger.info("event=circuit state=closed")
            self._save_persisted_state()
            return True
        return False

    # ---- 主入口：确保已登录 ----

    async def ensure_login(self) -> httpx.AsyncClient:
        """
        双重检查 + 单飞锁模式：
        1. 快速路径：状态 OK 且 TTL 有效 → 直接返回
        2. 熔断开启时有旧 client → 返回旧 client
        3. 否则通过 login_lock 排队，只允许一个真实登录
        """
        now = time.monotonic()

        # Cookie restoration shares the login lock; concurrent requests must not
        # replace or close each other's clients during startup.
        if self.auth.client is None and not self._restore_attempted:
            async with self._login_lock:
                if self.auth.client is None and not self._restore_attempted:
                    self._restore_attempted = True
                    try:
                        if await self._restore_session():
                            return self.auth.client
                    except Exception as e:
                        logger.warning("event=cookie_restore exception=%s", e)

        # 快速路径：无锁检查
        if (
            self._state == AuthState.OK
            and self.auth.client is not None
            and (now - self._last_login_time) <= self._cookie_ttl
        ):
            return self.auth.client

        # 熔断期间：若有旧 client 则继续使用（session 可能仍有效）
        try:
            self._check_or_raise_circuit()
        except CircuitOpenError:
            if self.auth.client is not None:
                return self.auth.client
            raise

        # SUSPECT 状态：不触发登录，继续使用旧 client
        if self._state == AuthState.SUSPECT and self.auth.client is not None:
            return self.auth.client

        # 进入单飞登录锁
        async with self._login_lock:
            # 双重检查：排队期间可能已被其他请求修复
            now2 = time.monotonic()
            if (
                self._state == AuthState.OK
                and self.auth.client is not None
                and (now2 - self._last_login_time) <= self._cookie_ttl
            ):
                return self.auth.client

            # 再次检查熔断
            try:
                self._check_or_raise_circuit()
            except CircuitOpenError:
                if self.auth.client is not None:
                    return self.auth.client
                raise

            # SUSPECT 复用旧 client（双重检查）
            if self._state == AuthState.SUSPECT and self.auth.client is not None:
                return self.auth.client

            # 检查退避
            if self._state == AuthState.LOGIN_BACKOFF:
                if time.monotonic() < self._backoff_until:
                    remaining = int(self._backoff_until - time.monotonic())
                    logger.info(
                        "event=login_attempt outcome=denied reason=backoff remaining=%ds",
                        remaining,
                    )
                    if self.auth.client is not None:
                        return self.auth.client
                    raise UpstreamUnavailableError(f"登录退避中（剩余 {remaining}s），请稍后重试")
                else:
                    self._transition(AuthState.EXPIRED, "backoff_expired")

            # 频率限制检查
            if not self._check_rate_limit():
                if self.auth.client is not None:
                    return self.auth.client
                raise UpstreamUnavailableError("登录频率过高，请稍后重试")

            # 登录最小间隔检查（防止登录风暴）
            now3 = time.monotonic()
            since_last_attempt = now3 - self._last_login_attempt_time
            if self._last_login_attempt_time > 0 and since_last_attempt < LOGIN_MIN_INTERVAL:
                remaining = int(LOGIN_MIN_INTERVAL - since_last_attempt)
                logger.warning(
                    "event=login_attempt outcome=denied reason=cooldown remaining=%ds "
                    "last_attempt=%.1fs_ago",
                    remaining,
                    since_last_attempt,
                )
                if self.auth.client is not None:
                    return self.auth.client
                raise UpstreamUnavailableError(f"登录间隔过短（剩余 {remaining}s），请稍后重试")

            # 真正执行登录
            return await self._do_login_with_protections()

    async def _do_login_with_protections(self) -> httpx.AsyncClient:
        """在 login_lock 持有下执行登录，记录结果并更新状态"""
        logger.info(
            "event=login_attempt outcome=allowed state=%s consecutive_failures=%d",
            self._state.value,
            self._consecutive_failures,
        )
        self._last_login_attempt_time = time.monotonic()
        self._record_login_attempt()

        try:
            await self.auth.login(self._consecutive_failures)
            # 登录成功
            self._consecutive_failures = 0
            self._backoff_until = 0
            self._transition(AuthState.OK, "login_success")
            self._last_login_time = time.monotonic()
            self._last_login_ok_time = time.monotonic()
            self._login_then_rejected = False
            logger.info("event=login_result outcome=success")
            self._save_persisted_state()
            self._save_cookies()
            return self.auth.client  # type: ignore[return-value]
        except TwoFactorError as e:
            self._consecutive_failures += 1
            # 2FA 失败使用固定短退避（30s），不触发熔断
            self._backoff_until = time.monotonic() + 30
            self._transition(AuthState.LOGIN_BACKOFF, f"2fa_failed:{e}")
            logger.error(
                "event=login_result outcome=failure type=2fa error=%s failures=%d",
                e,
                self._consecutive_failures,
            )
            if self._consecutive_failures >= MAX_CONSECUTIVE_FAILURES:
                self._open_circuit(
                    CIRCUIT_NORMAL_DURATION, f"consecutive_failures={self._consecutive_failures}"
                )
            self._save_persisted_state()
            raise
        except CriticalLoginError as e:
            self._consecutive_failures += 1
            logger.error("event=login_result outcome=failure type=critical error=%s", e)
            self._open_circuit(e.circuit_duration, str(e))
            raise
        except Exception as e:
            self._consecutive_failures += 1
            backoff = self._compute_backoff(is_critical=False)
            self._backoff_until = time.monotonic() + backoff
            self._transition(AuthState.LOGIN_BACKOFF, f"login_failed:{e}")
            logger.error(
                "event=login_result outcome=failure type=normal error=%s backoff=%.1fs failures=%d",
                e,
                backoff,
                self._consecutive_failures,
            )
            if self._consecutive_failures >= MAX_CONSECUTIVE_FAILURES:
                self._open_circuit(
                    CIRCUIT_NORMAL_DURATION, f"consecutive_failures={self._consecutive_failures}"
                )
            self._save_persisted_state()
            raise

    async def force_relogin(self):
        """
        仅在明确检测到 CAS session 失效时调用。
        调用者必须已经确认响应是真实的 CAS 登录页重定向。
        此方法仍需通过 ensure_login() 的所有保护层级。

        限流：10 秒内重复调用 force_relogin 会被忽略。
        """
        now = time.monotonic()
        since_last = now - self._last_force_relogin_time
        if self._last_force_relogin_time > 0 and since_last < FORCE_RELOGIN_THROTTLE:
            logger.warning(
                "event=force_relogin outcome=throttled "
                "since_last=%.1fs throttle=%ds — 忽略重复请求",
                since_last,
                FORCE_RELOGIN_THROTTLE,
            )
            if self.auth.client is not None:
                return self.auth.client
            raise UpstreamUnavailableError("登录请求过于频繁，请稍后重试")

        # A confirmed redirect still cannot bypass an active protection window.
        self._check_or_raise_circuit()
        if self._state == AuthState.LOGIN_BACKOFF and now < self._backoff_until:
            raise UpstreamUnavailableError("登录退避中，请稍后重试")
        self._last_force_relogin_time = now
        logger.warning("event=force_relogin requested — 检测到明确的 CAS 会话失效")
        self._transition(AuthState.EXPIRED, "force_relogin:definitive_cas_redirect")
        self._last_login_time = 0
        try:
            return await self.ensure_login()
        except (CircuitOpenError, UpstreamUnavailableError, CriticalLoginError):
            raise
        except Exception as e:
            logger.error("event=force_relogin failed: %s", e)
            raise

    async def check_and_refresh(self):
        """
        保活检查：轻量 HEAD 请求验证 Cookie 是否还有效。

        安全规则：
        - 网络异常 → 状态转 SUSPECT，不触发登录
        - 非 CAS 的 302/401/403 → 状态转 SUSPECT，不触发登录
        - 只有明确 CAS 重定向才转 EXPIRED
        - 熔断期间跳过检查
        """
        if not self.auth.client or self._state in (AuthState.CIRCUIT_OPEN, AuthState.LOGIN_BACKOFF):
            return

        try:
            headers = {"Host": self.settings.target_host}
            if self.settings.openwebui_api_key:
                headers["Authorization"] = f"Bearer {self.settings.openwebui_api_key}"

            resp = await self.auth.client.head(
                f"{self.settings.target_base}/api/config",
                headers=headers,
                follow_redirects=False,
            )

            # 只对明确的认证重定向触发登录
            if resp.status_code in (301, 302, 307):
                location = resp.headers.get("location", "")
                if _is_auth_redirect(resp):
                    logger.warning(
                        "event=keepalive result=auth_redirect location=%s", location[:80]
                    )
                    self._transition(AuthState.EXPIRED, "keepalive:auth_redirect")
                    try:
                        await self.ensure_login()
                    except (CircuitOpenError, UpstreamUnavailableError, CriticalLoginError):
                        pass
                    return

            # 其他非 2xx 响应：标记 SUSPECT
            if resp.status_code >= 400:
                logger.info("event=keepalive result=upstream_error status=%d", resp.status_code)
                self._transition(AuthState.SUSPECT, f"keepalive:upstream_status_{resp.status_code}")
            else:
                self._last_login_time = time.monotonic()
                if self._state == AuthState.SUSPECT:
                    self._transition(AuthState.OK, "keepalive:recovered")
                logger.debug("保活检查通过")

        except Exception as e:
            logger.warning("event=keepalive result=network_error error=%s", e)
            # 如果已经进入熔断或退避状态，不要覆盖（避免 keepalive 把 CIRCUIT_OPEN → SUSPECT 导致重试死循环）
            if self._state not in (AuthState.CIRCUIT_OPEN, AuthState.LOGIN_BACKOFF):
                self._transition(AuthState.SUSPECT, "keepalive:network_error")

    async def start_keepalive(self):
        if self._keepalive_task and not self._keepalive_task.done():
            return

        async def _keepalive_loop():
            while True:
                jitter = random.randint(-KEEPALIVE_JITTER_SECONDS, KEEPALIVE_JITTER_SECONDS)
                interval = KEEPALIVE_INTERVAL_SECONDS + jitter
                await asyncio.sleep(interval)
                try:
                    await self.check_and_refresh()
                except Exception as e:
                    logger.error("保活任务异常：%s", e)

        self._keepalive_task = asyncio.create_task(_keepalive_loop())
        logger.info("后台保活任务已启动（间隔：~5 分钟，含 ±30s 抖动）")

    async def stop_keepalive(self):
        if self._keepalive_task:
            self._keepalive_task.cancel()
            try:
                await self._keepalive_task
            except asyncio.CancelledError:
                pass

    async def close(self):
        await self.stop_keepalive()
        if self.auth.client:
            try:
                await asyncio.wait_for(self.auth.client.aclose(), timeout=2.0)
            except asyncio.TimeoutError:
                pass

    @property
    def client(self) -> httpx.AsyncClient | None:
        return self.auth.client

    def diagnostics(self) -> dict:
        now = time.monotonic()
        return {
            "circuit_remaining_seconds": int(max(0, self._circuit_until - now)),
            "backoff_remaining_seconds": int(max(0, self._backoff_until - now)),
            "last_login_ok_seconds_ago": int(now - self._last_login_ok_time)
            if self._last_login_ok_time
            else -1,
            "consecutive_failures": self._consecutive_failures,
            "login_attempts_last_hour": sum(
                t > time.time() - LOGIN_WINDOW_SECONDS for t in self._login_attempt_times
            ),
        }

    def record_proxy_failure(self, reason: str) -> None:
        self._record_proxy_failure()
        if self._state not in (AuthState.CIRCUIT_OPEN, AuthState.LOGIN_BACKOFF):
            self._transition(AuthState.SUSPECT, reason)

    def record_proxy_response(self, status_code: int) -> None:
        self._recent_proxy_failures.clear()
        self._login_then_rejected = False
        if status_code < 500 and self._state == AuthState.SUSPECT:
            self._transition(AuthState.OK, "proxy:recovered")

    async def fetch_models(self) -> dict:
        """Read-only monitoring: never restore or create an authentication session."""
        client = self.client
        if self.state != AuthState.OK or client is None:
            raise UpstreamUnavailableError("认证会话未就绪，跳过模型监控")
        response = await client.get(
            f"{self.settings.target_base}/v1/models",
            headers={
                "Host": self.settings.target_host,
                "Authorization": f"Bearer {self.settings.openwebui_api_key}",
            },
            follow_redirects=False,
        )
        response.raise_for_status()
        return response.json()
