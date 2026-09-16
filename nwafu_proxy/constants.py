"""Shared timeout and account-protection policy constants."""

import httpx

COOKIE_TTL_SECONDS = 120 * 60  # CAS rememberMe 开启后 TGC 存活 7 天，本地 TTL 设 2h 足够
KEEPALIVE_INTERVAL_SECONDS = 5 * 60
KEEPALIVE_JITTER_SECONDS = 30
MAX_LOGIN_REDIRECTS = 10
PROXY_MAX_RETRIES = 2
NETWORK_RETRY_ATTEMPTS = 3

# 登录频率限制
MAX_LOGINS_PER_HOUR = 6
LOGIN_WINDOW_SECONDS = 3600

# 退避
LOGIN_BACKOFF_BASE = 5
LOGIN_BACKOFF_MULTIPLIER = 4
LOGIN_BACKOFF_MAX_NORMAL = 900  # 15 min
LOGIN_BACKOFF_MAX_CRITICAL = 14400  # 4 hours

# 熔断
CIRCUIT_NORMAL_DURATION = 900  # 15 min
CIRCUIT_CRITICAL_DURATION = 21600  # 6 hours
CIRCUIT_CAPTCHA_DURATION = 7200  # 2 hours
CIRCUIT_PASSWORD_ERROR_DURATION = 3600  # 1 hour
MAX_CONSECUTIVE_FAILURES = 3

# Body 采样上限（用于 CAS 登录页识别）
BODY_SAMPLE_MAX_BYTES = 4096

STREAM_TIMEOUT = httpx.Timeout(300.0, connect=15.0)
DEFAULT_TIMEOUT = httpx.Timeout(60.0, connect=15.0)
DEGRADED_TIMEOUT = httpx.Timeout(8.0, connect=5.0)  # 上游异常时快速失败
DEGRADED_WINDOW = 120  # 2 分钟内
DEGRADED_THRESHOLD = 2  # 出现 2 次失败即进入降级模式
LOGIN_STICKY_WINDOW = 30  # 登录成功后短时间内仍被拒绝，视为会话建立异常
LOGIN_MIN_INTERVAL = 60  # 两次登录之间的最小间隔（防止登录风暴）
FORCE_RELOGIN_THROTTLE = 10  # force_relogin 限流窗口（秒）
RESPONSE_REWRITE_MAX_BYTES = 5 * 1024 * 1024

_RETRIABLE_NET_ERRORS = (
    httpx.ConnectError,
    httpx.NetworkError,
    httpx.ReadError,
    httpx.RemoteProtocolError,
)

_LOGIN_ERROR_MESSAGES = {
    "FAIL_UPNOTMATCH": "密码错误或账户不存在",
    "CAPTCHA_NOTMATCH": "需要输入验证码，账号可能被临时限制",
    "LOCK": "账户已被锁定",
}
