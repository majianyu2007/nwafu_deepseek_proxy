import enum

from nwafu_proxy.constants import CIRCUIT_CRITICAL_DURATION


class AuthState(enum.Enum):
    OK = "ok"  # 会话有效，正常运作
    SUSPECT = "suspect"  # 检测到异常但不确定是认证过期，不触发登录
    EXPIRED = "expired"  # 明确检测到 CAS 重定向，需要重新登录
    LOGIN_BACKOFF = "backoff"  # 登录失败，等待退避
    CIRCUIT_OPEN = "circuit_open"  # 熔断开启，保护账号


class CriticalLoginError(Exception):
    """高危登录失败（账号锁定/验证码/密码错误），需要更长熔断"""

    def __init__(self, message: str, circuit_duration: int = CIRCUIT_CRITICAL_DURATION):
        super().__init__(message)
        self.circuit_duration = circuit_duration


class CircuitOpenError(Exception):
    """熔断开启中，拒绝登录"""

    def __init__(self, message: str, retry_after: int = 0):
        super().__init__(message)
        self.retry_after = retry_after


class UpstreamUnavailableError(Exception):
    """上游暂不可达（用于向客户端返回 503）"""


class TwoFactorError(Exception):
    """二次验证失败（TOTP 码错误/过期等），使用较短退避"""

    def __init__(self, message: str):
        super().__init__(message)
