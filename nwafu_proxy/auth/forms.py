import re

from nwafu_proxy.constants import BODY_SAMPLE_MAX_BYTES

_RE_INPUT_BY_ID = lambda name: re.compile(
    rf'<input\b[^>]*\bid=["\']{re.escape(name)}["\'][^>]*>', re.I
)
_RE_VALUE_ATTR = re.compile(r'\bvalue=["\']([^"\']*)["\']', re.I)
_RE_ERROR_TIP = re.compile(
    r'id=["\']formErrorTip["\'][^>]*>.*?<span[^>]*>([^<]+)</span>',
    re.S | re.I,
)
_RE_CAS_FORM_FIELDS = re.compile(
    r'<input\b[^>]*\bid=["\'](?:execution|pwdEncryptSalt)["\'][^>]*>', re.I
)


def _extract_input_value(html: str, input_id: str) -> str | None:
    tag_match = _RE_INPUT_BY_ID(input_id).search(html)
    if not tag_match:
        return None
    val = _RE_VALUE_ATTR.search(tag_match.group(0))
    return val.group(1) if val else ""


def _parse_login_form(html: str) -> tuple[str, str]:
    execution = _extract_input_value(html, "execution")
    salt = _extract_input_value(html, "pwdEncryptSalt")
    if execution is None or salt is None:
        raise RuntimeError("登录页结构变更：无法提取 execution/pwdEncryptSalt")
    return execution, salt


def _extract_error_text(html: str) -> str | None:
    m = _RE_ERROR_TIP.search(html)
    return m.group(1).strip() if m else None


def _sample_contains_cas_fields(body_bytes: bytes) -> bool:
    """检查前 N 字节中是否包含 CAS 登录表单特征字段"""
    sample = body_bytes[:BODY_SAMPLE_MAX_BYTES].decode("utf-8", errors="ignore")
    found = set()
    for m in _RE_CAS_FORM_FIELDS.finditer(sample):
        tag = m.group(0).lower()
        if 'id="execution"' in tag or "id='execution'" in tag:
            found.add("execution")
        if 'id="pwdencryptsalt"' in tag or "id='pwdencryptsalt'" in tag:
            found.add("pwdEncryptSalt")
    return "execution" in found and "pwdEncryptSalt" in found
