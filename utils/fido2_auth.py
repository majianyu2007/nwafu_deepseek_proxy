"""
FIDO2/WebAuthn (passkey) 签名模块——用于绕过 CAS 登录的密码+验证码环节。

基于导出的 ECDSA P-256 私钥，手动构造 WebAuthn assertion。
用法：
    from utils.fido2_auth import build_webauthn_assertion
    assertion = build_webauthn_assertion(credential_json, challenge_b64, rp_id, origin)
"""

import base64
import hashlib
import json
import os
import struct

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.backends import default_backend


def _b64url_decode(s: str) -> bytes:
    s = s.replace("-", "+").replace("_", "/")
    padding = 4 - len(s) % 4
    if padding != 4:
        s += "=" * padding
    return base64.b64decode(s)


def _b64url_encode(b: bytes) -> str:
    return base64.b64encode(b).decode().rstrip("=").replace("+", "-").replace("/", "_")


def _sha256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def load_private_key(key_value_b64: str) -> ec.EllipticCurvePrivateKey:
    """
    解析导出的 keyValue（兼容 Base64 和 Base64URL 两种格式）。
    """
    # 先尝试标准 base64，失败则按 base64url 转换后再试
    try:
        der = base64.b64decode(key_value_b64)
    except Exception:
        der = _b64url_decode(key_value_b64)
    return serialization.load_der_private_key(der, password=None, backend=default_backend())  # type: ignore[return-value]


def build_client_data(challenge_b64: str, rp_id: str, origin: str) -> tuple[bytes, bytes]:
    """
    构造 clientDataJSON 并返回 (json_bytes, sha256_hash)。
    """
    client_data = {
        "type": "webauthn.get",
        "challenge": challenge_b64,
        "origin": origin,
        "crossOrigin": False,
    }
    # 不做额外空格，与浏览器行为对齐
    json_bytes = json.dumps(client_data, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    return json_bytes, _sha256(json_bytes)


def build_authenticator_data(rp_id: str, sign_count: int = 0, flags: int = 0x1d) -> bytes:
    """
    构造 authenticatorData。默认 flags=0x1d (UP|UV|BE|BS) 匹配浏览器 Bitwarden passkey。
    """
    rp_id_hash = _sha256(rp_id.encode("utf-8"))
    counter = struct.pack(">I", sign_count)
    return rp_id_hash + bytes([flags]) + counter


def build_webauthn_assertion(
    credential: dict,
    challenge_b64: str,
    rp_id: str,
    origin: str,
) -> dict:
    """
    输入 credential（从 CAS 导出的 fido2Credentials 条目）、
    服务端下发的 challenge（base64url）、rpId 和 origin，
    返回可供 POST 提交的 assertion 字典（对齐浏览器 responseToObject 结构）：
        {
            "id": credentialId (base64url),
            "response": {
                "clientDataJSON": base64url,
                "authenticatorData": base64url,
                "signature": base64url,
            },
            "type": "public-key",
            "clientExtensionResults": {},
        }
    """
    # 将 Bitwarden UUID 格式 credentialId (如 "a99118bb-...") 转为 WebAuthn 标准 base64url
    raw_id = bytes.fromhex(credential["credentialId"].replace("-", ""))
    credential_id = _b64url_encode(raw_id)
    private_key = load_private_key(credential["keyValue"])

    # 1. clientDataJSON
    client_data_bytes, client_data_hash = build_client_data(challenge_b64, rp_id, origin)

    # 2. authenticatorData (flags: UP|UV|BE|BS = 0x1d, matching browser Bitwarden passkey)
    auth_data = build_authenticator_data(rp_id, flags=0x1d)

    # 3. 签名 → DER 格式 (浏览器发送 ASN.1 DER，不转 raw RS)
    signed_data = auth_data + client_data_hash
    signature_der = private_key.sign(signed_data, ec.ECDSA(hashes.SHA256()))

    user_handle = credential.get("userHandle", "")

    result = {
        "id": credential_id,
        "type": "public-key",
        "response": {
            "authenticatorData": _b64url_encode(auth_data),
            "clientDataJSON": _b64url_encode(client_data_bytes),
            "signature": _b64url_encode(signature_der),
        },
        "clientExtensionResults": {},
    }
    if user_handle:
        result["response"]["userHandle"] = user_handle
    return result


def _der_to_raw(der_sig: bytes) -> bytes:
    """
    ECDSA DER 签名字节 → IEEE P1363 裸 R||S 格式。
    WebAuthn 规范要求后者。
    """
    # DER format: 0x30 | len | 0x02 | r_len | r_bytes | 0x02 | s_len | s_bytes
    # r_bytes 和 s_bytes 可能有 leading zero padding
    idx = 2  # skip 0x30 and total length
    assert der_sig[idx] == 0x02
    idx += 1
    r_len = der_sig[idx]
    idx += 1
    r = int.from_bytes(der_sig[idx : idx + r_len], "big")
    idx += r_len
    assert der_sig[idx] == 0x02
    idx += 1
    s_len = der_sig[idx]
    idx += 1
    s = int.from_bytes(der_sig[idx : idx + s_len], "big")
    # P-256 → 32 bytes each
    return r.to_bytes(32, "big") + s.to_bytes(32, "big")


# ============================================================
# 从环境变量加载 credential
# ============================================================

def load_credential() -> dict | None:
    """
    从 FIDO2_CREDENTIAL 环境变量或 .data/fido2_credential.json 加载凭据。
    格式：{"credentialId": "...", "keyValue": "...", "rpId": "...", ...}
    """
    # 优先环境变量
    env_val = os.getenv("FIDO2_CREDENTIAL", "").strip()
    if env_val:
        try:
            return json.loads(env_val)
        except json.JSONDecodeError:
            pass

    # fallback 文件
    file_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), ".data", "fido2_credential.json")
    try:
        with open(file_path, "r") as f:
            return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        return None
