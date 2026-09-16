"""Persistence only: session policy and HTTP validation stay in session.py."""

import json
import os
import tempfile
import time
from pathlib import Path

import httpx

from nwafu_proxy.logging import logger


class SessionStore:
    def __init__(self, data_dir: Path):
        self.data_dir = data_dir

    def _read(self, name: str):
        try:
            return json.loads((self.data_dir / name).read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return None

    def _write(self, name: str, data) -> None:
        """Replace atomically, with owner-only permissions for cookie material."""
        temp_path = None
        try:
            self.data_dir.mkdir(parents=True, exist_ok=True)
            with tempfile.NamedTemporaryFile(
                mode="w", encoding="utf-8", dir=self.data_dir, delete=False
            ) as file:
                temp_path = Path(file.name)
                json.dump(data, file)
            os.replace(temp_path, self.data_dir / name)
        except OSError as exc:
            logger.warning("event=persist_failed file=%s error=%s", name, exc)
        finally:
            if temp_path is not None:
                temp_path.unlink(missing_ok=True)

    def load_state(self) -> dict:
        data = self._read("login_state.json")
        return data if isinstance(data, dict) else {}

    def save_state(self, data: dict) -> None:
        self._write("login_state.json", data)

    def save_cookies(self, cookies: httpx.Cookies) -> None:
        values = [
            {"name": c.name, "value": c.value, "domain": c.domain, "path": c.path}
            for c in cookies.jar
        ]
        self._write("cookies.json", {"cookies": values, "saved_at": time.time()})

    def load_cookies(self) -> tuple[list[dict], float]:
        """Accept both the proxy envelope and exported browser cookie arrays."""
        data = self._read("cookies.json")
        if isinstance(data, list):
            cookies, saved_at = data, 0
        elif isinstance(data, dict):
            cookies, saved_at = data.get("cookies", []), data.get("saved_at", 0)
        else:
            return [], 0
        if not isinstance(cookies, list):
            return [], 0
        normalized = []
        for cookie in cookies:
            if not isinstance(cookie, dict):
                continue
            fields = {k.lower(): v for k, v in cookie.items()}
            if not isinstance(fields.get("name"), str) or not isinstance(fields.get("value"), str):
                continue
            normalized.append(
                {
                    "name": fields["name"],
                    "value": fields["value"],
                    "domain": fields.get("domain", ""),
                    "path": fields.get("path", "/"),
                }
            )
        return normalized, saved_at if isinstance(saved_at, (int, float)) else 0
