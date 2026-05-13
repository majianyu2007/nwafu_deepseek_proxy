"""
模型变更监控与多渠道通知（可选功能）。

启用方式：在 .env 中设置 MONITOR_ENABLED=true

安全规则：
- 仅在认证状态为 OK 时轮询
- 从不调用 force_relogin()
- 轮询失败只记录日志，不影响认证状态
- 熔断/退避/SUSPECT 状态下自动跳过
"""

import asyncio
import json
import logging
import os
import time
from dataclasses import dataclass, field
from typing import Optional, Callable

import httpx

logger = logging.getLogger("proxy.monitor")

# 默认配置
DEFAULT_POLL_INTERVAL = 600   # 10 min
DEFAULT_TIMEOUT = 30.0


# ============================================================
# 数据模型
# ============================================================


@dataclass(frozen=True)
class ModelInfo:
    id: str
    name: str
    model_type: str          # "chat" | "embedding" | "rerank" | "unknown"
    owned_by: str
    tags: list[str]
    capabilities: dict
    created_at: int
    updated_at: int

    def capability_summary(self) -> str:
        icons = {
            "vision": "视觉", "code_interpreter": "代码",
            "web_search": "搜索", "image_generation": "绘图",
            "file_upload": "文件",
        }
        active = [v for k, v in icons.items() if self.capabilities.get(k)]
        return " ".join(active) if active else "-"

    def type_emoji(self) -> str:
        return {"chat": "对话", "embedding": "嵌入", "rerank": "重排"}.get(self.model_type, "?")


@dataclass
class ModelDiff:
    added: list[ModelInfo]
    removed: list[ModelInfo]
    timestamp: float = field(default_factory=time.time)

    @property
    def has_changes(self) -> bool:
        return bool(self.added or self.removed)

    def to_text(self) -> str:
        if not self.has_changes:
            return ""
        lines = ["NWAFU 模型变更"]
        lines.append(f"{time.strftime('%m-%d %H:%M', time.localtime(self.timestamp))}")
        lines.append("")
        if self.added:
            lines.append(f"新增 {len(self.added)} 个模型：")
            for m in self.added:
                tag = f"[{m.tags[0]}]" if m.tags else f"[{m.model_type}]"
                cap = f"  {m.capability_summary()}" if m.model_type == "chat" else ""
                lines.append(f"  + {m.id} {tag}{cap}")
        if self.removed:
            if self.added:
                lines.append("")
            lines.append(f"移除 {len(self.removed)} 个模型：")
            for m in self.removed:
                tag = f"[{m.tags[0]}]" if m.tags else f"[{m.model_type}]"
                lines.append(f"  - {m.id} {tag}")
        return "\n".join(lines)

    def to_dict(self) -> dict:
        def _m(m: ModelInfo) -> dict:
            return {"id": m.id, "name": m.name, "model_type": m.model_type,
                    "tags": m.tags, "capabilities": m.capabilities}
        return {
            "event": "model_change", "timestamp": self.timestamp,
            "added": [_m(m) for m in self.added],
            "removed": [_m(m) for m in self.removed],
            "summary": self.to_text(),
        }


# ============================================================
# 模型解析
# ============================================================


def _detect_model_type(item: dict) -> str:
    mt = item.get("model_type") or item.get("openai", {}).get("model_type", "")
    if mt:
        mt = mt.lower()
        if "embed" in mt:
            return "embedding"
        if "rerank" in mt:
            return "rerank"
        return mt
    tags = [t.get("name", "") for t in (item.get("tags") or [])]
    for t in tags:
        tl = t.lower()
        if "embed" in tl:
            return "embedding"
        if "rerank" in tl:
            return "rerank"
    return "chat"


def _extract_capabilities(item: dict) -> dict:
    caps = item.get("info", {}).get("meta", {}).get("capabilities", {})
    return {k: caps.get(k, False) for k in
            ("vision", "file_upload", "web_search", "image_generation", "code_interpreter")}


def _parse_models(data: list[dict]) -> dict[str, ModelInfo]:
    result = {}
    for item in data:
        mid = item.get("id", "")
        if not mid:
            continue
        tags = [t.get("name", "") for t in (item.get("tags") or []) if t.get("name")]
        info = item.get("info", {})
        result[mid] = ModelInfo(
            id=mid, name=item.get("name", mid), model_type=_detect_model_type(item),
            owned_by=item.get("owned_by", "unknown"), tags=tags,
            capabilities=_extract_capabilities(item),
            created_at=info.get("created_at", 0), updated_at=info.get("updated_at", 0),
        )
    return result


def _diff_models(old: dict[str, ModelInfo], new: dict[str, ModelInfo]) -> ModelDiff:
    old_ids, new_ids = set(old), set(new)
    return ModelDiff(
        added=[new[i] for i in sorted(new_ids - old_ids)],
        removed=[old[i] for i in sorted(old_ids - new_ids)],
    )


# ============================================================
# 通知渠道
# ============================================================


class _NotifyChannel:
    async def send(self, diff: ModelDiff) -> bool:
        raise NotImplementedError


class _TelegramNotifier(_NotifyChannel):
    def __init__(self, bot_token: str, chat_id: str, proxy: str = ""):
        self.bot_token = bot_token
        self.chat_id = chat_id
        self.proxy = proxy or None

    def _client(self) -> httpx.AsyncClient:
        if self.proxy:
            return httpx.AsyncClient(timeout=15.0, proxy=self.proxy)
        return httpx.AsyncClient(timeout=15.0, trust_env=True)

    async def send(self, diff: ModelDiff) -> bool:
        if not diff.has_changes:
            return True
        url = f"https://api.telegram.org/bot{self.bot_token}/sendMessage"
        payload = {"chat_id": self.chat_id, "text": diff.to_text(), "disable_web_page_preview": True}
        try:
            async with self._client() as c:
                resp = await c.post(url, json=payload)
                ok = resp.status_code == 200
                if ok:
                    logger.info("Telegram 通知发送成功 -> %s", self.chat_id)
                else:
                    logger.error("Telegram 通知失败：%d %s", resp.status_code, resp.text[:200])
                return ok
        except Exception as e:
            logger.error("Telegram 通知异常：%s", e)
            return False


class _WebhookNotifier(_NotifyChannel):
    def __init__(self, url: str, secret: str = "", proxy: str = ""):
        self.url = url
        self.secret = secret
        self.proxy = proxy or None

    def _client(self) -> httpx.AsyncClient:
        if self.proxy:
            return httpx.AsyncClient(timeout=15.0, proxy=self.proxy)
        return httpx.AsyncClient(timeout=15.0, trust_env=True)

    async def send(self, diff: ModelDiff) -> bool:
        if not diff.has_changes:
            return True
        headers: dict[str, str] = {"Content-Type": "application/json"}
        if self.secret:
            headers["X-Webhook-Secret"] = self.secret
        try:
            async with self._client() as c:
                resp = await c.post(self.url, json=diff.to_dict(), headers=headers)
                ok = resp.status_code < 300
                if ok:
                    logger.info("Webhook 通知发送成功 -> %s", self.url[:60])
                else:
                    logger.error("Webhook 通知失败：%d %s", resp.status_code, resp.text[:200])
                return ok
        except Exception as e:
            logger.error("Webhook 通知异常：%s", e)
            return False


# ============================================================
# SSE 广播
# ============================================================


class _SSEBroadcaster:
    def __init__(self):
        self._queues: list[asyncio.Queue] = []

    def subscribe(self) -> asyncio.Queue:
        q: asyncio.Queue = asyncio.Queue(maxsize=50)
        self._queues.append(q)
        logger.info("SSE 客户端连接（当前 %d 个）", len(self._queues))
        return q

    def unsubscribe(self, q: asyncio.Queue):
        if q in self._queues:
            self._queues.remove(q)
        logger.info("SSE 客户端断开（当前 %d 个）", len(self._queues))

    async def broadcast(self, event: str, data: dict):
        payload = json.dumps(data, ensure_ascii=False)
        msg = f"event: {event}\ndata: {payload}\n\n"
        dead = []
        for q in self._queues:
            try:
                q.put_nowait(msg)
            except asyncio.QueueFull:
                dead.append(q)
        for q in dead:
            self._queues.remove(q)

    @property
    def client_count(self) -> int:
        return len(self._queues)


# ============================================================
# 模型监控器
# ============================================================


class ModelMonitor:
    """定期轮询模型列表，检测变更，分发通知"""

    def __init__(self, *, poll_interval: int = DEFAULT_POLL_INTERVAL,
                 api_base: str = "http://127.0.0.1:8000",
                 can_poll: Callable[[], bool]):
        self.poll_interval = poll_interval
        self.api_base = api_base.rstrip("/")
        self._can_poll = can_poll  # 返回 True 时允许轮询
        self.sse = _SSEBroadcaster()
        self._channels: list[_NotifyChannel] = []
        self._current_models: dict[str, ModelInfo] = {}
        self._history: list[ModelDiff] = []
        self._task: Optional[asyncio.Task] = None
        self._last_poll_time: float = 0
        self._last_poll_ok: bool = False
        self._poll_error: str = ""
        self._initialized: bool = False

    def add_channel(self, ch: _NotifyChannel):
        self._channels.append(ch)

    @property
    def status(self) -> dict:
        return {
            "running": self._task is not None and not self._task.done(),
            "poll_interval": self.poll_interval,
            "last_poll_time": self._last_poll_time,
            "last_poll_ok": self._last_poll_ok,
            "poll_error": self._poll_error,
            "model_count": len(self._current_models),
            "channel_count": len(self._channels),
            "sse_clients": self.sse.client_count,
            "history_count": len(self._history),
        }

    async def fetch_models(self) -> dict[str, ModelInfo]:
        async with httpx.AsyncClient(timeout=DEFAULT_TIMEOUT) as c:
            resp = await c.get(
                f"{self.api_base}/v1/models",
                headers={"Authorization": "Bearer sk-monitor"},
            )
            resp.raise_for_status()
            return _parse_models(resp.json().get("data", []))

    async def poll_once(self) -> Optional[ModelDiff]:
        # 安全规则：仅在 OK 状态轮询
        if not self._can_poll():
            logger.info("event=monitor_skip reason=auth_not_ok")
            return None

        try:
            new_models = await self.fetch_models()
            self._last_poll_time = time.time()
            self._last_poll_ok = True
            self._poll_error = ""
        except Exception as e:
            self._last_poll_time = time.time()
            self._last_poll_ok = False
            self._poll_error = str(e)
            logger.warning("event=monitor_poll_error error=%s", e)
            return None

        if not self._initialized:
            self._current_models = new_models
            self._initialized = True
            logger.info("模型基线建立：%d 个模型 [%s]", len(new_models), ", ".join(sorted(new_models)))
            await self.sse.broadcast("snapshot", self._snapshot_data())
            return None

        d = _diff_models(self._current_models, new_models)
        self._current_models = new_models

        if d.has_changes:
            logger.info("event=model_change added=%d removed=%d", len(d.added), len(d.removed))
            self._history.append(d)
            if len(self._history) > 50:
                self._history = self._history[-50:]
            await self._dispatch(d)
            return d
        return None

    async def _dispatch(self, diff: ModelDiff):
        await self.sse.broadcast("model_change", diff.to_dict())
        await self.sse.broadcast("snapshot", self._snapshot_data())
        tasks = [ch.send(diff) for ch in self._channels]
        if tasks:
            results = await asyncio.gather(*tasks, return_exceptions=True)
            for i, r in enumerate(results):
                if isinstance(r, Exception):
                    logger.error("通知渠道[%d]异常：%s", i, r)

    def _snapshot_data(self) -> dict:
        models = []
        for m in sorted(self._current_models.values(), key=lambda x: x.id):
            models.append({
                "id": m.id, "name": m.name, "model_type": m.model_type,
                "type_emoji": m.type_emoji(), "tags": m.tags,
                "capabilities": m.capabilities, "capability_summary": m.capability_summary(),
                "created_at": m.created_at, "updated_at": m.updated_at,
            })
        return {"models": models, "total": len(models), "timestamp": time.time()}

    def get_snapshot(self) -> dict:
        return self._snapshot_data()

    def get_history_data(self) -> list[dict]:
        return [d.to_dict() for d in reversed(self._history)]

    async def start(self):
        if self._task and not self._task.done():
            return

        async def _loop():
            logger.info("模型监控启动（轮询间隔 %ds）", self.poll_interval)
            await asyncio.sleep(5)  # 等待代理就绪，避免首次轮询因网络未就绪误报
            await self.poll_once()
            while True:
                await asyncio.sleep(self.poll_interval)
                try:
                    await self.poll_once()
                except Exception as e:
                    logger.error("监控轮询异常：%s", e)

        self._task = asyncio.create_task(_loop())

    async def stop(self):
        if self._task:
            self._task.cancel()
            try:
                await self._task
            except asyncio.CancelledError:
                pass
            logger.info("模型监控已停止")


# ============================================================
# 工厂函数 & 路由注册（供 server.py 调用）
# ============================================================


def create_monitor(settings, can_poll: Callable[[], bool]) -> ModelMonitor:
    """根据 Settings 创建并配置 ModelMonitor"""
    monitor = ModelMonitor(
        poll_interval=settings.monitor_poll_interval,
        api_base=f"http://127.0.0.1:{settings.proxy_port}",
        can_poll=can_poll,
    )
    if settings.notify_proxy:
        logger.info("通知代理已配置：%s", settings.notify_proxy)
    if settings.telegram_bot_token and settings.telegram_chat_id:
        monitor.add_channel(_TelegramNotifier(
            settings.telegram_bot_token, settings.telegram_chat_id,
            proxy=settings.notify_proxy,
        ))
        logger.info("通知渠道已注册：Telegram -> %s", settings.telegram_chat_id)
    for url in settings.webhook_urls:
        monitor.add_channel(_WebhookNotifier(
            url, secret=settings.webhook_secret, proxy=settings.notify_proxy,
        ))
        logger.info("通知渠道已注册：Webhook -> %s", url[:60])
    return monitor


def register_monitor_routes(app, monitor: ModelMonitor):
    """在 FastAPI app 上注册监控相关路由"""
    from fastapi.responses import HTMLResponse, StreamingResponse, JSONResponse
    import os as _os

    static_dir = _os.path.join(_os.path.dirname(_os.path.dirname(__file__)), "static")
    monitor_html_path = _os.path.join(static_dir, "monitor.html")

    @app.get("/monitor")
    async def monitor_page():
        try:
            with open(monitor_html_path, "r", encoding="utf-8") as f:
                return HTMLResponse(content=f.read())
        except FileNotFoundError:
            return HTMLResponse(content="缺少监控页面：static/monitor.html", status_code=500)

    @app.get("/monitor/sse")
    async def monitor_sse():
        q = monitor.sse.subscribe()

        async def _stream():
            try:
                snapshot = monitor.get_snapshot()
                yield f"event: snapshot\ndata: {json.dumps(snapshot, ensure_ascii=False)}\n\n"
                while True:
                    msg = await q.get()
                    yield msg
            except asyncio.CancelledError:
                pass
            finally:
                monitor.sse.unsubscribe(q)

        return StreamingResponse(
            _stream(), media_type="text/event-stream",
            headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
        )

    @app.get("/monitor/snapshot")
    async def monitor_snapshot():
        return JSONResponse(monitor.get_snapshot())

    @app.get("/monitor/history")
    async def monitor_history():
        return JSONResponse(monitor.get_history_data())

    @app.get("/monitor/status")
    async def monitor_status():
        return JSONResponse(monitor.status)

    @app.post("/monitor/poll")
    async def monitor_poll():
        diff = await monitor.poll_once()
        return JSONResponse({"changed": diff is not None and diff.has_changes})
