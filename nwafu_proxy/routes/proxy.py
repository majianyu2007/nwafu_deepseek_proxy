from fastapi import FastAPI, Request, WebSocket

from nwafu_proxy.proxy import ReverseProxy
from nwafu_proxy.websocket import WebSocketProxy

_PROXY_METHODS = ["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS", "HEAD"]


def register_proxy_routes(app: FastAPI, http: ReverseProxy, websocket: WebSocketProxy) -> None:
    @app.api_route("/", methods=_PROXY_METHODS)
    async def root(request: Request):
        return await http.handle(request, "/")

    @app.api_route("/{path:path}", methods=_PROXY_METHODS)
    async def catchall(request: Request, path: str):
        return await http.handle(request, f"/{path}")

    @app.websocket("/{path:path}")
    async def ws_catchall(ws: WebSocket, path: str):
        await websocket.handle(ws, f"/{path}")
