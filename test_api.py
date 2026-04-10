"""通过本地代理发送一次流式对话请求, 验证端到端连通性"""

import asyncio
import json
import sys

import httpx

API_BASE = "http://localhost:8000/v1"


async def main():
    model = sys.argv[1] if len(sys.argv) > 1 else None

    # 如果没有指定模型, 先查询可用列表
    if not model:
        async with httpx.AsyncClient(timeout=30.0) as client:
            resp = await client.get(
                f"{API_BASE}/models",
                headers={"Authorization": "Bearer sk-any"},
            )
            if resp.status_code != 200:
                print(f"获取模型列表失败 ({resp.status_code})")
                return

            models = resp.json().get("data", [])
            if not models:
                print("未发现可用模型")
                return

            # 排除 embedding 模型, 选第一个 chat 模型
            chat_models = [m["id"] for m in models if "embed" not in m["id"].lower() and "rerank" not in m["id"].lower()]
            model = chat_models[0] if chat_models else models[0]["id"]
            print(f"自动选择模型: {model}")

    payload = {
        "model": model,
        "messages": [{"role": "user", "content": "你好，简单介绍一下你自己。"}],
        "stream": True,
    }

    print(f"请求 {API_BASE}/chat/completions (model={model}) ...")

    async with httpx.AsyncClient(timeout=120.0) as client:
        async with client.stream(
            "POST",
            f"{API_BASE}/chat/completions",
            headers={
                "Authorization": "Bearer sk-any",
                "Content-Type": "application/json",
            },
            json=payload,
        ) as resp:
            if resp.status_code != 200:
                body = await resp.aread()
                print(f"请求失败 ({resp.status_code}): {body.decode()}")
                return

            async for line in resp.aiter_lines():
                if not line.startswith("data: "):
                    continue
                data_str = line[6:]
                if data_str == "[DONE]":
                    break
                try:
                    delta = json.loads(data_str)["choices"][0].get("delta", {})
                    content = delta.get("content", "")
                    if content:
                        print(content, end="", flush=True)
                except (json.JSONDecodeError, KeyError, IndexError):
                    continue

    print("\n\n测试完成。")


if __name__ == "__main__":
    asyncio.run(main())
