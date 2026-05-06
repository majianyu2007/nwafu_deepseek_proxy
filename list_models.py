"""查询代理后端可用的模型列表"""

import asyncio
import httpx

API_BASE = "http://localhost:8000"


async def main():
    async with httpx.AsyncClient(timeout=30.0, trust_env=False) as client:
        resp = await client.get(
            f"{API_BASE}/v1/models",
            headers={"Authorization": "Bearer sk-any"},
        )
        if resp.status_code != 200:
            print(f"请求失败 ({resp.status_code}): {resp.text}")
            return

        models = resp.json().get("data", [])
        if not models:
            print("未发现可用模型")
            return

        print(f"可用模型 ({len(models)}):")
        for m in models:
            print(f"  - {m['id']}")


if __name__ == "__main__":
    asyncio.run(main())
