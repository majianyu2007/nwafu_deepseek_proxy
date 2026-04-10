# nwafu_deepseek_proxy

西北农林科技大学校园网自部署大模型代理服务。

学校通过 [Open WebUI](https://github.com/open-webui/open-webui) 部署了 DeepSeek / Qwen 系列大模型，但前方架设了金智教育（Wisedu）统一身份认证网关，所有请求都会被拦截跳转至 AuthServer 登录页面。这意味着你没法直接拿到可用的 API 地址——即使拼上了正确的 token，请求也会在中间件层被 302 到 CAS 登录。

本项目通过在本地运行一个 Python 反向代理来解决这个问题：

1. 启动时自动完成 CAS 认证（包括 AES 密码加密、表单提交、ticket 兑换）
2. 获取到目标站点的有效 session cookie
3. 在本地暴露 `http://localhost:8000/v1` 端点
4. 所有经过代理的请求会自动附带 CAS cookie + Open WebUI API Key
5. 后台定时保活，cookie 过期时无感刷新

你只需要把 API 地址指向 `localhost:8000/v1`，就能在 Chatbox、LobeChat 等第三方客户端中正常使用学校的模型了。

## 快速开始

### 环境要求

- Python 3.9+
- 校园网环境（或 VPN）

### 安装

```bash
git clone https://github.com/majianyu2007/nwafu_deepseek_proxy.git
cd nwafu_deepseek_proxy

python3 -m venv venv
source venv/bin/activate  # Windows: venv\Scripts\activate
pip install -r requirements.txt
```

### 配置

```bash
cp .env.example .env
```

编辑 `.env`，填入以下三项：

| 变量 | 说明 | 获取方式 |
|------|------|----------|
| `NWAFU_USERNAME` | 学号 | — |
| `NWAFU_PASSWORD` | 统一身份认证密码 | 密码含 `#` 等字符时用双引号包裹 |
| `OPENWEBUI_API_KEY` | Open WebUI 的 API 密钥 | 登录 Open WebUI → 个人设置 → 账号 → API 密钥 |

### 启动

```bash
python server.py
```

启动后控制台会打印出代理地址和认证状态。

### 验证

查看可用模型：

```bash
python list_models.py
```

发送测试对话（自动选择第一个 chat 模型）：

```bash
python test_api.py
# 或指定模型
python test_api.py Qwen3-235B-A22B
```

## 客户端配置

在你使用的 LLM 客户端中：

- **API 地址** / **API Base**: `http://localhost:8000/v1`
- **API Key**: 填任意值（如 `sk-local`），代理内部会替换为真实 key

### 推荐的客户端

| 客户端 | 类型 | 设置位置 |
|--------|------|----------|
| [Chatbox](https://chatboxai.app) | 桌面应用 | 设置 → 模型提供商 → OpenAI → API Host |
| [LobeChat](https://github.com/lobehub/lobe-chat) | Web | 语言模型 → OpenAI → 接口地址 |
| [NextChat](https://github.com/ChatGPTNextWeb/ChatGPT-Next-Web) | Web | 设置 → 接口代理地址 |
| [Cherry Studio](https://github.com/kangfenmao/cherry-studio) | 桌面应用 | 模型服务商 → 自定义 OpenAI |

任何支持自定义 OpenAI API Base 的工具都可以直接对接。

## 工作原理

```
第三方客户端 (Chatbox / LobeChat / curl / ...)
        │
        ▼
localhost:8000  ← 本地 FastAPI 代理
        │
        │  ① CAS session cookie (通过认证中间件)
        │  ② Authorization: Bearer sk-xxx (通过 Open WebUI)
        ▼
deepseek.nwafu.edu.cn  ← 学校 Open WebUI 实例
        │
        ▼
    后端大模型 (DeepSeek / Qwen / ...)
```

### 认证流程细节

金智 AuthServer 使用 CAS 协议，密码在前端通过 AES-CBC 加密后提交。本项目完整还原了这个流程：

1. `GET /authserver/login?service=...` 获取登录页，提取 `execution` 和 `pwdEncryptSalt`
2. 使用与前端一致的 AES-CBC (PKCS7 padding) 加密密码：`randomString(64) + password`
3. `POST /authserver/login` 提交表单
4. 跟随 302 重定向链：AuthServer → CAS callback（带 ST ticket） → 目标站
5. 在重定向过程中收集 session cookie

### Cookie 保活

- 每 5 分钟向目标站发送心跳请求
- 25 分钟无活动主动刷新
- 检测到 302 / 401 / 403 时自动重新认证
- 对客户端完全透明，无需手动干预

## 配置项一览

| 环境变量 | 必填 | 默认值 | 说明 |
|----------|------|--------|------|
| `NWAFU_USERNAME` | ✅ | — | 学号 |
| `NWAFU_PASSWORD` | ✅ | — | 密码 |
| `OPENWEBUI_API_KEY` | ✅ | — | Open WebUI API Key |
| `PROXY_PORT` | | `8000` | 代理监听端口 |
| `TARGET_HOST` | | `deepseek.nwafu.edu.cn` | 目标 Open WebUI 域名 |
| `AUTH_SERVER` | | `https://authserver.nwafu.edu.cn` | AuthServer 地址 |

## 常见问题

**Q: 代理启动后报 `登录失败: 密码错误或账户不存在`**

确认 `.env` 中的学号密码正确。如果密码含特殊字符，请用双引号包裹。

**Q: 代理正常但模型请求返回 401**

检查 `OPENWEBUI_API_KEY` 是否正确。该 key 需要在 Open WebUI 的「个人设置 → 账号」页面中生成。

**Q: `Model not found`**

运行 `python list_models.py` 查看实际可用的模型 ID，在客户端中使用正确的名称。

**Q: 需要校园网吗？**

是的。代理服务器需要能访问 `authserver.nwafu.edu.cn` 和 `deepseek.nwafu.edu.cn`。
连接校园 VPN 也可以。

## License

MIT
