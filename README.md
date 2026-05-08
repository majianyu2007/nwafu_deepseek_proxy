# nwafu_deepseek_proxy

西北农林科技大学校园网自部署大模型代理服务。

学校通过 [Open WebUI](https://github.com/open-webui/open-webui) 部署了 DeepSeek / Qwen 系列大模型，但前方架设了金智教育（Wisedu）统一身份认证网关，所有请求都会被拦截跳转至 AuthServer 登录页面。因此，客户端无法直接使用源站 API 地址；即使携带正确 token，请求也可能在中间件层被 302 到 CAS 登录。

本项目通过在本地运行一个 **透明反向代理** 来解决该问题：

1. 启动时自动完成 CAS 认证（包括 AES 密码加密、表单提交、ticket 兑换）
2. 获取到目标站点的有效 session cookie
3. 在本地暴露 `http://localhost:8000`，**透明转发所有请求到源站**
4. 所有经过代理的请求会自动附带 CAS cookie + Open WebUI API Key
5. 后台定时保活，cookie 过期时自动刷新
6. 多层账号保护机制：状态机、单飞锁、频率限制、指数退避、熔断器

代理不对任何请求做特殊处理；源站支持的能力将被原样透传。直接将浏览器指向 `localhost:8000` 即可使用完整的 Open WebUI，包括聊天、模型管理等功能。

## 快速开始

### 环境要求

- Python 3.9+（或 Docker）
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
| `OPENWEBUI_API_KEY` | Open WebUI 的 API 密钥 | 登录 Open WebUI，在“个人设置 / 账号 / API 密钥”中生成 |

### 启动

```bash
python server.py
```

### Docker 部署

如果不想配置 Python 环境，也可以用 Docker：

```bash
cp .env.example .env
# 编辑 .env 填入学号、密码、API Key

docker compose up -d
```

停止：

```bash
docker compose down
```

启动后代理同样监听在 `localhost:8000`，行为与直接运行完全一致。

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

### 支持的端点

代理会透明转发所有请求到源站，不限于以下端点：

| 端点 | 说明 |
|------|------|
| `/` | Open WebUI 完整界面 |
| `/v1/models` | 查看全部可用模型 |
| `/v1/chat/completions` | 对话补全（支持流式） |
| `/v1/embeddings` | 向量嵌入 |
| `/v1/rerank` | 文档重排序（需源站支持） |
| `/api/*` | Open WebUI 内部 API |
| 任何其它路径 | 源站支持的任何其它端点 |

## 客户端配置

**直接使用 Open WebUI：** 浏览器访问 `http://localhost:8000` 即可。

**第三方 LLM 客户端：**
- **API 地址** / **API Base**: `http://localhost:8000/v1`
- **API Key**: 填写占位值（如 `sk-local`），代理内部会替换为真实 key

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
浏览器 / 第三方客户端 (Chatbox / LobeChat / curl / ...)
        │
        │  任意请求（/ 及所有子路径）
        ▼
localhost:8000  ← 本地 FastAPI 透明反向代理
        │
        │  ① 注入 CAS session cookie
        │  ② 注入 Authorization: Bearer sk-xxx
        │  ③ 透明转发, 不修改请求/响应内容
        │  ④ 重写 Location / Origin / Referer 头
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
4. 跟随 302 重定向链：AuthServer 到 CAS callback（携带 ST ticket）再到目标站
5. 在重定向过程中收集 session cookie

### Cookie 保活

- 每 ~5 分钟（含随机抖动）向目标站发送轻量 HEAD 心跳请求
- 25 分钟无活动主动刷新
- 检测到认证失效时自动重新认证（精确区分 CAS 失效与上游业务错误）
- 网络异常或上游故障时**不会**触发重新登录（避免误判导致账号锁定）

### 账号保护机制

代理内置多层保护，防止上游异常时频繁登录导致校园账号被锁定：

| 层级 | 机制 | 说明 |
|------|------|------|
| 1 | 状态机 | 区分"上游异常"(SUSPECT)与"认证过期"(EXPIRED)，只有后者才触发登录 |
| 2 | 单飞锁 | 并发请求最多触发一次真实 CAS 登录 |
| 3 | 频率限制 | 每小时最多 6 次登录尝试（持久化到 `.data/`） |
| 4 | 指数退避 | 登录失败后退避时间递增（5s → 20s → 80s → 15min） |
| 5 | 熔断器 | 连续 3 次失败后熔断 15 分钟 – 6 小时 |
| 6 | 失败分类 | 账号锁定/验证码/密码错误等高风险错误直接触发最长熔断 |

熔断期间，代理会返回 `503` 并附带 `Retry-After` 头，明确告知客户端当前处于账号保护模式。

## 模型变更监控（可选）

在 `.env` 中设置 `MONITOR_ENABLED=true` 可启用模型变更监控功能：

- 定期轮询模型列表，检测新模型上线或模型下线
- 支持多渠道通知：Telegram Bot、自定义 Webhook
- 提供实时 SSE 推送和 Web 监控面板（`/monitor`）
- 内置安全保护：仅在认证正常时轮询，不会在代理熔断期间触发登录

相关配置项见下方 `MONITOR_*` 系列。

## 配置项一览

| 环境变量 | 必填 | 默认值 | 说明 |
|----------|------|--------|------|
| `NWAFU_USERNAME` | 是 | — | 学号 |
| `NWAFU_PASSWORD` | 是 | — | 密码 |
| `OPENWEBUI_API_KEY` | 是 | — | Open WebUI API Key |
| `PROXY_PORT` | | `8000` | 代理监听端口 |
| `TARGET_HOST` | | `deepseek.nwafu.edu.cn` | 目标 Open WebUI 域名 |
| `AUTH_SERVER` | | `https://authserver.nwafu.edu.cn` | AuthServer 地址 |
| `MONITOR_ENABLED` | | `false` | 启用模型变更监控 |
| `MONITOR_POLL_INTERVAL` | | `600` | 监控轮询间隔（秒，最小 300） |
| `TELEGRAM_BOT_TOKEN` | | — | Telegram Bot Token |
| `TELEGRAM_CHAT_ID` | | — | Telegram Chat ID |
| `WEBHOOK_URLS` | | — | Webhook URL（多个用逗号分隔） |
| `WEBHOOK_SECRET` | | — | Webhook 签名密钥 |
| `NOTIFY_PROXY` | | — | 通知渠道 HTTP 代理 |

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
