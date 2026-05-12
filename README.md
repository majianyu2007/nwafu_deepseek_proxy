# nwafu_deepseek_proxy

西北农林科技大学 Open WebUI 本地透明反向代理。代理在本机完成金智教育（Wisedu）CAS 认证，维护上游会话 Cookie，并把浏览器或第三方客户端的请求转发到 `deepseek.nwafu.edu.cn`。

> 当前 `main` 分支是 Python/FastAPI 实现。Rust 重写版在 `rust-rewrite` 分支。

## 功能

- 访问 `http://localhost:8000/` 可直接使用完整 Open WebUI。
- OpenAI 兼容客户端使用 `http://localhost:8000/v1` 作为 API Base。
- 客户端 API Key 可填写占位值，代理会注入真实 Open WebUI API Key。
- 自动完成 CAS 登录（含二次验证 TOTP）、ST ticket 兑换、Cookie 保活和过期刷新。
- 内置登录频率限制、指数退避、熔断和单飞锁，避免上游异常导致账号频繁登录。
- 可选模型变更监控，支持 Telegram、Webhook、SSE 和 `/monitor` 面板。

## 快速开始

### 1. 准备环境

需要 Python 3.9+，并且运行环境可以访问：

- `authserver.nwafu.edu.cn`
- `deepseek.nwafu.edu.cn`

通常需要校园网或 VPN。

### 2. 安装依赖

```bash
git clone https://github.com/majianyu2007/nwafu_deepseek_proxy.git
cd nwafu_deepseek_proxy

python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

### 3. 配置

```bash
cp .env.example .env
```

编辑 `.env`，至少填写：

| 变量 | 必填 | 说明 |
| --- | --- | --- |
| `NWAFU_USERNAME` | 是 | 统一身份认证学号 |
| `NWAFU_PASSWORD` | 是 | 统一身份认证密码，包含 `#` 时请用引号包裹 |
| `OPENWEBUI_API_KEY` | 是 | Open WebUI「个人设置 / 账号 / API 密钥」中生成 |
| `PROXY_PORT` | 否 | 本地监听端口，默认 `8000` |
| `TARGET_HOST` | 否 | 上游 Open WebUI 域名，默认 `deepseek.nwafu.edu.cn` |
| `AUTH_SERVER` | 否 | CAS 服务地址，默认 `https://authserver.nwafu.edu.cn` |
| `TOTP_SECRET` | 否 | TOTP 安全令牌密钥（Base32），用于自动完成二次验证 |

### 4. 启动

```bash
python server.py
```

启动后：

- Web UI: `http://localhost:8000/`
- OpenAI API Base: `http://localhost:8000/v1`
- Health check: `http://localhost:8000/health`

## Docker

```bash
cp .env.example .env
# 编辑 .env
docker compose up -d
```

停止：

```bash
docker compose down
```

## 验证

列出模型：

```bash
python utils/list_models.py
```

发送测试对话：

```bash
python utils/test_api.py
python utils/test_api.py Qwen3-235B-A22B
```

也可以直接用 curl：

```bash
curl http://localhost:8000/v1/models \
  -H 'Authorization: Bearer sk-local'
```

## 客户端配置

任何支持自定义 OpenAI API Base 的客户端都可以使用：

| 配置项 | 值 |
| --- | --- |
| API Base | `http://localhost:8000/v1` |
| API Key | 任意占位值，例如 `sk-local` |

常见客户端：

- Chatbox
- LobeChat
- NextChat
- Cherry Studio

## 代理范围

代理透明转发所有路径，不限于：

| 路径 | 说明 |
| --- | --- |
| `/` | Open WebUI 页面 |
| `/v1/models` | OpenAI 兼容模型列表 |
| `/v1/chat/completions` | OpenAI 兼容对话补全，支持流式响应 |
| `/api/*` | Open WebUI 内部 API |
| `/ws/*` | WebSocket |
| 其它路径 | 由上游决定 |

## 工作原理

```text
浏览器 / 第三方客户端
        |
        |  http://localhost:8000/*
        v
本地 FastAPI 代理
        |
        |  注入 CAS Cookie
        |  注入 Authorization: Bearer <OPENWEBUI_API_KEY>
        |  重写 Origin / Referer / Location
        v
https://deepseek.nwafu.edu.cn
```

CAS 登录流程：

1. 获取 AuthServer 登录页，提取 `execution` 和 `pwdEncryptSalt`。
2. 使用 AES-CBC + PKCS7 按前端逻辑加密密码。
3. 提交登录表单。
4. 跟随 AuthServer 到 Open WebUI CAS callback 的重定向链。
5. **（新增）检测二次验证跳转**：若重定向到 `reAuthLoginView.do?isMultifactor=true`，自动切换至安全令牌 (TOTP) 并提交验证码。
6. 收集目标站会话 Cookie，用于后续代理请求。

## 账号保护

代理将认证失效与上游异常分开处理，只有明确的 CAS 登录重定向才会触发重新登录。

| 机制 | 说明 |
| --- | --- |
| 状态机 | 区分 `OK`、`SUSPECT`、`EXPIRED`、`LOGIN_BACKOFF`、`CIRCUIT_OPEN` |
| 单飞锁 | 并发请求最多触发一次真实 CAS 登录 |
| 频率限制 | 每小时最多 6 次登录尝试，状态持久化到 `.data/login_state.json` |
| 最小间隔 | 两次登录之间不少于 60s 冷却 |
| force_relogin 限流 | 10s 内重复 force_relogin 请求被忽略 |
| 指数退避 | 登录失败后逐步延长重试间隔 |
| 熔断器 | 连续失败后暂停登录，保护账号 |
| 失败分类 | 账号锁定、验证码、密码错误等高风险错误使用更长熔断 |
| 会话验证 | 登录成功后立即 HEAD 目标站验证会话有效性 |

## 二次验证 (TOTP)

自 2026-05-12 起，NWAFU 统一身份认证系统启用二次验证。代理支持通过 TOTP 安全令牌自动完成二次验证。

### 获取 TOTP 密钥

1. 打开你绑定安全令牌时使用的认证器 APP（Google Authenticator / Microsoft Authenticator / Authy 等）。
2. 找到 NWAFU 统一身份认证的账户条目，选择「查看详情」或「导出」。
3. 复制密钥（32 位 Base32 编码的字符串，如 `JBSWY3DPEHPK3PXP`）。

### 配置

```env
TOTP_SECRET=你的base32密钥
```

支持多种格式：纯 Base32、`otpauth://` URL、含空格字符串（自动清洗）。

未配置 `TOTP_SECRET` 时，代理会在需要二次验证时正常报错并进入退避流程，不会影响单次人工登录。

## 模型变更监控

可选启用：

```env
MONITOR_ENABLED=true
MONITOR_POLL_INTERVAL=600
```

通知配置：

```env
TELEGRAM_BOT_TOKEN=
TELEGRAM_CHAT_ID=
WEBHOOK_URLS=
WEBHOOK_SECRET=
NOTIFY_PROXY=
```

启用后可访问 `http://localhost:8000/monitor` 查看监控面板。监控只在认证状态正常时轮询，不会主动触发 CAS 登录。

## 分支

- `main`: Python/FastAPI 实现，功能完整，包含模型监控。
- `rust-rewrite`: Rust/Axum 重写版，包含 GitHub Actions Release 二进制构建。

## 常见问题

**启动时报密码错误或账户不存在**

检查 `.env` 中的 `NWAFU_USERNAME`、`NWAFU_PASSWORD`。密码包含 `#` 等特殊字符时需要加引号。

**模型请求返回 401**

检查 `OPENWEBUI_API_KEY` 是否有效。浏览器或客户端传入的 API Key 会被代理替换，不代表上游真实 Key。

**Model not found**

运行 `python utils/list_models.py` 查看实际上游模型 ID。

**浏览器出现 HTTPS localhost 相关错误**

清理 `localhost` 站点数据，或改用 `http://127.0.0.1:8000` 访问一次。

## License

MIT
