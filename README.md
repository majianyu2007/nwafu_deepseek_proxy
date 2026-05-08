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

- Rust 1.80+（或 Docker）
- 校园网环境（或 VPN）

### 安装

```bash
git clone https://github.com/majianyu2007/nwafu_deepseek_proxy.git
cd nwafu_deepseek_proxy

cargo build --release
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
cargo run --release
# 或直接运行构建产物：
./target/release/nwafu-deepseek-proxy
```

### Docker 部署

如果不想配置 Rust 环境，也可以用 Docker：

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
curl http://localhost:8000/v1/models \
  -H 'Authorization: Bearer sk-local'
```

### Release 构建

仓库包含 GitHub Actions workflow：`.github/workflows/release.yml`。

- 推送 `v*` 标签时自动构建 Linux / macOS / Windows 二进制并发布到 GitHub Release
- 也可在 GitHub Actions 页面手动触发构建，产物会作为 workflow artifacts 上传

发布示例：

```bash
git tag v0.1.0
git push origin v0.1.0
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
localhost:8000  ← 本地 Axum 透明反向代理
        │
        │  ① 注入 CAS session cookie
        │  ② 注入 Authorization: Bearer sk-xxx
        │  ③ 透明转发请求，并按需重写本地代理相关响应头/文本 URL
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

### 账号保护机制

代理内置多层保护，防止上游异常时频繁登录导致校园账号被锁定：

| 层级 | 机制 | 说明 |
|------|------|------|
| 1 | 登录后拒绝抑制 | 登录成功后短时间内仍被认证中间件拒绝时，不连续触发 CAS 登录 |
| 2 | 单飞锁 | 并发请求最多触发一次真实 CAS 登录 |
| 3 | 频率限制 | 每小时最多 6 次登录尝试 |
| 4 | 指数退避 | 登录失败后退避时间递增（5s → 20s → 80s → 15min） |
| 5 | 熔断器 | 连续 3 次失败后熔断 15 分钟 |

## 配置项一览

| 环境变量 | 必填 | 默认值 | 说明 |
|----------|------|--------|------|
| `NWAFU_USERNAME` | 是 | — | 学号 |
| `NWAFU_PASSWORD` | 是 | — | 密码 |
| `OPENWEBUI_API_KEY` | 是 | — | Open WebUI API Key |
| `PROXY_PORT` | | `8000` | 代理监听端口 |
| `TARGET_HOST` | | `deepseek.nwafu.edu.cn` | 目标 Open WebUI 域名 |
| `AUTH_SERVER` | | `https://authserver.nwafu.edu.cn` | AuthServer 地址 |

## 常见问题

**Q: 代理启动后报 `登录失败: 密码错误或账户不存在`**

确认 `.env` 中的学号密码正确。如果密码含特殊字符，请用双引号包裹。

**Q: 代理正常但模型请求返回 401**

检查 `OPENWEBUI_API_KEY` 是否正确。该 key 需要在 Open WebUI 的「个人设置 → 账号」页面中生成。

**Q: `Model not found`**

访问 `http://localhost:8000/v1/models` 查看实际可用的模型 ID，在客户端中使用正确的名称。

**Q: 需要校园网吗？**

是的。代理服务器需要能访问 `authserver.nwafu.edu.cn` 和 `deepseek.nwafu.edu.cn`。
连接校园 VPN 也可以。

## License

MIT
