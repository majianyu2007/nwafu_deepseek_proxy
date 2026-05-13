# nwafu_deepseek_proxy

西北农林科技大学 Open WebUI 透明反向代理。在本机完成金智教育（Wisedu）CAS 认证，维护上游会话 Cookie，所有请求转发到 `deepseek.nwafu.edu.cn`。

`main` 分支是 Python/FastAPI 实现，`rust-rewrite` 分支是 Rust/Axum 重写版。

## 它能做什么

- `http://localhost:8000/` 直接就是 Open WebUI，走代理认证过的会话。
- `http://localhost:8000/v1` 作为 OpenAI API Base，兼容各种第三方客户端。
- 客户端 API Key 任意占位值即可，代理会自动注入 `.env` 中配置的真实 Key。
- 自动完成 CAS 登录、TOTP 二次验证、ST ticket 兑换、Cookie 保活。
- 支持 passkey (FIDO2/WebAuthn) 登录，可绕过滑块验证码。
- 登录后的 Cookie 持久化到 `.data/cookies.json`，重启时自动恢复，避免每次重启重登。
- 内置登录保护：频率限制、单飞锁、指数退避、熔断器，防止账号因频繁登录被冻结。
- 支持用户通过 `/totp` 页面手动输入 TOTP 码（不依赖自动二次验证）。
- 可选模型变更监控，Telegram / Webhook / SSE 通知，带 `/monitor` 面板。

## 快速开始

### 1. 环境

Python 3.9+，能访问 `authserver.nwafu.edu.cn` 和 `deepseek.nwafu.edu.cn`（校园网或 VPN）。

### 2. 安装

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

最少填三项：

| 变量 | 说明 |
|------|------|
| `NWAFU_USERNAME` | 学号 |
| `NWAFU_PASSWORD` | CAS 密码，包含 `#` 等特殊字符用引号包起来 |
| `OPENWEBUI_API_KEY` | Open WebUI → 个人设置 → 账号 → API 密钥 |

其他可选变量见 `.env.example` 里的注释。

### 4. 启动

```bash
python server.py
# 或者 docker compose up -d
```

然后访问 `http://localhost:8000`。

## 客户端配置

API 支持 OpenAI 兼容协议，什么客户端都行：

- API Base: `http://localhost:8000/v1`
- API Key: 任意占位值，比如 `sk-local`

Chatbox、LobeChat、NextChat、Cherry Studio 都试过能用。

## 工作原理

```
浏览器 / 客户端
       │ http://localhost:8000/*
       ▼
  FastAPI 代理
       │ 注入 CAS Cookie + API Key
       │ 重写 Origin / Referer / Location
       ▼
https://deepseek.nwafu.edu.cn
```

登录流程为金智 CAS 标准步骤：获取登录页 → 提取 execution 和 salt → AES 加密密码 → 提交表单 → 跟随 CAS 重定向链 → 若触发二次验证则完成 TOTP → 收集目标站 Cookie。

## 登录方式

代理支持三种登录方式，优先级从高到低：

### Passkey 登录 (FIDO2/WebAuthn)

这个方案能绕过密码和滑块验证码。原理是用你 Bitwarden 里存的 ECDSA 私钥，等价模拟浏览器 `navigator.credentials.get()` 的签名流程。

**前提**：你在 CAS 个人中心开过生物识别，Bitwarden 里有对应的 passkey 条目。

**步骤**：

1. 先从浏览器取设备绑定 ID。在绑定过生物识别的浏览器里打开 CAS 登录页，F12 Console 跑：
   ```
   localStorage.getItem('anonbiometricsd')
   ```
   记下输出的值。

2. Bitwarden → 设置 → 导出密码库 → JSON（未加密）。

3. 执行提取脚本：
   ```bash
   python utils/extract_fido2.py bitwarden_export.json --name <你的Bitwarden条目名> --save --device-id <第1步取到的ID>
   ```
   这一步生成 `.data/fido2_credential.json`，里面有私钥、凭据ID、设备绑定ID。

4. `.env` 里加一行：
   ```env
   FIDO2_ENABLED=true
   ```

5. 重启代理。之后每次登录优先走 passkey，失败了再回退密码。

注意：如果你的 passkey 不在 Bitwarden 而在其他管理器，只要能把 ECDSA P-256 私钥导出来，手动写 `.data/fido2_credential.json` 也能用——格式参考 `utils/extract_fido2.py` 的输出。

### Cookie 持久化

密码或 passkey 登录成功后，CAS 会话 Cookie 自动保存到 `.data/cookies.json`。重启时先试恢复，有效就零次登录，无效才走完整登录。

Docker 每天重启也没有额外开销，搭配 CAS 的 `rememberMe`（7天免登录），每天最多登录一次。

如果已在其他设备的浏览器上登录过，可以将 Cookie 导出到本机使用：

1. 浏览器 F12 → Application → Cookies → 分别选择 `authserver.nwafu.edu.cn` 和 `deepseek.nwafu.edu.cn` → 逐个记录 Name、Value、Domain、Path。
2. 创建 `.data/cookies.json`：

```json
[
  {"name": "CASTGC", "value": "TGT-xxx...", "domain": "authserver.nwafu.edu.cn", "path": "/"}
]
```

字段名大小写无所谓，`domain`/`Domain` 都行。至少需要一个 `authserver.nwafu.edu.cn` 下的 `CASTGC`，其他 cookie 代理自己会补。

### 密码登录（兜底）

上面的都失败就走密码登录，该怎么做怎么做。

## TOTP 二次验证

NWAFU 从 2026-05-12 开始强制二次验证。代理支持两种方式。

### 自动模式

配置 TOTP 密钥，代理自动生成一次性密码完成验证。

打开认证器 APP（Google、Microsoft、Authy 等），找到 NWAFU 的条目，导出密钥（32 位 Base32），填入 `.env`：

```env
TOTP_SECRET=你的Base32密钥
TOTP_AUTO_ENABLED=true
```

密钥格式支持纯 Base32、`otpauth://` URL、含空格字符串（自动清洗）。

### 手动模式

不配 `TOTP_SECRET`，或将 `TOTP_AUTO_ENABLED` 设为 `false`。代理检测到二次验证时会暂停等待，日志提示：

```
请在浏览器访问 http://localhost:8000/totp 输入TOTP码
```

打开浏览器访问 `/totp`，页面上有输入框和当前 TOTP 窗口的倒计时。输入认证器 APP 里显示的 6 位数字，提交即可。代理收到后继续完成登录。

等待超时时间为 5 分钟，超过未提交则退避重试。

## 账号保护

代理会区分"上游挂了"和"认证过期"，不会把一次网络错误当成需要重登。只有真的 CAS 登录重定向才会触发重新登录，其他情况标记为可疑等下次再看。

几个关键防护：

- **单飞锁**：多个并发请求进来，只有第一个触发真实登录，其他的等着。
- **频率限制**：每小时最多 6 次登录，状态存到 `.data/login_state.json`。
- **指数退避**：登录失败后等 5s → 20s → 80s → 5min → 15min。
- **熔断器**：连续失败 3 次开熔断，根据失败类型 15min ~ 6h 不等。
- **验证码保护**：检测到滑块验证码后进入 2 小时熔断，不反复重试导致账号冻结。

## 模型监控

可选。`.env` 里：

```env
MONITOR_ENABLED=true
MONITOR_POLL_INTERVAL=600
TELEGRAM_BOT_TOKEN=
TELEGRAM_CHAT_ID=
WEBHOOK_URLS=
```

开了之后定期拉模型列表，检测到变化就通知你。`/monitor` 有面板看状态。监控只在认证正常时才拉，不会触发登录。

## 常见问题

**登录时触发滑块验证码**

代理检测到验证码后会进 2 小时熔断，不会反复重试。

1. 浏览器打开 `https://deepseek.nwafu.edu.cn`，手动过一遍验证码。
2. 代理熔断到了自动重试（此时 Cookie 已经有效，直接能用）。
3. 不想等可以手动导出浏览器 Cookie 到 `.data/cookies.json` 然后重启。

收到学校冻结短信的话，按短信里说的解冻时间等，别反复重启。

**启动报「密码错误或账户不存在」**

`.env` 里 `NWAFU_USERNAME` / `NWAFU_PASSWORD` 对不对，密码有 `#` 的话加引号。

**请求返回 401**

`OPENWEBUI_API_KEY` 可能过期了。去 Open WebUI 重新生成一个。

**Model not found**

跑 `python utils/list_models.py` 看上游实际有哪些模型，名字可能和预想的不同。

**localhost HTTPS 报错**

清掉 `localhost` 的浏览器站点数据，或者换 `http://127.0.0.1:8000`。

## License

MIT
