# Python 实现的结构与维护

`server.py` 只保留启动兼容层。运行时代码放在 `nwafu_proxy/`，实例之间通过参数传递配置和会话，不再共享全局 `settings` / `session_mgr`。

## 改哪儿

| 需求 | 位置 |
| --- | --- |
| 环境变量、配置默认值 | `nwafu_proxy/config.py` |
| 应用组装、启动/关闭、CORS、请求日志 | `nwafu_proxy/app.py` |
| 命令行启动 | `nwafu_proxy/cli.py` |
| 登录页面解析 | `nwafu_proxy/auth/forms.py` |
| 密码 / Passkey / TOTP、CAS/Vouch 重定向 | `nwafu_proxy/auth/cas.py` |
| 登录限流、并发锁、退避、熔断、保活 | `nwafu_proxy/auth/session.py` |
| Cookie 与登录保护状态文件 | `nwafu_proxy/auth/storage.py` |
| 识别认证失效响应 | `nwafu_proxy/auth/detection.py` |
| HTTP、SSE、请求头与响应内容重写 | `nwafu_proxy/proxy.py` |
| WebSocket 双向转发 | `nwafu_proxy/websocket.py` |
| 健康检查 / TOTP / catch-all 路由 | `nwafu_proxy/routes/` |
| 模型监控与通知 | `nwafu_proxy/monitor.py` |
| 页面 HTML | `static/` |
| 手工测试、凭据导出等脚本 | `utils/` |

`AuthSessionManager` 组合 `CasAuthenticator` 和 `SessionStore`。认证器只处理协议，会话管理器决定何时允许登录，存储层只负责文件读写。HTTP 和 WebSocket 代理共享同一个会话管理器。

`create_app(settings, manager)` 负责组装。也可以调用无参数的 `create_app()`，由工厂显式加载环境配置。导入包或 `server` 不会读取配置、创建 HTTP 客户端或发起登录。配置中的 `data_dir` 可在测试或嵌入使用时指定，默认仍为项目根目录 `.data/`。

本地路由先注册，代理 catch-all 最后注册。模型监控直接通过已有会话访问上游，跳过所有非 OK 状态，禁止借监控触发登录。健康检查只读。

## 使用兼容性

以下方式继续可用：

```bash
python server.py
python -m nwafu_proxy
uvicorn server:app
uvicorn nwafu_proxy.app:create_app --factory
```

环境变量、默认端口、API 路径、Docker Compose 命令不变。`.data/cookies.json` 和 `.data/login_state.json` 继续沿用，旧 Cookie 数组和对象格式均能读取。登录状态文件新增 `saved_at`，用于扣除停机期间已经经过的熔断时间；旧文件没有该字段时仍按原剩余时间恢复。

`utils/model_monitor.py` 保留三个公开对象的兼容导出。旧 `server.py` 内部函数不是稳定 API；开发代码应直接导入对应模块。

## 本次重构同时修正的行为

- 重启不会清除登录次数或有效熔断；明确认证失败也不能绕过正在生效的熔断/退避。
- Cookie 恢复和登录共用锁，避免并发请求互相替换 HTTP 客户端。
- 健康检查不再后台重登，上游 HTTP 错误不会被标成健康。
- 监控不再请求本地代理，避免间接触发登录。
- 手动 TOTP 错误不会尝试调用不存在的自动验证码生成器；表单只接受 6 位数字。
- 代理可以透传数组、数字、null 等 JSON 请求体，不会因假设它们都是对象而崩溃。
- 重复的前缀路由统一为 catch-all，保留原始路径，消除 `_prefix` 查询参数影响目标路径的问题。
- 页面从 Python 字符串移到 HTML 文件；状态文件改为原子替换，避免写入中断留下半个 JSON。
- 增加表单解析依赖 `python-multipart`；WebSocket 最低版本调为代码实际使用的 15.0（`proxy` 参数）。

## 验证

Python 3.10+，本地建议使用与 Docker 一致的 Python 3.12：

```bash
python -m pip install -r requirements-dev.txt
python -m unittest discover -s tests -v
ruff check nwafu_proxy server.py tests utils/model_monitor.py utils/fido2_auth.py
ruff format --check nwafu_proxy server.py tests utils/model_monitor.py utils/fido2_auth.py
```

测试使用临时数据目录和模拟上游，不需要校园网、真实账号或 `.env`。覆盖认证识别、密码登录链、并发登录和恢复、熔断跨重启恢复、手动 TOTP、请求头隔离、多实例配置、SSE 逐块转发与关闭、WebSocket 文本/二进制转发、只读监控和生命周期清理。

GitHub Actions 配置了 Python 3.10 / 3.12 检查；本地跑通并不代表远端 CI 已执行。实际校园网的密码 / Passkey / TOTP 登录和浏览器 UI 仍需部署环境验收。
