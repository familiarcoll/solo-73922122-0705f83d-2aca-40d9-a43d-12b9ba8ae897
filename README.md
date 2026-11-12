# 日志上报 TLS 反向代理（asyncio + h11，真实 TLS + CA 轮换）

单进程 Python asyncio 反向代理，部署在探针接入层，只放行 `POST /events` 上报。
上游为**真实 TLS 连接**：地址与证书校验 DNS 名由启动配置固定，仅信任指定 CA
包，核验证书链、有效期与主机名；验证失败不发正文、不回退明文。支持凭管理
密钥**整份替换 CA 包**（成功版本持久化），切换后旧信任下的连接按代际清理。
同时保留全部 HTTP/1.1 分帧安全校验（防请求走私）与连接池语义。

## 目录结构

```
.
├── docker-compose.yml          # 一键启动 proxy + upstream
├── certs/                      # 本地两套 CA + 同名接收端证书（演示专用，含私钥）
│   ├── ca1/  ca2/              # 两套根 CA（ca.crt / ca.key）
│   ├── server-ca1/             # logs-receiver.local 证书，CA1 签发
│   ├── server-ca2/             # logs-receiver.local 证书，CA2 签发（同名）
│   └── regenerate.sh           # 重新生成全部证书
├── proxy/
│   ├── Dockerfile
│   ├── requirements.txt        # 仅依赖 h11（TLS 用标准库 ssl）
│   └── app/main.py             # 反向代理（TLS 上游 + CA 管理 API + 分帧防护）
├── upstream/
│   ├── Dockerfile
│   ├── requirements.txt        # fastapi + uvicorn
│   └── app/main.py             # 日志接收端：TLS 终结 + 可控握手延迟 + /docs 控制面
└── demo/
    └── demo.py                 # 仅标准库：分帧防护 + CA 轮换全链路演示（28 项断言）
```

## 快速开始

```bash
docker compose up --build
```

| 入口 | 地址 | 说明 |
| --- | --- | --- |
| 代理（唯一对外业务入口） | http://localhost:8080 | 只接受 `POST /events`；`/admin/*` 为管理 API |
| 代理管理 API | http://localhost:8080/admin/status | 需头 `X-Admin-Key`（默认演示值 `demo-admin-key`） |
| 上游演示控制面 /docs | http://localhost:8000/docs | Swagger UI：换证书、设握手延迟、查看实收请求 |
| 上游 TLS 业务入口 | https://localhost:8443 | 代理的上游；可用 `openssl s_client` 直连观察 |

另开终端运行演示（28 项断言）：

```bash
python3 demo/demo.py
# 非默认地址时：PROXY_PORT=8080 UPSTREAM_URL=http://127.0.0.1:8000 \
#   ADMIN_API_KEY=demo-admin-key python3 demo/demo.py
```

## TLS 信任模型

```
探针 ──明文 HTTP──> 代理:8080 ──TLS(校验链/有效期/主机名)──> 上游:8443
                      │                                        │
                      │  仅信任 CA_BUNDLE_PATH 中的 CA 包       │  呈现 server-caN 证书
                      │  校验名 logs-receiver.local            │  （同名，CA1 或 CA2 签发）
                      ▼                                        ▼
              PUT /admin/ca-bundle                     POST /admin/tls/cert/{ca1|ca2}
              （凭 X-Admin-Key）                        POST /admin/tls/delay
```

- 代理上游地址（`UPSTREAM_HOST:UPSTREAM_PORT`）与证书校验 DNS 名
  （`UPSTREAM_TLS_SERVER_NAME`）都由**启动配置固定**，运行期不可改；
- 握手由 OpenSSL 完成证书链、有效期、主机名核验（`CERT_REQUIRED` +
  `check_hostname`），任一不符即失败——**正文尚未写出，且绝不回退明文**
  （代码中根本没有明文路径；上游 TLS 端口对明文首包直接关闭并计数）；
- 连接 + 握手限时 `UPSTREAM_CONNECT_TIMEOUT`（默认 3.0s），独立于
  “从发送起 2 秒”的转发预算。

## CA 包管理 API（凭配置管理密钥）

管理密钥由启动环境变量 `ADMIN_API_KEY` 固定；为空则管理 API 整体关闭（404）。

| 请求 | 说明 |
| --- | --- |
| `PUT /admin/ca-bundle`（也接受 POST） | 整份替换 PEM CA 包。头 `X-Admin-Key`，正文为 PEM |
| `GET /admin/status` | 当前 CA 版本/指纹/持久化状态 + 连接池代际统计 |

替换语义（严格按序，任一步失败旧版完整保留）：

1. **验证**：至少一个 PEM 证书块、每块可解析、能构建客户端 SSLContext，
   否则 `400`；
2. **持久化**：临时文件 + fsync + 原子 rename 写入 `CA_BUNDLE_PATH`，
   失败 `500`（磁盘上的旧版本不被破坏）；
3. **切换**：内存 SSLContext、版本号、代际号原子更新，立即关闭旧代际
   空闲连接，返回新版本信息（`version`/`generation`/`sha256`/
   `persisted_sha256`）。

成功版本落盘（compose 中映射到宿主机 `./.proxy-state/`），**重启后持久化
版本优先于种子** `CA_BUNDLE_SEED`；种子与持久化都不可用时代理拒绝启动
（exit 2），绝不静默降级。

### 切换瞬间的连接代际规则

- **尚未写出的上报**：只用新 CA 验证的连接——借出前、握手完成后、写出前
  三道代际检查，旧代际连接一律销毁；
- **旧空闲连接**：切换时立即关闭；
- **迟到的旧握手**：握手期间发生换代，即使握手成功也立即销毁，绝不借出
  （`stale_discarded` 计数）；
- **已写出的上报**：在旧连接上完成，随后连接销毁不回池；切换本身绝不
  取消在途交换，因此**不会因切换重发**；
- 池容量恒为 2：`destroy` 幂等（名额只归还一次），清理只按代际过滤，
  新代际连接绝不被误关。`/admin/status` 的 `pool` 计数可验证
  `opened - destroyed == active <= 2`。

## 通过 /docs 演示换 CA、错误证书拒绝、握手交错

打开 http://localhost:8000/docs ，以下操作均可在 Swagger UI 中直接执行
（`demo/demo.py` 的 [8]-[11] 自动完成同样流程并断言）：

**① 错误证书拒绝**
1. `POST /admin/tls/cert/ca2`（默认 `close_existing=true`，同时关闭现存
   TLS 会话，模拟 CA 更替后旧信任会话失效）；
2. `curl -X POST http://localhost:8080/events -d '{"event":"x"}'` →
   **502**；`GET /events` 中该事件**不存在**（验证失败，正文未发出）；
3. `GET /admin/tls` 的 `plaintext_probes_total` 不增（未回退明文）。

**② 换 CA 恢复**
1. `curl -X PUT -H 'X-Admin-Key: demo-admin-key' --data-binary @certs/ca2/ca.crt
   http://localhost:8080/admin/ca-bundle` → 200，`version`+1，
   `persisted_sha256` 与内存一致（已落盘）；
2. 再次 POST /events → **202**；
3. 对照实验：错误的 `X-Admin-Key` → 403；上传垃圾 PEM → 400 且版本不变。

**③ 握手交错**
1. `POST /admin/tls/delay` 设 `{"seconds": 1.2}`（握手延迟）；
2. 连续两次 `PUT /admin/ca-bundle`（同一 ca2 包也算换代）之间，从另一
   终端 POST /events：第一笔握手在迟到完成时被丢弃
   （`GET /admin/status` 中 `stale_discarded`+1），请求改走新代际连接，
   上游只收到**一条**记录（不重发）；
3. `GET /admin/tls` 可见 `tls_connections_total` +2：两次成功握手只对应
   一条上报。

也可直接观察 TLS 层：

```bash
openssl s_client -connect localhost:8443 -servername logs-receiver.local \
  -CAfile certs/ca1/ca.crt -verify_return_error
```

## 持久化与重启行为

- 替换成功的 CA 包写入 `./.proxy-state/ca-bundle.crt`（+ `.meta.json`）；
- `docker compose restart proxy` 后代理加载持久化版本（日志
  `trust store ready: source=persisted`）；
- **注意**：完整 `docker compose down && up` 后，上游恢复默认 CA1 证书，
  而代理仍加载持久化的 CA2 包 → POST /events 会 502。这正是“旧信任下
  不再上报”的预期行为。对齐方式：用上面 ② 的 API 把任一侧切回，或
  `rm -rf .proxy-state` 让代理重新用 CA1 种子播种。

## 安全策略与需求映射

| 需求 | 实现位置与行为 |
| --- | --- |
| 仅开放 `POST /events` | `InboundProtocol._loop`：路径/方法白名单，其余回 404/405 并关闭连接 |
| 真实 TLS 上游 | `UpstreamPool._connect_new`：`asyncio.open_connection(ssl=…)`，握手完成前不写任何字节 |
| 地址与校验 DNS 名启动固定 | `UPSTREAM_HOST/PORT` + `UPSTREAM_TLS_SERVER_NAME`，运行期无修改入口 |
| 仅信任指定 CA | `TrustStore`：客户端 SSLContext 只加载 `CA_BUNDLE_PATH` 中的 CA 包 |
| 核验链/有效期/主机名 | `PROTOCOL_TLS_CLIENT` + `CERT_REQUIRED` + `check_hostname`，OpenSSL 握手时强制 |
| 验证失败不发正文、不回退明文 | 握手在 `open_connection` 返回前完成，失败即 `UpstreamError`→502；全代码无明文路径；上游 TLS 端口明文首包计数为证 |
| 凭密钥整份替换 CA 包 API | `PUT /admin/ca-bundle` + `X-Admin-Key`（`hmac.compare_digest` 比对） |
| 成功版本持久保存 | `_persist_atomic`：tmp+fsync+rename+目录 fsync；重启优先于种子 |
| 坏包/保存失败保留旧版 | 先验证后落盘再切换，任一步失败内存与磁盘旧版完整（400/500） |
| 未写出上报用新 CA 连接 | 借出前/握手后/写出前三道代际检查 |
| 关闭旧空闲连接 | `close_stale_idle` 在切换时同步执行 |
| 旧握手迟到成功不借出 | `_connect_new` 完成后比对代际，不符即销毁（`stale_discarded`） |
| 已写出上报可完成、随后销毁、不重发 | 切换不取消在途交换；`release` 对旧代际连接销毁而非回池 |
| 池仍为 2，清理不重复还名额、不误关新连接 | `destroy` 幂等（`slot_returned`）；清理按代际过滤；不变量 `opened-destroyed==active<=2` |
| 保留分帧防护 | 重复 CL / TE+CL / 非法分块 / 64KiB 上限 / 尾余走私检查全部保留，管理 API 同样过校验 |
| 保留发送起 2 秒期限 | `_forward` 统一截止时刻，重试不突破预算；超时销毁连接 |
| 两套 CA + 同名证书 + 可控握手延迟 | `certs/`（CA1/CA2 签发的同名 logs-receiver.local 证书）+ `/admin/tls/delay` |
| /docs 演示 | 上游 8000 端口 Swagger UI，见上文三步演示 |

## 连接池与超时语义

```
客户端 ──入站──> InboundProtocol (h11 SERVER)
                    │  完整校验 + 完整收体（<=64KiB）
                    ▼
                UpstreamPool（容量 2，条件变量排队）
                    │  acquire：代际+活性预检 → busy 标记
                    ▼
                UpstreamConn (h11 CLIENT) ──TLS──> upstream:8443
                    │
   成功且响应为单一 Content-Length → release（旧代际则销毁）
   超时 / 断连 / 协议错误 / 非 CL 响应 / 代际过期 → destroy，永不回池
```

- **2 秒预算从首次向上游发送开始计时**；连接与 TLS 握手有独立的
  `UPSTREAM_CONNECT_TIMEOUT`（默认 3.0s）限时，不计入发送预算；
- 超时后连接立即销毁，即使上游之后把响应发回来，字节也只进入一个
  已关闭的 socket，不会被池里的下一个调用者读到；
- 空闲池化连接若被对端静默关闭，取出时有 `at_eof()` 预检；首笔交换失败
  还允许在剩余 2 秒预算内用全新连接重试一次（重试只针对未确认送达的
  失败，与 CA 切换无关——切换本身从不取消在途交换）。

## 演示脚本输出说明（28 项断言）

1. **分片合法请求**：每 3 字节一个 TCP 段，正常 202；
2. **流水线**：一条 TCP 连接上连续两个请求，各自独立响应；
3. **chunked 重建**：上游收到的只剩一个 `Content-Length`，无 `Transfer-Encoding`；
4. **六类走私/畸形**：重复 CL、逗号双 CL、TE+CL、坏分块、64KiB 超限、
   CL.TE 夹带 `/admin` —— 全部 400/413 并断连，上游新增记录为 0；
5. **延迟响应**：上游 sleep 2.5s，代理 2.00s 回 504 并销毁，后续新请求干净；
6. **池容量**：3 个 0.8s 并发请求总耗时约 1.6s（两车道，第三笔排队）；
7. **路由白名单**：`GET /`、`POST /admin` 回 404 并断连，上游无记录；
8. **错误证书拒绝**：接收端换 CA2 同名证书后 502，上游 0 新增，无明文回退；
9. **CA 包管理**：错密钥 403、坏包 400 旧版保留、合法替换 200 版本+1 且
   落盘一致、换 CA 后恢复 202；
10. **握手交错**：1.2s 握手延迟下换代，迟到旧握手被丢弃
    （`stale_discarded`+1），两次成功握手只对应一条上报；
11. **在途不重发**：换代时在途旧连接上的上报正常完成且只到达一次，
    旧连接用后即毁，池名额守恒。

脚本最后直接拉取 `GET /events` 打印上游实收请求清单（含原始头、正文、
TCP 连接标识），作为“走私流量确实没有到达上游”的证据。

## 本地无 Docker 开发运行

```bash
# 上游（另开终端）
pip install -r upstream/requirements.txt
( cd upstream && CERTS_DIR=../certs python -m app.main )

# 代理（另开终端）
pip install -r proxy/requirements.txt
mkdir -p /tmp/proxy-state
( cd proxy && UPSTREAM_HOST=127.0.0.1 UPSTREAM_PORT=8443 \
    CA_BUNDLE_PATH=/tmp/proxy-state/ca-bundle.crt \
    CA_BUNDLE_SEED=../certs/ca1/ca.crt \
    ADMIN_API_KEY=demo-admin-key python -m app.main )
```

## 环境变量一览

**代理**

| 变量 | 默认 | 说明 |
| --- | --- | --- |
| `UPSTREAM_HOST` / `UPSTREAM_PORT` | `upstream` / `8443` | 上游 TLS 地址（启动固定） |
| `UPSTREAM_TLS_SERVER_NAME` | `logs-receiver.local` | 证书校验 DNS 名（启动固定） |
| `UPSTREAM_CONNECT_TIMEOUT` | `3.0` | 连接+握手限时（秒） |
| `CA_BUNDLE_PATH` | `/run/platform/ca-bundle.crt` | CA 包持久化路径（优先） |
| `CA_BUNDLE_SEED` | `/certs-seed/ca-bundle.crt` | 首次启动种子 CA 包 |
| `ADMIN_API_KEY` | 空（关闭管理 API） | 管理密钥，生产必须高强度随机 |
| `LISTEN_HOST` / `LISTEN_PORT` | `0.0.0.0` / `8080` | 入站监听 |

**上游（演示接收端）**

| 变量 | 默认 | 说明 |
| --- | --- | --- |
| `CERTS_DIR` | `/certs` | 证书目录（`server-ca1/`、`server-ca2/`） |
| `TLS_ACTIVE_DEFAULT` | `ca1` | 启动时使用的证书集 |
| `UPSTREAM_MAX_STORED` | `200` | 证据记录上限 |

## 设计取舍

- 入站使用低层 `asyncio.Protocol` 而非 `StreamReader`，以便通过
  `connection_lost` 事件在**上游交换进行中**即时发现客户端断连；
- h11 只做无状态解析，所有安全策略（TE+CL、尾余走私、响应成帧）显式写在
  本仓库代码里，不依赖解析器版本的默认行为；
- CA 代际（generation）与版本（version）分离：版本面向运维审计（单调
  递增、落盘），代际面向连接归属（内存计数），同一份 CA 重复上传也会
  产生新代际，从而可演示“同 CA 换代”的交错场景；
- 上游用“延迟前门 + TLS 终结器”两段式：延迟在前门注入（ClientHello
  滞留内核缓冲区），TLS 终结交给 asyncio 标准 SSL 传输，避免私有
  握手状态机；证书切换用共享 `SSLContext.load_cert_chain`，只影响新握手；
- `certs/` 中的私钥仅用于本地演示，已随仓库提交，**禁止用于任何真实
  环境**；`certs/regenerate.sh` 可随时重新生成整套证书；
- 代理本身不缓存完整请求历史，入站正文超过 64 KiB 立即拒绝，内存占用有界。
