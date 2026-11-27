# echo-server

**官网：** https://crawler-requests.github.io/echo-server/

[English](README.md) | **简体中文**

[![CI](https://github.com/crawler-requests/echo-server/actions/workflows/ci.yml/badge.svg)](https://github.com/crawler-requests/echo-server/actions/workflows/ci.yml)
[![Release](https://github.com/crawler-requests/echo-server/actions/workflows/release.yml/badge.svg)](https://github.com/crawler-requests/echo-server/actions/workflows/release.yml)
[![Go 1.26+](https://img.shields.io/badge/Go-1.26%2B-00ADD8?logo=go&logoColor=white)](https://go.dev/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

用于爬虫调试的 HTTPS 回显服务：回显请求头/请求体、**完整的 TLS ClientHello**（原始字节、SNI、ALPN、
密码套件、扩展、JA3 **以及 JA4 / JA4_r / JA4_o**）、**识别调用方客户端**（curl / python-requests /
Node / Java / Go / OpenSSL / Chrome / ……，并检测 UA 伪装），以及客户端公网 IP 的 **ASN + 城市级地理
位置**（国家/地区/城市/邮编/经纬度）和**连接类型**（`datacenter` / `residential_proxy` / `unknown`）。

ClientHello 捕获按连接隔离且**抗分片**：字节会跨多次 TCP 读取与握手记录累积，直到完整 hello 可用，
因此也能处理大型后量子 hello（约 1.5 KB）以及 hello 被拆成许多小段到达的客户端。

单一 Go 二进制；通过 `//go:embed` 内嵌 React + Ant Design 管理控制台（`/ui/`）；SQLite 存储配置、查询
历史与用户账号（`admin` / `viewer`，PBKDF2-SHA256 密码，JWT 会话）、命名 API Key、审计日志、通知、
Webhook、日志筛选视图、Prometheus 指标与 OpenAPI 文档。

**极速版**：同一二进制以 `ECHO_SERVER_LITE=1` 启动即进入极速模式——完全不使用数据库，只提供 `/ip`
（返回出网 IP）与 `/echo`。实测 **10 万并发连接、0 失败、230k+ rps**（32 核机器）。详见
[极速版与并发](#极速版与并发)。

---

## 可直接复制给 AI agent 的提示词

以下提示词可以直接粘贴给 **Claude Code**、**Codex**、Cursor 或任何有 shell 权限的 agent，让它完成
安装、启动、验证乃至部署。每条提示词都内置了**验收测试**，agent 能据此判断"做完了"，而不是靠猜。

### 1. 部署完整产品并验证（Claude Code / Codex / 任意 shell agent）

```text
在这台机器上部署 echo-server 服务并端到端验证。

步骤：
1. 从 https://github.com/crawler-requests/echo-server/releases/latest 下载本 OS/arch 的最新 release
   （产物命名：echo-server_<version>_<os>_<arch>.tar.gz，Windows 为 .zip）。
   对照 checksums.txt 校验后解压。
2. 启动：ECHO_SERVER_DB=./echo.db ECHO_SERVER_ADMIN_USERNAME=admin \
        ECHO_SERVER_ADMIN_PASSWORD='<随机强密码>' PORT=23232 HTTP_PORT=23231 ./echo-server
   用 nohup/systemd 托管，并确认进程存活 10 秒。
3. 验收测试——全部通过才算完成：
   - curl -sf http://127.0.0.1:23231/health            -> {"status":"ok"}
   - curl -sf http://127.0.0.1:23231/ip                -> 含 "ip" 的 JSON
   - curl -sf http://127.0.0.1:23231/ip?format=text    -> 一个纯 IP
   - curl -sf -k https://127.0.0.1:23232/echo | head   -> 含 "headers" 与 "client_hello" 的 JSON
   - curl -sf -k -H 'User-Agent: curl/8.5.0' https://127.0.0.1:23232/echo?fields=client
                                                      -> "client.name" 为 curl（或同类）
   - curl -sf http://127.0.0.1:23231/ui/ | grep 'id="root"'   -> 控制台页面可加载
   - 用管理员凭据 POST /api/login 能拿到 JWT。
4. 打印控制台 URL（http://<lan-ip>:23231/ui/）与管理员用户名。
汇报：执行的命令、每项测试输出、URL。任何一项失败都要先修好再汇报。
```

### 2. 为代理/出网池部署极速版（无数据库）

```text
部署 echo-server 极速版，它是一个无状态的"我的出网 IP 是什么"端点。

步骤：
1. 下载极速版 release：纯语义化 tag（`1.x.y`，无 `v` 前缀），产物
   echo-server-lite_<version>_<os>_<arch>.tar.gz，校验 checksums 后解压。
2. 完全不使用数据库启动：
     ECHO_SERVER_LITE=1 PORT=23232 HTTP_PORT=23231 ./echo-server-lite
3. 验收测试——全部通过才算完成：
   - curl -sf http://127.0.0.1:23231/ip                -> 含 "ip" 的 JSON
   - curl -sf http://127.0.0.1:23231/ip?format=text    -> 一个纯 IP
   - curl -sf http://127.0.0.1:23231/echo?fields=ip.ip -> 含 ip 的 JSON
   - curl -s -o /dev/null -w '%{http_code}' http://127.0.0.1:23231/ui/        -> 404
   - curl -s -o /dev/null -w '%{http_code}' http://127.0.0.1:23231/api/config -> 404
   - 工作目录中不出现 *.db / *.db-wal 文件。
   - 连续 1000 次请求全部返回 200（循环 curl -sf）。
4. 提高文件句柄上限（ulimit -n 1048576）并在汇报中注明——这是它能承载约 10 万连接的前提。
汇报 URL、通过 /ip 拿到的 IP，并确认"无数据库"这一性质。
```

### 2b. 在本机验证"10 万并发"这一声明

这是一条可选验证提示词：它用仓库自带的压测工具（`tools/loadtest`）实测，而不是相信 README 里的表格。

```text
验证 echo-server 极速版在这台机器上真的能承载 10 万个并发连接。

1. 启动：ECHO_SERVER_LITE=1 PORT=23232 HTTP_PORT=23231 ./echo-server &
   （或在代码仓库里 go run .）
2. 应用测试所需的内核限制：
     sudo sysctl -w net.core.somaxconn=65535 net.ipv4.tcp_max_syn_backlog=65535
     sudo sysctl -w net.ipv4.ip_local_port_range="1024 65535"
     ulimit -n 1048576
3. 把客户端源端口分散到多个回环地址（单个源 IP 只有约 6.4 万个出站端口，这是客户端限制）：
     for ip in 127.0.0.2 127.0.0.3 127.0.0.4 127.0.0.5; do sudo ip addr add $ip/8 dev lo; done
4. 保持连接：
     go run ./tools/loadtest -mode hold -c 100000 -addr 127.0.0.1:23231 \
       -la 127.0.0.1,127.0.0.2,127.0.0.3,127.0.0.4,127.0.0.5 -d 20s
   验收：dialed==100000、failed==0。运行期间读取服务端 RSS（ps -o rss），约为每连接 7-8 KB。
5. 在同一批 10 万连接上持续发请求：
     go run ./tools/loadtest -mode drive -c 100000 -path /ip -addr 127.0.0.1:23231 \
       -la 127.0.0.1,127.0.0.2,127.0.0.3,127.0.0.4,127.0.0.5 -d 12s
   验收：dialed==100000、failed==0、errs==0，且 rps > 100000。
6. 清理：删除额外的回环地址（sudo ip addr del ...）并停止服务。
汇报：两次运行的 dialed/failed/requests/rps、实测 RSS，以及本机核数。
若 failed 非 0，先报告客户端侧错误——几乎总是源端口耗尽或 ulimit 过低，而非服务端问题。
```

### 3. 跑测试套件 / 贡献改动

```text
在 echo-server 仓库上工作（Go + React，单二进制）。

1. 安装 Go 1.26+ 与 Node 22。
2. make build        # 构建 frontend/dist 并通过 //go:embed 内嵌
3. 运行验收门槛，任何失败都要修：
     gofmt -l .            （必须无输出）
     go vet ./...
     go test ./... -race -count=1
4. 做你的改动，重跑完整门槛，并补一个"没有该改动就会失败"的测试。
5. 验证运行中的二进制，而不只是单元测试：
     PORT=@@KEEP_123232@@ HTTP_PORT=@@KEEP_123231@@ ./echo-server &
     curl -sf http://127.0.0.1:@@KEEP_123231@@/ip
     curl -sf -k https://127.0.0.1:@@KEEP_123232@@/echo?fields=ja4,tls,client
汇报：diff 摘要、门槛输出、手工 curl 输出。
```

### 4. 审查这个服务能告诉你关于客户端的哪些信息

```text
启动 echo-server，用多种客户端探测，观察指纹面。

1. 构建并运行：make build && PORT=23232 HTTP_PORT=23231 ./echo-server &
2. 对以下每个客户端，抓取 /echo?fields=client,ja4,tls,http2,ip 的响应，汇总 name、family、
   JA4、HTTP/2 指纹与 UA 伪装检测结果：
     curl、wget、python -c 'import requests; requests.get(...)'、node、go net/http、
     一个伪造 Chrome User-Agent 的 curl。
3. 确认：curl 伪造 Chrome UA 会被标记 "spoofed": true，且 Go 客户端缺失 http2 指纹这一点
   能与 curl 区分开。
4. 汇报一张表：客户端 -> 识别出的 name/family -> JA4 -> h2 指纹 -> 是否伪造。
```

## 运行

```bash
make build                       # 先构建 frontend/dist，再内嵌进 ./echo-server
PORT=23232 ./echo-server          # HTTPS（TLS 指纹）+ 明文 HTTP 控制台 :23231
```

`make build` 会先在 `frontend/` 执行 `npm ci && npm run build`，然后 `go build`。控制台通过
`//go:embed frontend/dist` 嵌入，因此 `./echo-server` 就是**唯一需要部署的文件**——不需要静态目录、
不需要 Node 运行时、也不需要反向代理。手动构建前端？请先执行
`cd frontend && npm ci && npm run build` 再 `go build`，否则二进制里会嵌入旧界面。

管理控制台默认通过 **23231 端口的明文 HTTP** 提供，打开 `http://HOST:23231/ui/` 无需信任自签名证书。
`PORT`（默认 23232）上的 HTTPS 监听器提供同一套 UI/API，**并**捕获明文 HTTP 拿不到的 TLS
ClientHello/JA3/JA4。可用 `HTTP_PORT=23231` 修改明文端口，或 `HTTP_PORT=0` 关闭它、只保留 HTTPS。

### 使用 Docker 运行

每次发布都会把多架构镜像（`linux/amd64`、`linux/arm64`）推到 GitHub 自带的镜像仓库，部署只需拉取。
镜像 tag 会去掉 `v` 前缀：发布 `v1.0.3` 时镜像为 `1.0.3`、`1.0`、`1` 和 `latest`。预发布 tag
（如 `v1.1.0-rc1`）只发布它自己的版本号，`latest` 继续指向上一个正式版本，直到正式版发布。

```bash
docker run -d --name echo-server \
  -p 23231:23231 -p 23232:23232 \
  -v echo-data:/data \
  -e ECHO_SERVER_ADMIN_USERNAME=admin \
  -e ECHO_SERVER_ADMIN_PASSWORD='change-me-please' \
  ghcr.io/crawler-requests/echo-server:latest
```

镜像基于精简的 Alpine 运行时，内部是同一个自包含二进制（含 CA 根证书与 tzdata）；SQLite 数据库位于
`/data` 卷。若不设置 `ECHO_SERVER_ADMIN_*`，可通过 `/ui/` 的首次初始化向导创建管理员。需要在本地构建时，
用 `docker build -t echo-server .`，并把上面的镜像名换成本地标签。

容器以非特权用户 `10001:10001` 运行。**命名卷**（上例的 `-v echo-data:/data`）会自动获得正确属主；
如果改为绑定宿主机目录，请先让它对该 UID 可写：`mkdir -p /srv/echo-data && sudo chown 10001:10001 /srv/echo-data`。

镜像自带 `HEALTHCHECK`，在容器内执行 `echo-server healthcheck`。它读取与服务端同一套 `PORT`/`HTTP_PORT`
环境变量并优先探测 HTTPS，因此无论默认端口、改过明文端口（`-e HTTP_PORT=8080`），还是关闭明文监听，
结论都正确——`HTTP_PORT=0`（下面的纯 HTTPS 布局）下容器依然是 `healthy`。用
`docker inspect --format '{{.State.Health.Status}}' echo-server` 查看状态。

只跑 HTTPS（只映射 `23232`，控制台改由 HTTPS 监听提供）：

```bash
docker run -d --name echo-server -p 23232:23232 -v echo-data:/data \
  -e HTTP_PORT=0 -e ECHO_SERVER_ADMIN_USERNAME=admin \
  -e ECHO_SERVER_ADMIN_PASSWORD='change-me-please' \
  ghcr.io/crawler-requests/echo-server:latest
```

同一个镜像也能以极速模式运行（`-e ECHO_SERVER_LITE=1`）：只提供 `/ip` 与 `/echo`，无数据库、无控制台、
不向卷写入任何内容；该模式下 `/ui/` 与 `/api/config` 按设计返回 404。

### 挂在反向代理的子路径下

控制台既可以在站点根（`/ui/`），也可以挂在 `/echo-srv/ui/` 这样的前缀下，**不需要为每次部署重新构建**：
前端资源使用相对路径，路由 basename 与 API 基址都由页面实际被加载的 URL 推导出来。让代理指向明文
HTTP 监听并按前缀转发（尾斜杠会把前缀剥掉）：

```nginx
location = /echo-srv { return 301 $scheme://$http_host/echo-srv/; }
location ^~ /echo-srv/ {
    proxy_pass http://127.0.0.1:23231/;      # 末尾斜杠 = 剥掉前缀
    proxy_http_version 1.1;
    proxy_set_header Host $host;
    proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    proxy_set_header X-Forwarded-Proto $scheme;
}
```

`^~` 不能省：静态文件的 regex location（`\.js$` 之类）优先级更高，会把整个 bundle 404 掉——这正是只写
`location /echo-srv/` 时页面白屏的原因。深链接（`/echo-srv/ui/logs`）刷新后仍能正常渲染，重定向使用相对
路径，不会把浏览器带出前缀。

JA3/JA4/h2 指纹来自 TLS 握手，只有 HTTPS 监听（`PORT`，默认 23232）才有；反代明文监听则拿不到指纹，
其余能力不受影响。如果要反代 HTTPS，请透传 TCP 或使用 `proxy_ssl_*`，否则被指纹的是代理自身的握手。

## 极速版与并发

`ECHO_SERVER_LITE=1` 让二进制进入极速模式：**无 SQLite、无用户、无数据集、无管理 API、无查询日志**。
只提供 `/ip`、`/echo`、`/health`、`/metrics`，其余一律 404。适合挂代理池、爬虫集群或出网校验。

| 模式 | 并发 | 吞吐 | 失败数 | 服务端 CPU |
|---|---|---|---|---|
| 极速 `/ip` | 1,000 | 217k rps | 0 | 约 2 核 |
| 极速 `/ip` | 10,000 | 298k rps | 0 | 约 2 核 |
| 极速 `/ip` | 50,000 | 221k rps | 0 | 约 2 核 |
| 极速 `/ip` | **100,000** | **230k–256k rps** | **0** | **约 2 核** |

10 万个**同时保持**的连接占用 **713 MB RSS**（每连接约 7.1 KB），零建连失败；在这 10 万连接上持续
发请求达到 **231k rps、零错误**。同一次压测中压测客户端需要 13 核以上，因此这些数字受限于客户端而非
服务端。

### 自行复现

压测工具就在仓库里（`tools/loadtest`），上面的数字可验证而非空口声明：

```bash
# 内核限制（服务端与客户端）
sudo sysctl -w net.core.somaxconn=65535 net.ipv4.tcp_max_syn_backlog=65535
sudo sysctl -w net.ipv4.ip_local_port_range="1024 65535"   # 仅客户端侧
ulimit -n 1048576

# 1) 启动极速版
ECHO_SERVER_LITE=1 PORT=23232 HTTP_PORT=23231 ./echo-server &

# 2) 保持 10 万连接（测每连接内存）
go run ./tools/loadtest -mode hold -c 100000 -addr 127.0.0.1:23231 \
  -la 127.0.0.1,127.0.0.2,127.0.0.3,127.0.0.4,127.0.0.5 -d 20s

# 3) 在 10 万连接上持续发请求（测吞吐）
go run ./tools/loadtest -mode drive -c 100000 -path /ip -addr 127.0.0.1:23231 \
  -la 127.0.0.1,127.0.0.2,127.0.0.3,127.0.0.4,127.0.0.5 -d 12s
```

单个源 IP 的本机源端口只有约 6.4 万个，所以压测时把客户端分散到 5 个回环地址（`-la`）；而**承载**
10 万**入站**连接只需要上面的服务端限制——真实客户端集群各自一个源 IP 即可达到。

## 极速版：`/ip`

如果只需要**调用方的出网 IP**，就不该为完整回显的全部开销买单（ClientHello 解析、JA3/JA4/JA4H/h2
指纹、客户端识别、地理查询、日志写入）。`GET /ip` 只回答这一个问题：

```bash
curl -k https://HOST:23232/ip                   # {"ip":"203.0.113.42"}
curl -k https://HOST:23232/ip?format=text       # 203.0.113.42
curl -k http://HOST:23231/ip                    # 明文监听，完全不走 TLS
```

它和 `/echo` 一样遵循 `X-Forwarded-For` / `X-Real-IP` / `CF-Connecting-IP`（仅当 TCP 对端是可信代理时，
并通过 `trusted_proxies` 配置），返回
`Cache-Control: no-store`，并在 `/metrics` 中计入 `echo_ip_only_requests_total`。它**刻意不写查询日志**，
因此代理池健康检查不会把控制台历史刷爆。

32 核机器实测（回环、明文 HTTP、`ab -k` 与 Go 压测工具）：

| 端点 | 并发 | 吞吐 | p50 | p99 |
|---|---|---|---|---|
| `/ip` | 1,000 | **127k rps** | 0.8 ms | 38 ms |
| `/ip` | 5,000 | 102k rps | 44 ms | 182 ms |
| `/echo`（完整） | 1,000 | 53k rps（明文）/ 29k（TLS） | 5.8 / 4.6 ms | 145 / 515 ms |

2000 并发时服务端只用了约 2.5 核，而压测客户端需要 13 核，因此上表受限于客户端而非服务端。真实远端
客户端还要加上网络 RTT 与 TLS 握手开销；表中反映的是 keep-alive 复用连接的情况（所有池化爬虫都是这样）。

## 回显端点 — 请求级控制

所有开关都可选。优先级：**查询参数 > 请求头 > 管理端默认值**。

| 控制项 | 查询参数 | 请求头 | 取值 |
|---|---|---|---|
| 格式 | `format` | `X-Echo-Format` | `json`（默认）/ `text` |
| 字段 | `fields` | `X-Echo-Fields` | 逗号分隔的点路径 |

```bash
# 全量（默认）
curl -k https://HOST:23232/echo

# 只要需要的字段，文本格式——响应最小
curl -k -H 'X-Forwarded-For: 8.8.8.8' \
  'https://HOST:23232/echo?format=text&fields=ip.country,ip.city,ip.latitude,ip.longitude,ip.connection_type'
# ip.city=San Jose
# ip.connection_type=datacenter
# ip.country=United States
# ip.latitude=37.3393939
# ip.longitude=-121.8949553

# 同样的字段，JSON 格式
curl -k 'https://HOST:23232/echo?format=json&fields=client_hello.sni,client_hello.ja3_hash,ip.asn,ip.org'

# 只看客户端判定（谁在调用、UA 是否诚实）
curl -k 'https://HOST:23232/echo?fields=client.name,client.family,client.spoofed,client.confidence'
# {"client":{"confidence":0.88,"family":"cli","name":"curl","spoofed":true}}
```

## 响应结构（节选）

```jsonc
{
  "timestamp": "...", "method": "GET", "scheme": "https", "host": "...", "remote_addr": "...",
  "path": "/echo", "http_version": "HTTP/1.1",
  "headers": { "...": ["..."] }, "body": "", "body_length": 0,
  "client_hello": {
    "raw_base64": "...", "raw_hex": "...", "raw_record_base64": "...",
    "length": 512, "record_length": 517, "record_count": 1, "record_version": 771,
    "version": 771, "cipher_suites": [4866, 4867, 4865], "extensions": [11, 10, 16, 43, 13, 51],
    "sni": "example.com", "alpn": ["h2", "http/1.1"],
    "supported_versions": [772, 771], "signature_algorithms": [1027, 1283], "supported_groups": [29, 23],
    "key_share_groups": [29], "has_grease": false,
    "ja3": "771,4866-...", "ja3_hash": "...",
    "ja4": "t13d3112h2_e8f1e7e78f70_b26ce05bbdd6", "ja4_r": "t13d...", "ja4_o": "t13d..."
  },
  "client": {
    "name": "curl", "family": "cli", "version": "8.5.0", "confidence": 0.95,
    "signal": "ja4_measured+user_agent", "source": "user_agent",
    "matches": ["JA4 exact match: t13i3111h2_…", "User-Agent: curl/8.5.0", "TLS family and User-Agent agree"],
    "header_set_hash": "a1b2c3d4e5f6"
  },
  "ja4h": "ge11nn020000_e5a56608905c_000000000000_000000000000",
  "tls": {
    "tls_version": "TLSv1.3", "cipher_suite": "TLS_AES_128_GCM_SHA256",
    "server_name": "example.com", "alpn": "h2",
    "ja3_string": "...", "ja3_hash": "...", "ja4": "...", "ja4_r": "...", "ja4_o": "..."
  },
  "ip": {
    "ip": "8.8.8.8", "asn": "AS15169", "org": "Google LLC", "isp": "Google LLC",
    "country": "United States", "country_code": "US", "region": "California", "city": "San Jose",
    "postal": "95025", "timezone": "America/Los_Angeles", "utc_offset": "-08:00", "continent": "North America",
    "latitude": 37.3393939, "longitude": -121.8949553,
    "connection_type": "datacenter", "geo_source": "ipwhois"
  }
}
```

`connection_type` = `datacenter`（托管/云 CIDR 表 + 组织名启发式，或 ipinfo `hosting`）、
`residential_proxy`（公开住宅代理出口，或 ipinfo `proxy`/`vpn`/`tor`），否则 `unknown`。

## 客户端识别

`client` 回答*到底是谁在调用我？*，它把 TLS 指纹（难以伪造）与 User-Agent 结合起来：

- **JA4 指纹库** —— 一个可嵌入/可插拔的真实世界 JA4 指纹库，把 ClientHello 映射到实际发送它的
  客户端。与服务端所有数据集一样，它由按优先级排序的 Provider 组装（见
  [数据源引擎](#数据源引擎provider)），内嵌的融合库始终是最后的兜底。

  内嵌库本身就是融合产物：JA4DB 众包快照（每个指纹实际伴随哪些 User-Agent）**加上** FoxIO 的人工
  映射（任何提交库都不包含的应用名——Cobalt Strike、Sliver、Qakbot、IcedID、Lumma、Pikabot、
  Darkgate、ngrok、SoftEther）。人工维护的恶意软件命中会标为 `family: "malware"`，隧道/VPN 工具标为
  `family: "tunnel"`，且每个命中都带上其提交记录里的 OS/库上下文（`client.os`、`client.library`、
  `client.fused`）。

  查找时从高优先级到低优先级遍历 Provider，先精确匹配 JA4，再匹配 JA4 前缀（head + cipher hash，
  浏览器跨版本保持不变）。第一个认识该指纹的 Provider 胜出，因此私有库或云端同步库可以覆盖快照中
  对应的指纹；其余仍由快照解析。自定义 Provider 的判定会标为 `source: "ja4db:<provider>"`。

- **TLS 表** —— 依次精确 JA4、精确 JA3 hash、family 启发式，数据来自对本服务实测的指纹：curl、wget
  （GnuTLS）、python-requests、Node.js、Java 21、OpenSSL、Go net/http、Chromium。
- **User-Agent** —— curl / wget / python-requests / aiohttp / httpx / node-fetch / okhttp / Postman /
  Java / Go-http-client / Chrome / Edge / Opera / Firefox / Safari / HeadlessChrome / Googlebot 等，
  带版本号。
- **请求头集合** —— `header_set_hash` 以及 browser-like 提示。

数据库分两级，让快照随时间推移仍然可用：**精确 JA4** 匹配与 **JA4 前缀**匹配（head + cipher hash；
浏览器跨版本保持稳定，而扩展 hash 会变）。快照中没有的新版 Chrome 仍可落到前缀层，并依据 5.5 万次
观测被识别为 Chrome。由于有些指纹确实被共享（Go 1.24+ 与 Chrome 都发送后量子
`X25519MLKEM768` key share，JA4DB 也见到大量披着 Chrome UA 的爬虫），结果会携带
`candidates`（每个候选客户端及其观测占比）、`db_observations`，以及当首选候选与自身实测不一致时的
说明——服务从不假装仅凭 TLS 就能判定共享指纹。

`family` 取值为 `browser | cli | library | runtime | tool | bot | http_client`。当 UA 与 TLS 握手
矛盾时，请求会被标记 `spoofed: true`，**身份以 TLS 结果为准**，并在说明中列出双方证据：

```bash
curl -k -A 'Mozilla/5.0 … Chrome/131.0.0.0 Safari/537.36' https://HOST:23232/echo?fields=client
# {"client":{"name":"curl","family":"cli","spoofed":true,"confidence":0.88,
#   "notes":["TLS fingerprint says curl (cli) but the User-Agent claims Chrome (browser) — the UA is very likely spoofed"]}}
```

### 数据源引擎（Provider）

服务端用到的每个数据集都是一个 *dataset*，由按优先级排序的 *Provider* 组装。四种 Provider 类型对所
有数据集通用，编译进二进制的数据永远是优先级最低的 `builtin` 兜底：

| 类型 | 来源 | 刷新 |
|---|---|---|
| `embedded` | 编译进二进制（`builtin`，不可变） | 从不 |
| `file` | 本地文件**或目录**（目录内每个可解码文件都会合并） | 可选周期（mtime 监听）+ 手动重载 |
| `remote` | URL（`http`/`https`，或任何通过 `datasets.RegisterScheme` 注册的协议） | 可选周期 + 手动同步 |
| `command` | shell 命令的 stdout —— 可用任何语言实现数据源 | 可选周期 + 手动同步 |

`file` Provider 上的 `refresh_min` 会把它变成被监听的文件：引擎按周期 stat（目录则取最新的非隐藏
文件），时间戳变化时原子重载，因此挂载的 ConfigMap 或每夜导出无需重启即可生效。间隔 `0` 表示仅手动。
Remote Provider 接受 `headers`（如 `{"Authorization":"Bearer …"}`）用于私有云；敏感值在所有 API 响应
中都会被掩码（`***`），把掩码原样提交回去会保留已存的值。

目前内置的数据集：

| 数据集 | 作用 |
|---|---|
| `ja4` | TLS 指纹 → 客户端名称（JSON 契约或社区 `ja4_fingerprint.csv`） |
| `datacenter_cidr` | 被判定为 `datacenter` 的 CIDR 前缀（所有 Provider 与内嵌表的并集） |
| `residential_proxy_cidr` | 被判定为 `residential_proxy` 的 CIDR 前缀 |
| `datacenter_orgs` | 作为托管兜底启发式的 ASN/组织名关键词 |

Remote 与 command 载荷会缓存到磁盘（`~/.echo-server/datasets/<dataset>/<provider>.data`，可用
`ECHO_SERVER_DATASET_CACHE_DIR` 覆盖），并保存最后一次 HTTP `ETag`，因此重启时用 `If-None-Match`
重新校验（304 则保留缓存）而不是重新下载。重启——或云端不可达——会继续使用最后一份好数据。刷新失败
会在 Provider 状态中报错，但绝不会丢弃可用值。拉取与解码在管理锁之外执行：慢云端或大库不会阻塞
状态/API 调用，Provider 被重新配置后才到达的结果会被丢弃。Provider 持久化在 SQLite 配置表的
`dataset_providers:<name>` 下，也可在启动时通过 `DATASET_PROVIDERS` 环境变量预置（以数据集名为键的
JSON 对象）。管理 UI 的*数据源（Provider）*卡片驱动同一套 API：选择数据集，新增/编辑/同步/删除其
Provider。

```bash
# 列出所有数据集及其 Provider 和实时状态（条目数、观测数、上次同步、错误）
curl -k -H "Authorization: Bearer $JWT" https://HOST:23232/api/datasets
# ……或只取一个数据集（返回对象而非数组）
curl -k -H "Authorization: Bearer $JWT" 'https://HOST:23232/api/datasets?dataset=ja4'

# 给 JA4 数据集添加本地库或目录（每 5 分钟监听变化）
curl -k -X POST -H "Authorization: Bearer $JWT" -H 'Content-Type: application/json' \
  -d '{"name":"my-fp","kind":"file","priority":10,"path":"/data/my-ja4db.json","refresh_min":5}' \
  'https://HOST:23232/api/datasets?dataset=ja4'

# 每 30 分钟拉取私有云库，用请求头认证
curl -k -X POST -H "Authorization: Bearer $JWT" -H 'Content-Type: application/json' \
  -d '{"name":"cloud","kind":"remote","priority":20,"url":"https://cloud.example.com/ja4db.json",
       "headers":{"Authorization":"Bearer CLOUD_TOKEN"},"refresh_min":30}' \
  'https://HOST:23232/api/datasets?dataset=ja4'

# 用任意脚本生成 datacenter CIDR 表（stdout 即数据）
curl -k -X POST -H "Authorization: Bearer $JWT" -H 'Content-Type: application/json' \
  -d '{"name":"nightly","kind":"command","priority":10,"command":"/opt/gen-cidrs.sh","refresh_min":720}' \
  'https://HOST:23232/api/datasets?dataset=datacenter_cidr'

# 立即强制同步（整个数据集的所有 Provider，或 ?provider=NAME —— file Provider 会重新读取）；
# DELETE 删除自定义 Provider
curl -k -X POST -H "Authorization: Bearer $JWT" 'https://HOST:23232/api/datasets/sync?dataset=ja4&provider=my-fp'
curl -k -X DELETE -H "Authorization: Bearer $JWT" 'https://HOST:23232/api/datasets?dataset=ja4&provider=cloud'
```

JA4 云端契约就是 `tools/ja4dbgen` 写出的 `{meta, ja4}` JSON ——
`{"ja4": {"<fingerprint>": {"n": observations, "uas": [[ua, count], …], "apps": …}}}`。引擎本身
（`datasets/`）是通用的：嵌入方通过 `datasets.New` 增加一个全新数据集，通过
`datasets.RegisterScheme` 接入传输协议，管理 API/UI 会自动暴露它。

### IP 情报查询链路（Provider）

地理位置、ASN 与隐私判定来自一条*查询链路*：按优先级排序的 Provider 列表，逐个 IP 查询。链路按优先级
尝试，第一个返回可用数据的 Provider 胜出；被限流、超时、报错或无数据的 Provider 会被记录，然后尝试
下一个。多个云 API 可以串联，因此免费 API 可作廉价默认值、付费/带 token 的 API 作兜底（反之亦然）。

| 类型 | 来源 | 回答 |
|---|---|---|
| `builtin` | 编译进二进制的驱动（`ipwhois`、`ipapi`、`ipinfo`） | Go 侧归一化字段 |
| `http` | 任意含 `{ip}`（已转义）或 `{ip_raw}` 的 HTTP API URL 模板 | JSON，可选字段映射 |
| `command` | 替换 `{ip}` 后执行 `sh -c '<command>'` 的 stdout | JSON，可选字段映射 |

已是归一化结构的响应（`country`、`country_code`、`region`、`city`、`postal`、`timezone`、
`utc_offset`、`latitude`、`longitude`、`continent`、`asn`、`asn_name`、`org`、`isp`、`is_proxy`、
`is_vpn`、`is_tor`、`is_hosting`、`anycast`）无需映射。其他 API 用 `mapping` 描述（Info 字段 → 点路径，支持数组
下标）：`{"country":"data.location.country_name","latitude":"data.location.lat","asn":"data.asn"}`。
`headers` 携带凭据；与数据集一样，它们在所有 API 响应中都会被掩码（`***`），把掩码原样提交回去会
保留已存的值。每个 Provider 的统计（调用、成功、失败、平均延迟、最后错误、最后成功）通过 API/UI
暴露，便于发现悄悄劣化的上游。

```bash
# 列出链路：配置（凭据已掩码）、顺序与实时统计
curl -k -H "Authorization: Bearer $JWT" https://HOST:23232/api/ipproviders

# 追加付费云 API；优先级更高时会在内置 Provider 之前尝试
curl -k -X POST -H "Authorization: Bearer $JWT" -H 'Content-Type: application/json' \
  -d '{"name":"cloud","kind":"http","enabled":true,"priority":100,
       "url":"https://api.example.com/v1/ip/{ip}",
       "headers":{"Authorization":"Bearer CLOUD_TOKEN"},
       "mapping":{"country":"data.country","city":"data.city","asn":"data.asn",
                  "is_proxy":"data.privacy.proxy","is_hosting":"data.privacy.hosting"}}' \
  https://HOST:23232/api/ipproviders

# 把本地脚本（任意语言）作为链路的另一环
curl -k -X POST -H "Authorization: Bearer $JWT" -H 'Content-Type: application/json' \
  -d '{"name":"local","kind":"command","enabled":true,"priority":-10,
       "command":"/opt/ipintel.sh {ip}","timeout_sec":3}' \
  https://HOST:23232/api/ipproviders

# 不经过结果缓存，直接查询一个 IP
curl -k -X POST -H "Authorization: Bearer $JWT" -H 'Content-Type: application/json' \
  -d '{"ip":"8.8.8.8"}' https://HOST:23232/api/ipproviders/test

# 删除自定义 Provider（内置项可禁用但不可删除）
curl -k -X DELETE -H "Authorization: Bearer $JWT" 'https://HOST:23232/api/ipproviders?name=cloud'
```

链路持久化在 SQLite 的 `ip_lookup_providers` 下，也可用 `IP_LOOKUP_PROVIDERS` 环境变量预置（JSON
数组，在持久化列表之后应用）。旧设置保持原语义：`enable_online_geo=false` 关闭整条链路；
`geo_provider=ipwhois|ipapi|ipinfo` 只运行该内置 Provider（自定义 Provider 仍参与）；
`geo_provider=auto`/未设置则运行全部，配置了 `ipinfo_token` 会把 `ipinfo` 内置项提升到链路最前。
内置项默认启用，优先级为 `ipwhois=20`、`ipapi=10`、`ipinfo=5`。管理 UI 的
*IP 查询链路（Provider）*卡片驱动同一套 API，包含逐 IP 的“测试链路”按钮。

### JA4H（HTTP 层指纹）

`ja4h` 是 JA4 的 HTTP 层搭档（FoxIO 规范）：方法、HTTP 版本、cookie/referer 是否存在、请求头名称
集合、Accept-Language，以及 cookie 字段/值，一起哈希。它无法仅靠修改 User-Agent 伪造，并能在 HTTP
层区分共享同一 TLS 栈的客户端。`show_ja4h`（管理端开关，默认开启）控制它。与参考实现的一处差异是
Go `http.Server` 强制的：哈希前请求头**名称会排序**（线上顺序无法从 `http.Header` 恢复，且 `Host`
位于 `r.Host` 而非 header map）；cookie 字段/值哈希与参考实现逐字节一致。

### HTTP/2 指纹

TLS 伪装工具（curl_cffi、uTLS）能把 JA3/JA4 抄得一模一样，所以 HTTP/2 层才是下一个区分维度：浏览器与
各 HTTP 库发送的 SETTINGS、是否使用 PRIORITY 帧、请求伪头的顺序都不一样。连接协商为 h2 时，回显响应会
带上 `http2` 对象：

```json
{
  "http2": {
    "raw": "3:100,4:10485760,2:0|:method,:scheme,:authority,:path",
    "settings": "3:100,4:10485760,2:0",
    "pseudo_header_order": [":method", ":scheme", ":authority", ":path"],
    "stream_id": 1
  }
}
```

`raw` 是广泛使用的 Akamai 风格指纹：`SETTINGS|PRIORITY|PSEUDO_HEADERS`。服务端自行运行
`golang.org/x/net/http2`，从原始连接上旁路记录 SETTINGS 与 PRIORITY 帧（Go `net/http` 会丢弃它们）；
请求处理（mux、鉴权、中间件、回显）保持不变。HTTP/1.x 连接没有 `http2` 对象；`enable_http2=false`
可把监听器固定为只支持 HTTP/1.1（该值在构建 TLS 配置时读取，重启后生效）。

同一实例实测：curl 发出 `3:100,4:10485760,2:0|:method,:scheme,:authority,:path`，而 Go 的 `net/http`
发出 `2:0,4:4194304,5:16384,6:10485760|:authority,:method,:path,:scheme`——SETTINGS 顺序与伪头顺序都不同。

### 凭据请求头默认脱敏

回显接口通常允许任何人访问，原样回显请求头会把每次请求都变成凭据泄露（日志、截图、分享的 curl
输出）。`redact_sensitive_headers`（默认**开启**）把 `Authorization`、`Cookie`、`Set-Cookie`、
`Proxy-Authorization`、`X-Api-Key`、`X-Api-Token`、`X-Auth-Token`、`X-Csrf-Token` 的值替换为 `***`
（`Bearer ***` 保留认证方案，便于区分 Bearer 与 Basic）。仅在调试令牌链路时于「回显设置」关闭。

### 运维说明

- **优雅关闭**：收到 `SIGINT`/`SIGTERM` 后停止接收新连接，最多 15 秒等完在途请求（可能正在等地理
  查询或大上传），关闭 SQLite 后退出。
- **回显请求体上限**：即使 `body_limit_kb=0` 也有 8MB 硬上限，因为处理逻辑会把整个 body 读进内存；
  需要更严格可把 `body_limit_kb` 设小。
- **限流与 IP 规则**同时按解析出的客户端地址与 TCP 对端计费，轮换伪造的请求头
  无法逃逸每分钟配额或允许列表。
- **登录 / 初始化 / 注册**按解析出的客户端限流（15 分钟内 10 次失败或 30 次尝试），始终开启，与
  `rate_limit_per_min` 无关；可信代理之后按代理追加的真实地址计费，不会让一个人锁死所有账号。
- **SQLite 索引**：`query_log` 按 `ts`、`ip`、`(connection_type, country)` 建索引；`audit_log` 按
  `ts`、`username`、`action`；另有 `notifications(ts)`、`notification_reads` 主键、`api_keys(key_hash)`、
  `webhooks(enabled)`、`saved_views(page)`。`TestQueryLogIndexesAreUsed` 断言查询计划确实命中它们。

### 重新生成 `data/ja4db.json`（多源融合）

内置库是**两个来源的融合**，因为各自覆盖了对方缺失的部分：

| 来源 | 贡献 |
|---|---|
| JA4DB 冻结快照（2026-05-15，镜像自 `github.com/Niicolaa/ja4db-export`） | 1,589 个指纹、约 32 万次真实提交：某指纹实际伴随哪些 User-Agent，以及 OS/库信息 |
| FoxIO `ja4plus-mapping.csv`（`github.com/FoxIO-LLC/ja4`） | 人工维护的应用名——包含任何提交库都没有的恶意软件 C2 与隧道工具：Cobalt Strike、Sliver、Qakbot、IcedID、Lumma、Pikabot、Darkgate、SoftEther、ngrok、Telegram |

一条命令重建两个来源：

```bash
go run ./tools/ja4dbgen                      # 自动下载两个镜像并写出 data/ja4db.json
go run ./tools/ja4dbgen -ja4db X.csv -mapping Y.csv   # 或使用本地文件
```

生成器把 JA4DB 快照固定到最后一个完整导出的 commit（`4e46ad5b4401`）：可变的 `@main` 现在只提供
596 个指纹的截断文件，而该 commit 有完整的 1,633 个。人工维护的名称按该指纹的提交量加权，使人工核实
的恶意软件指纹可见，同时不会盖过真实流量。输出保持 `{meta, ja4}` 契约，因此任何说同一 JSON 的自定义
Provider（file/remote/command）都能原样叠加。

融合效果在输出里可见：仅由人工库命名的指纹（`t13d201100_…` → IcedID，423 次观测；`t12d190800_…` →
Cobalt Strike beacon；`t13i190800_…` → Sliver Agent）能被识别，`family` 为 `malware`，且每个指纹都
携带其提交记录里的 OS/库上下文。

## ClientHello 指纹

- **JA3** —— 按线上顺序拼接 `version,ciphers,extensions,curves,point_formats`，保留 GREASE，用**真实
  MD5** 哈希（`ja3_hash`）。
- **JA4** —— 遵循 FoxIO 规范：`t` + TLS 版本（2 字符）+ SNI 标志（`d`/`i`）+ 两位密码套件数 + 两位
  扩展数 + ALPN 首/末字符，然后 `_<排序后的非 GREASE 密码套件 12 位十六进制>_<排序后的非 GREASE 扩展
  （去掉 SNI/ALPN）12 位十六进制 + "_" + 签名算法>`。
- **JA4_r / JA4_o** —— 相同布局但使用原始（未哈希）值：排序后（`_r`）与原始线上顺序（`_o`）。

## 面向 Agent 的接入（MCP）

本服务的全部能力都通过内置 **MCP server** 暴露给 agent：同一个二进制以 `echo-server mcp` 运行，
用 stdio 传输 JSON-RPC 2.0——即 Claude Code、Codex 等 MCP 客户端使用的传输方式。它是对**运行中部署**
的客户端，因此鉴权、审计、限流与查询日志全部沿用，不会绕过。

```bash
# 注册一次，之后 agent 就能调用下表中的工具
claude mcp add echo-server \
  --env ECHO_SERVER_URL=http://127.0.0.1:23231 \
  --env ECHO_SERVER_API_KEY=esk_... \
  -- /path/to/echo-server mcp
```

| 工具 | agent 能用它做什么 |
|---|---|
| `echo_server_health` | 确认部署在线 |
| `echo_server_my_ip` | 取得自己的出网 IP（走极速 `/ip` 路径） |
| `echo_server_self_fingerprint` | 看服务端如何识别自己——客户端名/类别、JA3/JA4、h2 指纹、UA 是否伪造；传入 `user_agent` 可测试伪装 |
| `echo_server_lookup_ip` | 最多 100 个地址的地理/ASN/连接类型 |
| `echo_server_search_ja4` | 检索指纹库（含恶意软件家族） |
| `echo_server_query_log` | 按客户端/类别/伪造/国家审计流量 |
| `echo_server_stats` | 流量形态：Top 客户端、伪造数、未识别客户端数 |
| `echo_server_providers` | 哪个地理 Provider 在劣化 |
| `echo_server_issue_password_reset` | 仅管理员：一次性重置令牌 |

需要 TLS 指纹的工具（`self_fingerprint`、伪造检测）默认走 HTTPS；仅当 TLS 监听不可达时 MCP 客户端才回落到明文端口。明文 HTTP 无法给出 JA3/JA4 或伪造判定。

配套的 Claude Code **Skill** 位于 [`skills/echo-server/SKILL.md`](skills/echo-server/SKILL.md)，说明了
每个工具的使用时机、如何解读 `spoofed`/`connection_type`/`anycast`，以及常见任务。

### 谁能调用 Agent 工具

`agent_access`（访问控制 → Agent 访问策略）决定 MCP 工具与 `/ip` 需要的凭证，与管 `/echo` 的
`require_token` 开关相互独立：

| 取值 | 可调用者 |
|---|---|
| `public` | 任何能访问端口的人——适合内网临时测试端点 |
| `token`（默认） | 任意角色的 JWT 或 API Key；写入类工具仍需管理员凭证 |
| `admin_token` | 仅 admin 作用域的 Key 或管理员 JWT——需要每次查询都可归因时使用 |

默认会拒绝匿名 `/ip`；此前该端点完全绕过了 `require_token`。拒绝时返回 401/403，带
`WWW-Authenticate` 头与说明策略和修改位置的 JSON 体，agent 能据此自行恢复而不是靠猜。`echo-server mcp`
也会在 `initialize` 握手中说明当前凭证状况，并在缺少管理员权限时用可读消息拒绝管理员专属工具。

### 安全说明

- 出站 URL（IP Provider、远端数据集）指向回环、RFC 1918、链路本地或云元数据地址时会被拒绝——在保存
  Provider 时检查一次，并在每次拨号时再次检查。
- `file` 数据源只能读取 `ECHO_SERVER_DATA_DIR`（默认：数据集缓存目录）内的文件。路径与目录条目都会
  解析符号链接；链接（包括父目录链接）的目标一旦指向沙箱外就会被拒绝。
- 登录耗时会做均衡，响应时间无法用于判断账号是否存在。
- 修改密码（自助修改、管理员重置或令牌兑付）会让此前签发的所有 JWT 立即失效；发起修改的浏览器
  标签页会收到替换后的新令牌，其余设备需重新登录。
- 自助注册上限为 1000 个账号；达到上限后管理员仍可直接创建账号。该上限用于防止公开注册无限
  增长用户表。

## 管理 UI 与 API

`/ui/` —— React + Ant Design 控制台，后端是 SQLite 用户系统。**全新安装没有账号，也没有默认
密码。** 打开 `/ui/`，初始化向导会要求你设置第一个管理员的用户名和密码；它创建的账号拥有整个安装。
安装后请立即完成：在账号存在之前，任何能访问端口的人都可以抢先占据第一个管理员。无头部署可在首次
启动前设置 `ECHO_SERVER_ADMIN_USERNAME`（默认 `admin`）和 `ECHO_SERVER_ADMIN_PASSWORD`。密码以加盐
PBKDF2-SHA256（21 万次迭代）存储。JWT 签名密钥来自 `ECHO_SERVER_JWT_SECRET`，否则生成一次并持久化
到 SQLite，因此会话可在重启后继续有效。

账号有角色：`admin` 管理用户与配置；`viewer` 获得只读控制台（所有变更请求在服务端被拒绝，UI 会
隐藏/禁用编辑控件）。被禁用或删除的用户立即失去访问权（每个请求都会重新读取账号），最后一个启用的
管理员不能被删除、禁用或降级。管理员在用户管理卡片控制*允许访客自助注册*（默认关闭）。关闭时只有
管理员能创建账号；开启时登录页提供注册，所有自助注册账号都是 viewer。

### 忘记密码后的找回

密码哈希是单向的，忘记后只能**替换**、无法读回。两条路径对应两种真实场景：

**1. 在线自助（还有管理员能登录）。** 在*用户管理*页，账号右侧的钥匙图标签发**一次性重置令牌**：

- 32 字节熵，只显示一次（服务器只存其 SHA-256——即使数据库泄露也无法伪造可用令牌），
- 30 分钟有效、一次性使用；为同一账号重新签发会让旧令牌失效，
- 用户在 `/ui/` 点**忘记密码？**，粘贴令牌并设置新密码，随即自动登录，
- 不依赖邮件（本产品没有 SMTP 依赖），令牌通过你们已有的私下渠道转交即可，
- 签发与兑付都会写入审计日志，兑付按解析后的客户端地址限流。

**2. 离线兜底（没人能登录，例如唯一的管理员忘了密码）。** 停掉服务，用重置模式直接操作数据库——这需要
本机对数据库文件的访问权，正是这个操作应有的信任边界：

```bash
./echo-server -reset-password -user root -password '新的强密码'
# 省略 -password 则无回显地交互输入：
./echo-server -reset-password -user root
```

若账号被禁用会自动重新启用，可选 `-role`；不会把密码打回终端，并以发起命令的操作系统用户名记录
`password.reset.offline` 审计。非默认路径时用 `ECHO_SERVER_DB` 指向正确的数据库。

控制台是单页应用，带分组、可折叠侧边栏和 `Ctrl/⌘+K` 页面命令面板。每个分区都是独立路由
（`/ui/users`、`/ui/logs`、……），因此链接与刷新都可用；服务端对无扩展名路径回退到 `index.html`，
缺失的资源仍返回 404。

| 页面 | 路由 | 功能 |
|---|---|---|
| 概览 | `/ui/` | 计数器、24h 趋势、最新通知、快捷操作、Provider 健康 |
| 回显设置 | `/ui/echo` | `show_*` 开关、响应字段矩阵、实时 JSON/text 预览、请求级控制与预设 |
| IP 定位查询 | `/ui/lookup` | 指定 IP 查询（单条/批量最多 100、`nocache`）、地图预览、连接与隐私标签、该 IP 的查询日志历史 |
| IP 情报 | `/ui/ip` | 在线查询开关、token、缓存 TTL、Provider 健康表、链路测试、字段/隐私参考 |
| 数据源 | `/ui/datasets` | 跨数据集统计、按数据集的 Provider（embedded/file/remote/command）、同步、合并顺序、字段参考 |
| IP 查询链路 | `/ui/chain` | 链路统计与顺序可视化、逐 Provider 统计、逐 IP 测试、归一化字段、配置示例 |
| JA4 指纹库 | `/ui/fingerprints` | 跨 Provider 指纹搜索、候选分布、Provider 健康 |
| 监控分析 | `/ui/monitor` | 6h/24h/7d 趋势、Top IP/国家/方法、系统资源、指标链接 |
| 查询日志 | `/ui/logs` | 服务端筛选 + 快捷预设、24h 趋势与 Top IP/国家、CSV/JSON 导出、筛选视图、详情抽屉、请求重放 |
| 审计日志 | `/ui/audit` | 统计、动作/操作者筛选、动作分布与操作者排行、详情抽屉、动作字典、CSV 导出 |
| 通知中心 | `/ui/notifications` | 统计、级别/关键词筛选、来源分布、触发规则、生命周期表、未读角标、清理 |
| 用户管理（admin） | `/ui/users` | 统计、搜索/角色/状态筛选、账号与角色、权限矩阵、最近账号活动、开通指引 |
| 访问控制 | `/ui/access` | require-token 开关、带强度计的共享 token、端点鉴权矩阵、代码示例、安全检查、最近事件 |
| 安全与防护 | `/ui/security` | 概览评分 + 检查清单、命名 API Key、鉴权优先级、IP 允许/拒绝规则、限流、请求体上限、CORS、维护模式、保留、备份、JWT 轮换 |
| 集成与 Webhook（admin） | `/ui/integrations` | Webhook CRUD、事件目录、投递日志、签名校验示例、签名测试投递、备份/配置下载 |
| 系统设置 | `/ui/system` | 站点名称/描述/时区、运行时信息、数据导出、非敏感环境变量 |
| API 文档 | `/ui/docs` | 可搜索的端点目录、可复制 curl、OpenAPI 链接 |
| 工具箱 | `/ui/tools` | 4 组标签页：CIDR 计算器、IPv4 进制转换、URL 解析、特殊网段参考、Base64、URL 编解码、JSON 格式化、时间戳、SHA/HMAC、token 生成、JWT 解码、UUID v4、密码强度、curl 构建器、UA 解析、HTTP 状态码参考、正则测试 |
| 我的账户 | `/ui/account` | 资料、JWT claims 与过期倒计时、密码强度、个人审计记录、权限摘要 |

### 安全控制（API Key、IP 规则、维护模式）

安全页新增的配置键：`ip_allowlist` / `ip_denylist`（IP、CIDR，逗号或换行分隔；拒绝优先，空允许列表
表示全部允许）、`trusted_proxies`（可信反向代理的 IP/CIDR 列表；仅来自这些对端的 `X-Forwarded-For`
等转发头会参与 IP 规则与审计。留空时只有回环对端被视为代理（代理在其他主机或容器时需显式列出），
因此直接暴露在公网或私网的客户端都无法靠伪造 `X-Forwarded-For` 绕过允许/拒绝列表）、`rate_limit_per_min`（按客户端 IP 与 TCP 对端双重计费，仅回显流量，`0` 关闭）、
`body_limit_kb`（回显请求体上限；`0` 时仍保留内置 8MB 硬上限。`/api` 的 JSON 请求在进入处理器前
同样有上限——默认 1MB，或更小的 `body_limit_kb`——超限直接返回 `413`）、`cors_origins`、`security_headers`、
`maintenance_mode` / `maintenance_message`（未认证回显请求返回 `503`，控制台/API 仍可用）、
`log_retention_days`（每 6 小时后台清理）、`log_max_rows`（查询日志总行数上限，默认 100 万，维护任务
裁剪最旧的行；`0` 关闭该上限）、`webhook_allow_private`（默认关闭：Webhook 投递经过 SSRF 防护，只允许
公网目标；确需投递到内网/回环时显式设为 `true`）以及站点键 `site_name` / `site_description` / `timezone` /
`locale` / `density`。IP 规则、限流与维护模式只作用于回显流量，因此控制台永远不会把运维人员锁在外面；
登录/初始化/注册另有独立的按解析客户端限流（可信代理之后按代理追加的真实地址，避免共享代理对端被一个人耗尽预算而锁死所有人）。

命名 API Key（`/api/apikeys`）是共享 token 的替代方案：明文 `esk_…` 密钥**只在创建时返回一次**，
仅存储其 SHA-256；每个 Key 有 scope（`viewer`/`admin`）和可选过期时间，`last_used` 异步更新。通过
`X-API-Key` 发送；有效 JWT 始终优先。Key 可禁用或删除，不影响账号。

### 审计、通知与 Webhook

`/api/audit` 记录每个变更类控制台操作（账号、配置、安全、系统、API Key 与 Webhook 变更），包含操作者、
动作、目标、详情、IP 与时间戳；支持按动作前缀和用户名筛选，并可导出 CSV。`user.*`、`security.*`、
`config.*` 和 `system.*` 事件还会创建应用内通知（`/api/notifications`），驱动顶部角标。Webhook
（`/api/webhooks`）对订阅事件向任意 URL POST JSON，使用每个 Webhook 的密钥对请求体计算
`X-Echo-Signature: sha256=<hmac>`（`X-Echo-Event` 携带事件名）；投递异步进行、超时 8 秒，失败会生成
警告通知。投递不会跟随 3xx 重定向，并在拨号时校验目标（默认只允许公网地址，防止 Webhook 被用作访问
回环、内网或云元数据的 SSRF 跳板）；需要投递到内网时显式设置 `webhook_allow_private=true`。测试端点
（`POST /api/webhooks/test`）立即发送示例载荷。

### 可观测性、导出、备份与重放

- `GET /metrics` —— Prometheus 文本（查询总数/今日、用户数、运行时长、协程、内存、DB 大小、启用的
  API Key/Webhook 数、未读通知）。
- `GET /api/metrics/summary?hours=N` —— 总数、唯一 IP、逐小时序列（补齐空档）、Top IP/国家/方法与
  连接类型，供监控页和仪表盘图表使用。
- `GET /api/openapi.json` —— OpenAPI 3.0.3（Bearer + API-key 安全方案）；`GET /api/endpoints` ——
  同样目录的精简形式，供 API 文档页使用。
- 导出：`/api/export/logs.csv|json`、`/api/export/users.csv|json`、`/api/export/config.json`
  （不含敏感值）以及 `/api/audit/export.csv`。
- `GET /api/system/backup` —— 用 `VACUUM INTO` 生成一致的 SQLite 副本并以流式下载。
- `GET /api/system` —— 版本、运行时、运行时长、协程/GC、内存、DB 路径/大小、端口、维护标志。
- `POST /api/system/purge-logs {days|all}` 与 `POST /api/system/rotate-jwt`（后者在密钥来自
  `ECHO_SERVER_JWT_SECRET` 时拒绝，并返回新 token）。
- `POST /api/replay {method,path,headers,body}` —— 通过 `httptest` 在进程内运行真实的
  `echoHandler`，因此可在控制台内用不同请求头/请求体重放已记录请求（例如确认 UA 伪装判定），无需离开
  控制台。重放不会写入查询日志。
- `GET /api/views` —— 保存的日志筛选视图（按页面），管理员之间共享。

可配置暴露哪些字段、默认格式、在线 IP 情报 Provider/缓存/token，以及 API token。启用*要求 API token*
后，回显请求需要 `X-API-Token: <token>`（或 `?token=<token>`）或有效 JWT。`GET /api/config` 只向
管理员返回 `api_token`；viewer 看到 `***`。

| 端点 | 鉴权 | 用途 |
|---|---|---|
| `GET /api/setup/status` | — | 登录/初始化页所需的 `{needs_setup,allow_registration,registration_open}` |
| `POST /api/setup` | —（仅在无账号时） | `{username,password}` → 第一个账号（始终 admin）+ token |
| `POST /api/login` | — | `{username,password}` → `{token,user}` |
| `POST /api/register` | —（管理员须开启注册） | `{username,password}` → viewer 账号 + token；关闭时 403 |
| `GET /api/me` | JWT | 当前账号与实际角色 |
| `POST /api/me/password` | JWT | `{old_password,new_password}` —— 轮换自己的密码 |
| `GET/POST /api/users` | admin JWT | 列出账号 / 创建或更新（`{username,password?,role,disabled?}`） |
| `DELETE /api/users?username=` | admin JWT | 删除账号（拒绝自我删除与删除最后一个管理员） |
| `GET/POST /api/config` | JWT（写入：admin） | 读取/更新配置键（包括 `allow_registration`） |
| `GET/POST/DELETE /api/datasets` | JWT / admin 写入 | 列出所有数据集+Provider（`?dataset=` 限定 GET，并指定 POST/DELETE 目标） |
| `POST /api/datasets/sync` | admin JWT | 强制同步/重载（`?dataset=`；`&provider=` 指定单个 Provider） |
| `GET/POST/DELETE /api/ja4providers` | JWT / admin 写入 | 固定到 `ja4` 数据集的 `/api/datasets` 别名（兼容旧版） |
| `POST /api/ja4providers/sync` | admin JWT | `ja4` 的 `/api/datasets/sync` 别名（兼容旧版） |
| `GET /api/stats` | JWT | 仪表盘使用的 `{users,queries_total,queries_today}` |
| `GET /api/logs?limit=N` | JWT | 最近查询历史（默认 50，最大 500） |
| `GET/POST/DELETE /api/ipproviders` | JWT / admin 写入 | IP 查询链路（列出、新增/更新、删除） |
| `POST /api/ipproviders/test` | admin JWT | 通过查询链路查询一个 IP |
| `GET/POST /api/ip/lookup` | JWT | 查询指定 IP（`?ip=`、`&nocache=1` 或 `{"ips":[…]}`，最多 100 个）；单个地址直接返回 IP 对象；每客户端 600 次/分钟 |
| `POST /api/ip/lookup/bulk` | JWT | 纯文本批量（每行一个或用逗号分隔），响应结构相同，共用同一配额 |
| `GET /api/ip/history?ip=` | JWT | 该 IP 是否/如何调用过 `/echo`，取自查询日志 |
| `GET /api/logs` | JWT | 筛选历史（`limit/method/country/type/ip/q/days`） |
| `GET /api/audit`、`/api/audit/export.csv` | JWT | 审计日志（`limit/action/username`，CSV 导出） |
| `GET/POST/DELETE /api/notifications` | JWT | 列表/未读数（已读状态按账号隔离）、标记单条/全部已读、仅管理员可清理 |
| `GET/POST/DELETE /api/views` | JWT | 保存的查询日志筛选视图 |
| `GET/POST/PATCH/DELETE /api/apikeys` | admin JWT | 命名 API Key（`X-API-Key`；明文只返回一次） |
| `GET/POST/PATCH/DELETE /api/webhooks` | admin JWT | 带签名的事件投递 |
| `POST /api/webhooks/test` | admin JWT | 向一个 Webhook 发送示例事件 |
| `GET /api/system`、`/api/system/environment` | JWT | 运行时信息 / 非敏感配置视图 |
| `GET /api/system/backup` | admin JWT | SQLite `VACUUM INTO` 下载 |
| `POST /api/system/purge-logs`、`/api/system/rotate-jwt` | admin JWT | 保留期清理 / 轮换签名密钥 |
| `GET /api/metrics/summary?hours=N` | JWT | 趋势与 Top-N 聚合 |
| `GET /metrics` | — | Prometheus 文本暴露 |
| `GET /api/export/{logs,users}.{csv,json}`、`/api/export/config.json` | JWT / admin | 数据导出（不含敏感值） |
| `POST /api/replay` | admin JWT | 通过真实回显处理器重放请求 |
| `GET /api/ja4/search?q=`、`/api/ja4/stats` | JWT | 指纹搜索与 Provider 统计 |
| `GET /api/endpoints` | JWT | 端点目录 |
| `GET /api/openapi.json` | — | OpenAPI 3.0.3 文档（公开，用于生成客户端） |
| `GET /health` | — | 存活探针 |

```bash
# 全新安装：从命令行创建第一个管理员（或使用 /ui/）
JWT=$(curl -sk -X POST https://HOST:23232/api/setup -H 'Content-Type: application/json' \
  -d '{"username":"owner","password":"a-long-password"}' | jq -r .token)

# ……或已有安装：登录并保存 token
JWT=$(curl -sk -X POST https://HOST:23232/api/login -H 'Content-Type: application/json' \
  -d '{"username":"owner","password":"a-long-password"}' | jq -r .token)

# 创建只读账号，然后轮换自己的密码
curl -k -X POST -H "Authorization: Bearer $JWT" -H 'Content-Type: application/json' \
  -d '{"username":"alice","password":"alice-pass","role":"viewer"}' https://HOST:23232/api/users
curl -k -X POST -H "Authorization: Bearer $JWT" -H 'Content-Type: application/json' \
  -d '{"old_password":"a-long-password","new_password":"a-longer-pass"}' https://HOST:23232/api/me/password

# 禁用账号（其现有 token 立即失效）
curl -k -X POST -H "Authorization: Bearer $JWT" -H 'Content-Type: application/json' \
  -d '{"username":"alice","disabled":true}' https://HOST:23232/api/users
```

## IP 情报

IP 定位既可以通过 `/echo`（自动识别调用方自身的来源 IP），也可以通过独立的查询 API 指定任意 IP
（`/api/ip/lookup`，控制台页面 `/ui/lookup`），适合排查日志里的陌生地址、处理滥用举报或批量补数据。

```bash
# 查询单个地址（单个结果直接返回 IP 对象）
curl -k -H "Authorization: Bearer $JWT" 'https://HOST:23232/api/ip/lookup?ip=8.8.8.8'

# 批量（最多 100 个，结果顺序与输入一致）；nocache=1 绕过结果缓存
curl -k -H "Authorization: Bearer $JWT" -H 'Content-Type: application/json' \
  -d '{"ips":["8.8.8.8","1.1.1.1","104.131.0.1"],"nocache":false}' https://HOST:23232/api/ip/lookup

# 纯文本批量（每行一个或用逗号分隔）
printf '8.8.8.8\n1.1.1.1\n' | curl -k -X POST -H "Authorization: Bearer $JWT" \
  --data-binary @- https://HOST:23232/api/ip/lookup/bulk
```

- 默认具备离线能力：约 1.48 万个内嵌 datacenter 前缀（AWS/GCP/DigitalOcean/Oracle 官方列表、
  Akamai 实际宣告前缀 + 主要托管品牌）以及 100 条住宅代理样本——无需网络。
- 在线（可选）：`ipwho.is` → `ip-api.com` → `ipinfo.io`，带缓存（`geo_cache_ttl`，默认 24h）。失败结果不写缓存，
  因此一次超时不会让该 IP 的地理信息空白一整天。
- 在管理 UI 设置 **ipinfo token**，可使用 ipinfo 的 `loc` 坐标和权威的 `proxy/vpn/tor/hosting` 标签；
  ipinfo 还会返回 `anycast` 标记，为 true 时城市字段没有地理意义。
- 通过*启用在线 IP 情报*完全关闭在线查询；查询失败时地理位置留空，而不是猜测。

### 准确率与边界

2026-11-18 通过运行中的服务（`/echo?fields=ip`）实测 620 个未缓存 IP：500 个按五大 RIR 分层
（每区 100 个）+ 120 个中国 IP。独立参照为 DB-IP City Lite（免费月度版），ASN 与国家另用
Team Cymru 交叉核对；中国样本再对照 zxinc 国内库。

| 字段 | ipwho.is（默认首选），n=620 | ip-api.com，n=150 | ipinfo.io（无 token），n=150 |
|---|---|---|---|
| 国家 | 96.6% | 98.6% | 98.7% |
| 省/州 | 77.5% | 79.7% | 79.1% |
| 城市名 | 51.6% | 68.1%† | 54.0% |
| 城市坐标 25km 内 | 76.1%（中位 6km） | 75.4%† | 70.7%（中位 5km） |
| ASN（有返回时） | 98.6% | 98.2% | 99.1% |
| 中国省级（79 个） | 66.2% | — | — |
| 中国城市级（46 个） | 47.8% | 28.3%* | 37.0% |
| 中国国家级（79 个） | 98.7% | 97.5% | 98.7% |

† ip-api 的城市数据与 DB-IP 同源（本次城市名一致、坐标中位距离为 0km），因此它相对 DB-IP 的
城市名/坐标一致率是循环印证，不能当作独立准确率。

\* 中国城市级一行是各 Provider 直接与 zxinc 对比；上面的产品级对比走 `auto` 链路，通常最终命中 ipwho.is。
在 zxinc 给出城市的 46 个 IP 中，ip-api 城市名匹配 28.3%，ipinfo 37.0%，ipwho.is 47.8%。

各家的可用率差别很大：ipwho.is 对 620 个 IP 全部返回，ipinfo 146/150，而 ip-api 免费额度只答了
66/150，另有 81 个完全无结果（限流会直接丢弃或超时）；还有 3 个由链路降级到 ipwho.is/ipinfo。
链路把“无结果”当作“换下一个”，因此默认 `auto` 链路仍能拿到数据。

国家级结果足够做统计聚合和粗粒度策略；城市级只能作为线索，不能作为证据。精确地理围栏、风控决策或
安全相关用途，请配合商业库（MaxMind、IPinfo 付费版、IPIP 等）并保留人工复核。

需要预期的边界：

- **Anycast**（8.8.8.8、1.1.1.1、CDN 边缘）没有唯一城市，各家结果天然不一致；看到 ipinfo 的 `anycast: true` 时应把城市视为未知。
- **VPN / 代理 / 移动网络**描述的是出口节点或运营商网关，不是真人位置。
- **中国**城市级精度明显低于北美/欧洲的免费国际 API（实测 47.8% 城市 / 66.2% 省级）；需要中国精度时请用国内库（IPIP、pconline）或 ipinfo token。
- **`X-Forwarded-For` 仅信任来自可信代理的值**（默认仅回环，或用 `trusted_proxies` 显式列出）；直连客户端无法伪造自己的允许列表身份。它仍然只是声明而非认证身份——需要可信来源时看 TCP 对端 `remote_addr`，并保持代理列表足够窄（宽泛 CIDR 会让其中每台主机都能伪造该头）。
- **离线 `connection_type`** 对 AWS/GCP/DigitalOcean/Cloudflare/Oracle/Akamai 官方前缀覆盖 99–100%，随机公网样本上误判 datacenter 约 0.2%；但对表外的小型托管 ASN 召回很低（约 3%），且内置住宅代理表只有 100 个出口，离线代理识别几乎总是 `unknown`。请用数据源引擎保持表更新，或配置 ipinfo token 获取隐私标签与 `hosting`。
- **延迟**：在线查询在回显路径上同步执行。缓存未命中时耗时即为 Provider 的响应时间（本次 ipwho.is 中位 365ms、p90 380ms）；ipwho.is 不可用时链路降级到 ip-api（中位约 1.2s、p90 约 4s，即其超时上限）。命中缓存约 5ms。需要严格延迟上限时请缩短链路。
- **缓存 TTL**（默认 24h）会延迟 IP 重新分配后的变化；`residential_proxy` 也覆盖 ipinfo 报告的 VPN/Tor 出口。

## 构建与发布

发布产物是每平台一个自包含可执行文件。CI 构建控制台，GoReleaser 把它编译进二进制，GitHub Releases
提供压缩包与 `checksums.txt`。

```bash
make frontend            # npm ci + tsc + vite build -> frontend/dist
make build               # 前端 + go build（通过 -ldflags 注入版本/提交/时间）
make test                # go test ./... -race -count=1
make lint                # 如有 Go 文件未 gofmt 则失败
make docker              # 容器镜像
make docker-smoke        # 容器镜像 + 端到端运行（控制台、版本、健康检查）
make snapshot            # 本地交叉编译所有发布目标（goreleaser build --snapshot）
make release-snapshot    # 本地生成 dist/ 压缩包 + 校验和（不发布）
```

发布流程（完整清单见 [RELEASING.md](RELEASING.md)）：

1. `git tag v1.0.0 && git push origin v1.0.0` —— 发布**完整产品**。
2. `git tag 1.0.0 && git push origin 1.0.0` —— 发布**极速版**，作为独立 release 单独
   打 tag、单独出产物（`echo-server-lite_*`），两者永不混淆。
3. `.github/workflows/release.yml` 运行测试、对构建出的二进制做实时冒烟测试（`/ip`、`/echo`、控制台
   页面与 `/api/login`），然后跑 GoReleaser；其 `before` 钩子构建 `frontend/dist`。
4. `.github/workflows/release-lite.yml` 构建极速二进制，以 `ECHO_SERVER_LITE=1` 启动后断言 `/ip` 可用、
   `/ui` 与 `/api` 返回 404、且不产生数据库文件，再用 `.goreleaser-lite.yaml` 运行 GoReleaser。
5. 产物：linux/darwin/windows × amd64/arm64 的 `echo-server_<version>_<os>_<arch>.tar.gz`（Windows
   为 zip）、`checksums.txt`、自动生成的 changelog，以及 GitHub Release。
6. 版本、提交与构建时间通过 `-X main.serverVersion/buildCommit/buildDate` 注入，展示在 `/ui/system`
   与 `GET /api/system`。源码构建报告 `version: dev`；发布二进制始终携带 tag。

`.github/workflows/ci.yml` 在每次 push 到 `main`、每个 PR 以及手动触发时运行：构建前端、检查
`gofmt`、执行 `go vet ./...` 与 `go test ./... -race -count=1`，然后构建单一二进制，在干净目录中冒烟
测试内嵌 UI + 注入版本，并构建 Docker 镜像。

## 测试

```bash
go test ./...            # 离线确定性；在线 Provider 测试在无网络时跳过
go test ./... -short     # 跳过所有网络测试
```

## 贡献

欢迎贡献——构建/测试流程与提交约定见 [CONTRIBUTING.md](CONTRIBUTING.md)。安全问题必须通过
[SECURITY.md](SECURITY.md) 中的私密公告链接报告，不要开公开 issue。

## 许可证

[MIT](LICENSE) © 2026 crawler-requests
