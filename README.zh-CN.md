# echo-server

[English](README.md) | **简体中文**

[![CI](https://github.com/crawler-requests/echo-server/actions/workflows/ci.yml/badge.svg)](https://github.com/crawler-requests/echo-server/actions/workflows/ci.yml)
[![Release](https://github.com/crawler-requests/echo-server/actions/workflows/release.yml/badge.svg)](https://github.com/crawler-requests/echo-server/actions/workflows/release.yml)
[![Go 1.26+](https://img.shields.io/badge/Go-1.26%2B-00ADD8?logo=go&logoColor=white)](https://go.dev/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

用于爬虫调试的 HTTPS 回显服务：回显请求头/请求体、**完整的 TLS ClientHello**（原始字节、SNI、ALPN、
密码套件、扩展、JA3 **以及 JA4 / JA4_r / JA4_o**）、**识别调用方客户端**（curl / python-requests /
Node / Java / Go / OpenSSL / Chrome / ……，并检测 UA 伪装），以及客户端公网 IP 的 **ASN + 高精度地理
位置**（国家/地区/城市/邮编/经纬度）和**连接类型**（`datacenter` / `residential_proxy` / `unknown`）。

ClientHello 捕获按连接隔离且**抗分片**：字节会跨多次 TCP 读取与握手记录累积，直到完整 hello 可用，
因此也能处理大型后量子 hello（约 1.5 KB）以及 hello 被拆成许多小段到达的客户端。

单一 Go 二进制；通过 `//go:embed` 内嵌 React + Ant Design 管理控制台（`/ui/`）；SQLite 存储配置、查询
历史与用户账号（`admin` / `viewer`，PBKDF2-SHA256 密码，JWT 会话）、命名 API Key、审计日志、通知、
Webhook、日志筛选视图、Prometheus 指标与 OpenAPI 文档。

## 运行

```bash
make build                       # 先构建 frontend/dist，再内嵌进 ./echo-server
PORT=8443 ./echo-server          # HTTPS（TLS 指纹）+ 明文 HTTP 控制台 :8080
```

`make build` 会先在 `frontend/` 执行 `npm ci && npm run build`，然后 `go build`。控制台通过
`//go:embed frontend/dist` 嵌入，因此 `./echo-server` 就是**唯一需要部署的文件**——不需要静态目录、
不需要 Node 运行时、也不需要反向代理。手动构建前端？请先执行
`cd frontend && npm ci && npm run build` 再 `go build`，否则二进制里会嵌入旧界面。

管理控制台默认通过 **8080 端口的明文 HTTP** 提供，打开 `http://HOST:8080/ui/` 无需信任自签名证书。
`PORT`（默认 8443）上的 HTTPS 监听器提供同一套 UI/API，**并**捕获明文 HTTP 拿不到的 TLS
ClientHello/JA3/JA4。可用 `HTTP_PORT=8080` 修改明文端口，或 `HTTP_PORT=0` 关闭它、只保留 HTTPS。

### 使用 Docker 运行

```bash
docker build -t echo-server .
docker run -d --name echo-server \
  -p 8080:8080 -p 8443:8443 \
  -v echo-data:/data \
  -e ECHO_SERVER_ADMIN_USERNAME=admin \
  -e ECHO_SERVER_ADMIN_PASSWORD='change-me-please' \
  echo-server
```

镜像基于精简的 Alpine 运行时，内部是同一个自包含二进制（含 CA 根证书与 tzdata）；SQLite 数据库位于
`/data` 卷。若不设置 `ECHO_SERVER_ADMIN_*`，可通过 `/ui/` 的首次初始化向导创建管理员。

## 回显端点 — 请求级控制

所有开关都可选。优先级：**查询参数 > 请求头 > 管理端默认值**。

| 控制项 | 查询参数 | 请求头 | 取值 |
|---|---|---|---|
| 格式 | `format` | `X-Echo-Format` | `json`（默认）/ `text` |
| 字段 | `fields` | `X-Echo-Fields` | 逗号分隔的点路径 |

```bash
# 全量（默认）
curl -k https://HOST:8443/echo

# 只要需要的字段，文本格式——响应最小
curl -k -H 'X-Forwarded-For: 8.8.8.8' \
  'https://HOST:8443/echo?format=text&fields=ip.country,ip.city,ip.latitude,ip.longitude,ip.connection_type'
# ip.city=San Jose
# ip.connection_type=datacenter
# ip.country=United States
# ip.latitude=37.3393939
# ip.longitude=-121.8949553

# 同样的字段，JSON 格式
curl -k 'https://HOST:8443/echo?format=json&fields=client_hello.sni,client_hello.ja3_hash,ip.asn,ip.org'

# 只看客户端判定（谁在调用、UA 是否诚实）
curl -k 'https://HOST:8443/echo?fields=client.name,client.family,client.spoofed,client.confidence'
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
  [数据源引擎](#数据源引擎provider)），内嵌 JA4DB 快照始终是最后的兜底。

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
curl -k -A 'Mozilla/5.0 … Chrome/131.0.0.0 Safari/537.36' https://HOST:8443/echo?fields=client
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
curl -k -H "Authorization: Bearer $JWT" https://HOST:8443/api/datasets
# ……或只取一个数据集（返回对象而非数组）
curl -k -H "Authorization: Bearer $JWT" 'https://HOST:8443/api/datasets?dataset=ja4'

# 给 JA4 数据集添加本地库或目录（每 5 分钟监听变化）
curl -k -X POST -H "Authorization: Bearer $JWT" -H 'Content-Type: application/json' \
  -d '{"name":"my-fp","kind":"file","priority":10,"path":"/data/my-ja4db.json","refresh_min":5}' \
  'https://HOST:8443/api/datasets?dataset=ja4'

# 每 30 分钟拉取私有云库，用请求头认证
curl -k -X POST -H "Authorization: Bearer $JWT" -H 'Content-Type: application/json' \
  -d '{"name":"cloud","kind":"remote","priority":20,"url":"https://cloud.example.com/ja4db.json",
       "headers":{"Authorization":"Bearer CLOUD_TOKEN"},"refresh_min":30}' \
  'https://HOST:8443/api/datasets?dataset=ja4'

# 用任意脚本生成 datacenter CIDR 表（stdout 即数据）
curl -k -X POST -H "Authorization: Bearer $JWT" -H 'Content-Type: application/json' \
  -d '{"name":"nightly","kind":"command","priority":10,"command":"/opt/gen-cidrs.sh","refresh_min":720}' \
  'https://HOST:8443/api/datasets?dataset=datacenter_cidr'

# 立即强制同步（整个数据集的所有 Provider，或 ?provider=NAME —— file Provider 会重新读取）；
# DELETE 删除自定义 Provider
curl -k -X POST -H "Authorization: Bearer $JWT" 'https://HOST:8443/api/datasets/sync?dataset=ja4&provider=my-fp'
curl -k -X DELETE -H "Authorization: Bearer $JWT" 'https://HOST:8443/api/datasets?dataset=ja4&provider=cloud'
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
`is_vpn`、`is_tor`、`is_hosting`）无需映射。其他 API 用 `mapping` 描述（Info 字段 → 点路径，支持数组
下标）：`{"country":"data.location.country_name","latitude":"data.location.lat","asn":"data.asn"}`。
`headers` 携带凭据；与数据集一样，它们在所有 API 响应中都会被掩码（`***`），把掩码原样提交回去会
保留已存的值。每个 Provider 的统计（调用、成功、失败、平均延迟、最后错误、最后成功）通过 API/UI
暴露，便于发现悄悄劣化的上游。

```bash
# 列出链路：配置（凭据已掩码）、顺序与实时统计
curl -k -H "Authorization: Bearer $JWT" https://HOST:8443/api/ipproviders

# 追加付费云 API；优先级更高时会在内置 Provider 之前尝试
curl -k -X POST -H "Authorization: Bearer $JWT" -H 'Content-Type: application/json' \
  -d '{"name":"cloud","kind":"http","enabled":true,"priority":100,
       "url":"https://api.example.com/v1/ip/{ip}",
       "headers":{"Authorization":"Bearer CLOUD_TOKEN"},
       "mapping":{"country":"data.country","city":"data.city","asn":"data.asn",
                  "is_proxy":"data.privacy.proxy","is_hosting":"data.privacy.hosting"}}' \
  https://HOST:8443/api/ipproviders

# 把本地脚本（任意语言）作为链路的另一环
curl -k -X POST -H "Authorization: Bearer $JWT" -H 'Content-Type: application/json' \
  -d '{"name":"local","kind":"command","enabled":true,"priority":-10,
       "command":"/opt/ipintel.sh {ip}","timeout_sec":3}' \
  https://HOST:8443/api/ipproviders

# 不经过结果缓存，直接查询一个 IP
curl -k -X POST -H "Authorization: Bearer $JWT" -H 'Content-Type: application/json' \
  -d '{"ip":"8.8.8.8"}' https://HOST:8443/api/ipproviders/test

# 删除自定义 Provider（内置项可禁用但不可删除）
curl -k -X DELETE -H "Authorization: Bearer $JWT" 'https://HOST:8443/api/ipproviders?name=cloud'
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

### 重新生成 `data/ja4db.json`

内嵌数据库由镜像在 `github.com/Niicolaa/ja4db-export` 的 JA4DB 冻结公共 API 快照生成（该项目在
2026 年 API 关闭前每天重新发布数据）：刷新快照后，可用以下命令重建压缩后的 JSON

```bash
go run ./tools/ja4dbgen -in /path/to/ja4_fingerprint.csv    # 默认输出：data/ja4db.json
```

## ClientHello 指纹

- **JA3** —— 按线上顺序拼接 `version,ciphers,extensions,curves,point_formats`，保留 GREASE，用**真实
  MD5** 哈希（`ja3_hash`）。
- **JA4** —— 遵循 FoxIO 规范：`t` + TLS 版本（2 字符）+ SNI 标志（`d`/`i`）+ 两位密码套件数 + 两位
  扩展数 + ALPN 首/末字符，然后 `_<排序后的非 GREASE 密码套件 12 位十六进制>_<排序后的非 GREASE 扩展
  （去掉 SNI/ALPN）12 位十六进制 + "_" + 签名算法>`。
- **JA4_r / JA4_o** —— 相同布局但使用原始（未哈希）值：排序后（`_r`）与原始线上顺序（`_o`）。

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

控制台是单页应用，带分组、可折叠侧边栏和 `Ctrl/⌘+K` 页面命令面板。每个分区都是独立路由
（`/ui/users`、`/ui/logs`、……），因此链接与刷新都可用；服务端对无扩展名路径回退到 `index.html`，
缺失的资源仍返回 404。

| 页面 | 路由 | 功能 |
|---|---|---|
| 概览 | `/ui/` | 计数器、24h 趋势、最新通知、快捷操作、Provider 健康 |
| 回显设置 | `/ui/echo` | `show_*` 开关、响应字段矩阵、实时 JSON/text 预览、请求级控制与预设 |
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
表示全部允许）、`rate_limit_per_min`（按客户端 IP，仅回显流量，`0` 关闭）、`body_limit_kb`（回显请求
体上限，`0` 关闭）、`cors_origins`、`security_headers`、`maintenance_mode` / `maintenance_message`
（未认证回显请求返回 `503`，控制台/API 仍可用）、`log_retention_days`（每 6 小时后台清理）以及站点
键 `site_name` / `site_description` / `timezone` / `locale` / `density`。IP 规则、限流与维护模式只作
用于回显流量，因此控制台永远不会把运维人员锁在外面。

命名 API Key（`/api/apikeys`）是共享 token 的替代方案：明文 `esk_…` 密钥**只在创建时返回一次**，
仅存储其 SHA-256；每个 Key 有 scope（`viewer`/`admin`）和可选过期时间，`last_used` 异步更新。通过
`X-API-Key` 发送；有效 JWT 始终优先。Key 可禁用或删除，不影响账号。

### 审计、通知与 Webhook

`/api/audit` 记录每个变更类控制台操作（账号、配置、安全、系统、API Key 与 Webhook 变更），包含操作者、
动作、目标、详情、IP 与时间戳；支持按动作前缀和用户名筛选，并可导出 CSV。`user.*`、`security.*`、
`config.*` 和 `system.*` 事件还会创建应用内通知（`/api/notifications`），驱动顶部角标。Webhook
（`/api/webhooks`）对订阅事件向任意 URL POST JSON，使用每个 Webhook 的密钥对请求体计算
`X-Echo-Signature: sha256=<hmac>`（`X-Echo-Event` 携带事件名）；投递异步进行、超时 8 秒，失败会生成
警告通知。测试端点（`POST /api/webhooks/test`）立即发送示例载荷。

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
| `GET /api/logs` | JWT | 筛选历史（`limit/method/country/type/ip/q/days`） |
| `GET /api/audit`、`/api/audit/export.csv` | JWT | 审计日志（`limit/action/username`，CSV 导出） |
| `GET/POST/DELETE /api/notifications` | JWT | 列表/未读数、标记单条/全部已读、清理 |
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
JWT=$(curl -sk -X POST https://HOST:8443/api/setup -H 'Content-Type: application/json' \
  -d '{"username":"owner","password":"a-long-password"}' | jq -r .token)

# ……或已有安装：登录并保存 token
JWT=$(curl -sk -X POST https://HOST:8443/api/login -H 'Content-Type: application/json' \
  -d '{"username":"owner","password":"a-long-password"}' | jq -r .token)

# 创建只读账号，然后轮换自己的密码
curl -k -X POST -H "Authorization: Bearer $JWT" -H 'Content-Type: application/json' \
  -d '{"username":"alice","password":"alice-pass","role":"viewer"}' https://HOST:8443/api/users
curl -k -X POST -H "Authorization: Bearer $JWT" -H 'Content-Type: application/json' \
  -d '{"old_password":"a-long-password","new_password":"a-longer-pass"}' https://HOST:8443/api/me/password

# 禁用账号（其现有 token 立即失效）
curl -k -X POST -H "Authorization: Bearer $JWT" -H 'Content-Type: application/json' \
  -d '{"username":"alice","disabled":true}' https://HOST:8443/api/users
```

## IP 情报

- 默认具备离线能力：约 1 万个内嵌 datacenter 前缀（AWS/GCP/DigitalOcean 官方列表 + 主要托管品牌）
  以及住宅代理样本集——无需网络。
- 在线（可选）：`ipwho.is` → `ip-api.com` → `ipinfo.io`，带缓存（`geo_cache_ttl`，默认 24h）。
- 在管理 UI 设置 **ipinfo token**，可获得街道级坐标和权威的 `proxy/vpn/tor/hosting` 标签。
- 通过*启用在线 IP 情报*完全关闭在线查询；查询失败时地理位置留空，而不是猜测。

## 构建与发布

发布产物是每平台一个自包含可执行文件。CI 构建控制台，GoReleaser 把它编译进二进制，GitHub Releases
提供压缩包与 `checksums.txt`。

```bash
make frontend            # npm ci + tsc + vite build -> frontend/dist
make build               # 前端 + go build（通过 -ldflags 注入版本/提交/时间）
make test                # go test ./... -race -count=1
make lint                # 如有 Go 文件未 gofmt 则失败
make docker              # 容器镜像
make snapshot            # 本地交叉编译所有发布目标（goreleaser build --snapshot）
make release-snapshot    # 本地生成 dist/ 压缩包 + 校验和（不发布）
```

发布流程（完整清单见 [RELEASING.md](RELEASING.md)）：

1. `git tag v1.0.0 && git push origin v1.0.0`
2. `.github/workflows/release.yml` 运行测试与 GoReleaser；其 `before` 钩子构建 `frontend/dist`。
3. 产物：linux/darwin/windows × amd64/arm64 的 `echo-server_<version>_<os>_<arch>.tar.gz`（Windows
   为 zip）、`checksums.txt`、自动生成的 changelog，以及 GitHub Release。
4. 版本、提交与构建时间通过 `-X main.serverVersion/buildCommit/buildDate` 注入，展示在 `/ui/system`
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
