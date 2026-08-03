# ReachRun Architecture Overview

> Authority：当前已实现 module、跨 module seam、Phase 0 证据契约与依赖方向
>
> Read when：修改 module interface、探测证据、平台 adapter、CLI 组合方式或跨模块测试
>
> Update when：新增真实 module/seam，或现有依赖方向、证据契约与能力边界变化

## 1. 当前实现范围

仓库目前实现了 Phase 0 的前十条垂直切片：

1. 通过操作系统普通 hostname 路径取得 **System Resolution**；
2. 分别取得 **Resolver Inventory**，以及对明确 resolver 发起 UDP、TCP 或 DoH **DNS Observation**；
3. 对 HTTPS/SVCB RR 形成类型化 DNS evidence，并以同一 resolver/transport 编排有界 **DNS HTTPS Path**，验证 AliasMode 重启、ServiceMode 兼容性与最终 A/AAAA 目标；
4. 对一个明确候选公网 IP 发起第一跳 HTTP/HTTPS **Web Observation**，同时保留正确的 Host、TLS SNI 与证书身份；
5. 对一个明确候选公网 IP 与 SSH 端口发起受限 **SSH Observation**，区分 TCP 未建立、端口可达但未确认 SSH，以及收到合法 SSH identification；
6. 对没有主要网站域名的服务器公网 IP 发起固定 `443` 的 **TLS Observation**，不发送 SNI、不执行身份验证，并区分 TCP 未建立、TLS 已完成和 TCP 可达但 TLS 未确认；
7. 从 hostname 出发，以系统解析、公网候选、HTTPS 优先、受限 HTTP fallback 与安全重定向编排一次 **Public Web Path**，同时保留每一跳的原始解析与 Web 证据；
8. 对同一 hostname 的本地与参考候选集合执行同地址族 **Web Candidate Recheck**，固定第一跳 HTTPS 条件并确保每个候选使用全新连接，只保留可比较证据而不产生 DNS 归因；
9. 在不发送网络载荷的前提下，通过内核 UDP route selection 分别取得 IPv4/IPv6 **Address Family Conditions**，区分已选路与明确的本机检测条件不可用；
10. 对有界公网 IP 集合执行并发受限的 **TLS Retry Batch**，只重试明确的暂态 TCP/TLS 结果，保留每次 TLS Observation，并验证 batch deadline 与取消传播。

临时 CLI 为每次调用输出一份版本化 JSON **探测证据或路径报告**。它们用于验证跨平台网络能力，不是 V1 浏览器应用，也不包含资产、批次、判断或持久化模型。

产品范围以 [`PRD.md`](../product/PRD.md) 为准，跨平台 Go 方案及理由以 [ADR 0001](../decisions/0001-cross-platform-go-local-web-architecture.md) 为准。本文件只描述已经存在的实现。

## 2. Module 与依赖方向

```text
cmd/reachrun
    ├── internal/platform/systemresolver
    ├── internal/platform/resolverinventory
    ├── internal/platform/familycondition
    │        └── Go net + golang.org/x/sys/windows
    ├── internal/dnsobservation
    │        └── golang.org/x/net/dns/dnsmessage
    ├── internal/dnshttpspath
    │        └── internal/dnsobservation
    ├── internal/webobservation
    │        └── Go net/http + crypto/tls
    ├── internal/webpath
    │        ├── internal/platform/systemresolver
    │        └── internal/webobservation
    ├── internal/webrecheck
    │        └── internal/webobservation
    ├── internal/sshobservation
    │        └── Go net
    ├── internal/tlsobservation
    │        └── Go net + crypto/tls
    └── internal/tlsretrybatch
             └── internal/tlsobservation

Public Web Path、Web Candidate Recheck、Web、SSH 与 TLS Observation
    └── internal/nettarget
            提供共享 Web hostname、request-target 与唯一公网字面量 IP 安全策略

七个 probe module
    └── internal/probe
            提供 Phase 0 共用 envelope 生命周期与不变量

Windows resolver inventory
    └── golang.org/x/sys/windows
```

| 路径 | 当前职责 |
|---|---|
| `cmd/reachrun` | Phase 0 临时 CLI；组合 timeout、命名 resolver、安全选择、JSON 与 exit-code 边界，不产生产品判断 |
| `internal/probe` | 版本为 1 的类型化 evidence envelope、probe kind、来源能力与 terminal outcome |
| `internal/platform/systemresolver` | 系统解析的一次尝试、地址规范化、错误归类、backend 能力说明与结果校验 |
| `internal/platform/resolverinventory` | 当前 resolver 配置的 best-effort 快照及平台能力说明 |
| `internal/platform/familycondition` | 以固定双栈策略观察本机内核能否选择公网 route 与 source address；UDP connect 后不写入载荷，明确不可用作为中性 evidence |
| `internal/dnsobservation` | 向不可变配置中的明确 resolver 发起一次 UDP、TCP 或 RFC 8484 DoH 查询，并解析类型化 DNS 响应 |
| `internal/dnshttpspath` | 使用同一 DNS Observer 编排 HTTPS AliasMode、ServiceMode 兼容性及最终 A/AAAA 观测；输出保留 partial evidence 的独立路径报告，不改变原域名身份 |
| `internal/webobservation` | 将 hostname 身份与拨号 IP 分开，对一个候选公网 IP 发起一次 HTTP/HTTPS 观测，并保留 TCP、TLS 与 HTTP 层证据；CLI 固定根路径，Web Path 可传入服务器派生的安全 path/query |
| `internal/webpath` | 从一个 hostname 编排系统解析、受限公网候选、HTTPS-first/HTTP fallback 与安全重定向；输出保留 partial evidence 的独立路径报告，不产生健康或因果判断 |
| `internal/webrecheck` | 对 caller 已分组的本地/参考公网候选执行同地址族、固定 HTTPS 第一跳的有界复核；交替保留完整 Web Observation，不证明候选来源且不产生 DNS 归因 |
| `internal/sshobservation` | 对一个候选公网 IP 与单个 SSH 端口执行 TCP 建连和受限 identification 交换，不进入密钥交换或认证 |
| `internal/tlsobservation` | 对没有 hostname 的一个候选公网 IP 固定执行 `443` TCP/TLS 观测；不发送 SNI、不验证证书身份、不发送 HTTP，并把握手完成或未确认保留为 TCP 建立后的 evidence |
| `internal/tlsretrybatch` | 对 caller 明确提供的公网 IP 集合执行固定并发、attempt、抖动、总 deadline 与取消策略；保留每次 TLS Observation，不产生资产判断 |
| `internal/nettarget` | 规范化 Web DNS hostname、受限 origin-form request-target 与单个公网字面量 IP，并集中拒绝 loopback、私网、链路本地、组播、文档/benchmark 保留等产品禁止地址 |
| 各 `*test` 子包 | 给调用方测试使用的有限队列 adapter；精确返回 fixture、记录调用，队列耗尽时 panic |

`internal/probe` 的泛型只统一 Phase 0 探测的公共头部；每种 probe 仍定义具体 `Input`、`Evidence` 和允许的失败类别，不得退化成 `map[string]any`、`json.RawMessage` 或无类型的万能事件。该 envelope 也不自动成为未来本地 HTTP event 或持久化 schema。

## 3. Probe evidence envelope v1

公共字段固定为：

- `schema_version`：当前只接受整数 `1`；
- `probe`：产生证据的具体 probe；
- `observed_at` 与 `duration_ms`：UTC 完成时间和非负耗时；
- `platform`：当前二进制的 `GOOS/GOARCH`；
- `source`：实际 backend、`native/degraded` 能力及降级原因；
- 类型化 `input`、terminal `outcome`，以及互斥的 `evidence` 或 `failure`。

公共 terminal invariant：

- `succeeded` 必须有 evidence，不能有 failure；
- `failed` 必须有非空、非 `cancelled` failure，不能有 evidence；
- `cancelled` 必须带 `cancelled` failure，不能有 evidence；
- `native` backend 不能带降级原因；`degraded` 必须解释原因；
- 原始 `failure.detail` 只用于 Spike 诊断，后续判断、黄金测试和用户结论只能依赖稳定类别与结构化证据。

失败码的 allowlist 由具体 probe module 自己校验。公共 envelope 不登记 DNS、SSH、Web 等所有未来错误，以免协议语义扩散到公共 module。

## 4. System Resolver seam

调用方只依赖一个方法：

```go
type Resolver interface {
    Resolve(ctx context.Context, hostname string) Result
}
```

一次调用代表一次系统查询，adapter 内不重试。名称未解析、超时和取消都是要保留的观测，因此返回 terminal `Result`，而不是让普通网络失败作为 Go `error` 终止更高层流程。

生产 adapter 使用 `net.DefaultResolver.LookupNetIP(ctx, "ip", hostname)`：

- 接受规范化 hostname；IP literal、scheme、port、path 与内嵌空白属于 `invalid_input`；
- 保留系统首次返回顺序；
- 去重并把 IPv4-mapped IPv6 规范化为 IPv4；
- 允许记录 private、loopback 与 link-local 地址，后续是否允许连接由目标安全策略决定；
- 不添加系统 interface 没有提供的 TTL、RCODE、回答服务器、CNAME 链或原始 DNS 报文；
- native 调用在 context 结束后迟到返回成功时丢弃地址。

System Resolution 允许 `invalid_input`、`name_unresolved`、`timeout`、`resolution_failure` 与 `cancelled` 五类失败。`name_unresolved` 不冒充分辨 NXDOMAIN 和 NODATA。

Go 不为每次 `LookupNetIP` 公开所选 backend。ReachRun 只在构建条件和 `GODEBUG=netdns` 能证明时标记 `native`，其余情况显式降级：

| 环境 | 报告行为 |
|---|---|
| macOS、Windows 的普通 `!netgo` 构建 | 对应系统 resolver，`native` |
| Linux `cgo + netcgo + !netgo` 构建 | libc/NSS，`native` |
| Linux 有 cgo 但未固定选择 | `linux-resolver-selection-unverified`，`degraded` |
| `netgo`、Linux 无 cgo 或 `GODEBUG=netdns=go` | Go DNS resolver，`degraded` |
| native backend 可用且 `GODEBUG=netdns=cgo` | 已强制 native backend，`native` |
| 带 bisect 条件的 `GODEBUG=netdns=...#...` | 调用前无法证明 backend，`degraded` |

来源 profile 在 `systemresolver.New()` 时锁定。进程不得在运行期间修改 `GODEBUG` 来改变同一批证据语义。Linux CI 用 `netcgo` 和原生 runner 执行 contract test；默认 Linux 本地构建即使实际碰巧走 libc，也不会在无法证明时声称 `native`。

## 5. Resolver Inventory seam

调用方只依赖：

```go
type Observer interface {
    Observe(ctx context.Context) Result
}
```

成功 evidence 由有序 resolver group 组成。每组保存取得到的服务器 IP/53 端口、IPv6 zone、interface 名称/索引、search domain、match domain 和 global/scoped 语义。它们只是配置候选及关联信息，不证明某次 System Resolution 实际由哪个服务器回答，也不证明某个 split-DNS 名称应选择哪一组。

平台 adapter：

| 平台 | backend | 能力语义 |
|---|---|---|
| macOS | 固定执行 `/usr/sbin/scutil --dns`，不经过 shell | `native`；解析 global/scoped resolver blocks |
| Windows | IP Helper `GetAdaptersAddresses` | `native`；只保留 up adapter 的 DNS server、interface 与 suffix |
| Linux | `/etc/resolv.conf` | 始终 `degraded`；不声称看到了 systemd-resolved upstream、per-link 或 split-DNS 完整配置 |
| 其他平台 | unsupported adapter | `degraded` failure |

Linux 若只看到 loopback/link-local stub，会用 `local_stub_hides_upstream_resolvers` 说明 upstream 不可见。其他 `resolv.conf` 结果使用 `resolv_conf_does_not_expose_per_link_resolvers`。成功 evidence 不能为空；配置无法取得或无法形成合法 typed evidence 时分别使用 `resolver_inventory_unavailable`、`resolver_inventory_invalid`。

## 6. DNS Observation seam

调用方只依赖：

```go
type Observer interface {
    Observe(ctx context.Context, request Request) Result
}
```

`New(Config)` 先复制并锁定一组命名 endpoint。`Request` 只能通过 `ResolverID` 选择其中一项，不能携带任意 IP、URL、端口、HTTP header 或 path。一个调用只查询一个 hostname、一个 `A/AAAA/CNAME/SVCB/HTTPS` 类型、一个 resolver 和一个明确 transport。

implementation 隐藏：

- UDP query/response；
- TCP 两字节长度 framing 与完整读取；
- RFC 8484 DoH `POST application/dns-message`；
- DNS ID、QR/opcode/question 校验；
- CNAME 链、A/AAAA/CNAME/SVCB/HTTPS、negative SOA、authority NS、RCODE、flags、TTL、响应大小与实际 endpoint 规范化；
- HTTPS/SVCB 的 AliasMode/ServiceMode、priority、TargetName，以及按 numeric key 排序并以 lowercase hex 保留的全部 SvcParam wire value；
- context timeout、主动关闭连接和迟到成功隔离；
- 最大 65,535 字节 DNS 响应与最多 128 条记录的资源限制。

一次 UDP 调用不会隐藏地切换 TCP。UDP `TC=1` 仍是 `succeeded/incomplete` evidence；后续诊断编排决定是否向同一 resolver 追加独立 TCP observation。

DNS 协议响应与 probe 执行结果必须分开：

- `NOERROR` 正回答、NODATA、NXDOMAIN、referral、SERVFAIL、REFUSED 等合法响应都是 `outcome=succeeded`；
- `answer_kind` 进一步区分 `answer`、`no_data`、`name_error`、`referral`、`rcode_error` 与 `incomplete`；
- 只有输入、transport、非法报文或 DoH HTTP 规则失败才产生 failure；允许 `invalid_input`、`timeout`、`cancelled`、`dns_transport_failure`、`dns_protocol_failure`、`doh_rule_failure`。

DoH 使用固定 HTTPS endpoint 和 bootstrap IP，保留正确 TLS hostname，不经环境代理、不跟随重定向、不携带 Cookie 或认证信息。CLI 当前内置 Cloudflare 和 Google 两组 Phase 0 reference endpoint；PRD §24 中 V1 最终参考 resolver 组合仍未关闭。

`golang.org/x/net/dns/dnsmessage` 只存在于 module implementation，不泄漏到 interface。当前固定版本负责 HTTPS/SVCB wire codec；ReachRun 自己的 evidence contract 不暴露该依赖的类型，未知 SvcParam 仍由 numeric key、稳定名称与原始 value 表达。

## 7. DNS HTTPS Path seam

调用方只依赖：

```go
type Observer interface {
    Observe(ctx context.Context, request Request) Result
}
```

`Request` 接受一个 DNS hostname、一个已配置 `ResolverID` 和一个明确 transport。生产 `New(Config)` 创建一份不可变 DNS Observer，整条路径只能复用该实例；调用方不能为后续 AliasMode 注入另一 resolver、endpoint 或 query type。路径总时限默认 30 秒，CLI 中每次底层 DNS Observation 仍使用 5 秒上限；最终最多观察 8 个按 priority 排序并去重的 ServiceMode hostname，报告明确记录其余数量。

编排固定从原 hostname 的 `HTTPS` RR 开始。每次响应先按普通 CNAME evidence 得到 `effective_name`；若存在 AliasMode，则按 wire order 选择第一条并对其 TargetName 再查询 `HTTPS`，最多实际跟随三层并检测对已查询名称或 CNAME effective name 的循环。AliasMode TargetName 为 `.` 时记录 `service_unavailable`；到达第四条可跟随 AliasMode 时以 `alias_limit` 有界停止。通用 `SVCB` 仍可由单次 `dns-observe` 查询，但不会混入 HTTPS 路径，因为 [RFC 9460](https://www.rfc-editor.org/rfc/rfc9460.html) 要求 AliasMode 后续保持同一 RR type。

AliasMode 结束后：

- 有可用 ServiceMode 时按 priority 升序、相同 hostname 去重，对每个 TargetName 查询独立 A 与 AAAA；ServiceMode TargetName `.` 使用该记录 owner name；
- 最终没有 HTTPS RR 时，按 RFC 9460 的 optional-client fallback 对最终 effective name 查询 A 与 AAAA，并区分原名 fallback 与 AliasMode target fallback；
- `ipv4hint`/`ipv6hint` 只保留为原始 DNS evidence，永不替代 A/AAAA，也不作为唯一连接真值；
- AliasMode 只改变地址候选的解析目标；报告 input 中的原 hostname 仍是未来 URL、HTTP Host、TLS SNI 与证书身份。

当前兼容性只接受可由已实现 Web backend 安全使用的 ServiceMode：默认 HTTPS 或显式 `443`，以及在 `no-default-alpn` 出现时明确包含 `http/1.1`。`mandatory` 指向未知/未支持 key、非默认 port、只允许其他 ALPN，或已识别参数 wire value 自相矛盾时，该 RR 标记为不支持或 malformed。若 RRset 仍有其他可用 ServiceMode，只查询可用 target；若全部不可用，路径以 `completed/unsupported_service_mode` 保存事实，后续 assessment 才映射为“无法判断”，不会伪造网络失败。未知非 mandatory 参数按 RFC 边界保留但忽略。

路径报告使用独立 `schema_version=1` 与 `operation=dns_https_path`。`completed` 进一步区分 `service_mode`、`alias_fallback`、`origin_fallback`、`service_unavailable` 和 `unsupported_service_mode`；`stopped/cancelled` 保留已经验证的完整 DNS Observation 与稳定 stop reason。路径报告不是 probe envelope，也不产生 Web 可达性、DNS 污染或跨境阻断判断。

## 8. Web Observation seam

调用方只依赖：

```go
type Observer interface {
    Observe(ctx context.Context, request Request) Result
}
```

一次调用只接受一个 `http` 或 `https` scheme、一个至少包含一个点的规范化 ASCII DNS hostname，以及一个明确候选公网 IP。port 由 scheme 固定为 `80/443`，method 固定为 `GET`；path/query 默认为 `/`，也可由内部 Web Path 从已校验的重定向 URL 派生，不能由 CLI 传入任意目标。IPv4 与 IPv6 候选始终分开调用和记录，module 不做地址族汇总或产品判断。

implementation 在连接前拒绝 loopback、私网、链路本地、组播、未指定、文档保留等非公网地址，随后只拨已校验的字面量 IP；URL hostname、HTTP Host、TLS SNI 和证书 hostname 验证使用同一 hostname。这使 DNS 返回的候选与实际 TCP 连接对象可以明确分开，也避免连接前再次解析导致 DNS rebinding。

每次观测使用新连接，禁用环境代理、Cookie、连接复用、隐藏重试和自动重定向。端口、method、request-target、header、响应头大小、响应体读取量与 timeout 都受固定约束，不向 CLI 调用方暴露任意网络能力；request-target 必须是最长 4 KiB 的 origin-form path/query，不能包含 fragment。当前 Phase 0 backend 只协商 HTTP/1.1，收到合法响应头后不读取响应体；h2-only 服务尚不在本切片的能力范围内，相关失败不得直接提升为资产结论。

每份 terminal envelope 在 input 中保留候选 IP 与地址族；成功 evidence 记录实际远端、分阶段耗时、HTTPS 的 TLS/证书事实以及 HTTP 状态。任意合法 HTTP 状态都证明服务已经响应；`4xx/5xx` 也是 `outcome=succeeded` 的 HTTP evidence，后续 assessment 才决定是否需关注。可选的 `Location` 或 `Retry-After` 超过证据上限或不是合法 UTF-8 时，保留这份成功与状态码，并通过对应 `*_omitted` 标志区分“响应没有该 header”和“header 因证据约束被省略”。TCP、TLS/证书和 HTTP 失败由 module 自己的 typed failure allowlist 保留终止阶段，平台原始错误文本不驱动产品判断。

公共 envelope v1 仍保持 evidence/failure 互斥，因此失败结果暂不携带失败前已完成阶段的 partial timing。当前使用稳定 failure code 保留失败层级，候选 IP 已在 input 中，总耗时由 envelope 记录；不使用 `failure.detail` 偷渡结构化判断。

## 9. Public Web Path seam

调用方只依赖：

```go
type Observer interface {
    Observe(ctx context.Context, request Request) Result
}
```

`Request` 只有一个 Web DNS hostname。module 内部拥有系统解析、候选选择、scheme fallback、重定向与资源上限，调用方不能注入 resolver、任意端口、header、凭据或连接 IP。生产 `New(Config)` 隐藏 `systemresolver` 与 `webobservation` adapter；scripted adapter 只用于确定性 contract test。

一次路径总时限默认 15 秒，每次解析或 Web Observation 最多 5 秒。每一跳保留系统返回顺序，每个地址族最多选择两个符合唯一公网策略的候选并串行尝试，在第一个合法 HTTP 响应处停止该跳。这个顺序是 Phase 0 可解释、可复现的有界策略，不等同于浏览器的 Happy Eyeballs，也不产生 IPv4/IPv6 可用性 assessment。

路径固定从 `https://<hostname>/` 开始。只有初始 HTTPS 的全部候选都在取得合法响应头之前失败，才重新执行 System Resolution 并尝试 `http://<hostname>/`；HTTPS 一旦收到任意 HTTP 状态，就不降级。HTTP fallback 不跨 redirect 链触发。

`301/302/303/307/308` 最多跟随三次。相对与绝对 `Location` 都先规范化，fragment 被移除；只允许 HTTP(S)、无 credentials、默认端口和规范化 ASCII DNS hostname，IP literal 与非默认端口均拒绝。每个 redirect hostname 必须重新执行 System Resolution、公网候选过滤与 direct-dial，避免 DNS rebinding 或 redirect 将工具变成内网访问入口。redirect target 失败时，先前成功响应及后续 partial evidence 都保留。

路径报告拥有独立的 `schema_version=1` 与 `operation=web_path`，不是把不同探测强塞进公共 probe envelope。每个 hop 嵌入一份完整 System Resolution 和零到多份 Web Observation；terminal `status` 为 `completed/stopped/cancelled`，稳定 `stop_reason` 只说明编排为何结束，不是资产健康、DNS 异常或跨境阻断判断。

## 10. Web Candidate Recheck seam

调用方只依赖：

```go
type Observer interface {
    Observe(ctx context.Context, request Request) Result
}
```

`Request` 只接受一个 Web DNS hostname、一个本地候选集合和一个参考候选集合。module 对候选做公网地址规范化与去重，要求两侧所有候选属于同一地址族；IPv4 与 IPv6 必须由调用方分别发起复核。每侧按输入顺序最多观察两个候选，超出数量记录为 `*_candidates_omitted`。调度按 `local[0] → reference[0] → local[1] → reference[1]` 交替推进，即使前一候选已取得合法 HTTP 响应也继续完成其余有界候选，避免用第一个结果代表整个来源集合。

所有尝试固定为 `https://<hostname>/`、`GET`、端口 `443`、零普通重试和零自动重定向。除了 `dial_ip` 外，scheme、URL hostname、HTTP Host、TLS SNI、证书 hostname 验证、method、path、port、地址族、timeout 上限、平台与 Web adapter 必须一致。底层 Web Observation 每次创建新的禁代理、禁连接复用 transport；因此不会把 Public Web Path 或其他快速体检的旧连接冒充成控制尝试。单次尝试最多 5 秒，聚合默认总时限 25 秒。

报告使用独立 `schema_version=1` 与 `operation=web_candidate_recheck`。`completed` 只表示每侧受控上限内的候选均得到 terminal Web Observation；两侧全失败、只有一侧成功或存在被省略候选都仍是完整的有界证据。`stopped/cancelled` 保留停止前已验证的 attempt。caller 对候选标注为 `local/reference` 不证明其 DNS 来源；未来 `checkrun` 仍须嵌入系统解析和两个独立参考解析证据、处理 CDN/GeoDNS 合法差异，`assessment` 才能按 PRD §13.7 判断是否满足“高可信本地解析路径异常”的完整因果链。

## 11. SSH Observation seam

调用方只依赖：

```go
type Observer interface {
    Observe(ctx context.Context, request Request) Result
}
```

`Request` 只有一个公网字面量 IP 和一个端口；端口为零时使用 `22`。IPv4 与 IPv6 分开调用，module 不重试、不扫描端口，也不产生资产或跨境阻断判断。Web 与 SSH 在连接前共同调用 `internal/nettarget` 的唯一公网地址策略，随后只用 `tcp4` 或 `tcp6` 拨已校验的字面量地址。

TCP 建立后，implementation 发送固定的 `SSH-2.0-ReachRun_Phase0` 客户端 identification，接受最多 16 条、合计最多 4 KiB 的服务端前置行，再读取最多 255 字节的 `SSH-` identification。只有 CRLF 结尾的 `2.0`，以及兼容用的 `1.99`（允许仅 LF 结尾）会被识别为 `received`；software version 与 comments 只接受协议允许的可打印 ASCII。收到合法行后立即关闭连接；单字节有界读取不会消费后续 key-exchange packet，也不会读取、上传或使用 SSH 密钥。这个交换遵循 [RFC 4253 §4.2](https://www.rfc-editor.org/rfc/rfc4253#section-4.2) 的版本交换形状，同时用固定资源上限约束恶意或错误端点。

证据按两层表达：

- TCP 未建立时产生 `tcp_connection_refused`、`tcp_no_route`、`tcp_timeout`、`tcp_connection_reset` 或 `tcp_failure`；由于没有进入后续阶段，此时 envelope 的 `duration_ms` 就是该次有界 TCP 建连尝试耗时；
- TCP 已建立后始终形成 evidence。合法 identification 为 `received`；非法 identification、等待超时、连接关闭/重置、前置行超限或其他交换错误为 `unconfirmed`，并保留稳定 `unconfirmed_reason`。

因此 `outcome=succeeded` 只表示探测成功取得了可用事实，不等于 SSH 登录成功。`received` 只确认 SSH 协议端点响应；`unconfirmed` 只确认端口可达但未确认 SSH。用户取消仍覆盖任何迟到成功并返回 `cancelled`。

## 12. TLS Observation seam

调用方只依赖：

```go
type Observer interface {
    Observe(ctx context.Context, request Request) Result
}
```

`Request` 只有一个公网字面量 IP。module 固定连接 `443`，不接受 hostname、port、HTTP path、TLS 选项或任意重试配置；IPv4 与 IPv6 分开调用，并复用 `internal/nettarget` 的唯一公网地址策略后直接使用 `tcp4` 或 `tcp6` 拨已校验的字面量地址。

TLS client 固定不发送 SNI，不执行公有信任链、有效期或 hostname 身份验证，也不发送 HTTP。每份 normalized input 都显式记录 `sni_mode=omitted_no_hostname` 与 `identity_verification=not_performed_no_hostname`，因此握手完成不会被误读为网站身份成立。完成 evidence 只保存 TLS version、cipher suite、ALPN、peer certificate 数量，以及未验证 leaf certificate 的 SHA-256 指纹和有效期字段；证书 subject/SAN 不进入当前有界契约。

证据按两层表达：

- TCP 未建立时产生 `tcp_connection_refused`、`tcp_no_route`、`tcp_timeout`、`tcp_connection_reset` 或 `tcp_failure`；
- TCP 已建立后始终形成 evidence。TLS handshake 完成为 `completed`；超时、关闭、重置、其他握手错误或本地交换失败为 `unconfirmed`，并保留稳定 `unconfirmed_reason`。该 reason 只描述实际交换，不声称缺少 SNI 就是失败原因。

因此 `outcome=succeeded` 只表示已取得可用的 TCP/TLS 分层事实。`completed` 证明对端在无 SNI 条件下完成 TLS，但不证明证书可信、有效或属于某个 hostname；`unconfirmed` 证明端口可达但在缺少 hostname 上下文的有限尝试中没有确认 TLS。后续 assessment 才能按 PRD §11.4 映射“身份未验证”或“可能需要域名/SNI”。用户取消仍覆盖任何迟到成功并返回 `cancelled`。

## 13. Address Family Conditions seam

调用方只依赖：

```go
type Observer interface {
    Observe(ctx context.Context) Result
}
```

`Input` 为空；调用方不能选择 target、port、network、地址族顺序或发送行为。module 固定按 IPv4、IPv6 顺序对 `1.1.1.1:53` 与 `[2606:4700:4700::1111]:53` 执行 `udp4/udp6` connect，让内核选择 route 与 source address，但从不调用 `Write`。因此 evidence 中固定记录 `payload_bytes_sent=0`；该操作不证明载荷已送达、公网端点响应或整条 Internet 路径可用。

成功 evidence 恰好包含两条 condition：

- 内核选出 route 与非未指定 source address 时为 `route_selected/kernel_route_selected`，IPv6 zone 与规范化地址分开保存；
- `no_route`、`address_family_unsupported`、`source_address_unavailable` 或 `network_down` 是成功采集到的 `unavailable` 本地条件，不是目标故障，整个 envelope 仍为 `outcome=succeeded`；
- timeout、取消与无法稳定归类的 route-selection 错误不伪装成“本机没有 IPv6 条件”，分别进入 `timeout`、`cancelled` 或 `route_check_failure`。

这个 seam 只回答“当前本机是否具备对该地址族继续检测的内核选路条件”。它与 Web、SSH、TLS 等目标 probe 保持独立，不把某个目标的 `no_route` 自动提升为资产异常，也不生成 IPv4/IPv6 assessment。Unix 与 Windows adapter 将各自稳定的 OS error 映射为相同 reason；原始错误文本只保留在失败 detail 中。

## 14. TLS Retry Batch seam

调用方只依赖：

```go
type Observer interface {
    Observe(ctx context.Context, request Request) Result
}
```

`Request` 只包含公网字面量 IP 列表。module 先使用 `internal/nettarget` 的唯一公网策略规范化、去重，最多接受 16 个唯一地址，并只调度前 4 个；其余数量通过 `targets_omitted` 明示。每个目标仍固定为 hostname-free `443` TLS Observation，不接受 hostname、port、SNI、证书开关、任意 backoff 或并发参数。

调度策略固定为并发上限 2、每目标最多 3 次 attempt（首次 + 2 次重试）、每次 attempt 上限 5 秒、重试前 100–300ms 抖动，以及 30 秒默认 batch deadline。每次 attempt 都由底层 TLS Observer 新建连接并完整嵌入原 envelope；aggregate 不把多次结果折叠成一个伪造 probe。

只有以下明确暂态结果会进入下一次 attempt：

- TCP connect timeout 或 reset；
- TCP 已建立后，TLS handshake timeout 或 connection reset。

TLS handshake 完成、连接拒绝、no-route、取消、普通 handshake failure 和无法稳定归类的错误都不机械重试。达到非重试结果或三次上限时，目标记为 `completed`；这里只表示固定重试序列已经收敛，不表示 TLS 成功。整个有界 schedule 完成时 batch 为 `completed`，即使目标最终仍失败，也只是成功取得了完整 retry evidence。

用户取消会同时传播到所有在途 TLS attempt 和 backoff wait；尚未开始的目标保持 `not_started`，已有合法 partial evidence 的目标为 `interrupted`，aggregate 不再产生 `completed` terminal。batch deadline、嵌套证据契约损坏与 scheduler failure 分别保留稳定 stop reason。这个 Phase 0 seam 只证明最小重试/取消机制，不是正式 `checkrun`、资产批次或持久化提交边界。

## 15. CLI 组合与安全选择

当前诊断入口：

```text
reachrun family-conditions
reachrun resolve <hostname>
reachrun resolver-inventory
reachrun dns-observe <udp|tcp|doh> <current|cloudflare|google> <A|AAAA|CNAME|SVCB|HTTPS> <hostname>
reachrun dns-https-path <udp|tcp|doh> <current|cloudflare|google> <hostname>
reachrun web-path <hostname>
reachrun web-recheck <hostname> <local-ip[,local-ip]> <reference-ip[,reference-ip]>
reachrun web-observe <http|https> <hostname> <public-ip>
reachrun ssh-observe <public-ip> [port]
reachrun tls-observe <public-ip>
reachrun tls-retry-batch <public-ip[,public-ip]>
```

每个合法命令只向 stdout 输出一份 terminal evidence document。probe envelope 成功或任一路径/批次报告 `completed` 退出 `0`，probe failure 或路径/批次 `stopped` 退出 `1`，用法错误退出 `2`，取消退出 `130`。Address Family Conditions 的明确本机不可用、NXDOMAIN、NODATA 或 SERVFAIL 等合法 DNS 响应、`unsupported_service_mode` 已完成兼容性观测、任意 `4xx/5xx` 已收到合法 HTTP 响应、SSH 端口可达但 identification 未确认、TLS 的 TCP 已连接但 handshake 未确认，以及 TLS Retry Batch 中所有目标按固定策略完成但仍失败，都是成功取得的 evidence，因此都退出 `0`。

`family-conditions` 不接受参数，执行第 13 节的固定双栈本机条件观察。它不发送 UDP payload；`unavailable/no_route` 只表示当前内核没有为该固定公网文字地址选出 route，不等于任意 IPv6 目标或资产异常。

`current` 只允许 UDP/TCP。CLI 先取得一次 inventory，再按观察顺序选择第一个可拨号的 53 端口 server；会跳过其他端口、缺少 zone 的 IPv6 link-local、multicast 与 limited broadcast，IPv6 link-local 使用 evidence 中的 zone/interface。这个入口只验证“向该明确候选查询会发生什么”，不声称自动实现平台的 split-DNS 路由。私网 resolver 只能以这条 inventory 派生路径进入 DNS observer。

`cloudflare` 与 `google` 映射到代码内固定的公网 DNS/DoH endpoint；CLI 不接受用户拼接的 resolver IP 或 URL。CI 只对 Address Family Conditions、System Resolution 与 Resolver Inventory 做不依赖公共服务的真实 runner smoke；UDP/TCP/DoH contract 使用本地受控服务器测试。

`dns-https-path` 复用相同 provider 选择，只允许用户提供 hostname，不暴露 alias limit、后续 query type、ServiceMode target、hint 或参数兼容性开关。它执行第 7 节的同 resolver/transport 路径；`completed` 只表示编排取得了完整 protocol evidence，不代表网站可达。

`web-observe` 不解析 hostname，也不会从 HTTPS 自动 fallback 到 HTTP；它只用 hostname 建立 Host/SNI/证书身份，并连接命令中的单个公网 IP。这是 Phase 0 诊断入口，不会将单次超时解释为跨境阻断，也不实现完整公开网站路径、候选对照或重定向编排。

`web-path` 使用系统解析执行第 9 节定义的默认公开网站路径。CLI 不暴露 scheme、IP、port、path、redirect 或 fallback 开关；用户只提供要观察的 hostname。`stopped` 报告仍保留到停止点为止的合法证据，退出 `1` 只表示路径没有到达 terminal HTTP response，不等于资产被判定异常。

`web-recheck` 执行第 10 节的候选集合复核。逗号只用于在每侧给出多个公网 IP；CLI 不接受 scheme、port、path、header、代理、重试或重定向开关，也不声称手工标注的 candidate 具有已验证的系统/参考解析来源。`completed` 退出 `0` 只表示受控比较完成，不表示参考侧更正确或本地解析异常。

`ssh-observe` 默认端口为 `22`，允许传入服务器资产所需的一个自定义合法端口。CLI 不接受范围、列表或 hostname，也不会调用系统 `ssh` 命令。合法 identification、TCP 已连接但未确认 SSH，以及 TCP 分层失败都只是一份 Phase 0 探测证据。

`tls-observe` 只接受一个公网 IP，固定连接 `443`，不接受 hostname、port、SNI、证书开关或 HTTP 参数。TLS handshake 完成和 TCP 已连接但 TLS 未确认都退出 `0`，因为它们是不同层级的有效证据；前者不等于身份验证成功，后者也不等于 IP 不可达。

`tls-retry-batch` 用一个逗号分隔参数接受明确公网 IP，执行第 14 节固定策略。它不会因某个目标最终失败而返回 `stopped`；只有 batch deadline、内部 evidence/scheduler 契约失败才退出 `1`，用户取消退出 `130`。该命令会真实连接最多 4 个明确目标，不是默认日常检测入口。

## 16. 当前边界与下一次扩展

尚不存在的能力包括把系统解析和两个独立参考解析自动接入候选复核并排除 CDN/GeoDNS 合法差异、把 Address Family Conditions 与各目标 probe 组合为中性 assessment、跨协议快速/深度队列与正式资产批次、snapshot、本地 HTTP 与 React UI。它们出现时应各自放入足够深的 module 或未来 `checkrun` implementation，不得给现有单次 probe 或四个 aggregate interface 增加无关方法，也不得建立巨型 `Platform` interface。

System Resolution、Resolver Inventory、Address Family Conditions、DNS Observation、Web Observation、SSH Observation 与 TLS Observation 必须继续保持各自的证据契约。DNS HTTPS Path、Web Path、Web Candidate Recheck 和 TLS Retry Batch 只在各自独立 aggregate 中引用完整的底层结果，不把它们合并成一种模糊事件。任何一个单独失败、差异或超时都不能直接产生“DNS 污染”“被墙”或其他因果结论。
