# ReachRun Architecture Overview

> Authority：当前已实现 module、跨 module seam、Phase 0 证据契约与依赖方向
>
> Read when：修改 module interface、探测证据、平台 adapter、CLI 组合方式或跨模块测试
>
> Update when：新增真实 module/seam，或现有依赖方向、证据契约与能力边界变化

## 1. 当前实现范围

仓库目前实现了 Phase 0 的前两条垂直切片：

1. 通过操作系统普通 hostname 路径取得 **System Resolution**；
2. 分别取得 **Resolver Inventory**，以及对明确 resolver 发起 UDP、TCP 或 DoH **DNS Observation**。

临时 CLI 为每次调用输出一份版本化 JSON **探测证据**。这些证据用于验证跨平台网络能力，不是 V1 浏览器应用，也不包含资产、批次、重试、判断或持久化模型。

产品范围以 [`PRD.md`](../product/PRD.md) 为准，跨平台 Go 方案及理由以 [ADR 0001](../decisions/0001-cross-platform-go-local-web-architecture.md) 为准。本文件只描述已经存在的实现。

## 2. Module 与依赖方向

```text
cmd/reachrun
    ├── internal/platform/systemresolver
    ├── internal/platform/resolverinventory
    └── internal/dnsobservation
             │
             └── golang.org/x/net/dns/dnsmessage

三个 probe module
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
| `internal/dnsobservation` | 向不可变配置中的明确 resolver 发起一次 UDP、TCP 或 RFC 8484 DoH 查询，并解析类型化 DNS 响应 |
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

`New(Config)` 先复制并锁定一组命名 endpoint。`Request` 只能通过 `ResolverID` 选择其中一项，不能携带任意 IP、URL、端口、HTTP header 或 path。一个调用只查询一个 hostname、一个 `A/AAAA/CNAME` 类型、一个 resolver 和一个明确 transport。

implementation 隐藏：

- UDP query/response；
- TCP 两字节长度 framing 与完整读取；
- RFC 8484 DoH `POST application/dns-message`；
- DNS ID、QR/opcode/question 校验；
- CNAME 链、A/AAAA/CNAME、negative SOA、authority NS、RCODE、flags、TTL、响应大小与实际 endpoint 规范化；
- context timeout、主动关闭连接和迟到成功隔离；
- 最大 65,535 字节 DNS 响应与最多 128 条记录的资源限制。

一次 UDP 调用不会隐藏地切换 TCP。UDP `TC=1` 仍是 `succeeded/incomplete` evidence；后续诊断编排决定是否向同一 resolver 追加独立 TCP observation。

DNS 协议响应与 probe 执行结果必须分开：

- `NOERROR` 正回答、NODATA、NXDOMAIN、referral、SERVFAIL、REFUSED 等合法响应都是 `outcome=succeeded`；
- `answer_kind` 进一步区分 `answer`、`no_data`、`name_error`、`referral`、`rcode_error` 与 `incomplete`；
- 只有输入、transport、非法报文或 DoH HTTP 规则失败才产生 failure；允许 `invalid_input`、`timeout`、`cancelled`、`dns_transport_failure`、`dns_protocol_failure`、`doh_rule_failure`。

DoH 使用固定 HTTPS endpoint 和 bootstrap IP，保留正确 TLS hostname，不经环境代理、不跟随重定向、不携带 Cookie 或认证信息。CLI 当前内置 Cloudflare 和 Google 两组 Phase 0 reference endpoint；PRD §24 中 V1 最终参考 resolver 组合仍未关闭。

`golang.org/x/net/dns/dnsmessage` 只存在于 module implementation，不泄漏到 interface。当前固定版本已具备后续 HTTPS/SVCB codec 能力，但本切片尚未把它们加入 ReachRun evidence contract。

## 7. CLI 组合与安全选择

当前诊断入口：

```text
reachrun resolve <hostname>
reachrun resolver-inventory
reachrun dns-observe <udp|tcp|doh> <current|cloudflare|google> <A|AAAA|CNAME> <hostname>
```

每个合法命令只向 stdout 输出一份 terminal envelope。退出码为：成功 `0`、probe failure `1`、用法错误 `2`、取消 `130`。NXDOMAIN、NODATA 或 SERVFAIL 已收到合法 DNS 响应，因此退出 `0`。

`current` 只允许 UDP/TCP。CLI 先取得一次 inventory，再按观察顺序选择第一个可拨号的 53 端口 server；会跳过其他端口、缺少 zone 的 IPv6 link-local、multicast 与 limited broadcast，IPv6 link-local 使用 evidence 中的 zone/interface。这个入口只验证“向该明确候选查询会发生什么”，不声称自动实现平台的 split-DNS 路由。私网 resolver 只能以这条 inventory 派生路径进入 DNS observer。

`cloudflare` 与 `google` 映射到代码内固定的公网 DNS/DoH endpoint；CLI 不接受用户拼接的 resolver IP 或 URL。CI 只对 System Resolution 与 Resolver Inventory 做真实 runner smoke，不依赖公共 DNS 服务是否可达；UDP/TCP/DoH contract 使用本地受控服务器测试。

## 8. 当前边界与下一次扩展

尚不存在的能力包括 HTTPS/SVCB AliasMode、Web/TLS/HTTP、SSH identification、批次编排、assessment、snapshot、本地 HTTP 与 React UI。它们出现时应各自放入足够深的 module 或未来 `checkrun` implementation，不得给三个现有 probe interface 增加无关方法或建立巨型 `Platform` interface。

System Resolution、Resolver Inventory 和 DNS Observation 必须继续作为三类并列证据。任何一个单独失败、差异或超时都不能直接产生“DNS 污染”“被墙”或其他因果结论。
