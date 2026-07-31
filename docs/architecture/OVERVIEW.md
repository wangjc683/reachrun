# ReachRun Architecture Overview

> Authority：当前已实现 module、跨 module seam、Phase 0 证据契约与依赖方向
>
> Read when：修改 module interface、探测证据、平台 adapter、CLI 组合方式或跨模块测试
>
> Update when：新增真实 module/seam，或现有依赖方向、证据契约与能力边界变化

## 1. 当前实现范围

仓库目前只实现 Phase 0 的第一条垂直切片：从临时诊断 CLI 发起一次 **系统解析**，经生产或脚本化 adapter 得到一份版本化 JSON **探测证据**。它用于验证跨平台网络能力，不是 V1 浏览器应用，也不包含资产、批次、判断或持久化模型。

产品范围以 [`PRD.md`](../product/PRD.md) 为准，跨平台 Go 方案及理由以 [ADR 0001](../decisions/0001-cross-platform-go-local-web-architecture.md) 为准。本文件只描述已经存在的实现。

## 2. Module 与依赖方向

```text
cmd/reachrun
    │  组合 timeout、Resolver 与 JSON/exit-code 边界
    ▼
internal/platform/systemresolver
    │  产出一个具体的系统解析 Result
    ▼
internal/probe
       提供 Phase 0 共用 envelope 生命周期与不变量
```

| 路径 | 当前职责 |
|---|---|
| `cmd/reachrun` | Phase 0 临时 CLI；当前只支持 `resolve <hostname>`，不包含产品判断 |
| `internal/probe` | 版本为 1 的类型化 evidence envelope、来源能力、terminal outcome 与稳定失败类别 |
| `internal/platform/systemresolver` | 系统解析的一次尝试、地址规范化、错误归类、backend 能力说明与结果校验 |
| `internal/platform/systemresolver/systemresolvertest` | 给调用方测试使用的有限队列 adapter；返回精确 fixture 并记录调用 |

`internal/probe` 的泛型只统一 Phase 0 探测的公共头部；每种 probe 仍必须定义具体 `Input` 和 `Evidence`，不得退化成 `map[string]any`、`json.RawMessage` 或无类型的万能事件。该 envelope 也不自动成为未来本地 HTTP event 或持久化 schema。

## 3. Probe evidence envelope v1

公共字段固定为：

- `schema_version`：当前只接受整数 `1`；
- `probe`：产生证据的具体 probe；
- `observed_at` 与 `duration_ms`：UTC 完成时间和非负耗时；
- `platform`：当前二进制的 `GOOS/GOARCH`；
- `source`：实际或可证明范围内的 backend、`native/degraded` 能力及降级原因；
- 类型化 `input`、terminal `outcome`，以及互斥的 `evidence` 或 `failure`。

Terminal invariant：

- `succeeded` 必须有 evidence，不能有 failure；
- `failed` 必须有非 `cancelled` failure，不能有 evidence；
- `cancelled` 必须带 `cancelled` failure，不能有 evidence；
- `native` backend 不能带降级原因；`degraded` 必须解释原因；
- 原始 `failure.detail` 只用于 Spike 诊断，后续判断、黄金测试和用户结论只能依赖稳定类别与结构化证据。

系统解析当前使用五个稳定失败类别：

| Code | 含义 |
|---|---|
| `invalid_input` | 输入无法发起系统解析 |
| `name_unresolved` | 系统路径未解析出名称；不冒充区分 NXDOMAIN 与 NODATA |
| `timeout` | context deadline 或可靠的 typed timeout |
| `resolution_failure` | 其他解析失败、空成功结果或非法 native 返回 |
| `cancelled` | 调用 context 已取消 |

新增错误类别必须来自已实现 probe 的稳定跨平台事实，不能预先枚举未来 SSH、TLS 或 HTTP 结论。

## 4. System Resolver seam

调用方只依赖一个方法：

```go
type Resolver interface {
    Resolve(ctx context.Context, hostname string) Result
}
```

一次调用代表一次系统查询，adapter 内不重试。名称未解析、超时和取消都是要保留的观测，因此返回 terminal `Result`，而不是让普通网络失败作为 Go `error` 终止更高层流程。

生产 adapter 使用 `net.DefaultResolver.LookupNetIP(ctx, "ip", hostname)`：

- 接受规范化 hostname；IP literal、scheme、port、path 与内嵌空白属于 `invalid_input`，避免把服务器 IP 快捷返回伪装成系统解析；
- 保留系统首次返回顺序；
- 去重并把 IPv4-mapped IPv6 规范化为 IPv4；
- 允许记录 private、loopback 与 link-local 地址，后续是否允许连接由目标安全策略决定；
- 不添加系统 interface 没有提供的 TTL、RCODE、回答服务器、CNAME 链或原始 DNS 报文；
- native 调用在 context 结束后迟到返回成功时丢弃地址，结果仍为 timeout/cancelled。

脚本化 adapter 与生产 adapter 实现同一个 interface。它在结果队列耗尽时 panic，避免测试悄悄制造未声明证据。

## 5. Resolver backend 能力

Go 不为每次 `LookupNetIP` 公开所选 backend。ReachRun 只在构建条件和 `GODEBUG=netdns` 能证明时标记 `native`，其余情况显式降级：

| 环境 | 报告行为 |
|---|---|
| macOS、Windows 的普通 `!netgo` 构建 | 对应系统 resolver，`native` |
| Linux `cgo + netcgo + !netgo` 构建 | libc/NSS，`native` |
| Linux 有 cgo 但未固定选择 | `linux-resolver-selection-unverified`，`degraded` |
| `netgo`、Linux 无 cgo 或 `GODEBUG=netdns=go` | Go DNS resolver，`degraded` |
| native backend 可用且 `GODEBUG=netdns=cgo` | 已强制 native backend，`native` |
| 带 bisect 条件的 `GODEBUG=netdns=...#...` | backend 条件无法在调用前证明，`degraded` |

来源 profile 在 `systemresolver.New()` 时锁定。进程不得在运行期间修改 `GODEBUG` 来改变同一批证据语义。Linux CI 用 `netcgo` 和原生 runner 执行 contract test；默认 Linux 本地构建即使实际碰巧走 libc，也不会在无法证明时声称 `native`。

## 6. 当前边界与下一次扩展

尚不存在的能力包括 Resolver Inventory、显式 UDP/TCP/DoH DNS Observation、Web/SSH probe、批次编排、assessment、snapshot、本地 HTTP 与 React UI。它们出现时应各自建立足够深的 module，不得给 `Resolver` 增加无关方法或建立巨型 `Platform` interface。

System Resolution、Resolver Inventory 和 DNS Observation 必须继续作为三类并列证据。配置盘点只能描述候选 resolver，不能反推某个服务器实际回答了系统查询。
