# ReachRun Development Setup

> Authority：当前可复现的环境准备、运行、格式化、测试与构建命令
>
> Read when：首次开发、验证变更、排查本地与 CI 差异或续接实现任务
>
> Update when：工具链版本、目录、稳定命令或平台验证方式变化

## Prerequisites

- Git
- Go `1.26.0` 或更新的兼容版本

Go 会通过 `go.mod` 自动取得固定版本的 `golang.org/x/net` 和 `golang.org/x/sys`。当前仍没有前端工程或 Node.js 依赖。

## Clone and run

```bash
git clone https://github.com/wangjc683/reachrun.git
cd reachrun
go run ./cmd/reachrun resolve localhost
go run ./cmd/reachrun resolver-inventory
go run ./cmd/reachrun dns-observe udp current A example.com
```

每个命令向 stdout 输出一份 terminal JSON evidence：

- `resolve <hostname>`：操作系统普通 hostname 路径返回的 System Resolution；
- `resolver-inventory`：当前可观察到的 resolver 配置候选；
- `dns-observe <transport> <provider> <type> <hostname>`：向一个明确 resolver 发起一次 DNS Observation。

`transport` 为 `udp`、`tcp` 或 `doh`；`provider` 为 `current`、`cloudflare` 或 `google`；`type` 当前为 `A`、`AAAA` 或 `CNAME`。`current` 只允许 UDP/TCP，并按 inventory 观察顺序选择第一个可拨号的 53 端口 server；它不声称复现平台 split-DNS 选择，也不会向 multicast 或 limited-broadcast 地址发送查询。Cloudflare/Google 是 Phase 0 的固定 reference endpoint，V1 最终组合仍未确定。

这些命令是诊断入口，不是 V1 最终的“运行后打开浏览器”体验。

Exit code：

- `0`：probe 成功取得合法证据；DNS 的 NXDOMAIN、NODATA、SERVFAIL 等合法响应也属于成功观测；
- `1`：probe 的 transport/平台/协议执行失败，或内部结果无法通过 contract 校验；
- `2`：命令用法错误；
- `130`：用户取消。

每个 CLI 意图当前共享 5 秒总 timeout。DNS observer 本身也有有界 timeout，不做普通重试。V1 的并发、分阶段 timeout、重试与熔断仍以 PRD 后续实现为准。

参考 DNS 示例：

```bash
go run ./cmd/reachrun dns-observe tcp current AAAA example.com
go run ./cmd/reachrun dns-observe doh cloudflare A example.com
go run ./cmd/reachrun dns-observe doh google CNAME example.com
```

单个 reference resolver 超时只说明当前网络未在期限内完成该 endpoint 的连接，不构成“被阻断”或 DNS 归因。

## Verify changes

```bash
gofmt -w cmd internal
go vet ./...
go test ./...
```

本机 smoke test：

```bash
go run ./cmd/reachrun resolve localhost
```

构建当前 CLI：

```bash
go build ./cmd/reachrun
```

## Linux native resolver contract

Linux 必须保留 libc/NSS 等系统解析语义。开发或 CI 要验证 native contract 时，需要启用 cgo 并固定 Go 使用 native resolver：

```bash
CGO_ENABLED=1 go test -tags=netcgo ./...
CGO_ENABLED=1 go vet -tags=netcgo ./...
CGO_ENABLED=1 go run -tags=netcgo ./cmd/reachrun resolve localhost
```

普通 Linux Go build 可能按系统配置动态选择 Go 或 libc resolver。ReachRun 无法证明某次 backend 时会保守报告 `degraded`；这不是解析失败。`CGO_ENABLED=0` 或 `netgo` 构建也会明确降级，不能作为 Linux 原生 resolver 发布验证。

macOS 和 Windows 的普通构建由 Go 默认选择对应系统 resolver；`GODEBUG=netdns=go` 或 `netgo` 会使证据降级。

## CI

[`.github/workflows/ci.yml`](../../.github/workflows/ci.yml) 在 GitHub-hosted macOS、Windows 和 Linux runner 上运行格式检查、`go vet`、全部测试，以及 System Resolution 与 Resolver Inventory 的真实 CLI smoke test。Linux job 统一设置 `-tags=netcgo`。

UDP、TCP 与 DoH contract test 使用进程内受控服务器，不依赖公共 resolver 是否可达。CI 不对 Cloudflare/Google 发真实请求，避免把外部网络波动变成构建结果。

CI 证明构建与 contract 在 runner 环境成立，不替代 PRD §19 要求的真实设备 VPN、split DNS、IPv4/IPv6 与平台策略场景验证。
