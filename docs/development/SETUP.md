# ReachRun Development Setup

> Authority：当前可复现的环境准备、运行、格式化、测试与构建命令
>
> Read when：首次开发、验证变更、排查本地与 CI 差异或续接实现任务
>
> Update when：工具链版本、目录、稳定命令或平台验证方式变化

## Prerequisites

- Git
- Go `1.26.0` 或更新的兼容版本

当前切片没有第三方 Go module，也没有前端工程或 Node.js 依赖。

## Clone and run

```bash
git clone https://github.com/wangjc683/reachrun.git
cd reachrun
go run ./cmd/reachrun resolve localhost
```

命令向 stdout 输出一行 `system_resolution` JSON evidence。它是 Phase 0 诊断入口，不是 V1 最终的“运行后打开浏览器”体验。

Exit code：

- `0`：系统解析成功；
- `1`：探测已完成但失败，或内部结果无法通过 contract 校验；
- `2`：命令用法错误；
- `130`：用户取消。

单次 CLI 诊断当前有 5 秒 timeout。V1 的并发、分阶段 timeout 与取消策略仍以 PRD 后续实现为准。

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

[`.github/workflows/ci.yml`](../../.github/workflows/ci.yml) 在 GitHub-hosted macOS、Windows 和 Linux runner 上运行格式检查、`go vet`、全部测试及 `localhost` CLI smoke test。Linux job 统一设置 `-tags=netcgo`。

CI 证明构建与 contract 在 runner 环境成立，不替代 PRD §19 要求的真实设备 VPN、split DNS、IPv4/IPv6 与平台策略场景验证。
