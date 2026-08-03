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
go run ./cmd/reachrun family-conditions
go run ./cmd/reachrun resolve localhost
go run ./cmd/reachrun resolver-inventory
go run ./cmd/reachrun dns-observe udp current A example.com
go run ./cmd/reachrun dns-observe doh cloudflare HTTPS example.com
go run ./cmd/reachrun dns-https-path doh cloudflare example.com
go run ./cmd/reachrun web-path example.com
go run ./cmd/reachrun web-recheck one.one.one.one 1.1.1.1 1.0.0.1
go run ./cmd/reachrun web-observe https one.one.one.one 1.1.1.1
# Replace YOUR_SERVER_IP with one of your public server addresses.
go run ./cmd/reachrun ssh-observe YOUR_SERVER_IP 22
go run ./cmd/reachrun tls-observe YOUR_SERVER_IP
```

每个命令向 stdout 输出一份 terminal JSON evidence：

- `family-conditions`：在不发送 payload 的前提下观察当前本机 IPv4/IPv6 内核选路条件；
- `resolve <hostname>`：操作系统普通 hostname 路径返回的 System Resolution；
- `resolver-inventory`：当前可观察到的 resolver 配置候选；
- `dns-observe <transport> <provider> <type> <hostname>`：向一个明确 resolver 发起一次 DNS Observation；
- `dns-https-path <transport> <provider> <hostname>`：使用同一明确 resolver/transport 编排 HTTPS AliasMode 与最终 A/AAAA 观测；
- `web-path <hostname>`：通过系统解析观察一个有界的公开网站路径；
- `web-recheck <hostname> <local-ip[,local-ip]> <reference-ip[,reference-ip]>`：在固定 HTTPS 第一跳条件下复核两组同地址族候选；
- `web-observe <http|https> <hostname> <public-ip>`：向一个明确候选公网 IP 发起一次第一跳 Web Observation；
- `ssh-observe <public-ip> [port]`：向一个明确公网 IP 和单个端口发起受限 SSH identification Observation；端口默认 `22`。
- `tls-observe <public-ip>`：向一个没有 hostname 上下文的明确公网 IP 发起固定 `443` 的有限 TLS Observation。

`transport` 为 `udp`、`tcp` 或 `doh`；`provider` 为 `current`、`cloudflare` 或 `google`；`type` 当前为 `A`、`AAAA`、`CNAME`、`SVCB` 或 `HTTPS`。`current` 只允许 UDP/TCP，并按 inventory 观察顺序选择第一个可拨号的 53 端口 server；它不声称复现平台 split-DNS 选择，也不会向 multicast 或 limited-broadcast 地址发送查询。Cloudflare/Google 是 Phase 0 的固定 reference endpoint，V1 最终组合仍未确定。

`family-conditions` 不接受参数，固定按 IPv4、IPv6 顺序对两个公网文字地址执行 UDP connect，只让内核选择 route/source address，从不写入载荷。`route_selected` 不证明 payload 送达或 endpoint 响应；`unavailable/no_route`、`address_family_unsupported`、`source_address_unavailable` 或 `network_down` 是成功取得的本机条件证据，不是目标资产失败。完整契约见 [Address Family Conditions seam](../architecture/OVERVIEW.md#13-address-family-conditions-seam)。

`dns-https-path` 固定从原 hostname 查询 `HTTPS`，遇到 AliasMode 后保持同一 resolver 与 transport 查询 TargetName 的 `HTTPS`，最多跟随三层并检测循环。最终 ServiceMode target 或无 HTTPS RR 时的 RFC 9460 fallback name 都会分别查询 A 与 AAAA；ServiceMode hostname 按 priority 排序、去重并最多观察 8 个，报告保留其余数量。`ipv4hint`/`ipv6hint` 只保留为 evidence，不替代地址查询。原 hostname 始终保留为未来 Web Host/SNI 身份。完整契约见 [DNS HTTPS Path seam](../architecture/OVERVIEW.md#7-dns-https-path-seam)。

`web-observe` 固定使用 `GET /`，`http` 连接 IP 的 `80` 端口，`https` 连接 `443`。它不用 hostname 做连接前解析，但 HTTP Host、TLS SNI 和证书 hostname 验证仍使用 hostname。每次命令只接受一个 IPv4 或 IPv6 公网候选；完整固定连接契约见 [Web Observation seam](../architecture/OVERVIEW.md#8-web-observation-seam)。当前 Phase 0 backend 只验证 HTTP/1.1，h2-only 服务仍属于未覆盖能力。

`web-path` 只接受 hostname。它对每一跳重新执行 System Resolution，只按返回顺序尝试每个地址族最多两个公网候选，并在第一个合法 HTTP 响应处停止该跳。路径从 HTTPS 开始；只有初始 HTTPS 的全部候选都在收到响应前失败，才重新解析并尝试 HTTP。重定向最多跟随三次，只接受无凭据、默认端口的 HTTP(S) DNS hostname，每一跳都重新执行公网地址校验。完整契约见 [Public Web Path seam](../architecture/OVERVIEW.md#9-public-web-path-seam)。

`web-recheck` 对本地与参考候选分别按输入顺序去重，每侧最多测试两个候选，并按 local/reference 交替执行。两侧必须属于同一地址族；所有尝试固定为 HTTPS `GET /`、端口 `443`、原 hostname Host/SNI/证书验证、零普通重试和零自动重定向，底层每次使用全新禁代理、禁连接复用的 Web client。即使某个候选成功也继续测试其余有界候选，超出上限的数量保留在报告中。CLI 参数中的 local/reference 只是手工分组，不能证明候选的解析来源，也不会生成 DNS 归因。完整契约见 [Web Candidate Recheck seam](../architecture/OVERVIEW.md#10-web-candidate-recheck-seam)。

`ssh-observe` 只接受一个 IPv4/IPv6 公网字面量和一个合法端口，不接受 hostname、端口范围或列表。它发送固定客户端 identification，有限读取服务端前置行与 identification 后立即关闭，不继续密钥交换或认证，也不读取 SSH 密钥。完整契约见 [SSH Observation seam](../architecture/OVERVIEW.md#11-ssh-observation-seam)。

`tls-observe` 只接受一个 IPv4/IPv6 公网字面量，固定连接 `443`；不接受 hostname、port、SNI、证书验证开关或 HTTP 参数。它不发送 SNI、不验证信任链/有效期/hostname 身份，也不发送 HTTP。TLS handshake 完成时证书只保存为未验证 evidence；TCP 已建立但 handshake 失败时保留 `unconfirmed_reason`，不把它判为 IP 不可达，也不声称失败一定由缺少 SNI 导致。完整契约见 [TLS Observation seam](../architecture/OVERVIEW.md#12-tls-observation-seam)。

这些命令是诊断入口，不是 V1 最终的“运行后打开浏览器”体验。

Exit code：

- `0`：probe 成功取得合法证据，或 aggregate/path 报告 `completed`；Address Family Conditions 的明确本机不可用、DNS 的 NXDOMAIN、NODATA、SERVFAIL 等合法响应、DNS HTTPS Path 的 `unsupported_service_mode`、Web Candidate Recheck 中两侧失败但受控尝试已完成、Web 的任意合法 `4xx/5xx` HTTP 响应、SSH 端口可达但 identification 未确认，以及 TLS 的 TCP 已建立但 handshake 未确认，也属于成功观测；
- `1`：probe 的 transport/平台/协议执行失败，任一路径有界停止，或内部结果无法通过 contract 校验；
- `2`：命令用法错误；
- `130`：用户取消。

单 probe CLI 意图当前使用 5 秒总 timeout。`web-path` 使用 15 秒路径总 timeout，其中每次解析或 Web attempt 最多 5 秒；`dns-https-path` 使用 30 秒路径总 timeout，其中每次 DNS Observation 最多 5 秒；`web-recheck` 使用 25 秒总 timeout，其中每次候选尝试最多 5 秒。三个 aggregate/path 都不做普通重试，只按各自固定候选、alias/redirect 与 fallback 规则推进。V1 的并发、分阶段 timeout、重试与熔断仍以 PRD 后续实现为准。

地址族检测条件示例：

```bash
go run ./cmd/reachrun family-conditions
```

结果中固定包含 IPv4、IPv6 两条 condition。`payload_bytes_sent=0` 是 module 契约；命令不会把 `unavailable` 升级为失败 exit code 或资产结论。

参考 DNS 示例：

```bash
go run ./cmd/reachrun dns-observe tcp current AAAA example.com
go run ./cmd/reachrun dns-observe doh cloudflare A example.com
go run ./cmd/reachrun dns-observe doh google CNAME example.com
go run ./cmd/reachrun dns-observe doh cloudflare HTTPS example.com
go run ./cmd/reachrun dns-observe tcp current SVCB example.com
go run ./cmd/reachrun dns-https-path doh cloudflare example.com
```

单个 reference resolver 超时只说明当前网络未在期限内完成该 endpoint 的连接，不构成“被阻断”或 DNS 归因。

Web 第一跳示例：

```bash
go run ./cmd/reachrun web-observe http one.one.one.one 1.1.1.1
go run ./cmd/reachrun web-observe https one.one.one.one 1.1.1.1
```

这两条命令会真实联系指定公网 IP，只适合手动 Spike 观察；公网服务的当前结果不属于仓库 contract。单次成功或超时也不足以生成 DNS 异常或跨境阻断归因。

同地址族候选复核示例：

```bash
go run ./cmd/reachrun web-recheck one.one.one.one 1.1.1.1 1.0.0.1
```

该命令只证明两次第一跳请求使用了同一 hostname、Host/SNI、证书验证和 Web 策略，并分别连接两个候选 IP。参数名不会把任一 IP 证明为系统解析或参考解析候选；要产生高可信归因，仍需 PRD §13.7 的完整 DNS 来源和 CDN/GeoDNS 排除证据。

公开网站路径示例：

```bash
go run ./cmd/reachrun web-path example.com
```

该命令会真实联系系统解析得到的公网候选。若 VPN/TUN 或其他本机网络组件返回 private、benchmark 或其他禁止连接的合成地址，路径会安全停止为 `no_public_candidates`，不会绕过策略连接该地址。这种停止只说明当前 System Resolution 没有给出允许直接连接的公网候选，不能单独证明网络阻断或解析污染。

SSH identification 示例：

```bash
go run ./cmd/reachrun ssh-observe YOUR_SERVER_IP
go run ./cmd/reachrun ssh-observe YOUR_SERVER_IP 2222
```

`identification.status=received` 只证明 SSH 服务返回了协议 identification；`unconfirmed` 证明 TCP 端口可达但没有在受限交换内确认 SSH。两者都没有测试密钥交换、服务器主机密钥或登录。TCP 超时也只描述当前网络到该服务端点的事实，不构成 GFW 归因。

无 hostname TLS 示例：

```bash
go run ./cmd/reachrun tls-observe YOUR_SERVER_IP
```

`tls.status=completed` 只证明该 IP 的 `443` 在不发送 SNI 时完成了 TLS handshake；`input.identity_verification=not_performed_no_hostname` 明确表示证书未验证，不能据此声称网站身份成立。`tls.status=unconfirmed` 仍保留 TCP 已建立事实，后续产品判断可以提示补充主要网站域名，但这份 probe 自身不生成该建议或资产结论。

## Verify changes

```bash
gofmt -w cmd internal
go vet ./...
go test ./...
```

本机 smoke test：

```bash
go run ./cmd/reachrun family-conditions
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

[`.github/workflows/ci.yml`](../../.github/workflows/ci.yml) 在 GitHub-hosted macOS、Windows 和 Linux runner 上运行格式检查、`go vet`、全部测试，以及 Address Family Conditions、System Resolution 与 Resolver Inventory 的真实 CLI smoke test。Linux job 统一设置 `-tags=netcgo`。

Address Family Conditions contract test 使用 fake connection 验证零 Write；真实 smoke 只执行 UDP route selection 而不发送 payload。DNS UDP、TCP、DoH、DNS HTTPS 路径、Web、公开 Web 路径、Web 候选复核、SSH 与 TLS contract test 使用进程内受控服务或 scripted adapter，不依赖公共 resolver 或公网站点是否可达。CI 不向 Cloudflare/Google 或示例 Web/SSH/TLS endpoint 发送探测请求，避免把外部网络波动变成构建结果。

CI 证明构建与 contract 在 runner 环境成立，不替代 PRD §19 要求的真实设备 VPN、split DNS、IPv4/IPv6 与平台策略场景验证。
