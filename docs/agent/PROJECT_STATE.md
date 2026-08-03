# Project State

> Authority：跨 session 使用的当前项目阶段与下一里程碑快照；不替代实时仓库检查
>
> Read when：没有更具体任务地续接项目、制定下一步或判断当前缺口
>
> Update when：项目阶段、下一里程碑或阻塞条件发生变化

> Last reviewed：2026-08-03
>
> Snapshot basis：本文件所在提交的仓库状态。任何后续实现、CI 或里程碑变化都必须现场核验并更新本快照。

## Current phase

ReachRun 处于 **Phase 0 in progress / browser placeholder fallback slice implemented** 阶段。

已经具备：

- 正式产品名、公开 GitHub 仓库和 MIT License；
- V1 产品需求、检测边界、结果模型、安全约束与验收标准；
- 领域术语表和 Agent 文档索引；
- 已接受的跨平台 Go 本地进程 + 系统浏览器架构（ADR 0001）；
- 已接受的 React + TypeScript + Vite 内嵌 UI 方案（ADR 0002）；
- Go module 与 Phase 0 CLI；
- 版本化、类型化的 probe evidence envelope 及 terminal invariant；
- 一个单方法 System Resolver seam、生产 adapter 与 scripted test adapter；
- 系统地址顺序保留、去重、IPv4-mapped 规范化、typed error 归类和迟到取消结果隔离；
- macOS `scutil --dns`、Windows `GetAdaptersAddresses` 与 Linux `/etc/resolv.conf` Resolver Inventory adapter；
- 显式 UDP、TCP 与 RFC 8484 DoH DNS Observation，当前支持 A、AAAA、CNAME、SVCB 和 HTTPS；
- RCODE、flags、CNAME 链、SOA、Authority NS、HTTPS/SVCB priority/TargetName/SvcParam、实际 endpoint 与传输元数据等 typed evidence；
- 对原 hostname 执行同一 resolver/transport 的 HTTPS AliasMode 路径，最多跟随三层并检测循环，再对可用 ServiceMode target 或 RFC 9460 fallback name 查询 A/AAAA；
- ServiceMode compatibility 明确区分可用、参数 malformed 与当前版本不支持；`ipv4hint`/`ipv6hint` 只作 evidence，不替代地址查询；
- 对一个明确候选公网 IP 执行第一跳 HTTP/HTTPS 的 Web Observation，hostname 仍用于 Host、TLS SNI 与证书验证；
- 对 caller 已分组的本地/参考候选集合执行同地址族、固定 HTTPS 第一跳的 Web Candidate Recheck；每侧最多两个候选，交替使用全新连接并在成功后继续完成其余有界候选；
- 对一个明确候选公网 IP 与单个 SSH 端口执行 TCP 建连和受限 identification 交换，不进入密钥交换或认证；
- 对未配置主要网站域名的一个明确公网 IP 固定执行 `443` TCP/TLS 观测；不发送 SNI、不执行证书身份验证、不发送 HTTP，并保留 handshake 完成或 TCP 可达但 TLS 未确认的分层证据；
- 通过固定、零 payload 的 UDP route selection 分别观察本机 IPv4/IPv6 内核选路条件；明确的无路由、地址族不支持、源地址不可用或网络关闭作为中性 `unavailable` evidence，不冒充目标故障；
- 对最多四个明确公网 IP 执行并发上限 2 的 hostname-free TLS Retry Batch；每目标最多三次，只重试明确的 TCP/TLS timeout 或 reset，并让 batch deadline/取消同时截断在途 attempt 与 backoff wait；
- 在 macOS 通过固定 `/usr/bin/open`、Linux 通过不经过 shell 的 `xdg-open`、Windows 通过 `ShellExecuteW` 打开经过严格校验的字面量 `127.0.0.1` URL，并把平台启动失败归入稳定 fallback 类别；
- 运行一次性 `tcp4/127.0.0.1:0` Browser Placeholder；BrowserOpener 失败时终端立即显示仍可访问的 URL，精确页面请求、60 秒 timeout 与取消形成独立 terminal capability report；
- 从 hostname 出发执行系统解析、公网候选筛选、HTTPS-first、受限 HTTP fallback 与最多三跳安全重定向的 Public Web Path；
- `reachrun browser-placeholder`、`reachrun family-conditions`、`reachrun resolve`、`reachrun resolver-inventory`、`reachrun dns-observe`、`reachrun dns-https-path`、`reachrun web-path`、`reachrun web-recheck`、`reachrun web-observe`、`reachrun ssh-observe`、`reachrun tls-observe` 与 `reachrun tls-retry-batch` 十二条命令；
- Public Web Path、Web、SSH 与 TLS 共用的公网字面量 IP 安全策略，以及共用的 Web hostname 规范化策略；
- macOS、Windows 与 Linux 原生 resolver/BrowserOpener contract test、受控 Browser Placeholder、Address Family Conditions、DNS/DNS HTTPS Path/Web/Web Candidate Recheck/SSH/TLS/TLS Retry Batch contract test，以及三平台 GitHub Actions workflow；
- 当前实现架构和可复现开发命令。

尚未具备：

- 将系统解析和两个独立参考解析自动接入候选复核、排除 CDN/GeoDNS 合法差异并生成克制 assessment；
- “本机没有可用 IPv6 路由”到中性检测条件结果的 assessment；
- 正式跨资产快速/深度批次编排、assessment、持久化、带 API 与生命周期的正式本地 HTTP 和前端工程；
- 带 token、API、heartbeat、静态 UI 与退出生命周期的正式“启动后打开浏览器”应用流程；
- 可运行二进制或 GitHub Release；
- 经目标 macOS、Windows、Linux 设备实测过的网络能力结论。

前十一条垂直切片已完成实现。当前代码和本地测试证明 envelope、System Resolution、Resolver Inventory、Address Family Conditions、DNS Observation、DNS HTTPS Path、Web Observation、Web Candidate Recheck、SSH Observation、TLS Observation、TLS Retry Batch、Public Web Path 与 Browser Placeholder fallback contract；GitHub-hosted runner 状态和真实设备 BrowserOpener/网络行为仍必须现场核验，不能由本快照推断。

2026-08-02 在当前 macOS 网络环境的实测中，多个公网 hostname 的 native System Resolution 都返回了 `198.18.0.0/15` benchmark 地址，而 Resolver Inventory 同时观察到 `223.6.6.6:53`。Public Web Path 因没有允许连接的公网候选而安全停止为 `no_public_candidates`。这个现象与 VPN/TUN 的 fake-IP 模式一致，但现有证据不能证明具体来源；关闭或调整相关网络模式后的真实设备复测仍是必要项。在明确产品安全边界前，不应把 benchmark 合成地址加入允许连接范围。该发现限制的是当前 VPN/TUN 环境兼容性结论，不否定受控 contract test 已证明的路径编排。

2026-08-03 在同一台 macOS 设备上实测 `family-conditions`：内核为固定 IPv4 文字地址选出了 route/source address，固定 IPv6 文字地址返回 `unavailable/no_route`，两条 condition 均记录 `payload_bytes_sent=0`，命令成功退出。该证据只说明当前本机的双栈检测条件，不证明 IPv4 载荷送达，也不构成任何 IPv6 资产异常。

2026-08-03 在当前 macOS 设备上连续三轮实测 `browser-placeholder`：`darwin-open` 均接受随机字面量 `127.0.0.1` URL，随后分别在 284ms、213ms、116ms 内观察到精确 Host 的 `GET /`，三轮都以 `completed/page_requested` 退出且未触发 fallback。该结果只证明当前 macOS/默认浏览器成功路径；没有证明 opener 直接导致请求，也不能替代 Windows、Linux 桌面环境和真实 opener 失败 fallback 的复测。

## Next intended milestone

继续执行 PRD 第 19 节定义的 **Phase 0：跨平台网络能力 Spike**。

Spike 应先建立版本化 JSON probe evidence envelope 和最小 CLI，再覆盖三平台 System Resolution adapter、resolver inventory、显式 DNS UDP/TCP/DoH、IPv4/IPv6、指定 IP + 正确 Host/SNI、SSH identification、HTTP/HTTPS、超时、取消、占位页浏览器 URL 回退与平台策略表现。该 envelope 只固定跨平台探测来源、能力、结果与错误类别；Phase 1 再扩展为完整资产、结果和变化模型。通过标准和场景矩阵以 PRD 第 19 节为准，不在本文件重复维护。

前十一份实现切片已完成，当前 macOS 的 Browser Placeholder 成功路径也已重复三轮。下一里程碑是在目标 Windows、Linux 桌面环境重复成功路径，并在三平台补做真实 opener 失败 fallback 场景，随后继续核对 PRD §19 场景矩阵；在相关网络模式关闭后还需复测当前 macOS 的公开 Web 路径。Browser Placeholder 只证明临时 listener、平台 opener 与 URL fallback，不是正式 `localhost`/UI。TLS Retry Batch 只证明最小重试、deadline 与取消机制；跨协议快速/深度队列仍留给正式 `checkrun`。Address Family Conditions 与目标 probe 的中性 assessment，以及系统候选、两个独立参考来源、Web Candidate Recheck 与 CDN/GeoDNS 排除证据的组合，都留给后续 `checkrun`/`assessment`，不得从手工 CLI 标签或单次 no-route 直接生成归因。

## Open decisions

非阻塞待确认事项以 PRD 第 24 节为唯一来源。ADR 0001 和 0002 已接受；若 Phase 0 证明核心假设不成立，应建立 Superseding ADR，不改写原 ADR。技术实现中出现其他难以逆转的新选择时，继续按 [`docs/decisions/README.md`](../decisions/README.md) 建立 ADR。

## Verify first

续接工作前至少运行：

```bash
git status --short
git log -5 --oneline
rg --files
```

当前稳定命令见 [`docs/development/SETUP.md`](../development/SETUP.md)。仍需现场运行，不能从本快照推断它们已经通过。
