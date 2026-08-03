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

ReachRun 处于 **Phase 0 in progress / Web candidate recheck slice implemented** 阶段。

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
- 从 hostname 出发执行系统解析、公网候选筛选、HTTPS-first、受限 HTTP fallback 与最多三跳安全重定向的 Public Web Path；
- `reachrun resolve`、`reachrun resolver-inventory`、`reachrun dns-observe`、`reachrun dns-https-path`、`reachrun web-path`、`reachrun web-recheck`、`reachrun web-observe` 与 `reachrun ssh-observe` 八条命令；
- Public Web Path、Web 与 SSH 共用的公网字面量 IP 安全策略，以及共用的 Web hostname 规范化策略；
- macOS、Windows 与 Linux 原生 resolver contract test、受控 DNS/DNS HTTPS Path/Web/Web Candidate Recheck/SSH contract test，以及三平台 GitHub Actions workflow；
- 当前实现架构和可复现开发命令。

尚未具备：

- 将系统解析和两个独立参考解析自动接入候选复核、排除 CDN/GeoDNS 合法差异并生成克制 assessment；
- 无主要域名时的有限 TLS 结论；
- “本机没有可用 IPv6 路由”到中性检测条件结果的 assessment；
- 批次编排、assessment、持久化、本地 HTTP 和前端工程；
- 面向用户的“启动后打开浏览器”应用流程；
- 可运行二进制或 GitHub Release；
- 经目标 macOS、Windows、Linux 设备实测过的网络能力结论。

前七条垂直切片已完成实现。当前代码和本地测试证明 envelope、System Resolution、Resolver Inventory、DNS Observation、DNS HTTPS Path、Web Observation、Web Candidate Recheck、SSH Observation 与 Public Web Path contract；GitHub-hosted runner 状态和真实设备网络行为仍必须现场核验，不能由本快照推断。

2026-08-02 在当前 macOS 网络环境的实测中，多个公网 hostname 的 native System Resolution 都返回了 `198.18.0.0/15` benchmark 地址，而 Resolver Inventory 同时观察到 `223.6.6.6:53`。Public Web Path 因没有允许连接的公网候选而安全停止为 `no_public_candidates`。这个现象与 VPN/TUN 的 fake-IP 模式一致，但现有证据不能证明具体来源；关闭或调整相关网络模式后的真实设备复测仍是必要项。在明确产品安全边界前，不应把 benchmark 合成地址加入允许连接范围。该发现限制的是当前 VPN/TUN 环境兼容性结论，不否定受控 contract test 已证明的路径编排。

## Next intended milestone

继续执行 PRD 第 19 节定义的 **Phase 0：跨平台网络能力 Spike**。

Spike 应先建立版本化 JSON probe evidence envelope 和最小 CLI，再覆盖三平台 System Resolution adapter、resolver inventory、显式 DNS UDP/TCP/DoH、IPv4/IPv6、指定 IP + 正确 Host/SNI、SSH identification、HTTP/HTTPS、超时、取消、占位页浏览器 URL 回退与平台策略表现。该 envelope 只固定跨平台探测来源、能力、结果与错误类别；Phase 1 再扩展为完整资产、结果和变化模型。通过标准和场景矩阵以 PRD 第 19 节为准，不在本文件重复维护。

前七份实现切片已完成。下一份切片补齐服务器未配置主要域名时的有限 TLS 观测：只证明 TCP/TLS 层事实，不执行 hostname 身份断言，并把缺少 SNI/身份条件与普通 TLS 故障分开；仍不进入资产 assessment。随后继续按 PRD §19 覆盖 IPv6 检测条件、重试、批次取消和平台策略场景，并在相关网络模式关闭后复测当前 macOS 的公开 Web 路径。系统候选、两个独立参考来源、Web Candidate Recheck 与 CDN/GeoDNS 排除证据的正式组合留给后续 `checkrun`/`assessment`，不得从手工 CLI 标签直接生成归因。

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
