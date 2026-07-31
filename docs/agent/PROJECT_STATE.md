# Project State

> Authority：跨 session 使用的当前项目阶段与下一里程碑快照；不替代实时仓库检查
>
> Read when：没有更具体任务地续接项目、制定下一步或判断当前缺口
>
> Update when：项目阶段、下一里程碑或阻塞条件发生变化

> Last reviewed：2026-08-01
>
> Snapshot basis：本文件所在提交的仓库状态。任何后续实现、CI 或里程碑变化都必须现场核验并更新本快照。

## Current phase

ReachRun 处于 **Phase 0 in progress / first system-resolution slice implemented** 阶段。

已经具备：

- 正式产品名、公开 GitHub 仓库和 MIT License；
- V1 产品需求、检测边界、结果模型、安全约束与验收标准；
- 领域术语表和 Agent 文档索引；
- 已接受的跨平台 Go 本地进程 + 系统浏览器架构（ADR 0001）；
- 已接受的 React + TypeScript + Vite 内嵌 UI 方案（ADR 0002）；
- Go module 与临时 `reachrun resolve <hostname>` Phase 0 CLI；
- 版本化、类型化的 probe evidence envelope 及 terminal invariant；
- 一个单方法 System Resolver seam、生产 adapter 与 scripted test adapter；
- 系统地址顺序保留、去重、IPv4-mapped 规范化、typed error 归类和迟到取消结果隔离；
- macOS、Windows 与 Linux 原生 resolver contract test，以及三平台 GitHub Actions workflow；
- 当前实现架构和可复现开发命令。

尚未具备：

- Resolver Inventory 与显式 UDP/TCP/DoH DNS Observation；
- Web、TLS/SNI、HTTP 与 SSH identification probe；
- 批次编排、assessment、持久化、本地 HTTP 和前端工程；
- 面向用户的“启动后打开浏览器”应用流程；
- 可运行二进制或 GitHub Release；
- 经目标 macOS、Windows、Linux 设备实测过的网络能力结论。

第一条切片已经进入正式开发。当前代码和本地测试证明 envelope 与本机 adapter contract；GitHub-hosted runner 状态和真实设备网络行为仍必须现场核验，不能由本快照推断。

## Next intended milestone

继续执行 PRD 第 19 节定义的 **Phase 0：跨平台网络能力 Spike**。

Spike 应先建立版本化 JSON probe evidence envelope 和最小 CLI，再覆盖三平台 System Resolution adapter、resolver inventory、显式 DNS UDP/TCP/DoH、IPv4/IPv6、指定 IP + 正确 Host/SNI、SSH identification、HTTP/HTTPS、超时、取消、占位页浏览器 URL 回退与平台策略表现。该 envelope 只固定跨平台探测来源、能力、结果与错误类别；Phase 1 再扩展为完整资产、结果和变化模型。通过标准和场景矩阵以 PRD 第 19 节为准，不在本文件重复维护。

第一份实现切片已完成。下一份切片优先建立 Resolver Inventory 与显式 DNS Observation（UDP/TCP/DoH）的清晰证据边界，并复用 envelope 生命周期，不进入 React UI。随后再按 PRD §19 覆盖地址族、指定 IP + Host/SNI、Web、SSH、取消和平台策略场景。

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
