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

ReachRun 处于 **implementation-ready / Phase 0 starting** 阶段。

已经具备：

- 正式产品名、公开 GitHub 仓库和 MIT License；
- V1 产品需求、检测边界、结果模型、安全约束与验收标准；
- 领域术语表和 Agent 文档索引；
- 已接受的跨平台 Go 本地进程 + 系统浏览器架构（ADR 0001）；
- 已接受的 React + TypeScript + Vite 内嵌 UI 方案（ADR 0002）；
- 已定义 Phase 0 验收门槛：macOS、Windows、Linux 必须共用最小 probe evidence envelope，并由平台 adapter 保持系统 resolver 真实性。

尚未具备：

- 应用源代码；
- Go module、前端工程或可执行的 CLI；
- 构建、测试或发布流程；
- 可运行二进制或 GitHub Release；
- 经目标 macOS、Windows、Linux 设备实测过的网络能力结论。

技术选择已经确定，因此可以进入正式开发。Accepted ADR 表示应按该方向实现，不表示任何 module 已经存在，也不表示系统 resolver、取消、分发或网络结论已经通过验证。

## Next intended milestone

执行 PRD 第 19 节定义的 **Phase 0：跨平台网络能力 Spike**。这是正式开发的第一阶段，不是额外的需求讨论。

Spike 应先建立版本化 JSON probe evidence envelope 和最小 CLI，再覆盖三平台 System Resolution adapter、resolver inventory、显式 DNS UDP/TCP/DoH、IPv4/IPv6、指定 IP + 正确 Host/SNI、SSH identification、HTTP/HTTPS、超时、取消、占位页浏览器 URL 回退与平台策略表现。该 envelope 只固定跨平台探测来源、能力、结果与错误类别；Phase 1 再扩展为完整资产、结果和变化模型。通过标准和场景矩阵以 PRD 第 19 节为准，不在本文件重复维护。

第一份实现切片应只完成：Go module 与 Phase 0 CLI 骨架、版本化 probe evidence envelope、跨平台 System Resolver interface、测试 adapter，以及三平台原生 resolver contract test。不要在这个切片中提前建设完整 React UI、所有协议探测或发布包装。

## Open decisions

非阻塞待确认事项以 PRD 第 24 节为唯一来源。ADR 0001 和 0002 已接受；若 Phase 0 证明核心假设不成立，应建立 Superseding ADR，不改写原 ADR。技术实现中出现其他难以逆转的新选择时，继续按 [`docs/decisions/README.md`](../decisions/README.md) 建立 ADR。

## Verify first

续接工作前至少运行：

```bash
git status --short
git log -5 --oneline
rg --files
```

有代码后，再运行仓库当时定义的格式化、静态检查与测试命令；不要从本快照推断它们已经存在或通过。
