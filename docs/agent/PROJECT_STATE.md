# Project State

> Authority：跨 session 使用的当前项目阶段与下一里程碑快照；不替代实时仓库检查
>
> Read when：没有更具体任务地续接项目、制定下一步或判断当前缺口
>
> Update when：项目阶段、下一里程碑或阻塞条件发生变化

> Last reviewed：2026-08-01
>
> Snapshot baseline：`c43e61b`（首次公开提交）。若后续 commit 已加入实现或改变里程碑，必须重新核验并更新本快照。

## Current phase

ReachRun 处于 **pre-implementation / product-defined** 阶段。

已经具备：

- 正式产品名、公开 GitHub 仓库和 MIT License；
- V1 产品需求、检测边界、结果模型、安全约束与验收标准；
- 领域术语表和 Agent 文档索引。

尚未具备：

- 应用源代码；
- 构建、测试或发布流程；
- 可运行二进制或 GitHub Release；
- 经目标 Mac 实测过的网络能力结论。

PRD 第 17 节描述的是当前建议的技术方向，尚没有 Accepted ADR。Phase 0 可以验证这些建议，但不得把尚未实测的 module 划分或 interface 当成已经实现的事实。

## Next intended milestone

执行 PRD 第 19 节定义的 **Phase 0：网络能力 Spike**，先验证关键网络假设，再确定 V1 检测引擎实现。

Spike 应覆盖 macOS 系统解析、显式 DNS UDP/TCP/DoH、IPv4/IPv6、指定 IP + 正确 Host/SNI、SSH identification、HTTP/HTTPS、超时与取消，以及本地网络权限表现。通过标准和场景矩阵以 PRD 第 19 节为准，不在本文件重复维护。

## Open decisions

非阻塞待确认事项以 PRD 第 24 节为唯一来源。技术实现中出现难以逆转的新选择时，按 [`docs/decisions/README.md`](../decisions/README.md) 建立 ADR。

## Verify first

续接工作前至少运行：

```bash
git status --short
git log -5 --oneline
rg --files
```

有代码后，再运行仓库当时定义的格式化、静态检查与测试命令；不要从本快照推断它们已经存在或通过。
