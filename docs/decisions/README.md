# Architecture Decision Records

> Authority：重要技术决策记录的索引、状态与使用规则
>
> Read when：任务引入依赖、改变 module interface 或 seam、修改持久化/安全/分发策略，或需要理解既有技术选择的理由
>
> Update when：新增、取代或拒绝 ADR

## Scope

ADR 记录影响广、难以逆转或仅看代码无法理解理由的技术选择。产品目标、范围和用户行为仍由 PRD 负责；PRD 第 23 节中的产品决策不在这里复制。

当前没有 Accepted ADR。PRD 第 17 节中的技术栈、module 划分和本地 interface 是 Phase 0 前的建议方案，不等同于已经锁定或实现的架构。首次建立代码骨架前，应根据实际验证结果决定是否将其中的关键选择记录为 ADR。

适合建立 ADR 的情况：

- 选择或更换核心语言、框架、持久化格式；
- 建立跨 module seam 或引入外部依赖；
- 改变本地服务、安全、隐私或分发策略；
- 多个可行方案存在长期权衡，需要保存选择理由。

不适合建立 ADR 的情况：

- 容易撤销的局部实现细节；
- 产品需求本身；
- 当前任务进度、临时实验输出或待办列表。

## Naming and status

- 文件名：`NNNN-short-kebab-case.md`；
- 状态：`Proposed`、`Accepted`、`Rejected` 或 `Superseded`；
- `Accepted` ADR 不重写历史结论；新建 ADR 并用 `Supersedes` 指向旧记录；
- 当前架构或行为由主题文档描述，ADR 只保存背景、决定和后果。

## Index

当前没有 ADR。第一项技术决策出现时，从 [`TEMPLATE.md`](TEMPLATE.md) 创建 `0001-*.md`，并在此表登记。

| ID | Decision | Status | Supersedes |
|---|---|---|---|
