# ReachRun Agent Index

> Authority：Agent 启动、按需加载与知识路由的唯一入口
>
> Read when：任何任务开始前；默认先只读本文件
>
> Update when：新增、移动或改变权威文档职责

## 1. 启动协议

1. 先读当前用户请求和本文件，不要默认通读整个 `docs/`。
   如果当前 coding agent 不会自动发现 `AGENTS.md`，启动提示必须显式包含：`Read and follow AGENTS.md before working.`
2. 现场检查仓库：`git status --short`、`git log -5 --oneline`、`rg --files`。
3. 根据下方任务路由，只加载完成当前任务所需的文档和章节。
4. 有代码后，继续查找目标目录中距离最近的嵌套 `AGENTS.md`；局部规则只约束其目录树。
5. 编辑前确定该事实的唯一权威来源；不要在第二份文档中复制同一规则。

## 2. 协作方式

- 默认使用中文沟通；代码、命令、标识符使用英文。
- 结论先行，并说明技术选择的原因及其对用户的影响。
- 从用户目标出发，不因技术上可做或行业惯例而扩张范围。
- 能由系统推断或自动完成的事情，不增加用户配置和操作步骤。
- 若缺少的信息不会实质改变结果，采用保守假设继续；若会改变产品方向、安全边界或公开行为，再请求确认。

## 3. 权威来源

| 知识类型 | 权威来源 |
|---|---|
| 产品目标、范围、行为、验收 | [`docs/product/PRD.md`](docs/product/PRD.md) |
| 领域术语与用户文案边界 | [`docs/product/GLOSSARY.md`](docs/product/GLOSSARY.md) |
| 当前技术方案 | PRD 第 17 节；选择理由与不可逆取舍见对应 Accepted ADR，能力是否已验证仍以代码、测试与 Phase 0 实测为准 |
| 已接受的技术决策及理由 | [`docs/decisions/README.md`](docs/decisions/README.md) 及对应 ADR |
| 当前已实现的 module、interface 与证据契约 | [`docs/architecture/OVERVIEW.md`](docs/architecture/OVERVIEW.md) |
| 开发环境、运行、构建与验证命令 | [`docs/development/SETUP.md`](docs/development/SETUP.md) |
| 当前项目阶段与下一里程碑 | [`docs/agent/PROJECT_STATE.md`](docs/agent/PROJECT_STATE.md)，随后必须现场核验 |
| 当前实现行为 | 代码、测试与实际运行结果 |
| 分支、提交、CI、发布和 GitHub 状态 | `git`、测试命令、`gh` 等实时工具输出 |
| 面向开源访问者的简要介绍 | [`README.md`](README.md)，不作为实现规范 |

当前用户的明确指令优先。如果用户指令改变了耐久的产品或技术事实，应在同一变更中更新对应权威文档。代码与文档冲突时，不要静默选择一方；先判断这是实现缺陷、文档过期还是尚未确认的产品变化。

## 4. 任务路由

| 任务 | 必读内容 | 条件性内容 |
|---|---|---|
| 无明确任务地续接项目 | `PROJECT_STATE.md`，然后现场检查 Git 与代码 | PRD 第 20、23、24 节 |
| 产品定位、范围、流程 | PRD 第 1–8、23–24 节 | 涉及命名或状态语义时读 `GLOSSARY.md` |
| 资产模型 | `GLOSSARY.md`；PRD 第 8、13 节 | 持久化任务再读第 15 节 |
| 结果状态、变化比较或结果文案 | `GLOSSARY.md`；PRD 第 13、14.2–14.5、15.1、21.1 节 | 只有涉及配置变化状态时再读第 8.1 节 |
| 域名、DNS、Web 探测或归因 | `GLOSSARY.md`；PRD 第 9–10、13、16、18 节 | Cloudflare 任务读第 12 节；系统 resolver 与平台 adapter 读第 17.4 节及 ADR 0001 |
| 服务器、SSH、HTTP/HTTPS 探测 | `GLOSSARY.md`；PRD 第 9、11–13、16、18–19 节 | 关联域名任务再读第 12 节 |
| UI、交互与结果呈现 | PRD 第 7–8、13–14、17.5、21 节；ADR 0002 | 用户文案再读 `GLOSSARY.md` |
| 存储、本地 API、生命周期或安全 | PRD 第 15–18、21 节 | 技术取舍再读相关 ADR |
| Phase 0 DNS Spike | `GLOSSARY.md`；PRD 第 10、16.2、16.4、17.4、19.1、19.3–19.4 节；ADR 0001；`PROJECT_STATE.md` | 涉及 Cloudflare 时再读第 12 节 |
| Phase 0 服务器 Spike | `GLOSSARY.md`；PRD 第 11、16.2、19.2–19.4 节；ADR 0001；`PROJECT_STATE.md` | 涉及域名关联时再读第 12 节 |
| 修改 probe envelope、System Resolver 或 scripted adapter | `GLOSSARY.md`；`docs/architecture/OVERVIEW.md`；目标代码与测试 | 运行命令读 `docs/development/SETUP.md`；语义变化再读 PRD 第 17.4、19 节与 ADR 0001 |
| 修改 Address Family Conditions、本机 IPv4/IPv6 检测条件或对应 scripted adapter | `GLOSSARY.md`；`docs/architecture/OVERVIEW.md`；目标代码与测试 | 运行命令读 `docs/development/SETUP.md`；语义变化再读 PRD 第 10.1、13、16、18–19 节与 ADR 0001 |
| 修改 Resolver Inventory、DNS Observation 或对应 scripted adapter | `GLOSSARY.md`；`docs/architecture/OVERVIEW.md`；目标代码与测试 | 运行命令读 `docs/development/SETUP.md`；语义变化再读 PRD 第 10、16、17.4、19 节与 ADR 0001 |
| 修改 DNS HTTPS Path、HTTPS/SVCB 或 AliasMode 编排 | `GLOSSARY.md`；`docs/architecture/OVERVIEW.md`；目标代码与测试 | 运行命令读 `docs/development/SETUP.md`；语义变化再读 PRD 第 10、16、18–19 节与 RFC 9460 |
| 修改 Web Observation、Public Web Path、公网目标策略或对应 scripted adapter | `GLOSSARY.md`；`docs/architecture/OVERVIEW.md`；目标代码与测试 | 运行命令读 `docs/development/SETUP.md`；语义变化再读 PRD 第 9–10、13、16、18–19 节与 ADR 0001 |
| 修改 Web Candidate Recheck、同地址族候选复核或对应 scripted adapter | `GLOSSARY.md`；`docs/architecture/OVERVIEW.md`；目标代码与测试 | 运行命令读 `docs/development/SETUP.md`；语义变化再读 PRD 第 10.3、13.7、16、18–19 节与 ADR 0001 |
| 修改 SSH Observation、公网目标策略或对应 scripted adapter | `GLOSSARY.md`；`docs/architecture/OVERVIEW.md`；目标代码与测试 | 运行命令读 `docs/development/SETUP.md`；语义变化再读 PRD 第 11、13、16、18–19 节与 ADR 0001 |
| 修改 TLS Observation、无主要域名服务器 HTTPS 探测或对应 scripted adapter | `GLOSSARY.md`；`docs/architecture/OVERVIEW.md`；目标代码与测试 | 运行命令读 `docs/development/SETUP.md`；语义变化再读 PRD 第 8.3、11.4、13、16、18–19 节与 ADR 0001 |
| 本地运行、构建、格式化、测试或 CI | `docs/development/SETUP.md`；目标 workflow/代码 | 只有行为或架构变化时再读对应权威文档 |
| 测试某项行为 | 对应产品章节、验收条目、目标代码与现有测试 | 跨 module 才读架构文档或 ADR |
| 整体验收 | PRD 第 21 节及失败条目对应的产品章节 | 性能验收再读第 18 节 |
| 架构、依赖或模块 interface 变化 | PRD 第 17 节；ADR 索引；相关产品章节 | 有代码后读取目标模块与测试 |
| Bug 诊断与修复 | 复现路径、目标代码和测试；相关验收条目 | 只有语义不清时才读对应 PRD 章节 |
| 文档新增、拆分或迁移 | [`docs/agent/DOCUMENTATION.md`](docs/agent/DOCUMENTATION.md) | 涉及产品事实时读对应权威文档 |
| 首次建立二进制发布能力 | `README.md`；`PROJECT_STATE.md`；PRD 第 17.1、20 Phase 3、23 节；现场检查 `git`、`gh` 和构建结果 | 用户行为变化时读对应 PRD 章节 |
| 已有流程下的常规发布 | `README.md`；现场检查发布文档、`git`、`gh` 和构建结果 | 只有发布行为变化时读产品或 ADR 文档 |

读取长文档时，先用 `rg -n '^#{1,4} ' <file>` 定位标题，再读取目标章节；不要因为文件被列为“必读”就无差别加载全文。

## 5. 实现与交付纪律

- 一个事实只保留一个权威来源；其他位置使用链接和章节引用。
- 行为、module interface 或安全规则变化时，在同一变更中更新测试和权威文档。
- 文档描述“应该怎样”；代码和测试证明“现在怎样”。两者都不能替代现场验证。
- 不为尚不存在的 module、命令或工作流编造文档。
- 新增依赖、跨 module seam、存储格式、安全策略或难以逆转的技术选择前，判断是否需要 ADR。
- 保持改动聚焦；不要顺带整理与任务无关的用户改动。
- 完成前运行与风险相称的验证，并再次检查 `git diff` 与 `git status`。

## 6. 当前文档地图

```text
AGENTS.md                         # 本索引；Agent 唯一稳定入口
README.md                         # 面向开源访问者
docs/
├── architecture/
│   └── OVERVIEW.md               # 已实现 module、seam 与 evidence contract
├── agent/
│   ├── DOCUMENTATION.md          # 文档维护、拆分和跨 Agent 规则
│   └── PROJECT_STATE.md          # 短期项目状态快照
├── decisions/
│   ├── 0001-cross-platform-go-local-web-architecture.md
│   ├── 0002-react-embedded-browser-ui.md
│   ├── README.md                 # ADR 索引与使用规则
│   └── TEMPLATE.md               # ADR 模板
├── development/
│   └── SETUP.md                  # 开发环境与稳定验证命令
└── product/
    ├── GLOSSARY.md               # 领域语言
    └── PRD.md                    # 完整产品规范
```
