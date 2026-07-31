# 0002: Use React and TypeScript for the embedded browser UI

> Status：Accepted
>
> Date：2026-08-01
>
> Supersedes：None

## Context

ReachRun 的 UI 只有一个主要工作区，但同时存在最近一次正式结果、当前完整批次的流式预览和单项临时复核三层状态。它们必须保持不同提交语义：取消或中断不能覆盖正式结果，临时恢复不能改变正式汇总，检测中又要保持行顺序、展开状态、滚动位置和键盘焦点稳定。

原生 JavaScript 能完成 V1，但随后需要手工建立 keyed DOM 更新、事件生命周期和焦点保留，等同于维护一个项目专用渲染框架。资源从本机提供，框架体积不是用户体验的主要约束；状态正确性、Agent 可维护性和跨浏览器一致性更重要。

## Decision

- 使用 React + React DOM、TypeScript `strict` 和 Vite；样式使用原生 CSS、CSS Modules 与 CSS Variables；
- 浏览器通信只使用原生 `fetch`、`ReadableStream` 和 `AbortController`；
- 前端只建立两个核心深 module：
  - `LocalBackend`：隐藏 token、请求头、HTTP 错误、NDJSON 跨 chunk/UTF-8 解析、取消传播和 terminal event 校验；生产使用 Fetch adapter，测试使用 scripted adapter；
  - `ReachRunModel`：以纯 reducer 集中正式快照、活动批次、临时复核和界面状态，向 React 呈现 implementation 提供派生 View Model 与用户动作；
- 普通流事件只能更新活动批次；只有后端确认完整批次已原子提交的 terminal event 才能替换正式快照；取消、意外 EOF、非法或乱序事件均不改变正式状态；
- 单项重测、待复核项重测和手动深度诊断只进入临时复核层；正式汇总、筛选计数和完成后排序只从正式快照派生；
- Go 是资产规范化、网络证据、结论和下一步建议的权威实现；前端不维护第二套领域规则；
- V1 不引入 Next.js/SSR、React Router、Redux/Zustand/XState、TanStack Query、Axios、Tailwind/shadcn、UI 套件、图表库、WebSocket 或 Service Worker；
- Vite 构建产物通过 Go `embed` 进入所有平台的同一类可执行文件，不加载 CDN、远程字体、分析或广告脚本；发布用户不需要 Node；
- 为保留个人自用阶段 `git clone` 后只安装 Go 即可运行的路径，前端生产产物随仓库版本化，CI 必须用锁文件重建并校验无漂移，产物不得手工编辑。

## Why

React 的价值不是页面数量，而是由状态驱动 DOM 更新；TypeScript 的价值是让 NDJSON event、运行状态与正式/临时结果来源形成可穷尽检查。一个 reducer 集中全部转换后，修复一次提交或覆盖规则即可影响汇总、筛选和行视图，形成更好的 locality。

Preact 的主要优势是更小，但 ReachRun 从 loopback 加载内嵌资源，减少少量体积对用户无可感知收益；React 更常见的 interface 和测试工具更利于开源贡献者与不同 coding agent。Svelte/Solid 能实现相同结果，但会引入专属状态语法，而没有对应产品收益。

## Consequences

- 前端开发和发布构建需要 Node、npm、锁文件和 Vite；发布用户仍只运行 ReachRun 二进制；
- 生成的静态产物会进入版本控制，需要 CI 防止源码与产物漂移；
- UI 测试重点从内部 React implementation 转向 reducer invariant、NDJSON parser、键盘交互和真实 Go 进程流程；
- React 呈现代码不得直接接收原始网络证据或自行决定 verdict，否则会破坏 module depth 与单一权威；
- 若未来出现历史趋势、多主页面或复杂编辑，可以重新评估路由和状态工具；不能仅因生态惯例预先加入。

## Alternatives considered

- **原生 ES Modules + JavaScript/JSDoc**：运行时与构建面最小，但需要项目自行维护 DOM reconciliation、焦点与事件细节，V1 已接近其合理复杂度上限；
- **Preact + TypeScript**：保留 JSX/reducer 且更小，但本地资源使体积优势无关紧要，兼容差异增加维护选择；
- **Svelte 或 Solid**：编译或细粒度响应性能足够，但约 70 个资产不需要其性能优势，专属模型不提高状态语义正确性；
- **服务端 HTML fragment/HTMX**：可减少客户端代码，但会把流式行更新、展开与焦点状态分散到 Go 模板和浏览器交换规则中，降低产品状态的 locality。

## Verification

未来 Agent 应检查：

1. `tsconfig` 是否保持 `strict`，依赖是否仍符合本 ADR 的最小栈；
2. 普通、取消、断流、非法、乱序和重复 terminal 事件是否都有 reducer/transport 测试，且不能修改正式快照；
3. 单项复核是否只影响临时层，正式汇总、筛选和排序是否只读取正式状态；
4. Playwright 是否通过真实 Go 进程验证首次保存、完整检测、停止、临时复核、编辑锁定、键盘操作与退出；
5. 构建产物是否通过 `go:embed` 提供、无外部资源，并由锁文件重建校验；
6. 是否新增了本 ADR 明确排除的框架或状态依赖；若确有真实收益，先创建 Superseding ADR。

在前端代码和测试尚未建立前，不得把本 ADR 的选择误写成已经通过上述验证。

## References

- [PRD §14](../product/PRD.md#14-结果界面)
- [PRD §17.5](../product/PRD.md#175-浏览器-ui)
- [React: Choosing the State Structure](https://react.dev/learn/choosing-the-state-structure)
- [React `useReducer`](https://react.dev/reference/react/useReducer)
- [TypeScript `strict`](https://www.typescriptlang.org/tsconfig/strict.html)
- [Vite: Building for Production](https://vite.dev/guide/build)
- [Go `embed`](https://pkg.go.dev/embed)
