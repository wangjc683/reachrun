# 0001: Use a cross-platform Go local process with browser UI

> Status：Accepted
>
> Date：2026-08-01
>
> Supersedes：None

## Context

ReachRun 必须在 JC 的 macOS、Windows 和 Linux 设备上从当前网络发起检测。纯远程 Web 服务测到的是服务器网络，不能代表当前设备；纯浏览器页面又无法可靠完成系统解析、受控 DNS、指定 IP + 正确 Host/SNI 和 SSH identification。

用户接受系统浏览器作为 UI，不需要原生客户端壳。V1 还要求从源码易于运行、公开发布后无需安装语言运行时，并让不同 coding agent 主要维护一套实现。

真正的平台差异集中在系统 resolver、网络环境盘点、打开默认浏览器和原子文件替换。尤其 Linux 的完全静态分发与 libc/NSS resolver 真实性存在取舍，不能用“编译成功”代替行为验证。

## Decision

- 使用 Go 实现检测核心、本地 HTTP、持久化与进程生命周期；
- 每个 OS/CPU 组合生成独立可执行文件，静态 UI 嵌入其中；程序只监听 `127.0.0.1:0`，自动打开系统默认浏览器，失败时打印可复制的本地 URL；
- 不使用 `.app` 客户端壳、Electron、Tauri、Wails、WebView 或另一套原生 UI；
- 核心保持少量深 module：`application`、`checkrun`、`assessment`、`snapshotstore` 与 `localhost`；DNS/Web/SSH 等协议实现默认留在 `checkrun` implementation 内部，不按每个协议暴露浅 module；
- 在 `platform` seam 提供 macOS、Windows、Linux 与测试 adapter，承载 system resolver、网络环境盘点、浏览器打开和原子文件替换；
- System Resolution、Resolver Inventory 和显式 UDP/TCP/DoH DNS Observation 始终是不同证据；Phase 0 的统一 probe evidence envelope 允许平台字段缺失，并记录实际 resolver backend 与 `native/degraded` 能力，Phase 1 再扩展完整产品模型；
- Linux V1 优先保持 libc/NSS/systemd-resolved 等系统语义，先发布经验证的 glibc 构建；不为追求完全静态而静默改变“系统解析”的含义；
- 各平台使用原生 runner 构建和运行 contract test，真实设备另行验证 VPN、split DNS、权限与当前网络；
- Phase 0 是正式开发的第一阶段。Go 选择已经接受，但任何平台网络能力只有通过 Phase 0 后才能宣称已支持。

## Why

Go 的标准库直接覆盖 ReachRun 需要的 TCP/UDP、HTTP、TLS、本地 HTTP、取消与并发，静态资源也可以嵌入可执行文件。Rust 能提供相同用户体验，但需要组合更多异步、HTTP、TLS 与 DNS 依赖，并不能自动获得更真实的系统 resolver。Swift 的主要 UI 与网络优势集中在 Apple 平台，与三平台和系统浏览器目标冲突。

把操作系统差异集中到真实 `platform` seam 后，共享引擎和产品判断只维护一份；平台不具备某项证据时显式降级，而不是迫使用户配置底层选项。

## Consequences

- 用户在三个系统上获得相同流程：运行一个文件、浏览器自动打开、点击一次检测；发布用户不需要 Go、Node 或客户端 runtime；
- 仓库需要三平台构建与测试矩阵，并在真实设备做补充验证；
- Linux 首发支持范围必须明确到架构、libc 与经验证发行版，不能笼统承诺所有 Linux；
- 平台原生 resolver 可能无法立即取消，implementation 必须把“用户停止后的界面终态”和“底层系统调用稍后返回”安全隔离；
- 如果 Phase 0 证明 Go 无法取得某项必需证据，只为该已证明缺口增加最薄平台 adapter；若必须更换核心语言或产品形态，创建 Superseding ADR。

## Alternatives considered

- **Rust 本地进程**：能力足够，但依赖、异步实现和跨 Agent 维护成本更高，对 V1 用户没有相应收益；
- **Swift 核心或 macOS adapter**：SwiftUI、AppKit 与 Network.framework 无法成为三平台共同实现；V1 没有已证明需要第二语言的 macOS 独占证据；
- **Tauri/Electron/Wails**：增加客户端壳、WebView 生命周期与平台打包成本，而用户已经接受系统浏览器；
- **云端 Web 服务**：无法代表运行设备的当前网络，也不符合本地保存和隐私约束；
- **Node/Python 核心**：运行时与打包复杂性高于 Go，不能改善网络证据语义。

## Verification

未来 Agent 应同时检查：

1. PRD §19 的 Phase 0 三平台通过标准；
2. release 产物是否为对应 OS/CPU 的单一可执行文件，UI 是否来自嵌入资源且只监听 `127.0.0.1`；
3. system resolver adapter 是否报告实际 backend/能力，显式 DNS 是否仍与 System Resolution 分开；
4. 相同 evidence fixture 是否在三个系统得到相同 assessment；
5. 浏览器打开失败、取消、退出、存储失败时是否满足 PRD 中的降级与原子提交规则；
6. 是否出现客户端壳、第二套核心引擎或未经 ADR 接受的新平台依赖。

在代码和测试尚未建立前，不得把本 ADR 的选择误写成已经通过上述验证。

## References

- [PRD §17–20](../product/PRD.md#17-技术方案)
- [Go `net` name resolution](https://pkg.go.dev/net#hdr-Name_Resolution)
- [Go resolver selection source](https://go.dev/src/net/conf.go)
- [Go supported platforms](https://go.dev/doc/install/source)
- [Go `embed`](https://pkg.go.dev/embed)
- [Go `os.UserConfigDir`](https://pkg.go.dev/os#UserConfigDir)
- [glibc NSS configuration](https://sourceware.org/glibc/manual/latest/html_node/NSS-Configuration-File.html)
