# 验证状态

更新时间：2026-10-28。以下状态只针对本次新增的腕部认证原型。

| 项目 | 状态与证据 |
| --- | --- |
| Rust 签名协议 | 11 项测试通过；独立规格与质量审查通过 |
| Rust 后端完整回归 | 最新 110 项通过，含集成测试；原版 watchd 有 3 项已有 dead-code 警告 |
| Apple 共享逻辑 | 云端 XCTest 7 项、Python 打包测试 2 项通过 |
| iPhone / Watch 真机目标编译 | 通过；[构建记录](https://github.com/fencingcell/apple-watch-unlock-windows/actions/runs/40632784401) |
| IPA 结构 | 云端打包验证通过；下载后独立核对 SHA-256、设备平台、嵌入路径和 Mach-O 架构 |
| Apple 代码独立审查 | 规格、实现质量均通过；审查不替代硬件测试 |
| Windows 蓝牙硬件 | 本机只读查询报告 BLE、Central Role、Peripheral Role 支持 |
| Windows GATT 程序 / 服务 | 18 项测试通过；新增 crate 格式检查、Clippy（拒绝警告）、GNU 发布版编译通过 |
| Windows MSVC 云端构建 | [构建 40686686593](https://github.com/fencingcell/apple-watch-unlock-windows/actions/runs/40686686593) 通过：协议与探测程序合计 29 项测试、发布版编译、53 项依赖许可清单导出均通过 |
| Windows 代码审查 | 独立审查发现的目录权限问题已修复并由主代理复核；最终独立复审因额度中断，未取得最终通过结论 |
| Windows 前台广播 | GATT 创建成功，但广播立即 Aborted；独立最小 WinRT 发布程序复现，原因未定位 |
| iOS 27 / watchOS 27 签名与安装 | 未实测；社区安装工具只提供其他 Watch 版本的成功记录 |
| 7 天后重签 / 续签 | 未实测 |
| 实际手表佩戴 / 解锁 / 摘下认证 | 未实测 |
| Watch 与 Windows 完整互通 | 未实测 |
| Session 0 / 重启后登录前通信 | 未实测；没有安装服务或重启测试 |
| Windows 首次登录 | 未实现，原型不收集或提交账户密码 |

Apple 构建使用 macOS 26 标准 runner、Xcode 26.6，iOS / watchOS 26.5 SDK；不是模拟器包。目标系统兼容性仍由设备安装和运行结果决定。构建产物附带工具链记录、日志与校验文件。

测试向量中的固定密钥仅用于公开的互操作测试；真正的电脑 / Watch 私钥在运行时各自生成，不包含在安装包或源码包中。协议只接受显式登记的公钥；有效请求最长 30 秒、绑定电脑 / 账户 / 会话与用途，并且批准只能消费一次。

当前未发生 Apple 账户云端登录、付费云 Mac 租用、Apple Developer 付费会员购买或 Windows 登录配置修改。

检查命令：`cargo test --locked --workspace`；`cargo fmt -p watch-unlock-auth -p watch-login-probe --check`；`cargo clippy --locked -p watch-unlock-auth -p watch-login-probe --all-targets -- -D warnings`；`cargo build --locked --release -p watch-login-probe`。全工作区格式检查会报告上游原有差异，没有批量格式化上游代码。GNU 工具链为 Rust 1.99.1 / LLVM-MinGW 20261020。

Windows 云端产物修订为 `2740e71dff16e9dd68ef8ac38d2a97a5dc743763`；下载的原始 ZIP SHA-256 为 `bd4af5fea4a21bfc9fa0d4426d3b477725e2b0eff1bc3788625da81e32ddaa80`，已与 GitHub 产物摘要核对。构建产物包含工具链记录。电脑蓝牙适配器报告 Realtek，驱动 `178.4039.2510.902`；只读检查未发现所查询的蓝牙广播策略值，不能据此排除其他系统或驱动原因。
