# 验证状态

更新时间：2026-10-29。以下状态只针对本次新增的腕部认证原型。

| 项目 | 状态与证据 |
| --- | --- |
| Rust 签名协议 | 11 项测试通过；独立规格与质量审查通过 |
| Rust 后端完整回归 | 最新 110 项通过，含集成测试；原版 watchd 有 3 项已有 dead-code 警告 |
| Apple 共享逻辑 | 云端 XCTest 7 项、Python 打包测试 2 项通过 |
| iPhone / Watch 真机目标编译 | 通过；[构建记录](https://github.com/fencingcell/apple-watch-unlock-windows/actions/runs/40632784401) |
| IPA 结构 | 云端打包验证通过；下载后独立核对 SHA-256、设备平台、嵌入路径和 Mach-O 架构 |
| Apple 代码独立审查 | 规格、实现质量均通过；审查不替代硬件测试 |
| Windows 蓝牙硬件 | 本机只读查询报告 BLE、Central Role、Peripheral Role 支持 |
| Windows GATT 程序 / 服务 | 21 项探测程序测试通过，含 3 项广播启动回归；新增 crate 格式检查、Clippy（拒绝警告）通过 |
| Windows MSVC 云端构建 | [构建 40831045900](https://github.com/fencingcell/apple-watch-unlock-windows/actions/runs/40831045900) 通过：7 项目录安全测试（含管理员正向私有目录 pin）、协议与探测程序共 32 项测试、探测程序及诊断工具的发布版编译、依赖许可导出均通过 |
| Windows 代码审查 | 本地 4cd3aed / cd8cacb 的最终独立规格、质量复审通过；先前目录权限与竞态问题已关闭。复审不替代设备测试 |
| Windows 前台广播 | 联合暂停两项 ASUS 服务后，自定义 UUID 和完整程序均能启动，完整程序 15 秒测试通过；后台服务恢复后仍不稳定。单项处理或缩短名称未解决，长期共存原因待定位 |
| 前台 Watch 公钥登记 | 用户在实体 Watch 核对完整指纹并允许登记，当前用户存储已登记该公钥；这不等于批准已验证 |
| iOS / watchOS 签名与安装 | 用户在 iOS 27.2 / Series 9、watchOS 27.0 上通过手机“全能签”安装，两端已打开；截图确认 Watch 公钥已传至手机。证书类型、有效期未知，不等于免费 Personal Team 路线已验证 |
| 7 天后重签 / 续签 | 未实测 |
| 实际手表佩戴 / 解锁 / 摘下认证 | 未实测 |
| Watch 与 Windows 完整互通 | 已实测但未通过：可发现电脑，连接后曾因 App inactive 取消；保持活动后仍出现连接 / 挑战超时，尚未收到或验证批准 |
| Session 0 / 重启后登录前通信 | 未实测；没有安装服务或重启测试 |
| Windows 首次登录 | 未实现，原型不收集或提交账户密码 |

Apple 构建使用 macOS 26 标准 runner、Xcode 26.6，iOS / watchOS 26.5 SDK；不是模拟器包。目标系统兼容性仍由设备安装和运行结果决定。构建产物附带工具链记录、日志与校验文件。

测试向量中的固定密钥仅用于公开的互操作测试；真正的电脑 / Watch 私钥在运行时各自生成，不包含在安装包或源码包中。协议只接受显式登记的公钥；有效请求最长 30 秒、绑定电脑 / 账户 / 会话与用途，并且批准只能消费一次。

当前未发生 Apple 账户云端登录、付费云 Mac 租用、Apple Developer 付费会员购买或 Windows 登录配置修改。

检查命令：`cargo test --locked --workspace`；`cargo fmt -p watch-unlock-auth -p watch-login-probe --check`；`cargo clippy --locked -p watch-unlock-auth -p watch-login-probe --all-targets -- -D warnings`；`cargo build --locked --release -p watch-login-probe`。全工作区格式检查会报告上游原有差异，没有批量格式化上游代码。GNU 工具链为 Rust 1.99.1 / LLVM-MinGW 20261020。

当前 Windows 云端产物修订为 `f81df2ea30c024f2966eba8e32b8d595302dc393`；原始 ZIP SHA-256 为 `b8ed49c3f8e33e5f675f0bc032b7bbb4a6315acc19d5d2c84e145de26e3125a1`，已下载并与 GitHub 产物摘要核对，下载后的 `doctor` 可正常运行。构建产物包含工具链记录。电脑蓝牙适配器报告 Realtek，驱动 `178.4039.2510.902`；只读检查未发现所查询的蓝牙广播策略值，不能据此排除其他系统或驱动原因。

手表截图的“Authentication cancelled because the app became inactive”表示 App 离开活动状态后主动取消，不能据此判定腕部认证失败或成功。用户随后已在实体手表核对完整指纹并授权登记公钥；这不等于电脑已在手表上配对或批准已通过验证。

Realtek 省电对照已结束：用户授权临时关闭适配器的电源管理开关，回读确认关闭，ETW 中 D2 休眠消失，但手表仍超时。开关已回读恢复原值，两项 ASUS 服务均已恢复 Running / Automatic。仅关闭省电不足以解决当前问题。

本次新增 0.1.1 / build 2 蓝牙诊断：手表显示 connecting / services / characteristics / control / reading 阶段、系统错误 domain/code 与广播 connectable 元数据；Windows 记录首次控制 / 读取回调和挑战生成，不记录设备标识、挑战内容或签名。现有腕部认证、活动状态取消、显式公钥配对和时效约束保持。此诊断版本仍待独立审查和云端构建，不能把旧版本的构建结果视为本次验证。
