# Apple Watch 登录 Windows 原型

目标是在 Windows 开机后的首次登录界面，通过戴着且已解锁的 Apple Watch 点一下确认来登录。

**当前交付的是身份验证原型，尚不能登录 Windows。** 已完成共享签名协议和 iPhone / Watch App 的真机目标编译；Windows 测试程序用于验证蓝牙通信、手表签名和开机服务可用性。首次登录还需要先通过设备实测，再接入 Windows 登录组件。

## 开始测试

- [安装与实测步骤](docs/first-login-prototype.md)：无需本地 Mac 的实验安装途径、两端配对和验证方法。
- [验证状态](docs/validation-status.md)：区分编译通过、设备安装、佩戴认证和实际登录。
- [Apple App 构建说明](apps/apple/README.md)：云端生成未签名的 iPhone / Watch 安装包。

原型不收集 Windows 密码，也不修改 Windows 登录组件或自动登录设置。Watch 使用本机私钥签署新鲜请求；Windows 只接受显式登记的 Watch 公钥。每次确认都调用非交互式腕部认证，实际系统行为仍需在目标手表上验证。

用户已在 iOS 27.2 / watchOS 27.0 通过手机“全能签”安装并打开两端 App，Watch 公钥已传至手机；所用证书类型、有效期和续签方式仍待确认。免费 Personal Team 描述文件的 7 天期限不能直接套用到这次安装。具体记录与后续测试见安装说明。

## 代码与来源

本分支基于 [whyy1/watch-unlock-windows](https://github.com/whyy1/watch-unlock-windows) 修订 `0c16912d633ff0be94c4e99fbfbec32f52722a67`。保留的原版桌面程序使用蓝牙身份和信号强度判断靠近，与本次腕部认证原型是两条独立路径；[原版说明](docs/upstream-readme.md) 中的测试结果来自上游，不能代表本原型已经通过实测。

新增代码位于 `backend/crates/auth`、`backend/crates/login-probe`、`apps/apple` 和 `protocol`。原版 Credential Provider 保持原状。构建工作流位于 `.github/workflows`。

按 [GNU AGPL v3](LICENSE) 发布；来源和修改记录见 [NOTICE](NOTICE)。Apple Watch、iPhone、Windows 等名称用于说明兼容性，本项目与 Apple、Microsoft 无关联。
