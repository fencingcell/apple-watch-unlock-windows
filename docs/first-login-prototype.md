# 无 Mac 的安装与实测

这是验证阶段。预期流程是：打开 Watch 上的 Login Test，确认电脑身份，点击 **Allow authentication test**，由 Windows 验证签名并报告通过。成功仍不会进入 Windows 桌面；密码登记和首次登录集成尚未启用。

目标设备：iPhone iOS 27.2、Apple Watch Series 9 / watchOS 27.0、Windows x64。用户已在 2026-10-29 确认两端 App 能打开。操作系统升级后应重跑安装和佩戴状态测试。

## 1. 获取安装包

Apple 工作流生成 `WatchLogin-unsigned.ipa`。这是包含 Watch App 的真机目标安装包，需要先用自己的 Apple 账户签名。云端构建不需要 Apple 账户、证书或密码。

- [本次已通过的 Apple 构建](https://github.com/fencingcell/apple-watch-unlock-windows/actions/runs/40632784401)，产物名 `apple-prototype-unsigned`。
- 解压产物后，`SHA256SUMS` 可核对安装包和构建报告。
- Windows 产物中的 `watch-login-probe.exe` 用于下面的命令；在解压目录中打开 PowerShell。

Apple 官方说明免费 Personal Team 的描述文件会在签发 7 天后到期，需要重新配置和安装。该规则说明免费签名的期限，不能证明某个 Windows 工具支持嵌入的 Watch App。见 [Apple 账户说明](https://developer.apple.com/help/account/basics/about-your-developer-account)。

## 2. 签名和安装

用户已通过 iPhone 上的“全能签”安装本次 App，iPhone 和 Watch 均可打开，Watch 公钥已传至手机。这是一次实际安装记录；尚未确认所用证书类型、有效期及到期后的续签方式，不能据此保证每 7 天免费重签可用。无需为了后面的通信测试重新安装已能运行的 App。

### 先前调查的 Windows 社区路线（未在本设备验证）

目前找到的是 **iLoader 社区 Watch/RSD 分支**。上游相关 [PR #740](https://github.com/nab138/iloader/pull/740) 已关闭且未合并；作者记录 Windows + iOS 27.0 + Watch Ultra 1 / watchOS 26.6 安装成功，也明确说明没有建立 watchOS 27 兼容性。

可检查的构建来源是 [社区分支 Windows 构建](https://github.com/AndreySemjonov/iloader/actions/runs/35017480604)，修订 `e42e4719afc12b5a7750e4b19a59ba7bfe3e3521`。在该页面下载 `iloader-watch-rsd-windows` 产物。它是第三方实验工具，不是 iLoader 官方发行版；本项目没有对其整个签名实现做安全审计。

该产物于 2026-10-28 查询时尚未到期，预计 2026-12-14 到期。构建引用的 isideload fork 地址目前返回 404；相同后端修订仍可在 [Rzbck 源码](https://github.com/Rzbck/isideload/tree/11063d9596b35589f1eb4e44283e6a29b7d9e6ea) 查看。如果产物失效，重建需要先修正依赖仓库地址并复核版本，不能直接依赖原工作流再次成功。

1. 按 [iLoader 官方仓库](https://github.com/nab138/iloader) 的 Windows 前置要求准备 iTunes / Apple 设备连接驱动。让已配对的 iPhone、Watch 和电脑在附近，手机和电脑连接同一局域网。
2. 用数据线连接 iPhone，解锁手机并确认“信任此电脑”。根据设备提示启用开发者模式；需要时在手表的隐私与安全设置中启用开发者模式。
3. 在本机自行启动上述社区工具并登录 Apple 账户。Apple 密码、验证码和设备配对记录都留在本机操作，不要填入 GitHub Secrets、仓库或反馈日志。
4. 导入本项目 `WatchLogin-unsigned.ipa`。该社区分支的 Watch 安装修复要求选择 **Network / RSD** 路径；普通 USB 安装不能代表这条修复路径。
5. 按安装提示信任开发者。确认 iPhone 出现 **Watch Login Test**，并且手表出现 **Login Test**，两端都能启动。仅安装手机 App 不算通过。

如果没有 Network 选项，或日志出现 companion proxy / RSD / 签名错误，记录失败步骤和错误文本；不要以“手机安装成功”替代手表安装成功。先确认 watchOS 27 安装可行，再做后续认证测试。当前没有已验证的每周自动续签流程；按期重复同一安装过程，并检查手表端确实恢复可运行。

## 3. 前台双向配对

先测试登录后的前台模式。

```powershell
.\watch-login-probe.exe doctor
.\watch-login-probe.exe show-identity
```

`doctor` 只查询蓝牙能力。保存 `show-identity` 显示的完整电脑 SHA-256 指纹。

本机开发验证目前在自定义 128 位服务 UUID 广播时持续得到 `Aborted`，即使 BLE / Peripheral Role 查询为真。16 位标准服务可在约 250 毫秒后恢复到 `Started`；项目 UUID 的最小 WinRT 程序持续 10 秒未启动。原因仍未定位，详见 [蓝牙诊断记录](bluetooth-advertising-diagnostics.md)。若 `serve` 等待后仍报广播启动失败，保留 `doctor` 和完整错误输出；此时没有可供 Watch 连接的广播，后面的配对测试尚不能进行。

运行测试服务：

```powershell
.\watch-login-probe.exe serve --seconds 300
```

1. 把手表戴在腕上，解锁并打开 **Login Test**。点 **Scan for computers**，选择电脑。
2. 逐字核对手表显示的完整电脑指纹与 Windows `show-identity` 的结果；一致才点 **Fingerprints match — pair computer**。蓝牙名称本身不证明电脑身份。配对后会获取另一条新请求。
3. 在手表下方 **Watch enrollment** 查看完整 Watch 指纹。点 **Send public key to iPhone**。
4. 打开手机 **Watch Login Test**，核对其指纹与手表一致，点 **Export public key file**，将 `watch-public-key.txt` 传到电脑。该文件仅包含公钥。
5. 用 Ctrl+C 停止前台程序，登记 Watch 公钥：

```powershell
.\watch-login-probe.exe trust-watch .\watch-public-key.txt
```

再次与手表屏幕逐字比对指纹，在电脑提示中输入完整指纹确认，然后重新启动 `serve`。若手表上的请求过期，重新扫描 / 连接以获取新请求。

```powershell
.\watch-login-probe.exe serve --seconds 300
```

检查手表显示的电脑、`Authentication test` 账户和会话。点击 **Allow authentication test**。Windows 必须报告 `approval=validated enrolled_watch=true purpose=probe logon_submitted=false`；Watch 完成蓝牙写入本身不能证明 Windows 接受了签名。

更换公钥、重装导致身份变化或重置手表密钥后，都需要重新逐字比较并登记。原型在 Watch 上一次只固定一台电脑。删除前台 Watch 登记：

```powershell
.\watch-login-probe.exe forget-watch
```

停止正在运行的前台程序，重新启动后撤销才会反映到该进程。

## 4. 佩戴、锁定和撤销测试

记录设备版本、操作、Watch 提示和 Windows 结果，不要只记“能用”。

| 操作 | 预期 Windows 结果 |
| --- | --- |
| 戴着、已解锁，主动点击确认 | 新鲜签名验证通过一次 |
| 摘下并锁定手表后尝试 | 没有通过的签名 |
| 手表锁定 / 请求需要输入手表密码 | 没有通过的签名；本 App 无交互式密码回退 |
| 获取请求后离开 App、断开蓝牙或等到过期 | 旧请求不再通过 |
| 重复提交已通过的批准 | 拒绝重放 |
| 更换电脑身份或重置 Watch 密钥 | 需要重新比较 / 登记，旧信任不能自动沿用 |

腕部认证调用、Keychain 保护和取消逻辑已实现；系统在不同佩戴状态下的实际行为仍需上述设备实测。这套协议也没有距离测量或防蓝牙中继能力。

## 5. 开机服务测试

先通过前台测试并完成独立代码复审，再在管理员 PowerShell 中安装测试服务。`Probe-DirectorySafety.ps1` 必须与安装脚本放在同一目录：

```powershell
.\Install-ProbeService.ps1 -Executable .\watch-login-probe.exe -WatchPublicKeyFile .\watch-public-key.txt -Start
```

核对脚本显示的 Watch 指纹后确认。服务配置为自动启动；只有加 `-Start` 才会在安装后立即启动。它只安装认证测试服务，不注册 Credential Provider，也不修改 Windows 自动登录。

服务使用 SYSTEM 身份，电脑私钥与前台模式不同，数据在 `%ProgramData%\WatchLoginProbe`，私钥由 SYSTEM 的 DPAPI 保护。安装时只提供 Watch **公钥文件**。必须重新查看服务的电脑指纹，并在 Watch 重新核对配对；不能沿用前台指纹。

```powershell
.\watch-login-probe.exe show-identity --service-data
```

测试开机服务时，在重启后的 Windows 登录界面保持不登录，尝试从 Watch 连接并确认。电脑仍会停留在登录界面。之后用原有方式登录，再检查 `%ProgramData%\WatchLoginProbe\public\service-events.log`：成功记录需要表明在 Session 0 验证了批准。这份日志有容量上限，应及时保存结果。这一步验证“首次登录前能否通信和认证”，尚未提交 Windows 凭据。

卸载用管理员 PowerShell 执行 `.\Remove-ProbeService.ps1`。它保留 ProgramData 中的密钥和登记数据；按脚本说明处理保留数据。当前交付过程没有替你安装服务或重启电脑。

## 接入首次登录之前

需要先取得三项证据：目标设备的安装、签名有效期及续签方式确认可用；佩戴解锁与摘下锁定的认证结果符合预期；开机登录前的 SYSTEM 服务能收到有效批准。之后再实现 Windows 账户登记、受保护的凭据存储和登录组件通信，并确认本地 / Microsoft 账户类型。首次登录与固件启动前的 BitLocker 解锁是不同阶段，本方案的目标是 Windows 登录界面。
