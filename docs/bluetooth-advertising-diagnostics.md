# Windows 广播诊断记录

2026-10-29；Windows 11 家庭版 10.0.26200，ASUS FA401KM，Realtek Bluetooth Adapter 驱动 178.4039.2510.902。以下是本机结果，不能外推到其他适配器。

`doctor` 报告 BLE、Central、Peripheral 和扩展广播支持，蓝牙电源 On。WinRT GATT 服务和特征创建成功。最初阻塞于广播启动；联合隔离两项后台服务后能广播并被 Watch 发现，当前阻塞于连接或挑战发现阶段。

| 有界实验 | 结果 |
| --- | --- |
| 项目自定义 128 位 UUID，Discoverable + Connectable | 10 秒内始终 Aborted，事件 BluetoothError 为 Success |
| 其他随机 128 位 UUID | 同样失败 |
| 标准 16 位 Battery Service UUID | 初始 Aborted，约 250 毫秒后 Started |
| 临时未分配 32 位 Bluetooth-base UUID，仅用于尺寸对照 | 约 50 毫秒后 Started；不作为协议 UUID 使用 |
| 先启动标准服务，再启动自定义服务 | 标准服务 Started，自定义服务仍失败 |
| 自定义 UUID 加 1 字节 ServiceData，含关闭 Discoverable 的变体 | 仍失败 |
| 自定义 UUID，选择 1M secondary PHY | 仍失败 |
| 蓝牙关 / 开并恢复 On 后重试 | 自定义服务仍失败 |
| 蓝牙显示名由 15 字节缩短为 6 字节，Win32 API 回读确认已生效 | 自定义 UUID 仍持续 Aborted；标准服务约 50 毫秒后 Started |
| GlideXService 单项停止 / 恢复对照 | 两种状态均失败；服务已恢复 Running、Automatic |
| 用户批准临时退出 Phone Link 后测试 | 10 秒内未自动重启，广播仍失败；测试后已恢复应用 |
| 用户批准临时退出 ArmouryCrate.UserSessionHelper 后测试 | 父服务自动重启了辅助进程，未形成完整隔离；末尾一次很晚的 Started 事件不计为持续成功 |
| 全部应用恢复后的独立 30 秒观察 | 自定义服务始终 Aborted，最长 Started 为 0 秒 |
| 用户批准同时停止 ArmouryCrateService 与 GlideXService 后对照 | 自定义 UUID 约 100 毫秒后 Started，持续整个 10 秒窗口；两服务的 Running / Automatic 均已恢复 |
| 联合隔离下的完整探测程序（含三个特征） | 成功广播并正常运行 15 秒，退出时清理待处理挑战；立即恢复服务后的 15 秒对照也通过 |
| 后台服务恢复一段时间后再次启动完整程序 | 再次超时 Aborted，尚未稳定解决共存问题 |
| 联合隔离下多次最多五分钟 Watch 实测 | 可扫描到 Unnamed computer；曾因放下手腕 / 屏幕变暗触发 inactive 取消。保持活动后仍出现 Connection lost 或连接 / 挑战超时，未到批准验证 |
| 临时关闭唯一 Realtek 适配器省电开关，联合隔离后测试 | 关闭回读确认，跟踪中 D2 休眠消失，但手表仍超时；原开关及两项服务均已恢复 |

独立 PowerShell WinRT 最小程序和 Rust 诊断程序得到一致的关键差异。最初的测试遇到 Aborted 就退出，无法辨认短暂过渡；后来改为观察完整 10 秒，才确认标准服务能恢复。生产探测程序的启动判断已相应修复，并增加过渡恢复、持续失败超时、取消三项测试；运行中失去 Started 仍立即终止并清理待处理请求。

微软说明传统广播包只有 31 字节，128 位 UUID 占 16 字节，Discoverable 会广播友好名称：[GATT Server 文档](https://learn.microsoft.com/en-us/windows/apps/develop/devices-sensors/gatt-server)。默认名称长 15 个 UTF-8 字节曾引出名称长度假设；用户缩短为 6 字节，且 Win32 `BluetoothGetRadioInfo` 确认生效后，失败仍持续，因此该假设没有得到实验支持。驱动版本与当前 [ASUS FA401KM 下载页](https://www.asus.com/me-en/laptops/for-gaming/tuf-gaming/asus-tuf-gaming-a14-2025/helpdesk_download?model2Name=FA401KM) 的 Realtek V178.4039.2510.0902 一致，没有重装或降级驱动。

两次约 20 秒、每次 16 MB 上限的本地 ETW 循环跟踪已完成并停止，没有事件丢失。用当前系统的微软公开 PDB 和本机 SDK 解码后，确认 GlideXService 及 ArmouryCrate.UserSessionHelper 也在调用 GATT 广播。公开符号只能还原部分事件，尚不能由此认定它们就是根因。单项停止 GlideXService 和退出 Phone Link 均未解决；辅助进程的父服务为 ArmouryCrateService，会将其自动拉起，因而仅退出辅助进程的测试不能排除资源争用。

控制器层记录显示 `PolicyManager_AllowAdvertising: 1`；观测到的 Set Extended Advertising Parameters / Data / Enable 命令完成状态为 Success / 0。这些记录没有确认自定义 UUID 已发到空中，也没有证明用户的既有耳机或鼠标连接出现问题。用户确认未实际遇到断联。根因仍未定位；用户选择继续蓝牙方案，不增加局域网通道。

用户随后批准同时临时停止 ArmouryCrateService 与 GlideXService 的联合对照。最小诊断与完整探测程序都在该隔离条件下成功；两服务恢复后短时测试也能成功，但后续重新启动又失败。这支持共用广播状态或启动顺序相关的假设，不能据此认定某一个服务单独是根因，也没有形成长期共存修复。

实体 Watch 的完整公钥指纹已由用户核对，公钥已显式登记到前台用户存储。用户另外批准最多五分钟的联合隔离测试窗口，完整程序已确认 Started，但尚无完整电脑配对或签名批准验证成功。所有测试窗口均已结束，finally 恢复两项服务，回读为 Running / Automatic；省电对照也回读恢复原值。蓝牙显示名仍为用户临时设置的短名称，完成诊断后应恢复此前记录的原名称。原始日志和包含进程启动参数的本地记录留在工作目录，不发布到仓库或交付包。

原 Watch 版本将连接、服务发现及特征发现合并在同一个 30 秒超时提示中，因此不能由该提示区分具体层级，也不能从 Windows 没有批准日志推出从未建立蓝牙连接。公开符号只能解码部分控制器事件。下一步使用 0.1.1 / build 2 诊断包显示具体阶段、CoreBluetooth domain/code 和广播 connectable 元数据，同时记录 Windows 的首次 GATT 请求。这个版本只补诊断，不放宽认证条件。

未发现所查询的 AllowAdvertising / ServicesAllowedList / LocalDeviceName 注册表值；策略 WMI 类在本机未返回可用蓝牙结果。没有改策略、驱动或电脑名，没有安装开机服务，没有改登录组件。

可从源码运行 `cargo run --locked -p watch-login-probe --example advertising-diagnostic -- custom-list`。默认仅创建临时服务，观察 10 秒后停止，不生成身份、读取密钥或提交登录。`standard` 是标准 UUID 的对照模式，`custom-data` / `custom-data-quiet` 用于数据字段对照；所有模式都不是 Windows 登录测试。

项目继续保留自己的 128 位服务 UUID。短 UUID 对照成功不会改变配对、签名验证或 Windows 登录条件；[Bluetooth SIG 规范](https://www.bluetooth.com/wp-content/uploads/Files/Specification/HTML/CSS_v12/out/en/supplement-to-the-bluetooth-core-specification/data-types-specification.html)规定 16 / 32 位服务 UUID 须使用其分配的编号。
