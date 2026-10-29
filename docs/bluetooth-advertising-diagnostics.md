# Windows 广播诊断记录

2026-10-29；Windows 11 家庭版 10.0.26200，ASUS FA401KM，Realtek Bluetooth Adapter 驱动 178.4039.2510.902。以下是本机结果，不能外推到其他适配器。

`doctor` 报告 BLE、Central、Peripheral 和扩展广播支持，蓝牙电源 On。WinRT GATT 服务和特征创建成功；失败发生在广播阶段，认证请求尚未到达 Watch。

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

独立 PowerShell WinRT 最小程序和 Rust 诊断程序得到一致的关键差异。最初的测试遇到 Aborted 就退出，无法辨认短暂过渡；后来改为观察完整 10 秒，才确认标准服务能恢复。生产探测程序的启动判断已相应修复，并增加过渡恢复、持续失败超时、取消三项测试；运行中失去 Started 仍立即终止并清理待处理请求。

微软说明传统广播包只有 31 字节，128 位 UUID 占 16 字节，Discoverable 会广播友好名称：[GATT Server 文档](https://learn.microsoft.com/en-us/windows/apps/develop/devices-sensors/gatt-server)。本机默认名称长 15 个 UTF-8 字节，因此广播容量或驱动对不同 UUID 编码的处理是待验证假设，尚无证据确认根因。下一步可临时缩短蓝牙显示名称进行对照；不需要改 Windows 电脑名或先重启。

未发现所查询的 AllowAdvertising / ServicesAllowedList / LocalDeviceName 注册表值；策略 WMI 类在本机未返回可用蓝牙结果。没有改策略、驱动或电脑名，没有安装开机服务，没有改登录组件。

可从源码运行 `cargo run --locked -p watch-login-probe --example advertising-diagnostic -- custom-list`。默认仅创建临时服务，观察 10 秒后停止，不生成身份、读取密钥或提交登录。`standard` 是标准 UUID 的对照模式，`custom-data` / `custom-data-quiet` 用于数据字段对照；所有模式都不是 Windows 登录测试。

项目继续保留自己的 128 位服务 UUID。短 UUID 对照成功不会改变配对、签名验证或 Windows 登录条件；[Bluetooth SIG 规范](https://www.bluetooth.com/wp-content/uploads/Files/Specification/HTML/CSS_v12/out/en/supplement-to-the-bluetooth-core-specification/data-types-specification.html)规定 16 / 32 位服务 UUID 须使用其分配的编号。
