# 低成本短信转发器

[繁體中文](README.md) | [简体中文](README.zh-CN.md) | [English](README.en.md)

用 ESP32-C3 与 ML307 系列 4G 模组，把 SIM 卡收到的短信转发到电子邮件或推送服务。日常配置、查看短信和诊断都可以在浏览器完成。

[下载固件](https://github.com/lekoOwO/sms_forwarding/releases) · [试用管理页](https://lekoowo.github.io/sms_forwarding/) · [反馈问题](https://github.com/lekoOwO/sms_forwarding/issues)

Demo 不连接真实设备，也不会执行备份、恢复或固件更新。

## 可以做什么

- 将短信转发到电子邮件，或同时使用最多五个推送通道。
  - 支持 Bark、Telegram、Discord Webhook、Gotify、ntfy、钉钉、飞书、PushPlus、Server 酱，以及自定义 GET／JSON 请求。
- 按来源号码或内容配置转发规则，并自定义通知标题与正文。
- 在管理页查看、发送短信，查询信号、SIM 与模组信息。
- 保存最多五组 WiFi，配置心跳通知，导出加密配置备份。
- 管理兼容 eSIM 卡的配置文件，实际功能依卡片、模组和运营商而异。
- 管理页提供繁体中文、简体中文和英文。

电子邮件只通过 WiFi 发送。使用 4G 推送前，请确认移动网络可用，并启用通道的移动网络功能与 HTTPS 证书。目前不支持漫游时的 4G 推送。实际可用性取决于模组、SIM 卡和网络。

## 准备硬件

- ESP32-C3 开发板，至少 4 MB Flash。
- ML307 系列模组、可以接收短信的 SIM 卡和合适的天线。
- 稳定电源、USB 线，以及首次配置使用的 WiFi 网络。

以下接线以 ESP32-C3 Super Mini 与 ML307R-DC 转接板为例。其他板型请先确认供电电压，不要将裸模组直接接到 5V。

<img src="assets/photo.png" width="200" alt="ESP32-C3 与 ML307R-DC 短信转发器" />

| ESP32-C3 | ML307R-DC |
|---|---|
| GPIO 3 (TX) | RX |
| GPIO 4 (RX) | TX |
| GPIO 5 | EN |
| GND | GND |
| 5V | VCC (5V) |

## 首次使用

1. 从 [Releases](https://github.com/lekoOwO/sms_forwarding/releases) 下载 `sms-forwarder-VERSION.bin`。标为 Pre-release 的版本供测试使用。
2. 使用乐鑫 [Flash Download Tool](https://docs.espressif.com/projects/esp-test-tools/en/latest/esp32c3/production_stage/tools/flash_download_tool.html) 或 [ESP Launchpad](https://espressif.github.io/esp-launchpad/)，将完整镜像烧录到 `0x0`。
3. 设备找不到已保存的 WiFi 时，连接到 `SMS-Forwarder-XXXXXX`，密码为 `sms-forwarder-setup`。
4. 打开 `http://192.168.1.1`，选择家中或办公室的 WiFi 并输入密码。
5. 配网完成后，让电脑或手机连回同一个局域网。打开配网页显示的设备地址。
6. 使用账号 `admin`、密码 `admin123` 登录，并立即修改管理密码。
7. 配置电子邮件或推送通道，使用通道测试确认通知能送达。

## 备份与更新

管理页可以导出加密的 `.smscfg` 配置备份。请将备份文件与密码短语分开保存。备份包含 WiFi、电子邮件和推送凭证。

Web 固件更新只接受适用于本设备的已签名 `.smsota` 包。如果下载页只有 `.bin`，请使用 USB 烧录方式。不要把 `.bin` 上传到 Web 更新页。

目前开发版下载提供 USB 完整镜像，正式签名 OTA 包尚未开放发布。

## 使用前请注意

- 管理页使用明文 HTTP。只在可信局域网使用，不要直接公开到 Internet。
- 收件箱和发件箱不会永久保存短信，设备重启后会清空。
- 设备不会执行短信内容中的远程控制命令。
- 发送短信或使用移动数据可能产生电信费用。

## 开发与致谢

源码构建、架构与测试说明统一放在 [开发文档](dev_doc/README.md)。本项目使用 [MIT 许可](LICENSE)。

本项目衍生自 [MineSunshineone/sms_forwarding](https://github.com/MineSunshineone/sms_forwarding)。感谢上游维护者与贡献者，也感谢 [LINUX DO](https://linux.do) 社区的交流与分享。
