# 低成本短信转发器

[繁體中文](README.md) | [简体中文](README.zh-CN.md) | [English](README.en.md)

使用 ESP32-C3 与 ML307 系列 4G 模块接收短信，并自动转发到电子邮件或推送服务。

[管理页 Demo](https://lekoowo.github.io/sms_forwarding/) · [视频教程](https://www.bilibili.com/video/BV1cSmABYEiX) · [旧版 LuatOS 分支](https://github.com/chenxuuu/sms_forwarding/tree/old-luatos)

> Demo 不连接真实设备，并停用备份、恢复和 OTA 操作。

<img src="assets/photo.png" width="200" alt="ESP32-C3 与 ML307R-DC 短信转发器" />

## 主要功能

- 通过 Web 管理页配置和查看设备状态，支持繁体中文、简体中文和英文。
- 将短信转发到电子邮件，或同时启用最多五个推送通道。
- 每个推送通道可设置独立名称、标题模板和正文模板。
- 支持长短信合并、黑名单、Web 发送短信和网络诊断。
- 可设置设备名称和 hostname，方便管理多台设备。
- 可导出加密配置备份，并恢复到另一台设备。
- 可从管理页安装已签名的 OTA 更新，并在启动失败时回滚旧版。
- 日志只保留在 RAM 并分页加载，不会磨损 flash。

设备只将收到的短信用于通知转发，不会执行短信中的远程控制指令。

## 推送服务

支持 POST JSON、Bark、GET、DingTalk、PushPlus、ServerChan、Custom JSON、Feishu、Gotify 和 Telegram。

普通服务可使用 `{device}`、`{sender}`、`{message}` 和 `{timestamp}` 自定义标题或正文。Custom JSON 可自定义完整 request body。

| 状态信息 | 主动 Ping |
|---|---|
| ![](assets/status.png) | ![](assets/ping.png) |

## 硬件与接线

已验证的组合是 ESP32-C3 Super Mini 与 ML307R-DC。设备需要 4 MB flash、Nano SIM，以及适合当地运营商网络的天线。

| ESP32-C3 | ML307R-DC |
|---|---|
| GPIO 3 (TX) | RX |
| GPIO 4 (RX) | TX |
| GPIO 5 | EN |
| GND | GND |
| 5V | VCC (5V) |

## 使用提醒

- 第一次从旧版分区升级时，先备份配置，再通过 USB 完整擦除并重刷。
- 默认管理账号是 `admin`，密码是 `admin123`。首次登录后立即修改密码。
- 管理页使用明文 HTTP，只适合可信局域网。不要直接公开到 Internet。
- 配置备份可能包含通知服务的 secret。妥善保存备份文件和 passphrase。

## 开发文档

构建、烧录、OTA 发布、配置格式、API、架构和验证流程见 [`dev_doc/`](dev_doc/README.md)。
