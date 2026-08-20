# 低成本短信转发器

[繁體中文](README.md) | [简体中文](README.zh-CN.md) | [English](README.en.md)

使用 ESP32-C3 与 ML307 系列 4G 模组接收短信，并通过 WiFi 转发到电子邮件或推送服务。

<p>
  <a href="https://github.com/lekoOwO/sms_forwarding/actions/workflows/build.yml"><img alt="CI" src="https://github.com/lekoOwO/sms_forwarding/actions/workflows/build.yml/badge.svg" /></a>
  <a href="LICENSE"><img alt="License: MIT" src="https://img.shields.io/badge/License-MIT-green.svg" /></a>
</p>

## 主要功能

- 原生 ESP-IDF 固件与三语 Web 管理页，支持繁体中文、简体中文和英文。
- 支持 PDU、Unicode、长短信合并、去重、黑名单、RAM 收件箱及 Web 短信发送。
- 可以使用 SMTP，或同时启用最多五个推送通道。
- 支持 POST JSON、Bark、GET、钉钉、PushPlus、Server 酱、自定义 JSON、飞书、Gotify、Telegram、Discord Webhook 和 ntfy。
- 每个推送通道可以设置名称、标题模板、正文模板和转发规则，并可以单独测试。
- 可以保存五组 WiFi 配置文件。设备会扫描并连接到可用且信号最佳的已保存网络。
- 可以设置每 1 至 240 小时发送心跳通知。NTP 时间同步完成后，心跳计时才会开始。
- 可以导出加密 `.smscfg` 配置备份，并将可移植配置恢复到另一台设备。
- Web OTA 只接受 Release 提供的已签名 `.smsota` 包，并具备重放保护和启动失败回滚。
- Web 页脚会显示固件版本。正式版显示 `releaseVersion (devBuild)`，开发版显示 `devBuild`。

> 通知目前只通过 WiFi 发送。设备会保存 4G 和混合模式选项，但移动网络推送在完成 CA provisioning 前会 fail closed。GET 和 ntfy 只支持 WiFi，漫游发送一律 fail closed。

## 快速开始

1. 从 [Releases](https://github.com/lekoOwO/sms_forwarding/releases) 下载 `sms-forwarder-VERSION.bin` 完整镜像。
2. 使用乐鑫 [Flash Download Tool](https://docs.espressif.com/projects/esp-test-tools/en/latest/esp32c3/production_stage/tools/flash_download_tool.html) 或 [ESP Launchpad](https://espressif.github.io/esp-launchpad/) 将镜像烧录到地址 `0x0`。
3. 设备找不到已保存的 WiFi 时，连接到 `SMS-Forwarder-XXXXXX`。
4. 输入密码 `sms-forwarder-setup`，然后打开 `http://192.168.1.1`。
5. 设备连接到路由器后，使用管理页显示的局域网地址登录。
6. 使用默认账号 `admin` 和密码 `admin123`，然后立即修改密码。
7. 配置电子邮件或推送通道，并使用通道测试确认发送结果。

### 后续 OTA 更新

从正式 Release 下载 `sms-forwarder-VERSION.smsota`。在管理页打开“系统设置 → 固件更新”，然后选择此文件。

**请勿将 `.bin` 文件上传到 Web OTA。** `.bin` 是 USB 完整镜像，`.smsota` 才是已签名的 Web OTA 包。

## 硬件与接线

已验证的组合是 ESP32-C3 Super Mini 与 ML307R-DC。设备需要 4 MB Flash、Nano SIM 和适合当地网络的天线。

<img src="assets/photo.png" width="200" alt="ESP32-C3 与 ML307R-DC 短信转发器" />

| ESP32-C3 | ML307R-DC |
|---|---|
| GPIO 3 (TX) | RX |
| GPIO 4 (RX) | TX |
| GPIO 5 | EN |
| GND | GND |
| 5V | VCC (5V) |

## 安全提醒

- 管理页使用明文 HTTP。只能在可信局域网使用，且不能直接公开到 Internet。
- 加密配置备份包含 WiFi、SMTP 和推送凭证。请分开保存备份文件与密码短语。
- 设备只将收到的短信用于通知转发，不会执行短信内容中的远程控制命令。

## 开发文档

构建、烧录、发布、架构、配置格式、API 和验证流程见 [`dev_doc/`](dev_doc/README.md)。

## 致谢

感谢 [LINUX DO](https://linux.do) 社区提供交流与灵感。
