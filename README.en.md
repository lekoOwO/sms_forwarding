# Low-Cost SMS Forwarder

[繁體中文](README.md) | [简体中文](README.zh-CN.md) | [English](README.en.md)

This project uses an ESP32-C3 and an ML307-series 4G modem. It forwards received SMS messages through WiFi to email or push services.

[Management UI demo](https://lekoowo.github.io/sms_forwarding/)

> The demo does not connect to a device. It disables backup, restore, and OTA operations.

<p>
  <a href="https://github.com/lekoOwO/sms_forwarding/actions/workflows/build.yml"><img alt="CI" src="https://github.com/lekoOwO/sms_forwarding/actions/workflows/build.yml/badge.svg" /></a>
  <a href="LICENSE"><img alt="License: MIT" src="https://img.shields.io/badge/License-MIT-green.svg" /></a>
</p>

## Features

- Native ESP-IDF firmware and a web UI in Traditional Chinese, Simplified Chinese, and English.
- PDU, Unicode, multipart SMS assembly, deduplication, a blacklist, a RAM inbox, and web SMS sending.
- SMTP and up to five active push channels.
- POST JSON, Bark, GET, DingTalk, PushPlus, ServerChan, Custom JSON, Feishu, Gotify, Telegram, Discord Webhook, and ntfy.
- A separate name, title template, body template, forwarding rules, and test for each push channel.
- Five saved WiFi profiles. The device selects, connects to, and reconnects to an available saved profile.
- Development builds can provide USB recovery after config load and before WiFi starts. Production builds exclude this path.
- USB recovery accepts seventeen fixed read-only modem query IDs (`0x01` through `0x11`) and WiFi provisioning commands. Generic USB console output is not a recovery endpoint.
- Heartbeat notifications at intervals from 1 through 240 hours. The timer starts after NTP time synchronization.
- Encrypted `.smscfg` configuration export and portable restore to another device.
- Web OTA accepts signed `.smsota` packages only. Releases publish them only after the readiness gate passes.
- A firmware version in the web footer. Releases show `releaseVersion (devBuild)`. Development firmware shows `devBuild`.

> Notifications currently use WiFi only. The device stores 4G and mixed-mode choices. 4G push fails closed without verified TLS and network registration. Current hardware evidence does not prove usable 4G data delivery. GET and ntfy are WiFi-only.

## Quick start

1. Download the `sms-forwarder-VERSION.bin` full image from [Releases](https://github.com/lekoOwO/sms_forwarding/releases).
2. Flash the image at address `0x0` with Espressif [Flash Download Tool](https://docs.espressif.com/projects/esp-test-tools/en/latest/esp32c3/production_stage/tools/flash_download_tool.html) or [ESP Launchpad](https://espressif.github.io/esp-launchpad/).
3. If the device cannot find saved WiFi, connect to `SMS-Forwarder-XXXXXX`.
4. Enter password `sms-forwarder-setup`. Then open `http://192.168.1.1`.
5. After the device joins the router, sign in at the LAN address that the management page shows.
6. Sign in with username `admin` and password `admin123`. Change the password after the first login.
7. Configure email or push channels. Use the channel test to confirm delivery.

### Later OTA updates

Download `sms-forwarder-VERSION.smsota` from a release that passed the readiness gate. Open System Settings → Firmware Update in the web UI, and select this file.

**Do not upload a `.bin` file through web OTA.** `.bin` is the full USB image flashed at `0x0`. `.smsota` is the signed Web OTA package.
Web OTA writes one OTA app slot, up to 1,920 KiB. It does not write the bootloader, partition table, `appcfg`, or `coredump` regions. It stores OTA metadata in `otadata` and NVS.

## Hardware and wiring

The tested combination is an ESP32-C3 Super Mini and an ML307R-DC. The device needs 4 MB flash, a Nano SIM, and a suitable antenna.

<img src="assets/photo.png" width="200" alt="ESP32-C3 and ML307R-DC SMS forwarder" />

| ESP32-C3 | ML307R-DC |
|---|---|
| GPIO 3 (TX) | RX |
| GPIO 4 (RX) | TX |
| GPIO 5 | EN |
| GND | GND |
| 5V | VCC (5V) |

## Security notes

- The management UI uses plain HTTP. Use it only on a trusted LAN. Do not expose it directly to the Internet.
- The encrypted configuration backup contains WiFi, SMTP, and push credentials. Store the backup file and passphrase separately.
- The device uses received SMS messages only for notification forwarding. It does not execute remote-control commands from message content.

## Development documentation

See [`dev_doc/`](dev_doc/README.md) for build, flash, release, architecture, configuration format, API, and validation information.

## Thanks

Thanks to the [LINUX DO](https://linux.do) community for discussion and ideas.
