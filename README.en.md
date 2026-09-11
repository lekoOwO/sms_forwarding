# Low-Cost SMS Forwarder

[繁體中文](README.md) | [简体中文](README.zh-CN.md) | [English](README.en.md)

Use an ESP32-C3 and an ML307-series 4G modem to forward SMS messages from your SIM card to email or push services. A browser provides daily configuration, message access, and diagnostics.

[Download firmware](https://github.com/lekoOwO/sms_forwarding/releases) · [Try the management UI](https://lekoowo.github.io/sms_forwarding/) · [Report a problem](https://github.com/lekoOwO/sms_forwarding/issues)

The demo does not connect to a real device or perform backups, restores, or firmware updates.

## What it does

- Forwards SMS messages to email or up to five push channels at once.
  - Supports Bark, Telegram, Discord Webhook, Gotify, ntfy, DingTalk, Feishu, PushPlus, ServerChan, and custom GET or JSON requests.
- Filters messages by sender or content, with a mobile CSV editor, rule previews, and custom notification titles and bodies.
- Shows and sends SMS messages, and provides signal, SIM, and modem diagnostics. A tap or keyboard action reveals the raw diagnostic values.
- Saves up to five WiFi profiles and provides heartbeat notifications and encrypted configuration backups.
- Downloads data over HTTP or HTTPS for cellular keepalive, with HTTPS certificate configuration in the management UI.
- Manages profiles on compatible eSIM cards. Available functions depend on the card, modem, and carrier.
- Provides a management UI in Traditional Chinese, Simplified Chinese, and English.

## Prepare the hardware

- An ESP32-C3 development board with at least 4 MB flash.
- An ML307-series modem, a SIM card that can receive SMS messages, and a suitable antenna.
- A stable power supply, a USB cable, and WiFi for the initial configuration.

This wiring example uses an ESP32-C3 Super Mini and an ML307R-DC adapter board. For other boards, check the supply voltage first. Do not connect a bare modem directly to 5V.

<img src="assets/photo.png" width="200" alt="ESP32-C3 and ML307R-DC SMS forwarder" />

| ESP32-C3 | ML307R-DC |
|---|---|
| GPIO 3 (TX) | RX |
| GPIO 4 (RX) | TX |
| GPIO 5 | EN |
| GND | GND |
| 5V | VCC (5V) |

## First use

1. Download `sms-forwarder-VERSION.bin` from [Releases](https://github.com/lekoOwO/sms_forwarding/releases). Versions marked Pre-release are for testing.
2. Flash the full image at `0x0` with Espressif [Flash Download Tool](https://docs.espressif.com/projects/esp-test-tools/en/latest/esp32c3/production_stage/tools/flash_download_tool.html) or [ESP Launchpad](https://espressif.github.io/esp-launchpad/).
3. If the device cannot find saved WiFi, connect to `SMS-Forwarder-XXXXXX` with password `sms-forwarder-setup`.
4. Open `http://192.168.1.1`. Select your home or office WiFi and enter its password.
5. After provisioning, reconnect your computer or phone to the same LAN. Open the device address shown on the provisioning page.
6. Sign in with username `admin` and password `admin123`. Change the management password immediately.
7. Configure email or a push channel. Use the channel test to check delivery.

## Daily configuration

### Forwarding rules

The management UI provides an interactive CSV editor and syntax checks. Enter a sender number and message text to preview the rules.
Previews do not save configuration or send notifications. Demo results are examples only.

Existing Tab-separated rules remain supported. The management UI can convert them to CSV. Check the content before you save it.

### Cellular delivery and keepalive

Email uses WiFi only. Before you use 4G push, check mobile connectivity and enable cellular support and HTTPS certificates for the channel. 4G push does not support roaming. Availability depends on the modem, SIM card, and network.

Cellular keepalive uses SIM data and can incur charges. It requires a compatible modem and home registration.
Keepalive supports HTTP and HTTPS. HTTP is unencrypted, so do not put sensitive information in the URL. HTTPS requires a certificate for the target.
HTTPS keepalive has a separate certificate control and does not require a push channel.

## Backups and updates

The management UI exports encrypted `.smscfg` configuration backups. Store the backup file and passphrase separately. Backups contain WiFi, email, and push credentials.

Web firmware updates accept only signed `.smsota` packages compatible with your device. If the download page provides only `.bin`, use USB flashing. Do not upload `.bin` files through the web UI.

Development downloads currently provide full USB images. Production signed OTA packages are not yet available.

## Before you use the device

- The management UI uses plain HTTP. Use a trusted LAN and do not expose it directly to the Internet.
- The inbox and outbox do not store messages permanently. A device restart clears both.
- The device does not execute remote-control commands from SMS content.
- SMS sending and mobile data can incur carrier charges.

## Development and thanks

Build, architecture, and test instructions are in the [development documentation](dev_doc/README.md). This project uses the [MIT license](LICENSE).

This project derives from [MineSunshineone/sms_forwarding](https://github.com/MineSunshineone/sms_forwarding). Thanks to the upstream maintainers and contributors, and to the [LINUX DO](https://linux.do) community for discussion and shared ideas.
