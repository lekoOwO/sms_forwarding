# AGENTS.md

This file provides guidance to Codex (Codex.ai/code) when working with code in this repository.

## What This Is

ESP32-C3 firmware for a low-cost SMS forwarder. A 4G/LTE modem (ML307R-DC) receives SMS over UART/AT; the ESP32-C3 decodes PDU, then forwards the message over WiFi to email (SMTP) and up to 5 simultaneous push channels, and serves a web UI for config/diagnostics.

The firmware is now native **ESP-IDF only**. The former Arduino fallback sketch has been removed. Keep inline docs/comments in Chinese when editing source files.

## Build / Flash / Monitor

Local ESP-IDF helper:

```powershell
powershell -ExecutionPolicy Bypass -File tools\idf.ps1 build
powershell -ExecutionPolicy Bypass -File tools\idf.ps1 flash -Port COM5
powershell -ExecutionPolicy Bypass -File tools\idf.ps1 monitor -Port COM5
```

The helper loads ESP-IDF 5.5.4, uses Ninja parallelism, and writes generated build files under `build/`.

Minimum ESP-IDF: **v5.3+** — `components/idf_web` registers multi-method routes with `HTTP_ANY` (added to `esp_http_server` in v5.3); older IDF versions will fail to compile. Local helper and CI (`espressif/idf:release-v5.5`) both satisfy this.

Before committing Web UI changes, run:

```powershell
npm --prefix web run check
npm --prefix web run build
node --test web/scripts/package.test.mjs
```

CI builds the ESP-IDF firmware via `.github/workflows/build.yml`.

## Architecture

Project entrypoints:

- `CMakeLists.txt`, `main/`, and `components/` are the ESP-IDF firmware.
- `components/idf_modem` owns UART1 and all modem AT traffic.
- `components/idf_sms` handles PDU SMS receive/send, SIM storage polling, multipart merge, dedup, blacklist/admin commands, and enqueueing forwards.
- `components/idf_push` owns HTTP/HTTPS push, SMTP, forward queues, retry queues, test push, and forward-rule evaluation.
- `components/idf_web` owns `esp_http_server`, all Web/API routes, scheduler, keep-alive jobs, OTA upload, diagnostics, and status JSON.
- `components/idf_wifi` owns STA/SoftAP provisioning, captive DNS, lightweight mDNS, SNTP, reconnect watchdog, and BOOT long-press provisioning.
- `components/idf_config` persists config in NVS namespace `sms_config`; old NVS keys remain additive/compatible.
- `components/web_assets` links generated gzip Web assets from `code/web_assets.cpp`; editable sources live in `web/`.

Slow work must stay off request handlers where possible: use existing worker queues for push/email/modem/keep-alive work so SMS receive and Web refresh stay responsive.

## Web UI Assets

Editable UI sources live in `web/`. Run `npm --prefix web run check` and
`npm --prefix web run build` after UI changes. The build updates generated
`code/web_assets.h` and `code/web_assets.cpp`; do not hand-edit those files.

Keep page data and dynamic values in the Svelte routes and API helpers under
`web/src/`, with matching config and locale keys where needed.

## Extension Conventions

- **New push channel**: add type handling in `components/idf_push/idf_push.cpp`, add validation, then add the Web UI option and hint under `web/src/`. `IDF_MAX_PUSH_CHANNELS` is 5.
- **New config field**: add to `IdfConfig`, load/save it in `components/idf_config/idf_config.cpp`, expose/parse it in Web config handlers, and keep the key additive with a default.
- **New HTTP route**: add a handler in `components/idf_web/idf_web.cpp`, register it in `idf_web_start()`, and prefer bounded/streaming responses over large one-shot strings.
- **Logging**: use `idf_log_line()` / `idf_logf()` for Web-visible logs. Logs are mirrored into the 120-entry ring buffer.
- **Privacy**: SMS body and phone numbers should remain masked in normal logs; full content belongs only behind explicit verbose/debug builds.
- **Modem order matters**: handshake, disable/enable data per config via `CGACT`, configure storage/CNMI/PDU mode, then wait for CEREG. PDU mode is required for Chinese SMS.
- **Receive robustness**: keep both URC receive and periodic `AT+CMGL` storage polling. Dedup makes the dual path safe.
