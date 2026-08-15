# Firmware change guide

This file applies to `code/`. The root `AGENTS.md` also applies.

## Read before editing

- Runtime overview and invariants: `../dev_doc/architecture.md`
- Build and verification commands: `../dev_doc/development.md`

## Change map

- Boot order and HTTP route registration: `code.ino`
- Shared types, limits, defaults: `config_types.h`
- Global hardware/services: `globals.h`, `globals.cpp`
- NVS load/save and validity rules: `config.cpp`
- AT transport, modem lifecycle, outbound SMS: `modem.cpp`
- PDU receive, multipart assembly, filtering, admin SMS: `sms_process.cpp`
- SMTP and push providers: `push.cpp`
- Authentication, request handlers, log ring: `web_handlers.cpp`
- Static page delivery and JSON API: `web_handlers.cpp`
- Web source and generated bundle: `../web/`, `data/index.html.gz`

Keep declarations in the matching header. Do not add a new module when an
existing owner already fits.

## Runtime invariants

- The management `WebServer` runs in its dedicated FreeRTOS task. Handlers put
  blocking work into the bounded job queue; the Arduino loop is the only job
  dispatcher and the only `Serial1` owner. Config backup cryptography uses one
  bounded crypto task. Protect config, logs, jobs, OTA, and backup transfer
  state with their existing mutexes, and never hold a mutex while sending an
  HTTP response. Do not recursively call `server.handleClient()` from a request
  handler, job, or modem wait.
- Keep `Serial1.begin(115200, SERIAL_8N1, RXD, TXD)` aligned with GPIO 4 RX and
  GPIO 3 TX. `MODEM_EN_PIN` is GPIO 5.
- Preserve the versioned config codec and legacy migration. Adding a persisted
  field requires a schema migration, matching encode/decode validation, and a
  safe default for existing devices; never raw-serialize Arduino `String`.
- Web authentication supports ten account slots. Keep legacy `webUser` and
  `webPass` migration when changing account storage.
- Every management route must pass through `checkAuth()`. Treat `/at`, modem
  reset, WiFi restart, flight mode, SMS send, configuration, and logs as
  privileged operations.
- Bound all serial/PDU indexing with `SERIAL_BUFFER_SIZE`, `MAX_CONCAT_PARTS`,
  and the actual decoded part count.
- Keep PDP data disabled outside operations that explicitly require it. The
  Ping flow must attempt to deactivate it before returning.
- Do not log credentials or add new logs containing webhook tokens, SMTP
  passwords, or authentication values. SMS bodies and phone numbers are also
  sensitive.

## Cross-file changes

Adding a push type normally touches exactly these existing locations:

1. `PushType` in `config_types.h`.
2. Required-field validation in `config.cpp`.
3. Delivery logic in `push.cpp`.
4. Select option, field hints, and field visibility in `../web/`.

Adding a web route requires a handler declaration/definition and one
`server.on(...)` registration in `code.ino`. Reuse the JSON and authentication
patterns already present.

## Verification

- For a behavior change, first leave one focused check that fails for the old
  behavior. Prefer a small host-side pure-logic check when hardware is not
  required.
- Keep using the same Compose container: `docker compose up -d dev`, then
  `docker compose exec dev arduino-cli compile --fqbn esp32:esp32:esp32c3:PartitionScheme=min_spiffs ./code`.
  Do not use throwaway `docker compose run --rm` builds.
- Modem, UART, PDU, SMS, network registration, and flash behavior are not proven
  by compilation. Run the relevant hardware check and record board, modem,
  command/fixture, and observed result.
- Do not claim hardware compatibility from an AT manual or source inspection
  alone.
