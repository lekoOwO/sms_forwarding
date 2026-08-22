# 開發、建置與驗證

所有命令都從 repository root 執行。

## 工具鏈基線

本專案的支援基線固定為 ESP-IDF 5.5.4 與 ESP32-C3。CI 使用固定 digest 的 `espressif/idf` container。

Production build output 必須位於 `build/idf`，而 production `sdkconfig` 必須位於 `build/sdkconfig`。
USB recovery build output 位於 `build/idf-usb-recovery`，其 `sdkconfig` 位於 `build/sdkconfig-usb-recovery`。

不安裝 ESP-IDF 也可執行 source baseline check：

```sh
python3 tools/check_idf_baseline.py
```

此命令會檢查工具鏈 pin、分區表與第三方授權文件。

## 建置韌體

在 POSIX shell 設定 `IDF_PATH`，然後使用單一裝置入口。Production 是預設，release 必須明確指定：

```sh
IDF_PATH=/path/to/esp-idf-v5.5.4 python3 tools/device.py build
IDF_PATH=/path/to/esp-idf-v5.5.4 python3 tools/device.py build --release
```

`tools/device.py` 會拒絕其他 ESP-IDF 版本，並在 build 後執行 image size check。

如果你使用其他方式完成建置，請執行：

```sh
python3 tools/check_idf_baseline.py --build-dir build/idf
```

### 開發 USB 恢復

USB 恢復預設關閉。需要測試時，使用獨立的 build 與 sdkconfig overlay：

```sh
IDF_PATH=/path/to/esp-idf-v5.5.4 python3 tools/device.py build --usb-dev
python3 tools/test_usb_recovery.py
python3 tools/device.py --device /dev/serial/by-id/usb-... state
python3 tools/device.py --device /dev/serial/by-id/usb-... diag all
python3 tools/usb_recovery.py --device /dev/serial/by-id/usb-... wifi-provision --ssid 'network-name'
```

日常裝置操作請使用 `tools/device.py`。它是單一入口：`build` 預設建立 production
映像，`build --usb-dev` 建立 USB recovery 映像；`state`（可加 `--json`）與 `diag` 只輸出
去識別化 JSON，`reset` 與 `flash-app0` 預設 dry-run。實際 reset 必須使用
`--live --confirm <by-id basename>`；reset 與 app0 flash 使用原生 USB Serial/JTAG
唯一固定的 `--before usb_reset --after hard_reset` sequence；reset 之後再 probe state。
實際 app0 flash 會先執行 baseline check，
只接受 `build/idf/sms_forwarding_idf.bin` 或
`build/idf-usb-recovery/sms_forwarding_idf.bin` 的 regular non-symlink app image，
固定寫入 `0x10000` 且不超過 `0x1e0000`；app0-only flash 不會修改 `nvs`、`appcfg` 或
`otadata`。Live flash 另須提供相符的
`--sha256 <64-hex-digest>` pin，完成後輸出 SHA-256。
`diag --raw` 必須明確指定，資料只寫到 stdout，不會寫入 evidence。
裝置路徑可由 `SMS_DEVICE` 提供；沒有明確 `/dev/serial/by-id/` 路徑時會 fail closed。
若 host 沒有 `esptool.py`，`reset` 與 live `flash-app0` 會使用既有 pinned
ESP-IDF 5.5.4 image；工具先解析 exact `/dev/serial/by-id/` symlink 並驗證其
target 是 character device，再以該 resolved target 映射為 container 內的單一
`/dev/sms-device`。container 使用 `--pull=never`、`--network=none`、read-only
worktree，不會直接映射 symlink、整個 `/dev` 或啟用 privileged mode。host 的
state/diag 若遇 USB permission 或 pyserial 問題，也會使用相同 pinned backend；
container 內不會遞迴啟動 container。固定的 `/dev/sms-device` 只在
`device.py` 傳遞的 hidden internal marker 下被 backend 接受；host CLI 仍只能使用
explicit by-id path。container 只另外掛載 16 MiB、`nosuid,nodev,noexec` 的
`/tmp` tmpfs，供 ESP-IDF entrypoint 使用；不會增加其他 writable volume。
USB recovery 的 state 與單一 query container process budget 不超過 30 秒，並且永遠不超過呼叫端剩餘
deadline；host 無法取得 tty 時，`diag all` 使用單一 development-only batch process，最多使用呼叫端剩餘的 90 秒總 deadline。
state backend 保留 5 秒單次 timeout，外層最多提供 30 秒以涵蓋既有 retries。

`tools/usb_recovery.py` 是既有的 USB recovery protocol backend 與低階測試 CLI；
目前仍用它執行 `wifi-provision`，一般 build、state、診斷、reset 與 app0 flash
請走 `tools/device.py`。`build --usb-dev` 會使用 `sdkconfig.usb-recovery`、
`build/idf-usb-recovery` 與 `build/sdkconfig-usb-recovery`。管理資料只走 ESP-IDF USB Serial/JTAG
driver；UART0 保留一般 console，USB secondary console 會關閉。CLI 只接受
明確的 `/dev/serial/by-id/` 路徑，WiFi 密碼由隱藏提示讀取，且不會輸出。
USB 恢復是開發功能；`FIRMWARE_IS_RELEASE=1 SMS_USB_RECOVERY=1` 會在 CMake
設定階段失敗。

設定載入成功後，USB recovery 立即啟動，並在 WiFi 啟動前提供服務。WiFi 啟動後，
韌體會自動選擇並重連已保存的 WiFi 設定檔。一般 USB console 輸出不等於 recovery endpoint。

`device.py diag` 只接受固定 17 個唯讀 symbolic query ID：`ati`、`cpin`、`cereg`、
`cops`、`cgatt`、`cgact`、`cgpaddr`、`iccid`、`csq`、`cesq`、`cfun`、`creg`、
`cgreg`、`ceer`、`cimi`、`cpol` 與 `cgdcont`，或使用 `all`。不接受 COPS test、
CRSM 或任意 AT 文字。
USB recovery 不接受任意 AT 命令。正式版不編譯 `main/usb_recovery.cpp`。

WiFi 配網會送出帶有非敏感 nonce 的版本化非同步請求。USB 先回覆已接受，
再由單一受控工作執行 NVS 寫入與連線啟動；USB CLI 只送出一次，之後以
nonce 輪詢唯讀狀態，因此遺失已接受回覆時不會重送憑證。狀態會分開表示
耐久設定/啟動結果與目前連線狀態；重新開機後 RAM 中的 nonce 不會被重播。
空白密碼只適用於 Web 已完成且仍可用、且已有資料的 Web scan cache；USB
CLI 不會新增 scan，沒有 populated cache 時會 fail closed。`state` 維持舊的
5-byte 回應、預設等待 5 秒並最多重試 3 次；`wifi-provision` 預設等待 90
秒。

## 建置 Web UI

第一次建置或 lockfile 變更後，安裝固定依賴：

```sh
npm ci --prefix web
```

執行型別檢查、production build 與可重現 bundle check：

```sh
npm --prefix web run check
npm --prefix web run build
node --test web/scripts/package.test.mjs
node web/scripts/package.mjs --check
```

`npm --prefix web run build` 會更新 `code/web_assets.h` 與 `code/web_assets.cpp`。請勿手動編輯這兩個檔案。

## 燒錄與監看

PowerShell helper 支援 USB 燒錄與 serial monitor：

```powershell
powershell -ExecutionPolicy Bypass -File tools\idf.ps1 flash -Port COM5
powershell -ExecutionPolicy Bypass -File tools\idf.ps1 monitor -Port COM5
```

請將 `COM5` 換成實際連接埠。不要將個人連接埠或裝置路徑寫入 repository 設定。

GitHub Release 的 `sms-forwarder-VERSION.bin` 是合併後的 USB 完整映像。此檔案必須從位址 `0x0` 燒錄。

Web OTA 會寫入一個 OTA app slot，大小上限為 1,920 KiB。它不會寫入 bootloader、
partition table、`appcfg` 或 `coredump`，但會更新 `otadata` 與 NVS 的 OTA metadata。
完整 `.bin` 的 `0x0` 燒錄路徑不等於 Web OTA 路徑。

## 版本與發佈

`firmware-version.json` 是正式版號與 Dev build 的唯一手寫來源。下列命令檢查產生的 header：

```sh
python3 scripts/generate-firmware-version.py --check
```

`develop` 的成功 push 會建立只含 USB `.bin` 的 Dev Pre-release。

`master` 上相符的 `vMAJOR.MINOR.PATCH` tag 會建立正式 Release。USB `.bin` 可由 release workflow 建立；已簽章 `.smsota` 只有在 readiness gate 通過時才會建立。

只有 `release` environment 可以讀取 OTA private key。Build 與 Pre-release job 不可取得此 key。

裝置只保存 public key。不要將 private key、測試憑證或未遮蔽 secret 寫入 repository。

目前 checkout 沒有 `components/idf_web/OTA_RUNTIME_READY`，也沒有 matching private key。
硬體 rollback/replay evidence 仍未完成，因此目前不能把 signed OTA 標記為 READY。

## Focused checks

裝置工具（不連接實機）：

```sh
python3 -m unittest tools/test_device.py tools/test_usb_recovery.py
python3 -m py_compile tools/device.py tools/test_device.py
```

設定 schema 與 persistence：

```sh
python3 tools/generate-config-schema.py --check
python3 -m unittest \
  tools/test_config_schema.py \
  tools/test_idf_config_codec.py \
  tools/test_idf_config_persistence.py \
  tools/test_idf_config_updates.py
```

Release、Web security 與 OTA：

```sh
python3 -m unittest \
  tools/test_firmware_release.py \
  components/idf_web/test/test_openapi_conformance.py \
  components/idf_web/test/test_ota_runtime.py \
  components/idf_web/test/test_web_security.py
```

模組、簡訊、推送與 WiFi：

```sh
python3 -m unittest \
  components/idf_modem/test/test_uart_owner.py \
  components/idf_push/test/test_push_runtime.py \
  components/idf_sms/test/test_sms_retention_policy.py \
  components/idf_wifi/test/test_wifi_security.py
```

文件語言與連結：

```sh
python3 -m unittest tests/test_document_languages.py
```

文件工作不需要建立人工 failing test。請使用 language manifest、JSON parser、link check 與 schema check 驗證結果。

## 實機驗證

CI compile 不會證明 UART 時序、SIM、PDU、SMTP、推送服務或 OTA rollback 的實機行為。

涉及這些路徑時，請記錄板型、模組型號、韌體版本、輸入與觀察結果。無實機時，請明確標示未執行。

### 2026-08-22 ML307A 紀錄

這是單次去識別化硬體紀錄，不是通用的 modem protocol fact：

- 板型：去識別化報告未記錄。
- 模組：ML307A。
- 輸入：`CPIN`、`CSQ`、`CESQ`、`CEREG`、`COPS`、`CGATT`、`CGACT`、`CGPADDR` 與 `ICCID` 查詢。
- 結果：`CPIN` ready；`CSQ=31`；`CESQ` 約為 RSRP -70 dBm；`COPS` 使用 auto 選擇但 operator absent；原始註冊回覆只記錄 `+CEREG: 0,11`。
  依 3GPP 定義，`stat=11` 是 RLOS-only；`n=0` 只控制 URC 詳細度。它不是 home、roaming 或 data-ready 狀態。
  另見 `CGATT=0`、PDP inactive、no IP；ICCID 只保留 hash。
- 識別資料已去識別化保存。

這次結果表示 SIM 與 RF 路徑有回應，但尚未完成標準網路註冊與資料啟用。
它不證明 4G 可用。4G push、roaming 與 data activation 必須維持 fail closed。

## PR 清理 gate

開啟 PR 前執行：

```sh
git status --short
git ls-files --others --exclude-standard
git ls-files --others --ignored --exclude-standard
git diff --check
git diff --cached --check
git show --stat --oneline --decorate -1
```

只 stage 預期檔案。請確認 build output、cache、憑證與個人路徑未進入 PR。
