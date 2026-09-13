# 開發、建置與驗證

所有命令都從 repository root 執行。

日常開發依序閱讀 [工具鏈基線](#工具鏈基線)、[建置韌體](#建置韌體) 與 [建置 Web UI](#建置-web-ui)。
發佈前核對 [版本與發佈](#版本與發佈) 及 [Focused checks](#focused-checks)。
歷次裝置操作的結果集中在 [實機驗證紀錄](hardware-evidence.md)，不作為目前所有功能均已通過的保證。

## 工具鏈基線

本專案的支援基線固定為 ESP-IDF 6.0.2 與 ESP32-C3。CI 使用固定 digest 的 `espressif/idf` container。

Production build output 必須位於 `build/idf`，而 production `sdkconfig` 必須位於 `build/sdkconfig`。
USB recovery build output 位於 `build/idf-usb-recovery`，其 `sdkconfig` 位於 `build/sdkconfig-usb-recovery`。

不安裝 ESP-IDF 也可執行 source baseline check：

```sh
python3 tools/check_idf_baseline.py
```

此命令會檢查工具鏈 pin、分區表與第三方授權文件。

### 持續開發 container

`dev` service 使用與 CI 相同的固定 ESP-IDF image。Repository 掛載在 `/workspace`，build output 會保留在 host。

此 service 預設不掛載 USB device，也不使用 privileged mode 或 host network。Container root filesystem 是唯讀的。

使用下列入口管理 service：

```sh
scripts/dev.sh dev-start
scripts/dev.sh dev-shell
scripts/dev.sh firmware-build
scripts/dev.sh dev-logs
scripts/dev.sh dev-stop
```

`dev-shell` 與 `firmware-build` 會在需要時啟動 service。`dev-shell` 會載入固定的 ESP-IDF 6.0.2 環境。

## 建置韌體

一般 production build 不需要硬體：

```sh
scripts/dev.sh firmware-build
```

如果 host 已安裝 ESP-IDF，請設定 `IDF_PATH` 並使用單一裝置入口。Production 是預設，release 必須明確指定：

```sh
IDF_PATH=/path/to/esp-idf-v6.0.2 python3 tools/device.py build
IDF_PATH=/path/to/esp-idf-v6.0.2 python3 tools/device.py build --release
```

`tools/device.py` 會拒絕其他 ESP-IDF 版本，並在 build 後執行 image size check。

如果你使用其他方式完成建置，請執行：

```sh
python3 tools/check_idf_baseline.py --build-dir build/idf
```

### 開發 USB 恢復

USB 恢復預設關閉。需要測試時，使用獨立的 build 與 sdkconfig overlay：

```sh
IDF_PATH=/path/to/esp-idf-v6.0.2 python3 tools/device.py build --usb-dev
python3 tools/test_usb_recovery.py
python3 tools/device.py --device /dev/serial/by-id/usb-... state
python3 tools/device.py --device /dev/serial/by-id/usb-... diag all
python3 tools/device.py --device /dev/serial/by-id/usb-... diag msslcipher
python3 tools/usb_recovery.py --device /dev/serial/by-id/usb-... wifi-provision --ssid 'network-name'
```

操作前可用唯讀檢查確認裝置權限與本機 pinned fallback image，不會開啟裝置或連線網路：

```sh
python3 tools/device.py --device /dev/serial/by-id/usb-... doctor
```

日常裝置操作請使用 `tools/device.py`。它是單一入口：`build` 預設建立 production
映像，`build --usb-dev` 建立 USB recovery 映像；`state`（可加 `--json`）與 `diag` 只輸出
去識別化 JSON，`reset`、`flash-app`（`flash-app0` 相容命令）與 `flash-bootloader` 預設 dry-run。實際 reset 必須使用
`--live --confirm <by-id basename>`；reset 與 app slot flash 使用原生 USB Serial/JTAG
唯一固定的 `--before usb_reset --after hard_reset` sequence；reset 之後再 probe state。
實際 app slot flash 會先執行 baseline check，`flash-app --slot` 只接受 `app0` 或 `app1`；
只接受 `build/idf/sms_forwarding_idf.bin` 或
`build/idf-usb-recovery/sms_forwarding_idf.bin` 的 regular non-symlink app image，
固定寫入 app0 `0x10000` 或 app1 `0x1f0000`，且不超過 `0x1e0000`；app-only flash 不會修改 `nvs`、`appcfg` 或
`otadata`。Live flash 另須提供相符的
`--sha256 <64-hex-digest>` pin，完成後輸出 SHA-256。
若裝置仍使用舊 bootloader，先使用相符的 ESP-IDF bootloader 進行一次性遷移：

```sh
python3 tools/device.py --device /dev/serial/by-id/usb-... flash-bootloader \
  build/idf-ota-test/bootloader/bootloader.bin --live \
  --sha256 <64-hex-bootloader-sha256> --confirm <by-id-basename>
```

`flash-bootloader` 只接受 repository 內固定 build profile 的 regular non-symlink
bootloader，固定寫入 `0x0` 且大小上限為 `0x7000`；不使用 erase、partition-table 或
merged image，因此會保留 `otadata`、`nvs`、`appcfg`、`coredump` 與兩個 app slot。
Live flash 同樣要求 baseline check、SHA-256 pin 與 exact by-id basename confirmation。
若 rollback state 無法讀取，或 pending counter 存在但 running image state 未被確認，
health task 會 fail closed 並保留 counter，不會清除 OTA floor；完成 bootloader 遷移後才可繼續 OTA。
`diag --raw` 必須明確指定，資料只寫到 stdout，不會寫入 evidence。
裝置路徑可由 `SMS_DEVICE` 提供；沒有明確 `/dev/serial/by-id/` 路徑時會 fail closed。
若 host 沒有 `esptool`，`reset` 與 live app slot flash 會使用既有 pinned
ESP-IDF 6.0.2 image；工具先解析 exact `/dev/serial/by-id/` symlink 並驗證其
target 是 character device，再以該 resolved target 映射為 container 內的單一
`/dev/sms-device`。container 使用 `--pull=never`、`--network=none`、read-only
worktree，不會直接映射 symlink、整個 `/dev` 或啟用 privileged mode。host 的
state/diag 若遇 USB permission 或 pyserial 問題，也會使用相同 pinned backend；
container 內不會遞迴啟動 container。固定的 `/dev/sms-device` 只在
`device.py` 傳遞的 hidden internal marker 下被 backend 接受；host CLI 仍只能使用
explicit by-id path。container 只另外掛載 16 MiB、`nosuid,nodev,noexec` 的
`/tmp` tmpfs，供 ESP-IDF entrypoint 使用；不會增加其他 writable volume。

### PSA configuration-backup hardware verification pending

IDF 6.0.2 移除了舊的 Mbed TLS GCM/PBKDF2 headers；target path 現在使用 PSA
PBKDF2-HMAC-SHA256 與 PSA AES-256-GCM。現有 host fixed vector 仍由 OpenSSL
path 驗證 envelope bytes，pinned IDF 6.0.2 只完成 compile/link 與 source
contract checks。尚未在實機執行 PSA fixed-vector round-trip，也尚未在實機
驗證 PSA key derivation abort、key destroy failure 的 cleanup 行為；因此不能
宣稱 PSA target runtime 與 host vector 等價。完成此項需要記錄板型、模組、
輸入與去識別化 observed result 的獨立硬體報告。

### USB recovery 協定與診斷

USB recovery 的 state 與單一 query container process budget 不超過 30 秒，並且永遠不超過呼叫端剩餘
deadline；host 無法取得 tty 時，`diag all` 使用單一 development-only batch process，最多使用呼叫端剩餘的 90 秒總 deadline。
state backend 保留 5 秒單次 timeout，外層最多提供 30 秒以涵蓋既有 retries。

`tools/usb_recovery.py` 是既有的 USB recovery protocol backend 與低階測試 CLI；
目前仍用它執行 `wifi-provision`，一般 build、state、診斷、reset 與 app slot flash
請走 `tools/device.py`。`build --usb-dev` 會使用 `sdkconfig.usb-recovery`、
`build/idf-usb-recovery` 與 `build/sdkconfig-usb-recovery`。管理資料只走 ESP-IDF USB Serial/JTAG
driver；UART0 保留一般 console，USB secondary console 會關閉。CLI 只接受
明確的 `/dev/serial/by-id/` 路徑，WiFi 密碼由隱藏提示讀取，且不會輸出。
USB 恢復是開發功能；`FIRMWARE_IS_RELEASE=1 SMS_USB_RECOVERY=1` 會在 CMake
設定階段失敗。

設定載入成功後，USB recovery 立即啟動，並在 WiFi 啟動前提供服務。WiFi 啟動後，
韌體會自動選擇並重連已保存的 WiFi 設定檔。一般 USB console 輸出不等於 recovery endpoint。

`device.py diag` 只接受固定 18 個唯讀 symbolic query ID：`ati`、`cpin`、`cereg`、
`cops`、`cgatt`、`cgact`、`cgpaddr`、`iccid`、`csq`、`cesq`、`cfun`、`creg`、
`cgreg`、`ceer`、`cimi`、`cpol`、`cgdcont` 與 `msslcipher`，或使用 `all`。不接受 COPS test、
CRSM 或任意 AT 文字。
USB recovery 不接受任意 AT 命令。正式版不編譯 `main/usb_recovery.cpp`。

The `msslcipher` query sends ID `0x12` and the exact command `AT+MSSLCIPHER=?`.
The 17 older queries keep their 96-byte response limit. `msslcipher` has a separate 192-byte
response and USB frame budget. The owner parses the capability line incrementally, including a line
longer than its 768-byte carry, then emits only the bounded canonical summary
`+MSSLCIPHER: SUMMARY;v=1;known=0xNN;count=N;unknown=0|1` followed by `OK`.
The input grammar accepts one-to-four-digit hexadecimal IDs with an optional `0x` prefix, optional
ASCII spaces, and optional parentheses. Malformed, empty, duplicate known, out-of-range, control,
inconsistent-parenthesis, trailing-junk, and `uint16_t` count-overflow input fails closed. Unknown
duplicates are counted without retaining a raw ID set. The host keeps the legacy bounded response
parser for compatibility/tests and accepts summary counts through `0xFFFF`, with `25+` as the top
count bucket.
The JSON result contains `c02b`, `c02c`, `c02f`, and `c030` support booleans, a bounded `count`, and `count_bucket`.
It contains `unknown_present` and named filter telemetry booleans: `other_line_present`, `line_overflow`,
`contains_msslcipher_token`, `contains_exact_official_prefix_anywhere`,
`leading_whitespace_before_prefix`, `parentheses_present`, and `comma_present`.
`other_line_present` is `false` when the owner filter sees no extra line and `true` when it sees a non-final line rejected or moved by the exact response-prefix filter. The remaining fields contain only bounded line-shape observations; the result does not contain raw response text or unknown IDs.
An accepted overlong capability line can set `line_overflow` while leaving `other_line_present` false.
This change adds the command and schema only. It does not claim a live hardware result.

### Web 備份與 OTA 工具

Web 設定備份與簽章 OTA 也使用同一個入口。密碼只從 `SMS_WEB_PASSWORD` 或 mode 0600
的 `--password-file` 讀取；備份 passphrase 只從 `SMS_CONFIG_PASSPHRASE` 或 mode 0600
的 `--passphrase-file` 讀取，兩者不會寫入輸出：

```sh
SMS_WEB_PASSWORD='<local-secret>' SMS_CONFIG_PASSPHRASE='<local-passphrase>' \
  python3 tools/device.py backup-config /path/to/config.smscfg --host 192.168.20.30
SMS_CONFIG_PASSPHRASE='<local-passphrase>' \
  python3 tools/device.py verify-config-backup /path/to/config.smscfg
python3 tools/device.py ota-upload /path/to/release.smsota --host 192.168.20.30
python3 tools/device.py ota-upload /path/to/release.smsota --host 192.168.20.30 \
  --live --confirm-host 192.168.20.30
SMS_WEB_PASSWORD='<local-secret>' \
  python3 tools/device.py ota-state --host 192.168.20.30
```

`backup-config --dry-run` 只檢查輸出目標。設定備份必須使用不存在的新路徑。
輸出 parent 必須是目前使用者控制的 trusted local directory。
工具先以 mode 0600 建立暫存 ciphertext。工具在發布 final path 前執行本機驗證。
驗證成功後，工具比對 inode，再以 exclusive hard link 發布設定備份。
驗證失敗或 inode 改變時，工具移除暫存檔案，且不保留 final path。

`verify-config-backup` 是純 offline 命令。此命令不建立 network client，也不連接裝置。
本機 helper 會驗證 `SMSCFG01`、AES-GCM tag、CFG2 v6／v7 header、generation、長度與 CRC。
CLI 傳給 helper 時，passphrase 只透過 stdin 傳遞。
child environment 不包含 `SMS_CONFIG_PASSPHRASE`、`SMS_WEB_PASSWORD` 或 `NODE_*` 變數。
解密後的 CFG2 只存在 RAM。helper 不輸出或寫入 plaintext，並清除可清除的 sensitive buffer。
成功輸出只包含 `bytes`、`envelopeVersion`、`schema` 與 `generation`。
此結果只證明加密備份通過認證，且 CFG2 v6／v7 容器欄位一致。
命令不執行還原，也不驗證完整欄位語意。結果不證明來源裝置或特定目標可套用。

`ota-upload` 預設只解析套件並輸出 hash、counter、version、大小與 host，不連線。
OTA live 會先取得 CSRF token，再以 8,192-byte chunk 上傳並輪詢有界 job。
只有 terminal `ACTION_OTA_READY` 才算成功。工具不會手動 reset。
這些命令不會輸出 credential、passphrase、signature、plaintext 或 image body。
`ota-state --host` 是純唯讀的 authenticated `GET /api/ota/state`，不取得或送出 CSRF token，
並以與 USB `ota-state` 相同的固定欄位輸出；`--host` 與 `--device` 互斥。
Web 回應若有未知欄位、未知 slot/state、counter 或 key fingerprint 型別錯誤，工具會停止且不輸出原始回應。

### USB WiFi 配網

WiFi 配網會送出帶有非敏感 nonce 的版本化非同步請求。USB 先回覆已接受，
再由單一受控工作執行 NVS 寫入與連線啟動；USB CLI 只送出一次，之後以
nonce 輪詢唯讀狀態，因此遺失已接受回覆時不會重送憑證。狀態會分開表示
耐久設定/啟動結果與目前連線狀態；重新開機後 RAM 中的 nonce 不會被重播。
空白密碼只適用於 Web 已完成且仍可用、且已有資料的 Web scan cache；USB
CLI 不會新增 scan，沒有 populated cache 時會 fail closed。`state` 維持舊的
5-byte 回應、預設等待 5 秒並最多重試 3 次；`wifi-provision` 預設等待 90
秒。

### Dev signed OTA test package

要在沒有 production private key 的情況測試 signed OTA，可使用：

```sh
python3 tools/device.py ota-test-package
```

此命令固定使用 `FIRMWARE_IS_RELEASE=0`、`SMS_USB_RECOVERY=1` 與
`SMS_OTA_TEST_KEY=1`，輸出預設為被忽略的
`dist/sms-forwarder-dev-test.smsota`。`--counter` 預設為 `1`，`--version`
預設為 `1.1.4-dev-test`，`--sha256` 可提供 build image 的 SHA-256 pin。
命令先在被忽略的 `build/idf-ota-test/` 固定 profile 路徑建立或重用
ephemeral P-256 private key，並把對應 public key 路徑傳給 CMake。private key 使用 mode 0600，
不進入 firmware、merged image、release workflow 或 package。命令只建置、
簽署與輸出 hash，不會上傳或重新啟動裝置。這是 NON-PRODUCTION profile；
其 counter 使用獨立的 `ota_test_meta` NVS namespace，不會改變 production
`ota_meta` floor。production public-key fingerprint
`a3b8325cb8bbff1acaa402b7f1a39124b1297462da44f4c57b60929c996c4735` 不會變更。
命令的 JSON 另含 `public_key_sha256`，它是簽署者綁定的 generated public DER
SHA-256，可與裝置 `ota-state` 的同名欄位直接比較；`.smsota` manifest 維持既有
六個欄位，不加入 key identity。

若要測試 app0 直接燒錄，先確認 `build/idf-ota-test/CMakeCache.txt` 同時顯示
`FIRMWARE_IS_RELEASE=0`、`SMS_USB_RECOVERY=1` 與 `SMS_OTA_TEST_KEY=1`，再使用
固定 image、SHA-256 與裝置名稱確認：

```sh
python3 tools/device.py --device /dev/serial/by-id/usb-... ota-state
python3 tools/device.py --device /dev/serial/by-id/usb-... flash-app --slot app0 \
  build/idf-ota-test/sms_forwarding_idf.bin --live \
  --sha256 <64-hex-image-sha256> --confirm <by-id-basename>
```

需要寫入 app1 時，只將 `--slot app0` 改為 `--slot app1`；其餘安全檢查相同。

若裝置必須以一次性方式重建目前 active app slot，才可使用下列明確的 recovery 旗標：

```sh
python3 tools/device.py --device /dev/serial/by-id/usb-... flash-app --slot app1 \
  build/idf-usb-recovery/sms_forwarding_idf.bin --replace-active \
  --confirm-active app1 --live --sha256 <64-hex-image-sha256> \
  --confirm <by-id-basename>
```

此模式需要 extended `ota-state`、valid running image、零 pending metadata、相同的 OTA public-key identity，
以及固定的 `build/idf-usb-recovery` 或 `build/idf-ota-test` profile；不會猜測其他 build 目錄。
`flash-app` 預設仍拒絕 active slot，`flash-app0` 不提供 active replacement。active 寫入、verify 或 readback
失敗時不會自動 hard-reset，裝置會留在 ROM loader，錯誤輸出固定且不包含 process detail；pre-read 可能先
hard-reset，但失敗時不會寫入 flash，且會明確回報此狀態。確認裝置狀態與 image pin 後才可重新執行。
成功時才會 hard-reset，並檢查 fresh boot、相同 slot、valid state 與 key identity。`public_key_sha256` 是唯一
可觀察的 compatibility identity；namespace 不作為 host 判斷依據。
若 reset 後驗證失敗，不要盲目重試；先以唯讀 `ota-state` 確認目前 slot、state、pending metadata 與 key identity。

若目前執行中的 USB recovery firmware 使用已遺失 private key 的非 production test key，
可用下列一次性命令以新的 test key image 重建 active slot：

```sh
python3 tools/device.py --device /dev/serial/by-id/usb-... flash-app --slot app1 \
  build/idf-ota-test/sms_forwarding_idf.bin --replace-active --confirm-active app1 \
  --rotate-test-key --confirm-new-key <new-public-key-sha256> --live \
  --sha256 <64-hex-image-sha256> --confirm <by-id-basename>
```

`--rotate-test-key` 必須同時使用 active slot、裝置、image 與新的完整 SHA-256 confirmation；
它只接受 non-release、USB recovery、`SMS_OTA_TEST_KEY=1`、`SMS_OTA_TEST_FAIL_HEALTH=0`
且 cache 指向 embedded `ota_test_public_key.der.b64` 的 test profile。執行中的 key 必須存在、
且不可是 production key；新 key 也不可與舊 key 相同。此模式不適用 production image，
也不會放寬 pending、invalid、state drift 或 readback 檢查。

新的 test private key 必須在建置時保留於 ignored profile，權限為 `0600`；不要把它加入版控，
也不要用 test key 建立 release firmware。成功重開後，先確認 `ota-state` 顯示新的 key identity，
再使用對應 private key 簽署後續 OTA。

`ota-state` 回報 app0/app1 offset、映像狀態、目前 OTA metadata 與
`public_key_sha256`；回報格式錯誤、
未知 offset 或 NVS 型別錯誤時停止，且不會清除 metadata。
TEST-key 的更新、rollback 與 replay 驗收見 [實機驗證紀錄](hardware-evidence.md)。
此證據不適用於 production 金鑰；正式發佈仍受下方 readiness gate 限制。
此 fingerprint 只是執行中韌體所回報的 observable trust key，不是 attestation。
`null` 只會在有效回退至較舊韌體的 legacy response 後出現，表示 key identity
無法觀察；它不代表 production key，也不能用於宣稱裝置未遭修改。

若一次性遷移後裝置停在 `pending-verify`，且舊 metadata 的
`accepted`、`pending`、`pendingAddr` 都不存在或是正確型別的零值，可在非 release
USB recovery build 使用下列明確命令：

```sh
python3 tools/device.py --device /dev/serial/by-id/usb-... ota-migration-recover \
  --live --confirm <by-id-basename>
```

命令只接受目前 running image 的 `pending-verify` 狀態，拒絕 active OTA、restart、
非零或錯誤型別 metadata，以及可辨識為 `VALID` 的另一個 app slot；成功後讀回
`VALID`。它不寫入 OTA counter，不提供 Web route，也不清除 NVS、`appcfg` 或 app
slot，亦不擦除 `otadata`；只有 ESP-IDF mark-valid 的 running-image state 會更新 `otadata`。
預設仍是 dry-run，且 `usb_recovery.py` 的底層命令只供
`device.py` 的 pinned container 使用。

要建立故意在 pending verification 回復的獨立開發映像，使用同一個 ignored ephemeral
key，但不同的 build/cache 目錄：

```sh
python3 tools/device.py ota-test-package --fail-health --counter <non-zero-uint32>
```

此命令只建置與簽署，不會上傳或重新啟動裝置；`build/idf-ota-test/` 的一般 test-key
映像不會被覆蓋。

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
node --test web/scripts/forward-rules.test.mjs web/scripts/diagnostic-values.test.mjs
node web/scripts/package.mjs --check
```

`npm --prefix web run build` 會更新 `code/web_assets.h` 與 `code/web_assets.cpp`。請勿手動編輯這兩個檔案。

轉發規則與保活的 host checks：

```sh
python3 tools/test_idf_config_updates.py
python3 -m unittest components/idf_web/test/test_diagnostics.py
python3 -m unittest components/idf_web/test/test_keepalive_ca.py components/idf_modem/test/test_keepalive.py
npm --prefix mock_server test
```

CSV fixtures 同時檢查 Web 解析／序列化與韌體 POSIX 比對；Mock 的規則測試結果只供示範。
瀏覽器測試涵蓋手機 CSV 編輯、舊 Tab 設定的明確轉換、來源號碼與簡訊預覽、診斷原值展開，
以及獨立保活憑證入口。保活 host fixtures 使用合成 HTTP 回應與憑證狀態，
不建立 SIM 連線、不下載真實保活流量，也不發送通知。這些檢查不能取代實機傳輸驗證。

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

`develop` 的成功 push 會建立只含 USB 完整 `.bin` 的 Dev Pre-release。此 job 不受 OTA readiness gate 影響。

`master` 上相符的 `vMAJOR.MINOR.PATCH` tag 只有在 `components/idf_web/OTA_RUNTIME_READY` 存在時才會執行正式 `release` job。
目前此檔案缺席，因此 workflow 會跳過整個正式 `release` job，不會發佈 USB `.bin` 或 `.smsota`。

只有 `release` environment 可以讀取 OTA private key。Build 與 Pre-release job 不可取得此 key。

裝置只保存 public key。不要將 private key、測試憑證或未遮蔽 secret 寫入 repository。

目前沒有可用的 matching production private key。TEST-key 的套件更新、health rollback 與 replay rejection
已有 [實機證據](hardware-evidence.md)，但不證明 production 簽章金鑰可用。正式 OTA 發佈 gate 維持關閉。

### 2026-08-27 TEST-key OTA hardware evidence

完整觀察與證據限制見 [實機驗證紀錄](hardware-evidence.md#2026-08-27-test-key-ota-hardware-evidence)。

## Focused checks

開發 stack：

```sh
python3 tools/test_mock_dev_stack.py
bash -n scripts/dev.sh
docker compose -f compose.yaml config --quiet
```

裝置工具（不連接實機）：

```sh
python3 -m unittest tools/test_device.py tools/test_usb_recovery.py
node --test tools/config_backup_verify.test.mjs
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
  tools/test_ota_observability.py \
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
  components/idf_sms/test/test_multipart.py \
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

### Cellular 推送路徑與證據

目前 4G-only 推送選擇 cellular 路徑。混合模式優先使用已連線的 WiFi，否則選擇 cellular。
SMTP 僅使用 WiFi。GET 與 POST 推送可使用 cellular。

Cellular 推送要求通道啟用 cellular 並使用 HTTPS 目標。
CA 必須綁定目標 origin，且 hash 相符。
cellular GET 僅使用固定 GET method、空 request body，rendered URL 上限為 4096 bytes；POST URL 上限為 2048 bytes，body 上限為 4096 bytes。未知 method 與超過上限的 URL 會在 owner queue 前拒絕。
模組、home registration 與 PDP 前置檢查仍須通過，資料與漫遊限制不因選擇路徑而放寬。
`idf_modem_https` 以 modem 的 MIP socket 提供 TCP，由 ESP32 上的 Mbed TLS 執行 CA 與 hostname 驗證。
cellular MIP 使用 request 的 provisioned CA。它不使用 `esp_crt_bundle_attach`；WiFi push、SMTP STARTTLS 及 ES9 仍使用 native ESP certificate bundle。
`components/idf_modem/test/https_post_fixture.cpp` 以 2048-byte URL 驗證 MIP HTTP framing。`idf_modem` 目前只把 CGPADDR 中的 IPv4 address 當作 cellular readiness；IPv6-only MIP、IPv6 SAN 與 provisioned-origin TLS 尚無 wire 或 hardware evidence。
`python3 components/idf_modem/test/test_uart_owner.py` 的 49 個 host tests 已在 sanitizer enabled environment 通過。這些 tests 不使用裝置、SIM data 或 cellular network。

[Counter42 R15](hardware-counter37.md#counter42-r15-successful-cellular-evidence) 記錄一次 cellular HTTP 200 與已確認的 cleanup。
該次 application-level success 仍為 `unknown`，不能推廣為其他目標或網路條件的成功保證。
[Counter43](hardware-counter37.md#counter43-reversible-cellular-failure) 記錄一次在收到 HTTP bytes 前的 `response_invalid`/`modem_read`，cleanup clean 且 mode restored。
[Counter44](hardware-counter37.md#counter44-final-reversible-cellular-gotify-evidence) 記錄一次 Web-only cellular Gotify HTTP 200/provider acceptance 與 mode/config/CA restore。
下方歷史紀錄各自保留原本的觀察與證據限制。

### 2026-08-24 ML307A 已註冊紀錄

完整觀察與證據限制見 [實機驗證紀錄](hardware-evidence.md#2026-08-24-ml307a-已註冊紀錄)。

### 2026-08-22 ML307A 未註冊歷史紀錄

完整觀察與證據限制見 [實機驗證紀錄](hardware-evidence.md#2026-08-22-ml307a-未註冊歷史紀錄)。

### 2026-08-16 Arduino 歷史 TLS 紀錄

完整觀察與證據限制見 [實機驗證紀錄](hardware-evidence.md#2026-08-16-arduino-歷史-tls-紀錄)。

### 2026-09-09 儲存與診斷回歸

完整觀察與證據限制見 [實機驗證紀錄](hardware-evidence.md#2026-09-09-儲存與診斷回歸)。

### 長簡訊回歸入口

`components/idf_sms/test/test_multipart.py` 編譯目前 production 合併函式與 RAM retry
函式，使用合成分段、可控時鐘與轉發入隊 sink。涵蓋晚段補齊、完成重送去重、
過期槽復用、五槽競爭、reference 衝突、入隊背壓、固定補齊窗口與通知 metadata。
舊碼會在「晚段補成 ABC 並發完整補充」斷言失敗。此測試不使用實機短信。

`components/idf_push/test/test_push_runtime.py` 的執行式 core fixture 驗證三語補充標題、
自訂範本及原文不變；同檔另有來源契約檢查。既有 SMS retention 測試主要也是來源
契約檢查，不能取代以上時序回歸。以上入口都由 firmware CI 的 focused checks 呼叫。
新加入的 diagnostics handler fixture 與文件語言／本地連結檢查也已接到同一 CI。
真實 UART／電信重送時序與 provider 送達仍須另外進行硬體驗收，本輪未執行。

### 2026-09-09 counter46 網路 OTA 驗收

完整觀察與證據限制見 [實機驗證紀錄](hardware-evidence.md#2026-09-09-counter46-網路-ota-驗收)。

## Upstream parity gap ledger

This ledger records the scoped audit of the upstream history. It does not claim full
line-by-line parity with all upstream history.

Audit boundary:

- Common ancestor: `6403a5601b2e94bbf440fa7a677d09d90a5b52a8`.
- Local delivery snapshot: `origin/develop` at `57ee000c814bcf1ac3b4419df70da8319b175002`.
- Upstream snapshot: `reference/master` at `04574e23748bf566e19e7a84343ea424f9aad38b`.
- Scope: 19 commits after the common ancestor, including merge commit `fff1595`.

The status labels have these meanings:

- `covered`: The current source and a focused host or CI check cover the behavior.
- `partial`: The current source covers part of the behavior. The row lists the gap.
- `intentional boundary`: The current source rejects or limits the input by contract.
  This does not prove that the upstream capability is unnecessary.
- `toolchain equivalent`: The old implementation does not apply to the current build.
- `missing`: The current source has no equivalent observable behavior.
- `unverified`: Source or host evidence exists, but hardware or external service evidence is absent.

| Upstream commit and behavior | Current source, tests, and evidence | Status and next action |
|---|---|---|
| `e113dd3` — move the build to ESP-IDF 6.0.2 | `.github/workflows/build.yml`, `CMakeLists.txt`, `sdkconfig.defaults`, and `tools/idf.ps1` use the current IDF 6 path. The workflow also runs the activation, install, eSIM Web, and native TLS checks. The persistent Compose `dev` build command `python3 tools/device.py build` passed, and `python3 tools/check_idf_baseline.py --build-dir build/idf` passed: firmware `1,576,032` bytes with `390,048` bytes of OTA headroom. Historical CI run `34694717521` passed lint, mock, and firmware build. | `covered` for the pinned local build baseline. The historical run and this local build do not prove a new GitHub CI run. The current delivery is tracked by [PR #6 checks](https://github.com/lekoOwO/sms_forwarding/pull/6/checks); this row does not claim that GitHub CI has passed. |
| `f7908fa` — accept equivalent gzip output in the old asset builder | The current Svelte builder is `web/scripts/package.mjs`. `web/scripts/package.test.mjs` checks deterministic output and decompressed content. | `toolchain equivalent`. The old `tools/build_web_assets.py` comparator is not a runtime feature. |
| `96c9a46` — update ESP-IDF 6 build documentation | Current `dev_doc/development.md`, `dev_doc/architecture.md`, and root build instructions describe the IDF 6.0.2 workflow. | `covered` as documentation. The language and link checks remain the acceptance check. |
| `2904be3` — add the eSIM profile download flow and activation-code parser | Current split modules are `idf_esim`, `idf_lpa_rsp`, `idf_lpa_install`, `idf_lpa_bpp`, and `idf_lpa_es9_transport`. The parser accepts three to seven fields. `components/idf_lpa/test/test_activation_code.py`, `components/idf_lpa/test/test_install.py`, and `components/idf_web/test/test_esim_install.py` cover validated optional fields and fail-closed malformed input. | `covered` for the parser and installer boundary. The tests do not assign provider-specific meaning to optional fields. |
| `12d2ef4` — report per-download heap statistics | `idf_lpa_bpp` exposes encoded and decoded byte counts. The install path logs bounded start, minimum, and end heap values. `components/idf_lpa/test/install_fixture.cpp` exercises these fields and the sanitized ES9 status log. The current ES9 and install host checks pass. | `covered` by focused host evidence. No hardware, provider delivery, or external service result is claimed. |
| `b06bd52` — recover pending profile-install notifications | `idf_esim` notification query and `idf_lpa_install` recovery handle BF37 PIR and OtherSigned entries, operation codes, stable host/sequence order, duplicate rejection, and independent host groups. `test_install.py` and `install_fixture.cpp` cover pending, removal failure, and deferred-host paths. | `covered` by focused host evidence. No hardware removal or provider delivery result is claimed. |
| `6b36bd5` — validate BPP metadata before card writes | `idf_lpa_bpp` validates the BPP profile metadata before A1/88 card writes. For BPP-first JSON order, it keeps the final profile block pending until the JSON envelope is complete. `test_es9_transport.py` covers valid BPP-first input and rejects a mismatched transaction before the final block write. | `covered` for the metadata safety gate and the tested BPP-first order. It does not claim that every provider order is valid. |
| `a6b7c02` — validate BF30 notification-removal results | `components/idf_esim/idf_esim.cpp` maps BF30 status `00` and idempotent `01` to success, and rejects failure and unknown status values. `esim_lpa_fixture.cpp` asserts these cases. | `covered` at the host parser boundary. No hardware removal result is claimed. |
| `3cb763d` — reduce profile-download memory use | Current eSIM modules use bounded strings and spans instead of the old monolithic module. `test_bpp.py`, `test_rsp.py`, `test_install.py`, and the current pinned firmware build cover the current split build. The notification path now sorts by host and sequence and rejects duplicates. | `covered` for the scoped memory and notification-order behavior. The current build passed the baseline check. |
| `a6eab1f` — bound ES9 transactions, abort BPP reads, and add generic notifications | `idf_lpa_es9_transport.cpp` has bounded transaction handling. `idf_lpa_bpp.cpp` aborts bounded reads. `test_es9_transport.py`, `test_bpp.py`, `test_rsp.py`, and `test_install.py` cover OtherSigned entries, operation codes, host grouping, and deferred independent groups. | `covered` by focused host evidence. The tests do not claim provider or card hardware behavior. |
| `fff1595` — merge the eSIM profile-download work | This is a merge commit. Its child behavior is recorded in the rows for `2904be3`, `12d2ef4`, `b06bd52`, `6b36bd5`, `a6b7c02`, `3cb763d`, and `a6eab1f`. | `reference only`. It adds no separate behavior to port. |
| `e319e67` — add cellular forwarding, caller recovery, larger MHTTP URLs, POST data, and IPv6 parsing | Current `components/idf_sms/idf_sms.cpp` has CLCC caller recovery. Current cellular push uses the MIP socket path in `idf_modem_https`, not the upstream MHTTP path. POST accepts 2048 bytes and GET accepts 4096 bytes. The data-mode path checks the IP after CGACT, and the existing sampling gate retries a missing IP. Focused UART, data-mode, and SIM-recovery fixtures cover these paths. | `covered` for the larger MIP POST framing and the CGACT/IP recovery behavior. `partial` for IPv6-only readiness: the current parser selects IPv4, and no MIP IPv6 wire or TLS IP-SAN evidence exists. The GET limit remains 4096 bytes. |
| `168a30e` — retry delayed SIM identity sampling | Local commit `958110a` implements bounded retry delays. `components/idf_modem/test/sim_identity_fixture.cpp` covers the schedule and terminal cases. | `covered` by the local implementation, with no device claim in this ledger. |
| `59d86cc` — refine eSIM download, notification, and diagnostic behavior | Current code sends unfiltered `BF 2B 00`, matching the upstream change. BPP metadata remains verified before the final card write, and valid BPP-first input is covered. Generic notification parsing, ordering, duplicate policy, and deferred host groups are covered by the LPA fixtures. Per-download encoded and decoded BPP counts, bounded start/minimum/end heap fields, and bounded `subjectCode` and `reasonCode` logging are covered by the current LPA host fixtures. | `covered` by focused host evidence. No hardware, provider delivery, or external service result is claimed. |
| `7fb43b9` — restore Telegram TLS and SIM ICCID reads | `components/idf_push/idf_push.cpp` SMTP STARTTLS and `components/idf_push/idf_push_ca.cpp` CA probing use native `esp_crt_bundle_attach`. `idf_lpa_es9_transport.cpp` also uses the native bundle. Cellular MIP uses a request-provisioned CA and is a separate trust path. Current modem identity code reads ICCID. | `covered` for the native bundle consumers and ICCID source path. The offline TLS fixture passes ordinary validity, hostname, and untrusted-root cases; it does not claim external service or hardware behavior. |
| `f375b9e` — restore the modem task include | `components/idf_modem/idf_modem.cpp` includes the task declaration needed by the current modem task. | `covered` by the firmware compile. |
| `466cdd2` — enable cross-signed certificate-chain verification | `sdkconfig.defaults` enables the full native bundle, the custom GSMA PEM bundle, and `CONFIG_MBEDTLS_CERTIFICATE_BUNDLE_CROSS_SIGNED_VERIFY=y`. The GSMA payload is the public Root CI1 source named in the config comment, with SHA-256 `01374ed6bc89ffa446d9dd38d52a8280624c5add811ba9dee7bea0bdc14b26e9`. The native bundle verifier is patched from pinned ESP-IDF commit `0e03327f698a9e69217fde1a647f5b8d4f34fd94`. The public cross-signed fixtures are `server_cert_chain.pem` (SHA-256 `eec0f042f6987193df2dce1305184cb8a39fc0845b3d0494230567598517e912`) and `server_root.pem` (SHA-256 `50ce56f5df0a10901160afd13395aea959793955fca28287fd2d88742d59f959`), copied from that Espressif test commit. No private test key is stored. | `covered` for flags, the offline verifier, and the generated artifact. The official public cross-signed fixture passes with both switch values; the test checks the synthetic-root validity difference instead of claiming that the raw public chain fails with the switch off. |
| `f507d5b` — reuse the BPP logical channel during profile download | Local commit `651d34c` owns the reusable `IdfEsimLpaBppSession`. BPP and ES9 host fixtures exercise the session boundary. | `covered` by an equivalent local implementation. |
| `04574e2` — restore SIM identity and shared forwarding-rule behavior, and add rule-index diagnostics | `components/idf_modem/idf_modem.cpp` reads ICCID when CPIN becomes ready. `/api/rules/preview` and `idf_config_evaluate_forward_rules` share the current CSV engine. The Svelte UI is the current asset architecture. The discard log uses the parser's CSV record-start `fd.line` in this worktree change; the CSV marker is not counted as a record line. | `partial`. The old generated UI is not a literal port. The quoted multi-line production discard fixture, source-language gate, current pinned firmware build, and baseline check pass. |

## Deduplicated gaps and acceptance

| Gap | Observable impact or boundary | Acceptance evidence | State |
|---|---|---|---|
| Discard-log rule line | The old discard log did not identify the matched CSV rule. The current log records the parser's CSV record-start line. | `components/idf_push/test/test_push_runtime.py` executes the production discard path with a quoted multi-line CSV fixture, captures the logger output, and asserts the forwarded ID and zero send attempts. A mutation restoring the old log fails. The current pinned firmware build and baseline check also pass. | Host and build evidence pass. No hardware or network result is claimed. |
| Generic eSIM notification recovery | Malformed or duplicate entries fail during list prevalidation. A transport, send, or removal failure for one host group can defer that group while independent groups continue. | `test_rsp.py`, `test_install.py`, `test_es9_transport.py`, and `install_fixture.cpp` cover BF37, OtherSigned, operation, host grouping, insertion order, malformed and duplicate prevalidation, deferred independent failure, and BF30 status handling. | Covered by focused host evidence. No hardware or provider delivery claim. |
| BPP-first download order | A provider package can arrive before the JSON metadata. Metadata verification must remain before the final card write. | `test_es9_transport.py` covers valid BPP-first input and a mismatched transaction. The fixture asserts that the final card write occurs only after metadata verification. | Covered by focused host evidence. |
| Activation optional fields | The parser accepts three to seven `$` fields. The installer now accepts validated optional fields and still rejects malformed input. | `components/idf_lpa/test/test_activation_code.py`, `components/idf_lpa/test/test_install.py`, and `components/idf_web/test/test_esim_install.py` cover seven-field success and fail-closed malformed input. They do not assign provider-specific OID semantics. | Covered at the parser and installer boundary. |
| Cross-signed TLS chains | The full native bundle, GSMA custom roots, and cross-signed switch are enabled. Cellular MIP trust remains separate from the native ESP bundle. | `python3 tools/test_tls_certificate_bundle.py --native` covers ordinary validity, hostname, untrusted-root, intermediate-date, and synthetic cross-signed-root cases. The generated bundle contains 145 certificates and one exact GSMA root match. | Covered by offline verifier and build-artifact evidence. No external traffic or hardware claim. |
| Download and response diagnostics | Per-download counts and heap fields, plus bounded `subjectCode` and `reasonCode` fields, are covered by the current LPA host checks. | `test_rsp.py`, `test_install.py`, `test_bpp.py`, and `test_es9_transport.py` pass in the current host evidence. Keep the Web diagnostic checks in their existing CI entry. | Covered by focused host evidence. No hardware, provider delivery, or external service result is claimed. |
| Cellular URL and IP behavior | The MIP transport accepts a 2048-byte POST URL and a 4096-byte GET URL. The production parser selects IPv4 from CGPADDR; IPv6-only MIP readiness is not proven. | Focused MIP wire, data-mode, and SIM-recovery fixtures cover the larger POST framing, CGACT/IP state, and gated missing-IP retry. A temporary post-fix mutation that restored the old CGACT error gate compiled but failed the valid-IP case. This mutation is regression evidence, not a test-first RED record. The tests do not claim IPv6 wire, IP-SAN TLS, or hardware behavior. | Covered for the tested MIP behavior; partial for IPv6-only readiness. |
| Persisted ICCID hygiene | SIM insert/remove clears runtime identity. The old NVS ICCID key remains stored, but this audit found no runtime credential lookup that consumes it. | Add a persistence test only if a future consumer needs deletion or replacement semantics. | Latent hygiene item; no current behavior fix. |

This ledger records source and host evidence. It does not claim provider, modem, SIM,
or external TLS parity. The focused discard-log slice uses host and build evidence
only; no device, network, or SIM action ran for that slice. Other goal slices can
require protocol fixtures or controlled hardware evidence, while cellular traffic
and paid side effects remain prohibited.

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
