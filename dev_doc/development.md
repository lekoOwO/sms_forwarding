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

`dev-shell` 與 `firmware-build` 會在需要時啟動 service。`dev-shell` 會載入固定的 ESP-IDF 5.5.4 環境。

## 建置韌體

一般 production build 不需要硬體：

```sh
scripts/dev.sh firmware-build
```

如果 host 已安裝 ESP-IDF，請設定 `IDF_PATH` 並使用單一裝置入口。Production 是預設，release 必須明確指定：

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
若 host 沒有 `esptool.py`，`reset` 與 live app slot flash 會使用既有 pinned
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
response and USB frame budget, so its maximum is 24 IDs and its top count bucket is `17-24`.
The host parser accepts one bounded response line with unique four-digit hexadecimal IDs.
Malformed, duplicate, out-of-range, and control-character input fails closed.
The JSON result contains `c02b`, `c02c`, `c02f`, and `c030` support booleans, a bounded `count`, and `count_bucket`.
It contains `unknown_present`, but it does not contain raw response text or unknown IDs.
This change adds the command and schema only. It does not claim a live hardware result.

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
```

`backup-config --dry-run` 只檢查輸出目標。設定備份必須使用不存在的新路徑。
輸出 parent 必須是目前使用者控制的 trusted local directory。
工具先以 mode 0600 建立暫存 ciphertext。工具在發布 final path 前執行本機驗證。
驗證成功後，工具比對 inode，再以 exclusive hard link 發布設定備份。
驗證失敗或 inode 改變時，工具移除暫存檔案，且不保留 final path。

`verify-config-backup` 是純 offline 命令。此命令不建立 network client，也不連接裝置。
本機 helper 會驗證 `SMSCFG01`、AES-GCM tag、CFG2 v6 header、generation、長度與 CRC。
CLI 傳給 helper 時，passphrase 只透過 stdin 傳遞。
child environment 不包含 `SMS_CONFIG_PASSPHRASE`、`SMS_WEB_PASSWORD` 或 `NODE_*` 變數。
解密後的 CFG2 只存在 RAM。helper 不輸出或寫入 plaintext，並清除可清除的 sensitive buffer。
成功輸出只包含 `bytes`、`envelopeVersion`、`schema` 與 `generation`。
此結果只證明目前 v6 envelope 通過認證，且 CFG2 容器欄位一致。
命令不執行還原，也不驗證完整欄位語意。結果不證明來源裝置或特定目標可套用。

`ota-upload` 預設只解析套件並輸出 hash、counter、version、大小與 host，不連線。
OTA live 會先取得 CSRF token，再以 8,192-byte chunk 上傳並輪詢有界 job。
只有 terminal `ACTION_OTA_READY` 才算成功。工具不會手動 reset。
這些命令不會輸出 credential、passphrase、signature、plaintext 或 image body。

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
未知 offset 或 NVS 型別錯誤時停止，且不會清除 metadata。尚未完成實機 rollback、
replay 與 signed OTA 證據前，停止於 host build/package 與唯讀 `ota-state`；不要執行
實機 flash、Web upload 或宣稱 signed OTA READY。
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

`develop` 的成功 push 會建立只含 USB 完整 `.bin` 的 Dev Pre-release。此 job 不受 OTA readiness gate 影響。

`master` 上相符的 `vMAJOR.MINOR.PATCH` tag 只有在 `components/idf_web/OTA_RUNTIME_READY` 存在時才會執行正式 `release` job。
目前此檔案缺席，因此 workflow 會跳過整個正式 `release` job，不會發佈 USB `.bin` 或 `.smsota`。

只有 `release` environment 可以讀取 OTA private key。Build 與 Pre-release job 不可取得此 key。

裝置只保存 public key。不要將 private key、測試憑證或未遮蔽 secret 寫入 repository。

目前 checkout 沒有 matching private key。2026-08-27 的 TEST-key hardware evidence 已證明 test-key package pipeline、health rollback 與 replay rejection，但不證明 production signing-key ownership。因此目前不能把 signed OTA 標記為 READY。

### 2026-08-27 TEST-key OTA hardware evidence

Board and modem details are intentionally omitted from this sanitized record.
Input: TEST-key signed OTA package flows and a replay request.

The healthy signed package was accepted and booted the inactive app.
Health validation accepted the image, and the accepted counter increased by one.

The forced fail-health package was staged and booted.
Automatic rollback restored the prior healthy app, and the accepted counter stayed unchanged.

A replay of the accepted counter returned HTTP 400 `ACTION_OTA_MANIFEST_INVALID`.
The active slot, accepted counter, and pending state stayed unchanged.

This record proves the TEST-key package pipeline, health rollback, and replay rejection.
It does not prove production signing-key ownership or authorize a release.
Keep `components/idf_web/OTA_RUNTIME_READY` absent. The formal release gate must fail closed.

The ignored test private key remains mode 0600. Encrypted configuration backups remain retained.

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

### 2026-08-24 ML307A 已註冊紀錄

這是單次去識別化的唯讀硬體紀錄，不是通用的 modem protocol fact：

- 板型與韌體版本：去識別化摘要未記錄。`device.py doctor` 回報 `ready=true` 與 `host_read_write=true`。
- 模組與輸入：ML307A；唯讀輸入為 `CPIN`、`CEREG`、`COPS`、`CGATT`、`CGACT` 與 `CGPADDR` 查詢。
- 結果：`CPIN` ready；`CEREG stat=1` 是 home registered、E-UTRAN 且 `roaming=false`。
  `COPS` 是 automatic，operator present，且 access technology 是 E-UTRAN。
  `CGATT` 是 attached；`CGACT` 只有一個 active context。
- `CGPADDR` 結構只有一個有效回覆行與一個 CID。該 CID 同時有 IPv4 與 IPv6。
- `cc10c2a` 提供 `CGPADDR` sanitizer 結構；`41d3708` 提供 runtime dual-stack parser。

文件不記錄 operator、ICCID、IMSI、IMEI、address、APN 或 credential 值。
此次操作沒有使用 write AT、manual `COPS`，也沒有執行 `CFUN`、`CGATT`、`CGACT` 或 PDP 狀態變更。
這份紀錄不證明 Internet、TLS 或 provider delivery 可用。4G push 維持 fail closed。

### 2026-08-22 ML307A 未註冊歷史紀錄

這是較早的單次去識別化硬體紀錄，不是通用的 modem protocol fact：

- 板型：去識別化報告未記錄。
- 模組：ML307A。
- 輸入：`CPIN`、`CSQ`、`CESQ`、`CEREG`、`COPS`、`CGATT`、`CGACT`、`CGPADDR` 與 `ICCID` 查詢。
- 結果：`CPIN` ready；`CSQ=31`；`CESQ` 約為 RSRP -70 dBm；`COPS` 使用 auto 選擇但 operator absent；原始註冊回覆只記錄 `+CEREG: 0,11`。
  依 3GPP 定義，`stat=11` 是 RLOS-only；`n=0` 只控制 URC 詳細度。它不是 home、roaming 或 data-ready 狀態。
  另見 `CGATT=0`、PDP inactive、no IP；ICCID 只保留 hash。
- 識別資料已去識別化保存。

這次結果表示 SIM 與 RF 路徑有回應，但尚未完成標準網路註冊與資料啟用。
它不證明 4G 可用。4G push、roaming 與 data activation 必須維持 fail closed。

### 2026-08-16 Arduino 歷史 TLS 紀錄

這份去識別化紀錄來自 `origin/develop` 的 Arduino 韌體，不是目前原生 ESP-IDF runtime 的實機證據：

- 板型與模組：ESP32-C3 與 ML307A。
- 輸入：NTP 同步後的嚴格 TLS 1.2 MHTTP private-CA probe。
- 結果：伺服器端確認正向 server-auth handshake 完成。
- 證據邊界：wrong-certificate、hostname mismatch 與 expired-certificate rejection 都沒有可信的負向證據。

此紀錄不證明目前原生 ESP-IDF 的 4G provider delivery 或 readiness。4G push 維持 fail closed。

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
