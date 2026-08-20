# 開發、建置與驗證

所有命令都從 repository root 執行。

## 工具鏈基線

本專案的支援基線固定為 ESP-IDF 5.5.4 與 ESP32-C3。CI 使用固定 digest 的 `espressif/idf` container。

Build output 必須位於 `build/idf`，而 `sdkconfig` 必須位於 `build/sdkconfig`。

不安裝 ESP-IDF 也可執行 source baseline check：

```sh
python3 tools/check_idf_baseline.py
```

此命令會檢查工具鏈 pin、分區表與第三方授權文件。

## 建置韌體

在 POSIX shell 設定 `IDF_PATH`，然後執行：

```sh
IDF_PATH=/path/to/esp-idf-v5.5.4 ./tools/idf.sh build
```

在 PowerShell 執行：

```powershell
powershell -ExecutionPolicy Bypass -File tools\idf.ps1 build
```

兩個 helper 都會拒絕其他 ESP-IDF 版本。POSIX helper 也會執行 image size check。

如果已使用其他方式完成建置，請執行：

```sh
python3 tools/check_idf_baseline.py --build-dir build/idf
```

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

## 版本與發佈

`firmware-version.json` 是正式版號與 Dev build 的唯一手寫來源。下列命令檢查產生的 header：

```sh
python3 scripts/generate-firmware-version.py --check
```

`develop` 的成功 push 會建立只含 USB `.bin` 的 Dev Pre-release。

`master` 上相符的 `vMAJOR.MINOR.PATCH` tag 會建立正式 Release。正式 Release 包含 USB `.bin` 與已簽章 `.smsota`。

只有 `release` environment 可以讀取 OTA private key。Build 與 Pre-release job 不可取得此 key。

裝置只保存 public key。不要將 private key、測試憑證或未遮蔽 secret 寫入 repository。

## Focused checks

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
