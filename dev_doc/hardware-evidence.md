# 實機驗證紀錄

本文件集中保存去識別化的硬體觀察。每筆結果只適用於記錄的版本、輸入與當次環境。
板型或版本未記錄時保留此限制，不以後續成功補寫舊紀錄。

目前程式行為見 [系統架構](architecture.md)，操作流程見 [開發指南](development.md)。
Counter36–45 的 parser 分類與 cellular 傳輸細節保留在 [專門報告](hardware-counter37.md)。

TEST-key OTA 成功不代表 production 金鑰可用，也不開放正式 OTA 發佈。
CI 與 host fixtures 不能取代實機傳輸、電信時序或 provider 送達驗證。

## 2026-08-16 Arduino 歷史 TLS 紀錄

這份去識別化紀錄來自 `origin/develop` 的 Arduino 韌體，不是目前原生 ESP-IDF runtime 的實機證據：

- 板型與模組：ESP32-C3 與 ML307A。
- 輸入：NTP 同步後的嚴格 TLS 1.2 MHTTP private-CA probe。
- 結果：伺服器端確認正向 server-auth handshake 完成。
- 證據邊界：wrong-certificate、hostname mismatch 與 expired-certificate rejection 都沒有可信的負向證據。

此紀錄不證明目前原生 ESP-IDF 的 4G provider delivery 或 readiness。

## 2026-08-22 ML307A 未註冊歷史紀錄

這是較早的單次去識別化硬體紀錄，不是通用的 modem protocol fact：

- 板型：去識別化報告未記錄。
- 模組：ML307A。
- 輸入：`CPIN`、`CSQ`、`CESQ`、`CEREG`、`COPS`、`CGATT`、`CGACT`、`CGPADDR` 與 `ICCID` 查詢。
- 結果：`CPIN` ready；`CSQ=31`；`CESQ` 約為 RSRP -70 dBm；`COPS` 使用 auto 選擇但 operator absent；原始註冊回覆只記錄 `+CEREG: 0,11`。
  依 3GPP 定義，`stat=11` 是 RLOS-only；`n=0` 只控制 URC 詳細度。它不是 home、roaming 或 data-ready 狀態。
  另見 `CGATT=0`、PDP inactive、no IP；ICCID 只保留 hash。
- 識別資料已去識別化保存。

這次結果表示 SIM 與 RF 路徑有回應，但尚未完成標準網路註冊與資料啟用。
這個未註冊、RLOS-only 狀態不證明 4G push、roaming 或 data activation 已成功。

## 2026-08-24 ML307A 已註冊紀錄

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
這份紀錄不證明 Internet、TLS 或 provider delivery 可用。

## 2026-08-27 TEST-key OTA hardware evidence

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

## 2026-09-09 儲存與診斷回歸

- 修正前，在 ESP32-C3／ML307 裝置提交一次原值名稱與 hostname，HTTP 回覆
  `202`，後續 job 查詢逾時。恢復連線後 uptime 已重新計數，啟動紀錄為
  `Program panic (4)`。沒有取得 backtrace，因此不能將 panic 原因定論為 stack overflow。
- ESP-IDF target 編譯的 `handle_modern_save` frame 原為 3552 bytes；將設定快照
  改為 heap 配置後，production 與 USB profile 都是 1440 bytes。建置會執行
  `tools/check_web_stack.py`，限制此 frame 不超過 2048 bytes。配置失敗須回覆
  out-of-memory，並釋放設定鎖；`tools/test_idf_config_updates.py` 用實際配置失敗驗證。
- 裝置當次為 roaming（registration 5）。模組與 SIM API 成功但識別欄位皆空，
  原有採樣 gate 只允許 home registration。修正允許 roaming 的唯讀識別採樣，
  保留 home-only 的 operator 設定與行動傳送限制。
- 當次唯讀 operator 回覆為 `+COPS: 0,0,"",7`。這只是該次 capture，
  不代表所有模組或網路的回覆。`components/idf_web/test/test_diagnostics.py`
  執行 production query handler，驗證只呈現 operator 欄位且只送出查詢命令。
- Browser 回歸涵蓋儲存成功、失敗、重試、job 失聯及結果位於按鈕上方。
  已接受但失聯的操作顯示「結果未知」，不自動重送。正常成功未重現 Svelte 狀態更新問題。
- 本機 production、USB 編譯、48 項 modem 測試、13 項 Web package 測試與
  37 項 Mock／browser 測試通過。這是部署前的結果；後續實機儲存與識別資訊驗收
  見本文件的 counter46 網路 OTA 紀錄。

## 2026-09-09 counter46 網路 OTA 驗收

- 裝置：ESP32-C3／ML307 系列，使用既有 TEST-key USB-recovery profile；本次未接 USB。
  輸入為已提交來源 `9a40705`（包含 save／diagnostics 修復、三語 README 與長簡訊修復）。
  diagnostics CI 入口以 `python3 -m unittest components/idf_web/test/test_diagnostics.py`
  實際執行通過；multipart 與 document-language 的 CI 命令也實際執行通過。
- 建置：固定 ESP-IDF 6.0.2，`SMS_USB_RECOVERY=1`、`SMS_OTA_TEST_KEY=1`、
  `SMS_OTA_TEST_FAIL_HEALTH=0`。App 為 1,542,944 bytes，SHA-256
  `7a7893771b25756f7d63f07b7048da937e1f5d3d8fe8610e13a463fc3fec4f29`。
  已確認內嵌既有 public key，不建立或更換 trust key。
- 刷入前：app0／valid、accepted 45、零 pending。既有 public-key SHA-256 為
  `8a10937f712f0948aef8c59e22b244f61f7411722575f32f688a690c5edc7b9f`。
  加密設定 export-only 備份通過本機認證，mode 0600、863 bytes，SHA-256
  `bcdf4bbb44c2883bc774d21a1e8a3f748ef1650182fe52d2e14a5c8bffe378d3`。
- 透過既有 Web OTA 傳送 counter46、version `1.1.4-dev-9a40705` 的簽章套件。
  套件 SHA-256 為 `4e4dfe59c1e3317665d3c25ad3f27e6c9494e6443d3d7ff534f5126dfd3e3bbb`，
  terminal 結果為 `ACTION_OTA_READY`。重啟後首次 180 秒等待未能連線；延長唯讀觀察後，
  原位址恢復，確認 app1／valid、accepted 46、pending 0、pendingVerify false，key 相同。
  未重傳套件、手動 reset、切換 WiFi 或執行還原；網路恢復延遲原因未確定。
- 完整 Web gzip bundle 為 162,305 bytes，與候選逐 byte 相同；解壓後也與 build HTML 相同。
  SHA-256 為 `467c5d96a465d761f9395fc93d59822a5564fd20e5deeb9adbe2e82533bad4cc`。
- 只提交一次原值 deviceName／hostname：HTTP 202 後取得 `ACTION_CONFIG_SAVED`，
  含三秒觀察共 3.6 秒。API 可見設定前後逐值相同，uptime 連續；後續觀察 uptime
  403 → 415 → 569 秒，reset reason 為 `Software restart (3)`。本次未重現原值儲存 panic。
- 只讀診斷：manufacturer／model／revision 皆有值；IMSI／ICCID／MSISDN 皆有值。
  operator 成功回覆空字串，不再把整行 COPS 當作名稱；匹配的 Web bundle 以無可用值標示。
  不記錄識別資料原文。
- 刷入後另存一份已認證加密備份，mode 0600、863 bytes，SHA-256
  `206be2f5c0cc6c695ecb6055622126c5598420876c83008748564a46dcea99ca`。
  兩份備份在 RAM 解密後逐 byte 相同，未輸出或寫入明文。此比較涵蓋可攜設定與 data 選項，
  不涵蓋格式刻意排除的裝置本地身份／roaming 欄位。modern API 未暴露 roaming 旗標，
  因此未直接量測它的跨 OTA 值；本次沒有修改網路設定，home-only guard 的程式未變。
- 證據邊界：長簡訊修復已隨核對套件刷入，host 時序回歸通過；本次未發送實體簡訊、
  測試外部推送或驗證電信重送，不據此保證真正遺失的分段可恢復。此 TEST-key 驗收
  不提升 production OTA readiness。

## 2026-09-10 dev18／counter47 網路 OTA 驗收

- 裝置：ESP32-C3／ML307，沿用既有 TEST-key USB recovery profile。本次透過 WiFi 操作。
  來源 tree 與合併版本 `a7a39c3` 一致，韌體為 dev18，OTA counter 為 47。
- App 為 1,590,352 bytes，SHA-256 為
  `b583b5325dc90074117cbe008d869877e2889e03e516e97d919cdc323616d7f8`。
  套件 SHA-256 為 `08ac5633876865e98ef9f19a8868492d449e05f42b666b2cff41011cdf4917f6`。
- 只上傳一次簽章套件，terminal 結果為 `ACTION_OTA_READY`。
  重啟後為 app0／valid、accepted 47、pending 0、pendingVerify false，驗證金鑰不變。
- 裝置 Web gzip bundle 與候選逐 byte 相同：179,695 bytes，SHA-256 為
  `e39e0d50b73f85600bfe79c887061d43152bab55530721f76967d4791776e67f`。
- 更新前後的加密備份各為 863 bytes、mode 0600，均通過 AES-GCM 認證。
  在 RAM 解密後，803 bytes 的內容完全相同，未輸出或寫入明文。
  備份內的 `dataEnabled=false`、`kaEnabled=false` 與 network mode 0 保持不變。
  此比較涵蓋可攜設定，不涵蓋備份排除的裝置本地身份與 roaming 欄位。
- 本次未另寫設定、還原、使用 SIM 資料、探測 CA、執行保活或測試推送。
  此結果證明上述 TEST-key 套件完成 WiFi OTA 與健康確認，不證明保活或行動傳輸的實機效果。
  Production OTA 發佈 gate 維持不變。
