# 開發、建置與驗證

所有命令預設從 repository root 執行。

## 常用指令

`scripts/dev.sh` 會重用固定的 Compose container：

```sh
scripts/dev.sh build frontend
scripts/dev.sh build firmware
scripts/dev.sh lint all
scripts/dev.sh start mock-server
scripts/dev.sh restart mock-server
scripts/dev.sh stop mock-server
```

## 韌體版號

`firmware-version.json` 保存正式版號和 Dev build。建置只讀取這個檔案。

每個 clone 執行一次此命令：

```sh
git config core.hooksPath .githooks
```

在 `develop` 建立 commit 時，pre-commit hook 會增加 `devBuild`。如果版本檔已
加入 staged diff，hook 只會同步產生的 header，不會重複增加版號。

準備正式版時，先修改 `releaseVersion`。然後把相同 commit 合併到 `master`，
並建立相符的 `vMAJOR.MINOR.PATCH` tag。Actions 會拒絕其他 tag 或不在
`master` 上的 tag。

Dev Pre-release 只包含 USB 燒錄映像。正式 Release 包含 USB 映像和已簽章的
OTA 套件。只有正式 Release job 能讀取 OTA 私鑰。

## 唯一開發環境

本機只需要 Docker Engine 與 Docker Compose。不要在 host 另外維護一套
Arduino CLI；日常開發固定重用 Compose 的 `dev` container。

第一次建立：

```sh
docker compose build dev
docker compose up -d dev
docker compose exec dev arduino-cli version
```

之後只需啟動同一個 container：

```sh
docker compose start dev
```

進入 shell 或直接執行命令：

```sh
docker compose exec dev sh
docker compose exec dev arduino-cli compile --fqbn esp32:esp32:esp32c3:PartitionScheme=min_spiffs ./code
```

停止時用 `docker compose stop dev`，不要用 `docker compose run --rm` 建立一次
性環境。只有 Dockerfile/版本變更或環境損壞時，才用
`docker compose up -d --build --force-recreate dev` 重建。

### 鎖定版本

`Dockerfile` 以 Alpine Linux 為底，安裝官方 Arduino CLI release 並驗證
SHA-256；ESP32 的 Linux GNU 工具透過 Alpine `gcompat` 執行。
Compose 只在 image build 階段使用 host network，以避開本機 Docker bridge
DNS 問題；執行中的 `dev` container 仍使用一般 Compose network。

| 元件 | 版本 |
|---|---:|
| Alpine | 3.22 |
| Arduino CLI | 1.5.1 |
| ESP32 Arduino core | 3.3.10 |
| Node.js | 22（Alpine 3.22 package） |
| Alpine-native esptool | 5.3.0 |
| pdulib | 0.5.11（固定在 `code/src/pdulib/`） |
| ReadyMail | 0.4.2 |
| ArduinoJson | 7.4.3 |

ESP32 core 安裝後必須執行
`scripts/apply-esp32-webserver-3.3.10-patch.sh`。腳本先驗證原始
`Parsing.cpp` SHA-256，再套用 request line/header/body 上限；core 版本或來源
不符時會直接失敗。Docker image 與 CI 已自動執行，同一腳本可重複執行。

映像支援 Docker 的 `linux/amd64` 與 `linux/arm64`。升級版本時，同步修改
Dockerfile、重建映像、執行 smoke check 與完整 firmware compile；Arduino
CLI archive 的 checksum 必須取自對應官方 release，不可略過。

Boards Manager 會先安裝整個 ESP32 platform；Dockerfile 立即刪除非 C3
的 compiler/SDK 與下載暫存。這是本專案專用環境，不支援用同一 image
編譯其他 ESP32 型號；需要其他型號時再移除對應的清理項。
ESP32 core 附帶的 Linux `esptool` 是 glibc PyInstaller binary，`gcompat` 不足
以執行；映像用同版的 Alpine-native Python venv 取代這個單一可執行檔。

### Host 檔案權限

映像預設使用 UID/GID 1000。Host 帳號不同時，在第一次 build 傳入實際值：

```sh
USER_ID="$(id -u)" GROUP_ID="$(id -g)" docker compose build dev
docker compose up -d dev
```

這兩個值只影響 container 使用者，不會寫入專案設定。

## WiFi 設定陷阱

`code/wifi_config.h` 目前同時「被 Git 追蹤」且「列在 `.gitignore`」。Git
仍會追蹤它的修改；不要把真實 SSID/密碼提交。實機測試前可在本機暫時修改，
但提交或切換工作前務必執行：

```sh
git diff -- code/wifi_config.h
git status --short
```

看到真實憑證時，先將內容恢復為無敏感資訊的 placeholder，再進行任何
stage、commit 或 PR 操作。

## 編譯

### Web UI

第一次安裝或 lockfile 變更後，在同一個 container 安裝依賴：

```sh
docker compose exec dev sh -lc 'cd web && npm ci'
```

開發伺服器可把 API 請求代理到實機。將位址換成裝置目前的 IP，然後瀏覽
`http://localhost:5174`；HTTP Basic Auth challenge 也會經由 proxy 傳回：

```sh
docker compose exec -e DEVICE_URL=http://192.168.1.50 dev sh -lc 'cd web && npm run dev'
```

Production build 與型別檢查：

```sh
docker compose exec dev sh -lc 'cd web && npm run check && npm run build'
python3 -m unittest tests/test_web_bundle.py
```

`npm run build` 會更新 `code/data/index.html.gz` 與 `code/web_bundle.h`。Firmware
使用 header 內的 gzip bytes；舊 gzip 檔只保留供 bundle reproducibility test。
Build 設有 256 KiB 上限。`web/build/` 是可重建輸出，不應提交。

GitHub Pages Demo 使用 build-time in-memory API。Demo 會停用備份、還原與 OTA：

```sh
docker compose exec -e VITE_DEMO_MODE=1 dev sh -lc 'cd web && npm run build'
```

完成 Demo artifact 後，重新執行一般 production build，避免把 Demo 編入 firmware。

### Mock Server

Mock Server 使用 `node:22-alpine` 與 Express。它掛載並提供相同的
`web/build/index.html`，因此不維護第二份 Mock 專用 UI。啟動與重新啟動會先
檢查並建置 production frontend：

```sh
scripts/dev.sh start mock-server
```

開啟 `http://localhost:4174`，或從區網開啟
`http://<開發主機的區網 IP>:4174`。Compose 的 LAN Mock 會停用 Basic Auth，
避免瀏覽器快取帳密後進入認證重試。OpenAPI 文件位於
`dev_doc/openapi.json`，也可讀取 `http://localhost:4174/openapi.json`。

Mock 的 contract test 仍以 Basic Auth 啟用的預設模式執行，並驗證未認證
request 會收到 `401`。實機韌體始終要求 Basic Auth。

Mock 設定只保存在記憶體，container 重新建立後會回到預設值。它模擬 HTTP
contract，不模擬 UART 時序、行動網路、簡訊或硬體故障。

API 與 production UI 的自動驗證在同一個 Mock container 執行：

```sh
docker compose exec -T mock-server npm test
python3 -m unittest tests/test_api_contract.py tests/test_config_schema.py tests/test_runtime_ota.py
```

### Firmware

CI 的唯一基線命令是：

```sh
docker compose exec dev arduino-cli compile --fqbn esp32:esp32:esp32c3:PartitionScheme=min_spiffs ./code
```

目前鎖定版本的基線結果為 Flash `1462019 / 1966080 bytes`（74%）、全域變數
`63316 / 327680 bytes`（19%）。這只證明編譯與靜態配置，不代表實機 heap
尖峰、UART 時序或 modem 相容性已驗證。

這證明 generic ESP32-C3 編譯通過。實際 MakerGO ESP32 C3 SuperMini 若已由
所裝 core 提供專用 FQBN，可先查詢再使用：

```sh
docker compose exec dev sh -lc "arduino-cli board listall | grep -E 'ESP32.*C3|MakerGO'"
```

不要把 `esp32:esp32:makergo_c3_supermini` 當成所有 core 版本都保證存在的
CI 事實。

### OTA release

GitHub `release` environment 的 secret `OTA_SIGNING_PRIVATE_KEY` 必須包含完整
PEM private key，並為該 environment 設定 required reviewer。一般 build job 只有
read 權限且接觸不到 private key；`v` tag 的 firmware artifact 會交給隔離的
release job 驗證 signer、簽署 `.smsota`，再建立 GitHub Release。裝置只保存
public key。不要把 private key 或未遮蔽 secret 寫入檔案。

本機只需驗證 package builder 時，可使用測試 key 與下列命令。`counter` 必須
大於裝置已接受的 release counter：

```sh
python3 scripts/sign-ota-release.py build/firmware/code.ino.bin build/firmware/test.smsota \
  --private-key /path/to/test-private.pem --version v1.0.0 --counter 1
```

PBKDF2 目前使用 210,000 iterations。這個值來自 schema manifest，不代表
ESP32-C3 實機延遲已達標。Release 前必須記錄 crypto task 時間、free heap、
stack high-water mark，以及 OTA 期間的 UART 接收結果。

## 燒錄與 Serial

Container 預設只負責可重現編譯，不取得 host 裝置。需要燒錄時，在 Linux
為同一個 `dev` service 增加本機 Compose override，把實際 serial device 與
其群組權限映射進 container；不要提交個人 `/dev/tty*` 或 COM port。
根目錄 `compose.override.yaml` 已被忽略，可在本機寫入：

```yaml
services:
  dev:
    devices:
      - /dev/ttyACM0:/dev/ttyACM0
    group_add:
      - "${SERIAL_GID}"
```

啟動前取得該裝置的實際 group ID：

```sh
export SERIAL_GID="$(stat -c %g /dev/ttyACM0)"
docker compose up -d --force-recreate dev
```

映射完成後，在同一個 container 先辨識連接埠：

```sh
docker compose exec dev arduino-cli board list
```

管理頁已編入 firmware。`code/partitions.csv` 是 4 MB OTA layout：兩個
`0x1E0000` app slot、128 KiB `appcfg` NVS 與 64 KiB coredump。它不使用
LittleFS，並由 bootloader 提供 app rollback。

第一次從舊 layout 升級必須先匯出需要保留的設定，再用 USB 完整擦除並重刷
firmware。改分區會移動 app 與 NVS，不能透過舊版 OTA 安全遷移：

```sh
docker compose exec dev /opt/esptool-venv/bin/esptool --chip esp32c3 --port /dev/ttyACM0 erase-flash
docker compose exec dev arduino-cli compile --upload --fqbn esp32:esp32:esp32c3:PartitionScheme=min_spiffs --port /dev/ttyACM0 ./code
```

改用其他 FQBN、flash size 或 partition scheme 前，先讀對應 partition CSV，
重新確認兩個 OTA slot、`otadata`、`appcfg` 與 coredump 的 offset 和 size。

下面只是一個 Linux + MakerGO FQBN 範例；請把 FQBN 與 serial
device 換成實際查到的值：

```sh
docker compose exec dev arduino-cli compile --upload --fqbn esp32:esp32:makergo_c3_supermini --port /dev/ttyACM0 ./code
docker compose exec dev arduino-cli monitor --port /dev/ttyACM0 --config baudrate=115200
```

## 實機驗證紀錄

2026-08-16 以 ESP32-C3 rev 0.4、4 MB XMC flash、USB ID `303a:1001`、未插 SIM
驗證目前 `develop` 工作樹：

- 完整擦除舊 layout 後，新雙 OTA slot partition、內嵌 UI、首次開機帳號與
  management HTTP task 正常；未認證 401、缺 CSRF 403、超過 body cap 413。
- 無 SIM 時 `modemReady=false`，管理 API 仍可用；modem query job 有界失敗，
  不會卡住 HTTP。RAM log 的 cursor pagination 可連續取頁，重開即清空，
  沒有 NVS/flash 寫入。
- 210,000 次 PBKDF2 在 crypto task priority 0 時超過 5 分鐘；調整為與 loop
  同級後，加密匯出為 22.746 秒，期間 HTTP poll 約 38 ms。錯誤密碼不寫入，
  正確還原會原子保存並重啟，identity 與管理帳號保留。
- 實機發現同步 WebServer 的 raw body 會在 binary NUL 截斷；chunk 改為
  Base64 後，302-byte 含 NUL 備份完整收到 `nextOffset=302`。最大合法
  32,828-byte restore 另發現 6 KiB management HTTP task stack overflow；改為
  12 KiB 後連續六次安全失敗且 coredump 維持空白。
- Crypto task 原本在 `vTaskDelete(nullptr)` 前仍持有 C++ owner，失敗 restore
  每次會遺失約 36 KiB heap。讓 owner 在刪除 task 前正常解構後，六次最大
  restore 未再出現相同累積下降。
- 1,461,584-byte 正簽 OTA 在 19.562 秒完成、切換 slot 並健康開機；錯誤簽章
  在 flash write 前拒絕，同一 release counter 重播亦拒絕。另以一次性測試
  key 驗證 healthy counter 2 後，counter 3 在健康確認前重啟會被 bootloader
  標為 aborted 並回到 counter 2；accepted floor 保持 2，pending 已清除。
- 有訊號但無流量的 SIM 可識別、註冊、切換飛航模式並在 modem soft restart
  後恢復；無流量 ping 於 30 秒內以 unreachable 結束，隨後 AT dispatcher
  仍可用。測試未撥號或啟用漫遊資料。
- 同板 ML307A 搭配可上網 SIM 在本地網路註冊（`CEREG=1`，營運商代碼
  `46697`），取得 IPv4/IPv6 並以單一 ICMP request 驗證資料可達；未撥號、
  未傳簡訊、未啟用漫遊。嚴格 MHTTP HTTPS probe 使用 CA、server auth、
  certificate time check 與 TLS 1.2，但公開正向 fixture 仍無法完成 handshake，
  因此無法證明 hostname 驗證；未嘗試 `auth=0`，也未傳送真實 provider token，
  shipping firmware 繼續 fail-closed。
- 同日後續以同板 ML307A、臨時私有 CA relay fixture 重跑嚴格 TLS 1.2
  MHTTP probe；NTP 已同步（log 的 UTC epoch `1786884318`，即
  `2026-08-16 12:45:18 UTC`），OpenSSL server 收到完整 `Finished`，私有 CA
  正向 handshake 成功。錯誤憑證 fixture 曾回 MHTTP error 2，但 probe 中斷且
  server 沒有收到連線，未形成可信的負向驗證，不能據此宣稱憑證拒絕已證實。
- 此 SIM 在 LTE 註冊後會自動 attach 並讓 context 1 保持 active；即使
  `CGACT=0,1` 回覆 `OK`，讀回仍為 active。`CGATT=0` 才能得到
  `CGATT=0`、`CGACT: 1,0`，但同時變成 `CEREG=11`、無法接收 LTE 簡訊。
  本次收尾另對 `MHTTPDEL=0..3` 與 `MHTTPTERM` 逐一取得 `OK`，再以
  `AT+CGATT=0` 收尾，讀回 `+CGATT: 0`、`+CGACT: 1,0`（context 8 亦為 0）、
  `+CEREG: 0,11`。NAT-PMP gateway `192.168.10.1` 對 TCP `18443` 的
  lifetime=0 request 回 result 0、public port 0、lifetime 0；relay server
  與 listener 均已停止。正式執行時依靠 cellular delivery
  fail-closed，不能把 bearer active 誤報成韌體已產生流量。
- 可收簡訊的 SIM 只向 `10010` 發送 `HFMX`。實機回覆的單段 PDU 為約
  326--330 個 hex 字元，揭露舊 300 字元上限會誤判合法 UCS-2 multipart。
  上限改為 400 後，完整多段回信成功重組並經 WiFi POST 到臨時本地接收器；
  接收器與通道在驗證後停用並清空。
- 最大設定檔、三個 active Web jobs、job queue overflow、RAM log pagination、
  healthy OTA 與 forced rollback 均已在同一板上驗證。開機後 free heap 約
  130--149 KiB。
- 同日將一台舊版 ESP32-C3 從舊分區升級至 Dev 11。升級只清除新的 128 KiB
  `appcfg` 區域，並保留位於 `0x9000` 的舊 NVS。
- 第一次開機從舊 NVS 遷移兩組 WiFi、管理帳號、Gotify、network mode、
  heartbeat 與 device name。硬重啟後，所有遷移值仍存在，預設管理帳號回傳
  `401`。
- 實機匯出的加密備份為 `SMSCFG01` envelope。離線解密結果為 `CFG2` schema
  v4。此驗證沒有啟用 CEREG、CGACT、MHTTP 或行動數據。

尚未在此板執行實際斷電發生於 flash/config commit 中間的 power-cut campaign；
軟體重啟只能覆蓋 OTA pending-verify rollback，不能取代真實斷電測試。

Linux 連接埠通常是 `/dev/ttyACM*` 或 `/dev/ttyUSB*`。Docker Desktop 對 USB
serial 的支援依 host 平台而異；無法安全映射時，容器只負責編譯，燒錄列為
未執行，不能用 host 的另一套未鎖版工具冒充相同環境。

## 開發迴圈

### 探索與文件工作

不需要製造失敗測試。用原始碼搜尋、固定輸入 fixture、schema/連結檢查、
source hash 或可重現命令證明結論；硬體觀察要記錄板型、模組、韌體版本、
輸入與實際輸出。

### 功能、行為與 bug fix

1. 先追蹤完整資料流與所有 caller。
2. 建立一個會在舊行為失敗的最小檢查。
3. 在共同責任點做最小修正。
4. 跑同一檢查確認轉綠。
5. 在固定 Compose container 跑 CI-equivalent compile。
6. 涉及 UART、PDU、NVS、WiFi、SMTP、HTTP delivery 或模組時，補做相關
   實機驗證；無硬體時明確標註未驗證。

目前倉庫沒有 host test harness。只有在新邏輯可脫離 Arduino runtime 測試
且確實降低風險時才加入最小測試；不要為單行 mapping 建立框架。

UART dispatcher、PDU、`CGACT`、reset 或 modem retry 的修改可在 deterministic
fixture 與 CI compile 通過後 commit/push 或放入 draft PR，但在實機 smoke
完成前不得標為 ready、merge 或 release。最小 smoke 應記錄板型、modem 型號
與 firmware，並覆蓋 transaction 中插入 `+CMT`、CMGS、普通/UCS-2/multipart
短信、malformed line、Ping cleanup、finite retry/degraded 與 soft/hard reset。

## 最小驗證矩陣

| 變更 | 必跑 | 額外證據 |
|---|---|---|
| 容器環境 | `docker compose config`、image build、CLI/core/lib 版本、firmware compile | amd64/arm64 至少驗證實際使用架構 |
| 僅文件 | `git diff --check`、相對連結/命令人工核對 | 無 |
| 純計算或 parser | 最小失敗/通過檢查、CI compile | 固定 fixture |
| 設定/NVS | 檢查新舊預設與遷移、CI compile | 實機重開機後讀回 |
| Web handler/UI | 失敗/通過檢查、CI compile | 瀏覽器操作與 auth/錯誤路徑 |
| OpenAPI/Mock Server | route parity、API test、production UI browser test | 實機 response 對照 |
| Push/SMTP | payload/signature fixture、CI compile | 測試 endpoint；遮蔽秘密 |
| UART/PDU/SMS/模組 | parser fixture（可行時）、CI compile | 實機收發與 Serial 記錄 |
| GitHub workflow | YAML/diff 檢查 | 對應 Actions run |

## CI 行為

`.github/workflows/build.yml` 在所有 push、pull request 與手動觸發時建置 Web
bundle，執行 schema、route parity、Mock API 與 production UI browser test，
再編譯 generic ESP32-C3。`v` 開頭的 tag 會另外簽署 OTA package 並建立 Release。

本機無 `arduino-cli` 或依賴下載失敗時，不能把「未執行」寫成「通過」；
交付時列出缺少的工具或網路限制即可。

## PR 清理 gate

開 PR 前依序檢查：

```sh
git status --short
git ls-files --others --exclude-standard
git ls-files --others --ignored --exclude-standard
git diff --check
git diff --cached --check
git show --stat --oneline --decorate -1
```

接著檢查 unstaged/staged diff，只 stage 預期檔案，確認 build/cache、真實憑證
與本機路徑都未進入 PR。跑變更範圍的 focused check 與必要 build；除非明確
要求 ready-for-review，否則建立 draft PR。
