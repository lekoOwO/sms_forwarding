# 開發文件

這裡是本專案開發資訊的唯一入口。公開功能、硬體採購與接線說明仍放在
根目錄 `README.md`；實作、建置、驗證與維護資訊集中在本目錄。

## 先讀哪一份

- 要建立環境、編譯、燒錄或驗證：讀 [development.md](development.md)。
- 要理解啟動、資料流、模組邊界或 HTTP 路由：讀
  [architecture.md](architecture.md)。
- 要查 HTTP request、response 與狀態碼：讀 [openapi.json](openapi.json)。
- 要修改韌體：再讀 [`../code/AGENTS.md`](../code/AGENTS.md)。
- 要維護文件：再讀 [`AGENTS.md`](AGENTS.md)。

## 30 秒專案地圖

這是一個 ESP32-C3 Arduino sketch。ESP32 透過 UART 控制 4G 模組，以 PDU
模式接收/發送簡訊，透過 WiFi 提供 HTTP 管理頁，並把收到的簡訊寄到 SMTP
或最多五個推送通道。所有執行期程式都在 `code/`。

| 位置 | 職責 |
|---|---|
| `code/code.ino` | `setup()`、`loop()`、HTTP 路由註冊 |
| `code/config*` | 資料型別、NVS 持久化、設定有效性 |
| `code/modem*` | AT 傳輸、模組生命週期、簡訊發送 |
| `code/sms_process*` | URC/PDU 接收、長簡訊、黑名單、管理員命令 |
| `code/push*` | SMTP 與十種推送 provider |
| `code/web_handlers*` | Basic Auth、HTTP handler、日誌環形緩衝 |
| `web/` | shadcn-svelte 管理頁、三語字典、單檔 bundle builder |
| `mock_server/` | Express Mock Server、API 與瀏覽器驗證 |
| `scripts/dev.sh` | 前端、韌體與 Mock Server 的統一操作入口 |
| `code/data/index.html.gz` | Web production build，由 LittleFS 提供 |
| `Dockerfile`、`compose.yaml` | 固定版本的 Alpine 開發環境 |
| `.github/workflows/build.yml` | CI 的 Arduino CLI 編譯基線 |

## 證據邊界

文件中的資訊分三種：

- **程式事實**：可直接由目前原始碼或 workflow 重現。
- **CI 基線**：只證明 generic ESP32-C3 FQBN 能編譯，不證明實機行為。
- **硬體事實**：必須附實際板型、模組、指令/fixture 與觀察結果；未附者只
  能視為待驗證假設。

若文件與程式衝突，以根目錄 `AGENTS.md` 的 source-of-truth 順序為準。
