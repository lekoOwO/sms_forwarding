# 開發文件

本目錄是開發資訊的唯一入口。使用者功能、硬體接線與安裝步驟位於根目錄的三語 README。

## 文件地圖

- [development.md](development.md)：環境、建置、燒錄、發佈與驗證命令。
- [architecture.md](architecture.md)：ESP-IDF 元件、資料流、安全邊界與 OTA 流程。
- [openapi.json](openapi.json)：管理 API 的 machine-readable request 與 response contract。
- [config-schema/README.md](config-schema/README.md)：版本化設定格式、加密備份與產生器。
- [document-languages.json](document-languages.json)：文件語言與三語等價群組。
- [AGENTS.md](AGENTS.md)：本目錄的維護規則。

目前韌體只保留原生 ESP-IDF 路徑。Web OTA 只接受已簽章的 `.smsota` 套件。

## 證據邊界

- **程式事實**來自目前原始碼、OpenAPI 或 workflow。
- **CI 基線**只證明固定工具鏈可建置，不證明實機模組行為。
- **硬體事實**必須記錄板型、模組、輸入、韌體版本與觀察結果。

如果文件與程式衝突，請依根目錄 `AGENTS.md` 的 source-of-truth 順序處理。
