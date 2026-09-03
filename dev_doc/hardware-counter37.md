# Counter37 ML307 parser 硬體報告

## 範圍與輸入

這是一筆 counter36 的 bounded、去識別化硬體分類觀察。輸入來自 R9
one-shot runner 的同一個 MIPSTATE/MIPCLOSE-shaped 場景；runner source SHA-256
為 `c3b5c0f7c7fe627236b7e23928aad416d6256f3d35c5aed72dd70f948b0eaf31`。

R9 沒有保存 raw bytes、raw evidence hash、timestamp、command/time sequence 或
post-close state。因此本報告不能判定 MIPCLOSE line 的原始空白形式，也不能把
shape 推廣成 ML307 家族的通用 wire grammar。本報告不保存或重述 raw modem、raw
HTTP、host、IP、URL、token、CSRF、憑證、裝置識別資料或設定內容。

可執行的 sanitized inline transcripts 位於
`components/idf_modem/test/https_post_fixture.cpp`，只使用公開 placeholder
endpoint，並由本報告的 bounded shape 描述連結；它們不是私有 raw capture。

## 同一觀察的 bounded shape

下表是同一個 counter36 硬體觀察的兩個 parser-relevant shape projection，並非
兩筆獨立的 wire 證據：

| 觀察 | bounded 結構 | R9 counter36 分類 |
| --- | --- | --- |
| MIPSTATE transitional-shaped line | 5 fields；`quoteMask=22`；`presenceMask=3` (`mipopen|mipstate`)；state class `connecting`；line class `none`；single-field class `none` | parser failure reason `state` |
| MIPCLOSE-shaped result line | 1 unquoted field；`fieldCount=1`；`quoteMask=0`；`presenceMask=4` (`mipclose`)；single-field class `zero` | parser failure reason `field_count` |

這些欄位只表示欄位數、引號位置、固定 prefix presence 與 closed
classification；不含欄位值、raw bytes、長度、offset、endpoint 或其他識別資料。
由於沒有 raw 或 time sequence，表格不主張兩個 shape 的精確原始行格式或先後順序。

## R9 bounded runner result

R9 receipt 的安全 projection 只保留 symbolic status 與 bounded booleans/counters：

- transport path `cellular`；dispatch attempted `true`。
- failure stage `registration`；failure reason `response_invalid`；failure
  parse reason `state`。
- cleanup reason `response_invalid`；cleanup parse reason `field_count`；cleanup
  confirmed `false`。
- reset needed `true`；worker idle `false`；network home `true`；HTTP 2xx
  `false`；application result `unknown`。

這是一次輸入的 bounded hardware classification，不是成功宣稱，也不表示 runner
曾自動執行 reset 或 recovery。R9 沒有 post-close state 證據，不能用 receipt 推論
MIPCLOSE 已完成有效關閉。

## Counter37 行為與安全邊界

- 精確 uppercase `CONNECTING` 在 endpoint、CID、quote 與欄位數通過嚴格驗證後，
  現在是 valid transitional disposition。`wait_for_connected()` 會像其他有效的
  nonterminal state 一樣繼續 bounded polling，永遠不把它當成成功；initial-state
  gate 仍拒絕它，不會因該狀態執行 stale close。endpoint 語意錯誤仍 fail closed，
  並在失敗 shape 中保留 bounded `connecting` state class。
- MIPCLOSE 的既有 two-field contract 不變。新增的 single-field candidate 只有在
  raw line gate 通過精確格式、且 expected CID 為 0 時才可被接受；這是目前程式的
  acceptance contract，不是本次硬體觀察已證明的通用 wire fact。
- single-field acknowledgement 永遠不是 cleanup 的最終成功。cleanup 會透過
  現有 owner 提交 exactly one post-close MIPSTATE query，且只接受 well-formed
  CID0 `INITIAL`；connected、connecting、closed、unknown、schema、timeout 或
  ambiguity 都 fail closed 並標記 reset required。stale-close 路徑也保留既有
  post-close state gate。
- MIPSEND、MIPOPEN 與 generic result parser 的 acceptance 未放寬；成功解析不產生
  parse shape/reason telemetry，失敗 single-field input 保留 bounded shape。
- 模組只記為 ML307 family。exact variant、modem firmware、operator 與 board
  不在本報告中 promoted。家族 manual 是 model-mismatch 的 supporting context
  only，不能覆蓋本次 observation，也不能單獨提升為 protocol fact。

## Acceptance promotion path

要把這些候選行為提升為目前 runtime 的可接受行為，必須同時完成：

1. sanitized executable fixtures：exact uppercase `CONNECTING` 只作 bounded
   transitional disposition；single-field MIPCLOSE 僅依 raw-line contract
   並要求 post-state confirmation。
2. negative fixtures：tabs、double/leading/trailing spaces、quoted single、
   nonzero、leading-zero、sign、junk、extra、duplicate、after-terminal，及
   malformed CONNECTING endpoint/CID/quote；generic `parse_result`、MIPSEND、
   MIPOPEN 行為維持原有 strictness。
3. stale-close 與 cleanup 的 initial/noninitial/failure/timeout/ambiguity
   bounded fixtures、modem/runtime/push tests、OpenAPI/security checks 與
   CI-equivalent firmware compile 全部通過。

在上述證據完成前，這份文件只是一筆 bounded hardware classification，不授權
live reset、push、OTA 或任何設定寫入。
