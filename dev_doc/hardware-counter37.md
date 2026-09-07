# Counter36–42 ML307 parser 與 cellular 硬體報告

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

## R10 bounded follow-up

R10 對同一類 counter37 observation 只保留了 response stage 的 bounded failure
projection；當時 firmware result 沒有 `failureResponseReason`，因此 client 只能
分類為 `unknown`。cleanup projection 仍是 lexical/normalized MIPCLOSE shape
failure，沒有 post-close MIPSTATE 證據，不能把它分類為確認成功。R10 沒有宣稱
modem recovery，也沒有因為 ambiguous acknowledgement 再送一次 close、reset 或
其他 recovery action。

目前新增的 outer-space/tab normalization 只接受 single-field CID0 candidate；它
可以出現在唯一 terminal `OK` 的前後，但 frame 仍必須只有一個 candidate、一個
terminal，且沒有 `ERROR`、duplicate 或未知/額外行。它只有在 cleanup 隨後 exactly
one well-formed CID0 `INITIAL` post-state confirmation 成功時才安全。candidate 本身
永遠不是 final success；沒有該 confirmation 時，stale、delayed、non-initial、
ambiguous 或 timeout 都必須 fail closed 並要求 reset。這是 bounded implementation
contract，不是 R10 對原始空白、行順序或通用 modem wire grammar 的推論。

## R11 bounded diagnosis

R11 的 sanitized receipt 只保留 bounded parser projections：response stage 的
`failureResponseReason` 是 `modem_read`；cleanup 是 `response_invalid`、parse
reason `field_count`；cleanup shape 是 `fieldCount=1`、`quoteMask=0`、
`presenceMask=4`、state class `none`、line class `none`、single-field class `zero`。
cleanup 未確認且 `resetNeeded=true`。這個 shape 只表示 parser 到達 single-field
fallback；shape 不記錄 raw bytes、行順序或 terminal 相對位置，因此不能從它判定
candidate 在 `OK` 前或後，也不能主張任何通用 ML307 wire grammar。

counter39 將 response-stage owner command failure 與 MIPRD parse rejection 分開為
`modem_command` 與 `modem_read`。這是 bounded telemetry，沒有增加 raw response、
errno、modem code 或 endpoint 資料；既有 detail0/active/success coupling 維持不變。
single-field candidate 的安全性仍只來自 strict frame validation、唯一性與 exactly
one CID0 `INITIAL` post-state confirmation。這個 confirmation 是安全不變量，不是把
一次硬體 observation 推廣成 protocol fact。R11 沒有宣稱 modem recovery，也沒有
因為 ambiguous acknowledgement 再送一次 close、reset 或其他 recovery action。
若 post-state 已確認為 CID0 `INITIAL`，single-field candidate 即使是 stale
acknowledgement，也只代表 cleanup goal 已安全達成；這不是對 candidate 的 protocol
語意或 modem 家族行為的推論。

## Counter37 行為與安全邊界

- 精確 uppercase `CONNECTING` 在 endpoint、CID、quote 與欄位數通過嚴格驗證後，
  現在是 valid transitional disposition。`wait_for_connected()` 會像其他有效的
  nonterminal state 一樣繼續 bounded polling，永遠不把它當成成功；initial-state
  gate 仍拒絕它，不會因該狀態執行 stale close。endpoint 語意錯誤仍 fail closed，
  並在失敗 shape 中保留 bounded `connecting` state class。
- MIPCLOSE 的既有 two-field contract 不變。新增的 single-field candidate 只有在
  strict frame、prefix、single-field、unquoted checks 通過後，trim outer SP/TAB
  後仍精確等於 `0`、expected CID 為 0、且唯一 candidate/terminal 與無錯誤或未知
  額外行時才可被接受；這是目前程式的 acceptance contract，不是本次硬體觀察
  已證明的通用 wire fact。
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

## Counter40 MIPRD bounded diagnosis

R12 的既有安全摘要只記錄 response-stage `failureResponseReason=modem_read`；它
沒有保存 raw response、資料內容、長度、錯誤碼或時間序列，因此不能進一步判斷
MIPRD 是哪一種 parser rejection。Counter40 只補上 parser 已經看見的 bounded
分類，沒有把 R12 重新標成成功，也沒有把這筆 observation 推廣成 modem protocol
fact。

`parse_read()` 現在沿用既有 parser reason：frame/terminal 使用 `terminal` 或
`oversize`、URC 使用 `urc`、行與 prefix 使用 `prefix`、CSV 欄位與引號使用
`field_count`/`quote`、CID 使用 `cid`。只有 unread、宣告長度、hex 或 disconnect
一致性檢查使用新封閉值 `read_data`。shape 仍只保存欄位數、引號遮罩、固定
presence 與 closed enums；不保存 raw line、資料、長度、offset、error/token、
timing 或 endpoint/config/credential 資料。

真正的 MIPRD rejection 會同時保留 `failureReason=response_invalid` 與既有
`failureResponseReason=modem_read`，再由 detail=1 serializer 透出 parser reason，
detail=0、active、成功與其他 response stage 維持原有 coupling。合法讀取會先在
暫存 buffer 完成 decode，只有完整通過後才提交 unread/data/remote-close 狀態；
失敗時不會向上層洩漏部分資料。owner command failure、TLS/HTTP failure 與
cleanup 行為沒有改變。

callback 回傳 OK 但 response 超過既有整體 response 上限，仍在 `send_command()`
邊界被拒絕，沒有被重新分類為 `read_data`；這是刻意保留的 bounded residual，
避免為了 telemetry 改動 command/control flow。這份報告不宣稱 R12 已由新分類
重新驗證，亦不授權 live push、reset、OTA 或設定寫入。

## Counter41 R13 terminal-only no-data implementation contract

Counter41 定義一個只有 command echo 與唯一 terminal `OK`、沒有 retained result 的
bounded implementation contract；這不是硬體報告。R13 沒有保存板型、modem、輸入、
observed result provenance、raw response、hash、時間序列或裝置資料，因此本節不把
這個形狀提升為通用 modem protocol fact，也不記錄或重述 raw modem、host、IP、URL、
token、CSRF、憑證或設定內容。

Counter41 只在 `parse_read()` 內分類這個狹窄形狀：必須存在 command echo，
`scan_frame()` 必須確認唯一 terminal，body 必須為空，且沒有被 scanner 忽略的
已知 URC、SMS indication 或 PDU。未知/額外行、非 disconnect MIPURC、ERROR/CME/CMS、
缺少或重複 terminal 仍 fail closed。輸出會先清為 zero/empty/not-closed；只有
`no_data=true` 這個 internal provisional disposition 成功時才返回，永遠不設定
remote-close，也不表示 HTTP response 或 delivery success。

transport 會把該 disposition 轉成 non-closed empty read，並以現有 bounded poll
cadence、按剩餘 operation deadline 截斷的 RTOS delay 後再輪詢。它不能直接餵出 HTTP
bytes，也不能透過 EOF 完成 HTTP parser；deadline、TLS、HTTP 與 retry/control flow
仍維持既有邊界。明確 disconnect URC 仍是唯一可設定 remote-close 的空讀路徑。

這是對這個 R13-shaped input 的最小安全分類，不是宣稱空 body 在所有 ML307 韌體上都代表
「暫時沒有資料」。若未來遇到其他空 frame，必須重新提供 bounded fixture 或硬體報告，
且不得因此放寬未知行、輔助訊息或 EOF 語意。

## Counter42 echo-free implementation correction

目前 source 的 owner UART path 會在寫入 MIP command 前做 bounded pending drain，之後把
UART 收到的 bytes 原樣放入 response 與 scanner；owner 不會自行加入或移除 command echo
（`components/idf_modem/idf_modem.cpp:1972-1983,2060-2072`）。但啟動與 recovery 的
`try_unlock_sim()` 及 `configure_sms_and_registration()` 都會送出 `ATE0`，而目前沒有
`ATE1` 路徑（同檔 `:1501`、`:2587`）。因此 command echo 是可選的 source/runtime
狀態，不可作為 production response 必然存在的前提；這段只記錄 implementation
contract，不宣稱任何通用 ML307 wire grammar。

R14 receipt 的安全 projection 只記錄 cellular dispatch attempted、mode1/push/cleanup
各一次，最後落在 response/cleanup failure；response 的 bounded reason 是
`modem_read` + `prefix`，cleanup 需要 reset。這個 receipt 沒有保存或證明 raw response
是否含 echo，也沒有宣稱 push 成功、modem recovery 或 protocol 語意。

Counter42 因此只把 terminal-only no-data 的 echo 條件由「恰好一個」調整為「零或一個」：
唯一 terminal、空 retained body、無被忽略的輔助行與非 disconnect remote-close 等既有
guards 全部保留；duplicate echo 仍拒絕。成功仍只是 provisional no-data，transport 以
bounded cadence 回到同一 operation deadline，回傳 WANT_READ 而非 EOF，不會直接完成
HTTP response。未知行、SMS/PDU、錯誤、duplicate terminal 與真正的 MIPRD data path
仍維持原有 fail-closed 行為。

R13 的 terminal-only no-data 與 R14 的失敗 receipt 仍是 parser/cleanup 的
implementation contract 與 bounded failure record；它們不是 R15 成功結果的回溯解釋，
也不因 R15 而取得通用 protocol 語意。R15 是另一筆 counter42 的 bounded hardware
observation，結果與前述 parser candidate 的 promotion path 分開記錄如下。

## Counter42 R15 successful cellular evidence

### Hardware boundary and provenance

這是一筆單次、去識別化的 counter42 硬體觀察。來源是私有 R15 receipt 的
SHA-256 `3e60616890633fcb20be98a1b57fe8d8c8694851569660393ed0bfed5e6fcdb7`；本節只
引用 receipt 的安全 projection。

- 板型：去識別化 receipt 未保留，因此不作板型或裝置識別聲明。
- 模組：ML307 family；exact variant 與 modem firmware 未保留。
- 輸入：R15 counter42 執行中，使用既有已設定的單一 candidate，執行 exactly one
  cellular push，並完成 bounded mode cleanup。
- 觀察結果：cellular transport 回報 HTTP 200（2xx）；application-level success
  保持 `unknown`。cleanup confirmed，最後為 mode 0、workers idle，且
  `resetNeeded=false`。

本紀錄不保存或重述 raw endpoint、token、message、device identity、CA data、raw
HTTP、raw modem 或設定內容。它證明這一次 counter42 輸入在該硬體觀察中完成一次
cellular push 與安全 cleanup；它不保證其他 endpoint、訊息、網路條件或 modem
variant，也不把 R13/R14 的 parser shape 提升為通用 wire grammar。

## Counter43 reversible cellular failure

這是一筆單次、去識別化的 counter43 硬體觀察。輸入是 TEST-key OTA 後的
ESP-IDF firmware，暫時選擇 cellular path，對既有 Gotify 通道執行 exactly one
可逆測試，之後恢復 network mode。板型、exact modem variant、firmware build
identity、endpoint、provider token 與裝置識別資料不在本節保存。

- transport path `cellular`，dispatch attempted `true`。
- terminal failure 是 response stage、`failureReason=response_invalid`，且
  `failureResponseReason=modem_read`；在收到任何 HTTP bytes 前停止，因此沒有
  HTTP status，也沒有 provider acceptance 證據。
- cleanup clean；沒有 cleanup failure、沒有 reset required，最後 network mode
  恢復為 0。這筆失敗不能判定 provider 收到通知，也不能推論 modem wire grammar。

本節不保存或重述 raw response、payload、raw modem line、URL、host、token、CA
內容、時間序列或設定內容。

## Official manual evidence boundary

本次查閱的 [OneMO TCP/IP User Manual V5.0.0](https://github.com/RomaWan/ML307/blob/main/14_TCP_IP%E7%94%A8%E6%88%B6%E6%89%8B%E5%86%8A_V5.0.0.pdf)
官方手冊材料只足以保留兩個窄邊界：MIPRD 的 documented no-data 結果是 terminal
`OK`（§3.6，pp.29–30），而 `+MIPURC: "rtcp"` 是 asynchronous indication
（§3.14，pp.47–48）；§3.3 與 §4.4 也只作為 command/流程背景。
材料沒有證明 ML307Y 的 zero-length frame、`OK` 與 `rtcp` 的先後順序，亦沒有提供
本專案可重現的 wire fixture。因此目前 parser 仍對未知與不完整 frame fail closed；
沒有把 URC-only 或 zero-length ordering 提升為 protocol fact，也沒有放寬 runtime
acceptance。未保存手冊全文或長引文。

## Counter44 diagnostic telemetry and OTA evidence

counter44 package 由 commit `6f58aae72b8a32363288285247d934d7e81815a5` 的官方
offline TEST-key profile 建立；profile flags 是 non-release、USB recovery、TEST
key、fail-health 0。package 與 image 的 bounded metadata 如下：

| 項目 | 值 |
| --- | --- |
| package | `dist/sms-forwarder-dev-test-counter44-6f58aae.smsota` |
| package mode/bytes | `0644` / `1542174` |
| package SHA-256 | `57c51c3e76bf19bb06ff9b24e35157017115c739adf76e583ed4ab5e25cfaac6` |
| manifest | format 1；target `esp32c3`；counter 44；version `1.1.4-dev-test` |
| image bytes/SHA-256 | `1541920` / `8f01ba0eb17a2d567ce93596969e26582b9dc6f616be2a195e4d6154119db9dc` |
| TEST public-key SHA-256 | `8a10937f712f0948aef8c59e22b244f61f7411722575f32f688a690c5edc7b9f` |

離線簽章驗證使用 recovered TEST public key；live OTA 前後 public-key fingerprint
一致。OTA 將 app0 更新後啟動為 app1，USB 與 authenticated Web state 一致回報
image `valid`、accepted counter 44、pending 0、pending address 0、pending verify
false。之後的一次 USB recovery read-only probe 只得到未分類 transport error；Web
state 仍健康，因此這筆 probe 不能被解讀為 OTA state invalid，也沒有執行 USB retry、
reset 或其他寫入。

counter43 package 亦完成 recovered TEST-key 驗證與 app1→app0 OTA：

| 項目 | 值 |
| --- | --- |
| package | `dist/sms-forwarder-dev-test-counter43-d52d082.smsota` |
| package mode/bytes | `0644` / `1541245` |
| package SHA-256 | `ee209c3d7ef0b8c1fc76c1e350e9a3f9e8d7b94fa8e314eda1fef726d9c46ec2` |
| manifest/image | format 1；target `esp32c3`；counter 43；version `1.1.4-dev-test`；image `1540992` bytes |
| image SHA-256 | `3025b514d9e0ef24ac3cb83631286b02f64e984324447337757e922f7ec7ec0b` |
| key/live match | TEST public-key fingerprint match；USB/Web OTA state agreement |

counter43 OTA 後 app1→app0 為 valid、accepted counter 43、無 pending；authenticated
root UI 回應與 built current gzip asset byte/hash 相同。這些結果是 bounded hardware
observations，不是 production signing-key ownership 或 release authorization。

## Counter44 final reversible cellular Gotify evidence

在 counter44 app1 健康狀態下，使用 authenticated Web-only preflight；USB gate 沒有
被重試或用來替代 Web state。preflight 確認 mode 0、modem ready、home registration、
not roaming、channel0 Gotify/cellular/required fields、CA configured 與 push idle。

只送出一次 `networkMode=1` save job，確認非 mode config projection 與 CA 未改變；
接著只送出一次 channel0 `detail=1` push test。terminal evidence 是：

- transport path `cellular`；dispatch attempted `true`；HTTP status `200`；
  terminal success `true`；failure stage `none`；provider acceptance confirmed。
- 沒有 retry、第二個 notification、reset、OTA 或其他 config write；確認產生一個
  external Gotify notification。
- failure parser 未被使用，因此本次成功 terminal 沒有 `failureParseShape`、
  `responseTraceMask` 或 rtcp length 欄位；這不構成對失敗 frame 的 shape 證據。
- finally 只送出 `networkMode=0`；restore job 成功，最終 mode 0、非 mode config
  projection unchanged、CA unchanged、push idle。

本節只記錄 bounded result，不保存或重述 URL、host、token、custom body、raw HTTP、
raw modem、電話、SSID、IMEI、EID、ICCID、憑證或其他設定內容。counter43 的
`response_invalid/modem_read` 與 counter44 的 HTTP 200 是兩筆不同輸入的觀察；前者
仍不能推論 parser bug，後者也不保證其他 provider、網路條件或 modem variant。

## Counter45 rollout evidence

這是一筆單次、去識別化的 counter45 TEST-key OTA 觀察，來源是 current HEAD
`d4ba19f`。該 HEAD 同時修正 ServerChan cellular inherited endpoint 與 demo
`smtpPort` numeric persistence。

| 項目 | 值 |
| --- | --- |
| manifest | format 1；target `esp32c3`；counter 45；version `1.1.4-dev-test` |
| package bytes/SHA-256 | `1542303` / `715ff60b7574ae8b914a00b085189232706858210ddeeaf00c4357d17d4322ad` |
| image bytes/SHA-256 | `1542048` / `f24af3441271d6011760a99235fc30fb79b184153093ce73e8b4698b2d1ef462` |
| TEST key | recovered key matched before upload and remained unchanged after boot |
| root gzip asset | exact current `WEB_INDEX_DATA` match；`162111` bytes；SHA-256 `d6821d00edf3397c3824afbd011eb587985902ab4ec77c2f49ce749d37e07e90` |

authenticated Web OTA was sent exactly once from app1 to app0 and returned
`ACTION_OTA_READY`. Final authenticated Web state was app0 `valid`, accepted counter
45, pending 0, pending address 0, and unchanged TEST key identity. The sanitized config
gates remained network mode 0, AP mode false, and modem ready. No upload retry, reset,
config write, or push test was performed. No USB cross-check was available, so this record makes
no USB state claim.

This section does not preserve or restate an IP address, credential, provider URL, key
material, token, device identifier, raw response, raw modem line, or raw configuration.

## Encrypted backup evidence

OTA 前完成一次 encrypted configuration backup export；只記錄 artifact metadata：

- path category `.secrets/backups/ota-preflash-d52d082.smscfg`；mode `0600`；
  `863` bytes；SHA-256
  `65871bc01fc4d3ccb86468b5788e0b8afb56a1bd0b10f031d12655ad5c31c00a`。
- 沒有解密、還原、列印內容或保存 passphrase。此 backup 是保留的 recovery artifact，
  不代表 configuration field semantics 已被公開。

## Acceptance promotion path for parser candidates

要把這些候選行為提升為目前 runtime 的可接受行為，必須同時完成：

1. sanitized executable fixtures：exact uppercase `CONNECTING` 只作 bounded
   transitional disposition；single-field MIPCLOSE 僅依 normalized-line contract
   並要求 post-state confirmation。
2. negative fixtures：tabs、double/leading/trailing spaces、quoted single、
   nonzero、leading-zero、sign、junk、extra、duplicate、after-terminal，及
   malformed CONNECTING endpoint/CID/quote；after-terminal candidate 的 duplicate、
   extra、unknown、ERROR 與 missing/duplicate terminal；generic `parse_result`、
   MIPSEND、MIPOPEN 行為維持原有 strictness。
3. stale-close 與 cleanup 的 initial/noninitial/failure/timeout/ambiguity
   bounded fixtures、modem/runtime/push tests、OpenAPI/security checks 與
   CI-equivalent firmware compile 全部通過。

上述 promotion path 只針對 R13/R14 parser candidates；R15 的成功結果是另外保存的
bounded hardware evidence。兩者都不授權額外的 live reset、push、OTA 或任何設定寫入，
也不取代目前 source、fixture 與安全 gate 的驗證。
