# Configuration schema contract

`manifest.json` keeps the `SMSCFG01` envelope unchanged: the CFG2 payload is
little-endian, the 20-byte CFG2 header is included in the 32,768-byte binary
limit, and the encrypted envelope is at most 32,828 bytes (44-byte envelope
header plus the payload and 16-byte GCM tag).

`v1.json` through `v5.json` are compatibility fixtures. `v6.json` is the
current native ESP-IDF schema and appends `kaTrafficKB`. Every variable-length
string is bounded by `x-maxUtf8Bytes`; fixed arrays contain exactly their
declared item count. The legacy ESP-IDF `webUser`/`webPass` pair is
migration-only and is copied to `webAccounts[0]`; neither field is encoded in
v6.

The v6 wire-size metadata uses a 2-byte string-length prefix, a 1-byte count
for each fixed array, and 1-byte booleans or 4-byte integers. The worst-case
CFG2 payload is 26,736 bytes; with its 20-byte header the encoded binary is
26,756 bytes, leaving 6,012 bytes under the 32,768-byte limit. Push template
alternatives are counted exclusively because custom channels use `customBody`
instead of title/body templates.

Portable restore keeps target-local identity, hostname, web accounts, SIM
identity and failure counters, phone number, and profile/timestamp references.
The five WiFi profiles, network mode, and heartbeat settings remain portable
v4 configuration. `wifiFromFallback` is runtime-only and is intentionally
absent. Provider values 1 through 12 are supported; value 0
(`PUSH_TYPE_NONE`) remains in the mapping for v1-v4 compatibility.

Regenerate and check the native header with:

```sh
python3 tools/generate-config-schema.py
python3 tools/generate-config-schema.py --check
python3 -m unittest tools/test_config_schema.py
```
