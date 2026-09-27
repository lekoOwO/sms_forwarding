# Third-party notices

## PDUlib

The `components/idf_pdu` component contains PDUlib SMS PDU encoding and
decoding sources. It is licensed under LGPL-2.1-or-later; the complete license
text is in [components/idf_pdu/LICENSE](components/idf_pdu/LICENSE).

The component is rebuilt from the checked-in source by the ESP-IDF build:

```sh
IDF_PATH=/path/to/esp-idf-v6.0.2 ./tools/idf.sh build
```

After the pinned build completes, verify it with:

```sh
python3 tools/check_idf_baseline.py --build-dir build/idf
```
