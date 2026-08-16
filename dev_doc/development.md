# 开发与验证

## ESP-IDF 基线构建

本项目固定使用 ESP-IDF **5.5.4**，目标为 ESP32-C3。构建产物只能写入
`build/`，配置文件使用 `build/sdkconfig`。

POSIX shell：

```sh
IDF_PATH=/path/to/esp-idf-v5.5.4 ./tools/idf.sh build
```

PowerShell：

```powershell
powershell -ExecutionPolicy Bypass -File tools\idf.ps1 build
```

两个入口都会拒绝其他 ESP-IDF 版本。CI 使用相同的 `idf.py` 参数，并运行
`espressif/idf:v5.5.4` 容器。

## 基线检查

不安装 ESP-IDF 也可以检查分区布局、版本固定和第三方许可文件：

```sh
python3 tools/check_idf_baseline.py
```

构建完成后传入镜像目录；检查会验证固件不超过 0x1E0000 OTA 槽位，并输出
固件大小与剩余空间：

```sh
python3 tools/check_idf_baseline.py --build-dir build/idf
```

分区表为 4MiB：两个 0x1E0000 OTA 槽位、0x20000 `appcfg`、0x10000
`coredump`；不提供持久化 `smsdata` 或 `inbox` 分区。
