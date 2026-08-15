ARG ALPINE_VERSION=3.22
FROM alpine:${ALPINE_VERSION}

ARG ARDUINO_CLI_VERSION=1.5.1
ARG ESP32_CORE_VERSION=3.3.10
ARG READYMAIL_VERSION=0.4.2
ARG ARDUINOJSON_VERSION=7.4.3
ARG TARGETARCH
ARG USER_ID=1000
ARG GROUP_ID=1000

ENV ARDUINO_DIRECTORIES_DATA=/opt/arduino/data \
    ARDUINO_DIRECTORIES_DOWNLOADS=/opt/arduino/downloads \
    ARDUINO_DIRECTORIES_USER=/opt/arduino/user \
    ARDUINO_UPDATER_ENABLE_NOTIFICATION=false

COPY scripts/apply-esp32-webserver-3.3.10-patch.sh \
     scripts/check-esp32-webserver-3.3.10-patch.sh \
     /tmp/esp32-webserver-patch/
COPY scripts/patches/esp32-webserver-3.3.10-request-limits.patch \
     /tmp/esp32-webserver-patch/patches/

RUN apk add --no-cache \
        bash \
        ca-certificates \
        curl \
        git \
        gcompat \
        libstdc++ \
        patch \
        python3 \
        py3-pyserial \
        tar \
    && case "${TARGETARCH}" in \
         amd64) archive=Linux_64bit; sha256=28a8e119c498a25607821c36cb2dc49e8463941b261a0d99091baa7bc692dd2b ;; \
         arm64) archive=Linux_ARM64; sha256=1e69e077479f300614d4551334e0a33f08ee40b04315d83b8e7e0e94f0d0ee62 ;; \
         *) echo "Unsupported architecture: ${TARGETARCH}" >&2; exit 1 ;; \
       esac \
    && curl -fsSL "https://github.com/arduino/arduino-cli/releases/download/v${ARDUINO_CLI_VERSION}/arduino-cli_${ARDUINO_CLI_VERSION}_${archive}.tar.gz" -o /tmp/arduino-cli.tar.gz \
    && echo "${sha256}  /tmp/arduino-cli.tar.gz" | sha256sum -c - \
    && tar -xzf /tmp/arduino-cli.tar.gz -C /usr/local/bin arduino-cli \
    && rm /tmp/arduino-cli.tar.gz \
    && mkdir -p "${ARDUINO_DIRECTORIES_DATA}" "${ARDUINO_DIRECTORIES_DOWNLOADS}" "${ARDUINO_DIRECTORIES_USER}" \
    && arduino-cli core update-index --additional-urls https://espressif.github.io/arduino-esp32/package_esp32_index.json \
    && arduino-cli core install "esp32:esp32@${ESP32_CORE_VERSION}" --additional-urls https://espressif.github.io/arduino-esp32/package_esp32_index.json \
    && /tmp/esp32-webserver-patch/apply-esp32-webserver-3.3.10-patch.sh \
    && arduino-cli lib install "ReadyMail@${READYMAIL_VERSION}" \
    && arduino-cli lib install "ArduinoJson@${ARDUINOJSON_VERSION}" \
    && rm -rf /tmp/esp32-webserver-patch \
    && rm -rf \
        "${ARDUINO_DIRECTORIES_DATA}/packages/esp32/tools/esp-x32" \
        "${ARDUINO_DIRECTORIES_DATA}/packages/esp32/tools/xtensa-esp-elf-gdb" \
        "${ARDUINO_DIRECTORIES_DATA}/packages/esp32/tools/riscv32-esp-elf-gdb" \
        "${ARDUINO_DIRECTORIES_DATA}/packages/esp32/tools/esp32-libs" \
        "${ARDUINO_DIRECTORIES_DATA}/packages/esp32/tools/esp32c5-libs" \
        "${ARDUINO_DIRECTORIES_DATA}/packages/esp32/tools/esp32c6-libs" \
        "${ARDUINO_DIRECTORIES_DATA}/packages/esp32/tools/esp32h2-libs" \
        "${ARDUINO_DIRECTORIES_DATA}/packages/esp32/tools/esp32p4-libs" \
        "${ARDUINO_DIRECTORIES_DATA}/packages/esp32/tools/esp32p4_es-libs" \
        "${ARDUINO_DIRECTORIES_DATA}/packages/esp32/tools/esp32s2-libs" \
        "${ARDUINO_DIRECTORIES_DATA}/packages/esp32/tools/esp32s3-libs" \
        "${ARDUINO_DIRECTORIES_DATA}/staging" \
        "${ARDUINO_DIRECTORIES_DATA}/tmp" \
        "${ARDUINO_DIRECTORIES_DOWNLOADS}" \
    && mkdir -p "${ARDUINO_DIRECTORIES_DOWNLOADS}" \
    && addgroup -g "${GROUP_ID}" developer \
    && adduser -D -u "${USER_ID}" -G developer developer \
    && chown -R developer:developer /opt/arduino

RUN apk add --no-cache nodejs npm

ARG ESPTOOL_VERSION=5.3.0
RUN apk add --no-cache py3-pip \
    && python3 -m venv /opt/esptool-venv \
    && /opt/esptool-venv/bin/pip install --no-cache-dir "esptool==${ESPTOOL_VERSION}" \
    && rm "/opt/arduino/data/packages/esp32/tools/esptool_py/${ESPTOOL_VERSION}/esptool" \
    && ln -s /opt/esptool-venv/bin/esptool "/opt/arduino/data/packages/esp32/tools/esptool_py/${ESPTOOL_VERSION}/esptool"

USER developer
WORKDIR /workspace

CMD ["sh"]
