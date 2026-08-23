#ifndef FIRMWARE_IS_RELEASE
#define FIRMWARE_IS_RELEASE 0
#endif
#ifndef SMS_USB_RECOVERY
#define SMS_USB_RECOVERY 0
#endif

#if FIRMWARE_IS_RELEASE && SMS_USB_RECOVERY
#error "SMS_USB_RECOVERY cannot be enabled in a release firmware"
#endif

#if SMS_USB_RECOVERY

#include "usb_recovery.h"

#include <string.h>

#include <new>
#include <string>
#include <stdint.h>

#include "driver/usb_serial_jtag.h"
#include "esp_err.h"
#include "esp_system.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "config_schema_generated.h"
#include "idf_config.h"
#include "idf_log.h"
#include "idf_modem.h"
#include "idf_web_ota.h"
#include "idf_wifi.h"
#include "lwip/inet.h"
#include "lwip/sockets.h"
#include "nvs.h"

namespace {

constexpr uint8_t kMagic0 = 'S';
constexpr uint8_t kMagic1 = 'R';
constexpr uint8_t kVersion = 1;
constexpr uint8_t kCommandState = 0x01;
constexpr uint8_t kCommandWifiProvision = 0x02;
constexpr uint8_t kCommandWifiProvisionAsync = 0x03;
constexpr uint8_t kCommandWifiProvisionStatus = 0x04;
constexpr uint8_t kCommandModemQuery = 0x05;
constexpr uint8_t kCommandOtaState = 0x06;
#if !FIRMWARE_IS_RELEASE
constexpr uint8_t kCommandOtaMigrationRecover = 0x07;
#endif
constexpr uint8_t kResponseMask = 0x80;
constexpr size_t kHeaderSize = 7;
constexpr size_t kCrcSize = 2;
constexpr size_t kMaxLegacyPayload = 100;
constexpr size_t kMaxAsyncPayload = 104;
constexpr size_t kMaxQueryRequestPayload = 1;
constexpr size_t kMaxQueryResponsePayload = IDF_MODEM_USB_QUERY_MAX_RESPONSE;
constexpr size_t kMaxPayload = kMaxAsyncPayload;
constexpr size_t kMaxFrame = kHeaderSize + kMaxPayload + kCrcSize;
constexpr size_t kParserCapacity = kMaxFrame * 2;
constexpr TickType_t kIoTimeout = pdMS_TO_TICKS(2000);
constexpr TickType_t kParserIdleTimeout = pdMS_TO_TICKS(1000);
constexpr size_t kProvisionStatusPayload = 11;
constexpr size_t kOtaStatePayload = 18;

enum class Status : uint8_t {
    Ok = 0,
    InvalidArg = 1,
    NotFound = 2,
    InvalidState = 3,
    Timeout = 4,
    NoMem = 5,
    Busy = 6,
    NotReady = 7,
    Internal = 255,
};

enum class ProvisionState : uint8_t { Idle = 0, Pending = 1, SetupStarted = 2, Failed = 3 };
enum class ProvisionConnection : uint8_t { Unknown = 0, Starting = 1, StaObserved = 2, Failed = 3 };

struct Frame {
    uint8_t command = 0;
    uint8_t sequence = 0;
    uint16_t payload_length = 0;
    uint8_t payload[kMaxPayload] = {};
};

struct WifiProvisionRequest {
    uint64_t nonce = 0;
    uint8_t ssid_length = 0;
    uint8_t password_length = 0;
    char ssid[MAX_WIFI_SSID_BYTES + 1] = {};
    char password[MAX_WIFI_PASSWORD_BYTES + 1] = {};
};

static portMUX_TYPE s_provision_lock = portMUX_INITIALIZER_UNLOCKED;
static TaskHandle_t s_provision_worker = nullptr;
static WifiProvisionRequest* s_provision_request = nullptr;
static uint64_t s_provision_nonce = 0;
static ProvisionState s_provision_state = ProvisionState::Idle;
static ProvisionConnection s_provision_connection = ProvisionConnection::Unknown;
static Status s_provision_error = Status::Ok;
static uint32_t s_boot_id = 0;

static void secure_zero(void* data, size_t length)
{
    volatile uint8_t* bytes = static_cast<volatile uint8_t*>(data);
    while (length-- != 0) *bytes++ = 0;
}

static size_t command_payload_limit(uint8_t command)
{
    if (command == kCommandModemQuery) return kMaxQueryRequestPayload;
    if (command == kCommandOtaState
#if !FIRMWARE_IS_RELEASE
        || command == kCommandOtaMigrationRecover
#endif
    ) return 0;
    return command == kCommandWifiProvisionAsync ? kMaxAsyncPayload : kMaxLegacyPayload;
}

static bool request_command(uint8_t command)
{
    return command == kCommandState || command == kCommandWifiProvision ||
           command == kCommandWifiProvisionAsync || command == kCommandWifiProvisionStatus ||
           command == kCommandModemQuery || command == kCommandOtaState
#if !FIRMWARE_IS_RELEASE
           || command == kCommandOtaMigrationRecover
#endif
        ;
}

static uint16_t crc16(const uint8_t* bytes, size_t length)
{
    uint16_t crc = 0xFFFF;
    for (size_t i = 0; i < length; ++i) {
        crc ^= static_cast<uint16_t>(bytes[i]) << 8;
        for (int bit = 0; bit < 8; ++bit) {
            crc = (crc & 0x8000) ? static_cast<uint16_t>((crc << 1) ^ 0x1021)
                                  : static_cast<uint16_t>(crc << 1);
        }
    }
    return crc;
}

class FrameParser {
public:
    void feed(const uint8_t* bytes, size_t length)
    {
        if (length == 0) return;
        last_activity_ = xTaskGetTickCount();
        for (size_t i = 0; i < length; ++i) {
            if (size_ == sizeof(buffer_)) {
                memmove(buffer_, buffer_ + 1, sizeof(buffer_) - 1);
                secure_zero(buffer_ + sizeof(buffer_) - 1, 1);
                --size_;
            }
            buffer_[size_++] = bytes[i];
        }
    }

    void reset_if_idle(TickType_t now)
    {
        if (size_ != 0 && now - last_activity_ >= kParserIdleTimeout) {
            secure_zero(buffer_, size_);
            size_ = 0;
        }
    }

    bool next(Frame& out)
    {
        while (true) {
            size_t magic = 0;
            while (magic + 1 < size_ &&
                   !(buffer_[magic] == kMagic0 && buffer_[magic + 1] == kMagic1)) {
                ++magic;
            }
            if (magic + 1 >= size_) {
                if (size_ && buffer_[size_ - 1] == kMagic0) {
                    secure_zero(buffer_, size_ - 1);
                    buffer_[0] = kMagic0;
                    size_ = 1;
                } else {
                    secure_zero(buffer_, size_);
                    size_ = 0;
                }
                return false;
            }
            discard(magic);
            if (size_ < kHeaderSize) return false;

            const uint8_t version = buffer_[2];
            const uint8_t command = buffer_[3];
            const uint16_t payload_length = static_cast<uint16_t>(buffer_[4]) |
                                            static_cast<uint16_t>(buffer_[5]) << 8;
            if (version != kVersion || !request_command(command) ||
                payload_length > command_payload_limit(command)) {
                discard(1);
                continue;
            }
            const size_t frame_length = kHeaderSize + payload_length + kCrcSize;
            if (size_ < frame_length) return false;
            const uint16_t expected = static_cast<uint16_t>(buffer_[frame_length - 2]) |
                                      static_cast<uint16_t>(buffer_[frame_length - 1]) << 8;
            if (crc16(buffer_, frame_length - kCrcSize) != expected) {
                discard(1);
                continue;
            }
            out.command = command;
            out.sequence = buffer_[6];
            out.payload_length = payload_length;
            memcpy(out.payload, buffer_ + kHeaderSize, payload_length);
            discard(frame_length);
            return true;
        }
    }

private:
    void discard(size_t count)
    {
        if (count >= size_) {
            secure_zero(buffer_, size_);
            size_ = 0;
            return;
        }
        memmove(buffer_, buffer_ + count, size_ - count);
        size_ -= count;
        secure_zero(buffer_ + size_, count);
    }

    uint8_t buffer_[kParserCapacity] = {};
    size_t size_ = 0;
    TickType_t last_activity_ = 0;
};

static Status map_error(esp_err_t err)
{
    if (err == ESP_OK) return Status::Ok;
    if (err == ESP_ERR_INVALID_ARG) return Status::InvalidArg;
    if (err == ESP_ERR_NOT_FOUND) return Status::NotFound;
    if (err == ESP_ERR_NVS_NOT_FOUND) return Status::NotFound;
    if (err == ESP_ERR_INVALID_STATE) return Status::InvalidState;
    if (err == ESP_ERR_TIMEOUT) return Status::Timeout;
    if (err == ESP_ERR_NO_MEM) return Status::NoMem;
    return Status::Internal;
}

static Status map_query_error(esp_err_t err)
{
    if (err == IDF_MODEM_ERR_BUSY) return Status::Busy;
    if (err == ESP_ERR_INVALID_STATE) return Status::NotReady;
    if (err == ESP_ERR_INVALID_SIZE) return Status::InvalidArg;
    return map_error(err);
}

static uint64_t read_u64(const uint8_t* bytes)
{
    uint64_t value = 0;
    for (size_t i = 0; i < sizeof(value); ++i) {
        value |= static_cast<uint64_t>(bytes[i]) << (8U * i);
    }
    return value;
}

static void write_u64(uint8_t* bytes, uint64_t value)
{
    for (size_t i = 0; i < sizeof(value); ++i) {
        bytes[i] = static_cast<uint8_t>(value >> (8U * i));
    }
}

static void write_u32(uint8_t* bytes, uint32_t value)
{
    for (size_t i = 0; i < sizeof(value); ++i) {
        bytes[i] = static_cast<uint8_t>(value >> (8U * i));
    }
}

static Status copy_credentials(const Frame& frame, size_t offset, WifiProvisionRequest& request)
{
    if (frame.payload_length < offset + 2) return Status::InvalidArg;
    const uint8_t ssid_length = frame.payload[offset];
    const uint8_t password_length = frame.payload[offset + 1];
    const size_t expected = offset + 2U + ssid_length + password_length;
    if (ssid_length == 0 || ssid_length > MAX_WIFI_SSID_BYTES ||
        (password_length != 0 && password_length < 8) ||
        password_length > MAX_WIFI_PASSWORD_BYTES || expected != frame.payload_length) {
        return Status::InvalidArg;
    }
    memcpy(request.ssid, frame.payload + offset + 2, ssid_length);
    memcpy(request.password, frame.payload + offset + 2 + ssid_length, password_length);
    for (size_t i = 0; i < ssid_length; ++i) {
        if (request.ssid[i] == '\0') return Status::InvalidArg;
    }
    for (size_t i = 0; i < password_length; ++i) {
        if (request.password[i] < 0x20 || request.password[i] > 0x7E) return Status::InvalidArg;
    }
    request.ssid_length = ssid_length;
    request.password_length = password_length;
    return Status::Ok;
}

static void usb_wifi_provision_task(void*)
{
    while (true) {
        ulTaskNotifyTake(pdTRUE, portMAX_DELAY);
        WifiProvisionRequest* request = nullptr;
        portENTER_CRITICAL(&s_provision_lock);
        request = s_provision_request;
        portEXIT_CRITICAL(&s_provision_lock);
        if (!request) continue;

        const esp_err_t save_err = idf_config_save_wifi(
            request->ssid, request->ssid_length, request->password, request->password_length);
        esp_err_t connect_err = save_err;
        if (save_err == ESP_OK) {
            connect_err = idf_wifi_provision_connect(
                request->ssid, request->ssid_length, request->password, request->password_length);
        }

        portENTER_CRITICAL(&s_provision_lock);
        if (connect_err == ESP_OK) {
            s_provision_state = ProvisionState::SetupStarted;
            s_provision_connection = ProvisionConnection::Starting;
            s_provision_error = Status::Ok;
        } else {
            s_provision_state = ProvisionState::Failed;
            s_provision_connection = ProvisionConnection::Failed;
            s_provision_error = map_error(connect_err);
        }
        s_provision_request = nullptr;
        portEXIT_CRITICAL(&s_provision_lock);
        secure_zero(request, sizeof(*request));
        delete request;
    }
}

static Status provision_wifi_legacy(const Frame& frame)
{
    portENTER_CRITICAL(&s_provision_lock);
    const bool async_pending = s_provision_state == ProvisionState::Pending;
    portEXIT_CRITICAL(&s_provision_lock);
    if (async_pending) return Status::Busy;

    WifiProvisionRequest request;
    const Status parse_status = copy_credentials(frame, 0, request);
    if (parse_status != Status::Ok) {
        secure_zero(&request, sizeof(request));
        return parse_status;
    }
    const esp_err_t save_err = idf_config_save_wifi(
        request.ssid, request.ssid_length, request.password, request.password_length);
    const esp_err_t connect_err = save_err == ESP_OK
        ? idf_wifi_provision_connect(request.ssid, request.ssid_length,
                                     request.password, request.password_length)
        : save_err;
    secure_zero(&request, sizeof(request));
    return map_error(connect_err);
}

static Status provision_wifi_async(const Frame& frame, TaskHandle_t* deferred_task)
{
    *deferred_task = nullptr;
    if (frame.payload_length < 10) return Status::InvalidArg;
    const uint64_t nonce = read_u64(frame.payload);
    if (nonce == 0) return Status::InvalidArg;

    portENTER_CRITICAL(&s_provision_lock);
    const ProvisionState current_state = s_provision_state;
    const uint64_t current_nonce = s_provision_nonce;
    const Status current_error = s_provision_error;
    portEXIT_CRITICAL(&s_provision_lock);
    if (current_state == ProvisionState::Pending) {
        return current_nonce == nonce ? Status::Ok : Status::Busy;
    }
    if (current_state == ProvisionState::SetupStarted || current_state == ProvisionState::Failed) {
        if (current_nonce == nonce) return current_state == ProvisionState::SetupStarted ? Status::Ok : current_error;
    }

    auto* request = new (std::nothrow) WifiProvisionRequest();
    if (!request) return Status::NoMem;
    request->nonce = nonce;
    const Status parse_status = copy_credentials(frame, 8, *request);
    if (parse_status != Status::Ok) {
        secure_zero(request, sizeof(*request));
        delete request;
        return parse_status;
    }

    portENTER_CRITICAL(&s_provision_lock);
    if (s_provision_state == ProvisionState::Pending) {
        const Status result = s_provision_nonce == nonce ? Status::Ok : Status::Busy;
        portEXIT_CRITICAL(&s_provision_lock);
        secure_zero(request, sizeof(*request));
        delete request;
        return result;
    }
    if (s_provision_worker == nullptr) {
        TaskHandle_t worker = nullptr;
        if (xTaskCreate(usb_wifi_provision_task, "usb_wifi_prov", 8192, nullptr, 2, &worker) != pdPASS) {
            portEXIT_CRITICAL(&s_provision_lock);
            secure_zero(request, sizeof(*request));
            delete request;
            return Status::NoMem;
        }
        s_provision_worker = worker;
    }
    s_provision_nonce = nonce;
    s_provision_request = request;
    s_provision_state = ProvisionState::Pending;
    s_provision_connection = ProvisionConnection::Starting;
    s_provision_error = Status::Ok;
    *deferred_task = s_provision_worker;
    portEXIT_CRITICAL(&s_provision_lock);
    return Status::Ok;
}

static Status provision_wifi_status(const Frame& frame, uint8_t* output, size_t* output_length)
{
    if (frame.payload_length != sizeof(uint64_t)) return Status::InvalidArg;
    const uint64_t nonce = read_u64(frame.payload);
    ProvisionState state;
    ProvisionConnection connection;
    Status error;
    portENTER_CRITICAL(&s_provision_lock);
    if (s_provision_state == ProvisionState::Idle || s_provision_nonce != nonce) {
        portEXIT_CRITICAL(&s_provision_lock);
        return Status::NotFound;
    }
    state = s_provision_state;
    connection = s_provision_connection;
    error = s_provision_error;
    portEXIT_CRITICAL(&s_provision_lock);
    if (state == ProvisionState::SetupStarted && connection == ProvisionConnection::Starting &&
        idf_wifi_get_status().staConnected) {
        connection = ProvisionConnection::StaObserved;
    }
    write_u64(output, nonce);
    output[8] = static_cast<uint8_t>(state);
    output[9] = static_cast<uint8_t>(error);
    output[10] = static_cast<uint8_t>(connection);
    *output_length = 1 + kProvisionStatusPayload;
    return Status::Ok;
}

static Status modem_query(const Frame& frame, uint8_t* output, size_t* output_length)
{
    if (frame.payload_length != 1) return Status::InvalidArg;
    std::string response;
    uint8_t busy_reason = 0;
    const esp_err_t err = idf_modem_usb_query(frame.payload[0], response, &busy_reason);
    if (err != ESP_OK) {
        if (err == IDF_MODEM_ERR_BUSY) {
            output[0] = busy_reason;
            *output_length = 2;
        }
        return map_query_error(err);
    }
    if (response.size() > kMaxQueryResponsePayload) return Status::InvalidArg;
    memcpy(output, response.data(), response.size());
    *output_length = 1 + response.size();
    return Status::Ok;
}

static Status ota_state(const Frame& frame, uint8_t* output, size_t* output_length)
{
    if (frame.payload_length != 0) return Status::InvalidArg;
    IdfWebOtaState state;
    const esp_err_t err = idf_web_ota_get_state(&state);
    if (err != ESP_OK) return map_error(err);
    write_u32(output, state.active_offset);
    output[4] = static_cast<uint8_t>(state.image_state);
    output[5] = state.pending_verify ? 1 : 0;
    write_u32(output + 6, state.accepted);
    write_u32(output + 10, state.pending);
    write_u32(output + 14, state.pending_address);
    *output_length = 1 + kOtaStatePayload;
    return Status::Ok;
}

#if !FIRMWARE_IS_RELEASE
static Status ota_migration_recover(const Frame& frame)
{
    if (frame.payload_length != 0) return Status::InvalidArg;
    return map_error(idf_web_ota_migration_recover());
}
#endif

static size_t state_payload(uint8_t* output)
{
    const IdfWifiStatus wifi = idf_wifi_get_status();
    uint8_t flags = 0;
    if (wifi.staConnected) flags |= 0x01;
    if (wifi.apMode) flags |= 0x02;
    if (idf_config_wifi_network_count() > 0) flags |= 0x04;
    uint8_t ip[4] = {};
    if (!wifi.ip.empty() && inet_pton(AF_INET, wifi.ip.c_str(), ip) == 1) flags |= 0x08;
    output[0] = flags;
    memcpy(output + 1, ip, sizeof(ip));
    write_u32(output + 1 + sizeof(ip), s_boot_id);
    return 1 + sizeof(ip) + sizeof(s_boot_id);
}

static esp_err_t write_frame(uint8_t command, uint8_t sequence,
                             const uint8_t* payload, size_t payload_length)
{
    if (payload_length > kMaxPayload) return ESP_ERR_INVALID_ARG;
    uint8_t frame[kMaxFrame] = {};
    frame[0] = kMagic0;
    frame[1] = kMagic1;
    frame[2] = kVersion;
    frame[3] = command;
    frame[4] = static_cast<uint8_t>(payload_length);
    frame[5] = static_cast<uint8_t>(payload_length >> 8);
    frame[6] = sequence;
    memcpy(frame + kHeaderSize, payload, payload_length);
    const uint16_t crc = crc16(frame, kHeaderSize + payload_length);
    frame[kHeaderSize + payload_length] = static_cast<uint8_t>(crc);
    frame[kHeaderSize + payload_length + 1] = static_cast<uint8_t>(crc >> 8);
    const size_t frame_length = kHeaderSize + payload_length + kCrcSize;
    const int written = usb_serial_jtag_write_bytes(frame, frame_length, kIoTimeout);
    if (written != static_cast<int>(frame_length)) return ESP_ERR_TIMEOUT;
    return usb_serial_jtag_wait_tx_done(kIoTimeout);
}

static void handle_frame(const Frame& frame)
{
    uint8_t payload[1 + kMaxPayload] = {};
    TaskHandle_t deferred_task = nullptr;
    Status status = Status::InvalidArg;
    size_t payload_length = 1;
    if (frame.command == kCommandState && frame.payload_length == 0) {
        status = Status::Ok;
        payload_length += state_payload(payload + 1);
    } else if (frame.command == kCommandWifiProvision) {
        status = provision_wifi_legacy(frame);
    } else if (frame.command == kCommandWifiProvisionAsync) {
        status = provision_wifi_async(frame, &deferred_task);
    } else if (frame.command == kCommandWifiProvisionStatus) {
        status = provision_wifi_status(frame, payload + 1, &payload_length);
    } else if (frame.command == kCommandModemQuery) {
        status = modem_query(frame, payload + 1, &payload_length);
    } else if (frame.command == kCommandOtaState) {
        status = ota_state(frame, payload + 1, &payload_length);
#if !FIRMWARE_IS_RELEASE
    } else if (frame.command == kCommandOtaMigrationRecover) {
        status = ota_migration_recover(frame);
#endif
    }
    payload[0] = static_cast<uint8_t>(status);
    (void)write_frame(static_cast<uint8_t>(frame.command | kResponseMask), frame.sequence,
                      payload, payload_length);
    if (deferred_task) xTaskNotifyGive(deferred_task);
}

static void usb_recovery_task(void*)
{
    s_boot_id = esp_random();
    if (s_boot_id == 0) s_boot_id = 1;
    FrameParser parser;
    Frame frame;
    uint8_t input[64] = {};
    while (true) {
        const int read = usb_serial_jtag_read_bytes(input, sizeof(input), pdMS_TO_TICKS(500));
        parser.reset_if_idle(xTaskGetTickCount());
        if (read <= 0) continue;
        parser.feed(input, static_cast<size_t>(read));
        while (parser.next(frame)) handle_frame(frame);
        secure_zero(&frame, sizeof(frame));
        secure_zero(input, sizeof(input));
    }
}

}

esp_err_t idf_usb_recovery_start(void)
{
    static bool installed = false;
    if (installed) return ESP_OK;
    usb_serial_jtag_driver_config_t config = {};
    config.rx_buffer_size = 256;
    config.tx_buffer_size = 256;
    esp_err_t err = usb_serial_jtag_driver_install(&config);
    if (err != ESP_OK) return err;
    if (xTaskCreate(usb_recovery_task, "usb_recovery", 4096, nullptr, 2, nullptr) != pdPASS) {
        usb_serial_jtag_driver_uninstall();
        return ESP_ERR_NO_MEM;
    }
    installed = true;
    return ESP_OK;
}

#endif
