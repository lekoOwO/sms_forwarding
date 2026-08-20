#include "idf_log.h"
#include "idf_util.h"

#include <inttypes.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <array>
#include <atomic>

#include "esp_attr.h"
#include "esp_system.h"
#include "freertos/FreeRTOS.h"
#include "freertos/semphr.h"
#include "freertos/task.h"
#include "nvs.h"
#include "nvs_flash.h"

static constexpr size_t LOG_RING_SIZE = 120;
static constexpr size_t LOG_LINE_MAX = 192;

static SemaphoreHandle_t s_log_mutex = nullptr;
static std::array<std::string, LOG_RING_SIZE> s_lines;
static uint32_t s_seq = 0;
// Lock-free mirror of s_seq. The lock-timeout fallback can still return the actual sequence number.
// The Web UI treats seq=0 as a device restart and clears and replays the log.
static std::atomic<uint32_t> s_seq_mirror{0};
static size_t s_count = 0;
static size_t s_next = 0;

// ---- Previous-run log (pre-restart image) ----
// The log also enters a .noinit RAM byte ring. Software, watchdog, and panic resets preserve this memory.
// Startup extracts the previous session so the user can see the final actions before a crash.
// A power-on reset loses RAM, so an abnormal reset also saves the ring in the smsdata NVS partition.
static constexpr size_t PREV_RING_SIZE = 8192;
static constexpr uint32_t PREV_MAGIC = 0x4C4F4752;  // 'LOGR'

struct NoinitLogRing {
    uint32_t magic;
    uint32_t head;   // Next write position
    uint32_t used;   // Valid byte count (<= PREV_RING_SIZE)
    uint32_t check;  // Simple consistency check that rejects random power-on contents
    char buf[PREV_RING_SIZE];
};

static __NOINIT_ATTR NoinitLogRing s_prev_ring;
static bool s_prev_ring_ready = false;   // Do not write before capture completes, to preserve the previous session
static std::string s_prev_log;           // Previous log extracted at startup, including its header
static bool s_prev_deferred_save = false;
static bool s_prev_deferred_started = false;
static bool s_prev_flash_load_tried = false;

// smsdata is a dedicated 640 KB NVS partition that also stores retained SMS data. Write only after an abnormal reset.
static constexpr const char* PREV_NVS_PART = "smsdata";
static constexpr const char* PREV_NVS_NS = "prevlog";
static constexpr const char* PREV_NVS_KEY = "log";

static uint32_t prev_ring_checksum()
{
    return PREV_MAGIC ^ s_prev_ring.head ^ (s_prev_ring.used << 8) ^ 0xA5A5A5A5u;
}

static bool prev_ring_valid()
{
    return s_prev_ring.magic == PREV_MAGIC &&
           s_prev_ring.head < PREV_RING_SIZE &&
           s_prev_ring.used <= PREV_RING_SIZE &&
           s_prev_ring.check == prev_ring_checksum();
}

static void prev_ring_reset()
{
    s_prev_ring.magic = PREV_MAGIC;
    s_prev_ring.head = 0;
    s_prev_ring.used = 0;
    s_prev_ring.check = prev_ring_checksum();
}

// Append to the noinit ring. Write data before metadata so a crash loses at most the current line.
static void prev_ring_append(const char* data, size_t len)
{
    if (!s_prev_ring_ready || len == 0) return;
    if (len > PREV_RING_SIZE) {
        data += len - PREV_RING_SIZE;
        len = PREV_RING_SIZE;
    }
    size_t head = s_prev_ring.head;
    size_t first = PREV_RING_SIZE - head;
    if (first > len) first = len;
    memcpy(s_prev_ring.buf + head, data, first);
    if (len > first) memcpy(s_prev_ring.buf, data + first, len - first);
    s_prev_ring.head = (head + len) % PREV_RING_SIZE;
    s_prev_ring.used += len;
    if (s_prev_ring.used > PREV_RING_SIZE) s_prev_ring.used = PREV_RING_SIZE;
    s_prev_ring.check = prev_ring_checksum();
}

static const char* reset_reason_text(esp_reset_reason_t reason)
{
    switch (reason) {
        case ESP_RST_POWERON: return "Power-on reset";
        case ESP_RST_EXT: return "External reset";
        case ESP_RST_SW: return "Software restart";
        case ESP_RST_PANIC: return "Program panic";
        case ESP_RST_INT_WDT: return "Interrupt watchdog";
        case ESP_RST_TASK_WDT: return "Task watchdog";
        case ESP_RST_WDT: return "Other watchdog";
        case ESP_RST_DEEPSLEEP: return "Deep-sleep wakeup";
        case ESP_RST_BROWNOUT: return "Brownout reset";
        case ESP_RST_SDIO: return "SDIO reset";
        case ESP_RST_USB: return "USB/serial reset";
        case ESP_RST_JTAG: return "JTAG reset";
        case ESP_RST_EFUSE: return "eFuse error reset";
        case ESP_RST_PWR_GLITCH: return "Power-glitch reset";
        case ESP_RST_CPU_LOCKUP: return "CPU lockup reset";
        default: return "Unknown";
    }
}

static bool reset_reason_abnormal(esp_reset_reason_t reason)
{
    switch (reason) {
        case ESP_RST_PANIC:
        case ESP_RST_INT_WDT:
        case ESP_RST_TASK_WDT:
        case ESP_RST_WDT:
        case ESP_RST_BROWNOUT:
        case ESP_RST_PWR_GLITCH:
        case ESP_RST_CPU_LOCKUP:
            return true;
        default:
            return false;
    }
}

static esp_err_t prev_log_prepare_nvs()
{
    esp_err_t err = nvs_flash_init_partition(PREV_NVS_PART);
    if (err == ESP_ERR_NVS_NO_FREE_PAGES || err == ESP_ERR_NVS_NEW_VERSION_FOUND) {
        // smsdata retains SMS data. Only the inbox initialization flow can erase this partition.
        return err;
    }
    if (err == ESP_ERR_INVALID_STATE) return ESP_OK;
    return err;
}

// Read the log saved after the previous abnormal reset when power loss removed the RAM image.
static bool prev_log_load_from_nvs(std::string& out)
{
    if (prev_log_prepare_nvs() != ESP_OK) return false;
    nvs_handle_t handle = 0;
    if (nvs_open_from_partition(PREV_NVS_PART, PREV_NVS_NS, NVS_READONLY, &handle) != ESP_OK) {
        return false;
    }
    size_t len = 0;
    bool ok = false;
    if (nvs_get_blob(handle, PREV_NVS_KEY, nullptr, &len) == ESP_OK && len > 0 && len <= PREV_RING_SIZE + 1024) {
        out.resize(len);
        ok = nvs_get_blob(handle, PREV_NVS_KEY, &out[0], &len) == ESP_OK;
        if (!ok) out.clear();
    }
    nvs_close(handle);
    return ok;
}

static void prev_log_save_to_nvs(const std::string& text)
{
    if (text.empty() || prev_log_prepare_nvs() != ESP_OK) return;
    nvs_handle_t handle = 0;
    if (nvs_open_from_partition(PREV_NVS_PART, PREV_NVS_NS, NVS_READWRITE, &handle) != ESP_OK) {
        return;
    }
    if (nvs_set_blob(handle, PREV_NVS_KEY, text.data(), text.size()) == ESP_OK) {
        nvs_commit(handle);
    }
    nvs_close(handle);
}

static void prev_log_set(std::string text)
{
    if (!s_log_mutex) {
        s_prev_log = std::move(text);
        return;
    }
    if (xSemaphoreTake(s_log_mutex, pdMS_TO_TICKS(500)) != pdTRUE) return;
    s_prev_log = std::move(text);
    xSemaphoreGive(s_log_mutex);
}

static std::string prev_log_get()
{
    if (!s_log_mutex || xSemaphoreTake(s_log_mutex, pdMS_TO_TICKS(500)) != pdTRUE) return std::string();
    std::string out = s_prev_log;
    xSemaphoreGive(s_log_mutex);
    return out;
}

static void prev_log_deferred_task(void*)
{
    // Capture RAM only on the startup path. Defer flash writes after an abnormal reset to avoid blocking early startup.
    vTaskDelay(pdMS_TO_TICKS(15000));

    if (s_prev_deferred_save) {
        std::string snapshot = prev_log_get();
        if (!snapshot.empty()) {
            prev_log_save_to_nvs(snapshot);
            idf_log_line("The previous-run log was saved to flash in the background");
        }
    }

    vTaskDelete(nullptr);
}

static void prev_log_start_deferred_save()
{
    s_prev_deferred_save = true;
    if (s_prev_deferred_started) return;
    s_prev_deferred_started = true;
    BaseType_t ok = xTaskCreate(prev_log_deferred_task, "prev_log_save", 6144, nullptr, 1, nullptr);
    if (ok != pdPASS) {
        s_prev_deferred_started = false;
        idf_log_line("Failed to start the previous-run log task");
    }
}

// At startup, extract the previous session from the noinit ring. Persist it only after an abnormal reset.
static void prev_log_capture()
{
    esp_reset_reason_t reason = esp_reset_reason();
    bool abnormal = reset_reason_abnormal(reason);

    std::string body;
    bool from_ram = prev_ring_valid() && s_prev_ring.used > 0;
    if (from_ram) {
        size_t used = s_prev_ring.used;
        size_t start = (s_prev_ring.head + PREV_RING_SIZE - used) % PREV_RING_SIZE;
        body.reserve(used);
        for (size_t i = 0; i < used; ++i) {
            char ch = s_prev_ring.buf[(start + i) % PREV_RING_SIZE];
            // A crash during a ring write can leave a partial line. Replace control characters to keep it readable.
            if (ch != '\n' && static_cast<unsigned char>(ch) < 0x20) ch = ' ';
            body += ch;
        }
        // A full ring usually truncates its oldest line. Remove the fragment before the first newline.
        if (used == PREV_RING_SIZE) {
            size_t nl = body.find('\n');
            if (nl != std::string::npos) body.erase(0, nl + 1);
        }
    }
    prev_ring_reset();
    s_prev_ring_ready = true;

    if (from_ram) {
        std::string text = "===== Previous-run log =====\n";
        text += "Current reset reason: ";
        text += reset_reason_text(reason);
        char num[16];
        snprintf(num, sizeof(num), " (%d)\n", static_cast<int>(reason));
        text += num;
        if (abnormal) {
            text += "The log will be saved to flash after startup. Download the full crash dump from the log page.\n";
        }
        text += "------------------------\n";
        text += body;
        prev_log_set(std::move(text));
        // Write flash only after an abnormal reset and only in the background. Startup flash operations can cause watchdog reset loops.
        if (abnormal) prev_log_start_deferred_save();
    }

    idf_logf("Current startup reset reason: %s (%d)%s", reset_reason_text(reason), static_cast<int>(reason),
             prev_log_get().empty() ? "" : ", previous log retained (available on the log page)");
}

static void ensure_init()
{
    if (!s_log_mutex) s_log_mutex = xSemaphoreCreateMutex();
}

void idf_log_init(void)
{
    ensure_init();
    static bool s_captured = false;
    if (!s_captured) {
        s_captured = true;
        prev_log_capture();
    }
}

void idf_log_line(const char* line)
{
    ensure_init();
    if (!s_log_mutex || !line) return;

    std::string item(line);
    if (item.size() > LOG_LINE_MAX) {
        size_t end = LOG_LINE_MAX - 3;
        // Move back to a UTF-8 character boundary to prevent invalid output after truncation.
        while (end > 0 && (static_cast<unsigned char>(item[end]) & 0xC0) == 0x80) --end;
        item.resize(end);
        item += "...";
    }

    if (xSemaphoreTake(s_log_mutex, pdMS_TO_TICKS(500)) != pdTRUE) return;
    prev_ring_append(item.data(), item.size());
    prev_ring_append("\n", 1);
    s_lines[s_next] = std::move(item);
    s_next = (s_next + 1) % LOG_RING_SIZE;
    if (s_count < LOG_RING_SIZE) ++s_count;
    ++s_seq;
    s_seq_mirror.store(s_seq, std::memory_order_relaxed);
    xSemaphoreGive(s_log_mutex);
}

void idf_logf(const char* fmt, ...)
{
    char buf[LOG_LINE_MAX + 1];
    va_list ap;
    va_start(ap, fmt);
    int ret = vsnprintf(buf, sizeof(buf), fmt, ap);
    va_end(ap);
    if (ret > static_cast<int>(LOG_LINE_MAX)) {
        // vsnprintf can truncate inside a multibyte character. Move back to a UTF-8 boundary.
        size_t end = LOG_LINE_MAX;
        size_t p = end;
        while (p > 0 && (static_cast<unsigned char>(buf[p - 1]) & 0xC0) == 0x80) --p;
        if (p > 0) {
            unsigned char lead = static_cast<unsigned char>(buf[p - 1]);
            size_t need = (lead >= 0xF0) ? 4 : (lead >= 0xE0) ? 3 : (lead >= 0xC0) ? 2 : 1;
            if (need > 1 && p - 1 + need > end) end = p - 1;  // Remove an incomplete final character
        }
        buf[end] = '\0';
    }
    idf_log_line(buf);
}

std::string idf_log_json_since(uint32_t since)
{
    ensure_init();
    std::string out;
    out.reserve(2048);

    if (!s_log_mutex || xSemaphoreTake(s_log_mutex, pdMS_TO_TICKS(500)) != pdTRUE) {
        // Return the latest known sequence instead of 0. A sequence decrease makes the Web UI replay the log.
        char fallback[48];
        snprintf(fallback, sizeof(fallback), "{\"seq\":%" PRIu32 ",\"lines\":[]}",
                 s_seq_mirror.load(std::memory_order_relaxed));
        return fallback;
    }

    uint32_t seq = s_seq;
    size_t count = s_count;
    size_t start = (s_next + LOG_RING_SIZE - count) % LOG_RING_SIZE;
    uint32_t oldest = seq >= count ? seq - static_cast<uint32_t>(count) + 1 : 1;
    // A client cursor above the current sequence means the device restarted. Replay from 0.
    // Otherwise the Web UI waits until the new log reaches the old cursor.
    if (since > seq) since = 0;

    char head[48];
    snprintf(head, sizeof(head), "{\"seq\":%" PRIu32 ",\"lines\":[", seq);
    out += head;
    bool first = true;
    for (size_t i = 0; i < count; ++i) {
        uint32_t line_seq = oldest + static_cast<uint32_t>(i);
        if (line_seq <= since) continue;
        if (!first) out += ",";
        first = false;
        out += "\"";
        idf_util_json_escape_append(out, s_lines[(start + i) % LOG_RING_SIZE]);
        out += "\"";
    }
    out += "]}";
    xSemaphoreGive(s_log_mutex);
    return out;
}

std::string idf_log_text_dump(void)
{
    ensure_init();
    std::string out;
    out.reserve(4096);
    if (!s_log_mutex || xSemaphoreTake(s_log_mutex, pdMS_TO_TICKS(500)) != pdTRUE) return out;

    size_t count = s_count;
    size_t start = (s_next + LOG_RING_SIZE - count) % LOG_RING_SIZE;
    for (size_t i = 0; i < count; ++i) {
        out += s_lines[(start + i) % LOG_RING_SIZE];
        out += "\r\n";
    }
    xSemaphoreGive(s_log_mutex);
    return out;
}

bool idf_log_has_prev(void)
{
    return !prev_log_get().empty();
}

std::string idf_log_prev_dump(void)
{
    std::string out = prev_log_get();
    if (!out.empty() || s_prev_flash_load_tried) return out;

    s_prev_flash_load_tried = true;
    std::string saved;
    if (prev_log_load_from_nvs(saved) && !saved.empty()) {
        out = "(This startup did not read flash. This is the latest abnormal-reset log read at the user's request.)\n";
        out += saved;
        prev_log_set(out);
    }
    return out;
}
