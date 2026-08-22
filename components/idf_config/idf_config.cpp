#include "idf_config.h"
#include "idf_config_storage.h"
#include "config_schema_generated.h"

#include <algorithm>
#include <cstring>
#include <ctype.h>
#include <errno.h>
#include <limits.h>
#include <iterator>
#include <memory>
#include <new>
#include <regex.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <utility>

#include "esp_log.h"
#include "freertos/FreeRTOS.h"
#include "freertos/semphr.h"
#include "idf_log.h"

static const char* TAG = "idf_config";
static IdfConfig s_config;
static_assert(sizeof(IdfConfig) == 3216, "IdfConfig size changed; review stack/heap persistence bounds");
static SemaphoreHandle_t s_config_mutex = nullptr;
static SemaphoreHandle_t s_persist_mutex = nullptr;
static IdfConfigLoadStatus s_config_load_status = IdfConfigLoadStatus::Unknown;

struct ConfigUpdate {
    std::unique_ptr<IdfConfig> base;
    std::unique_ptr<IdfConfig> next;
    bool locked = false;
    bool factory_reset = false;

    ~ConfigUpdate()
    {
        if (locked) xSemaphoreGive(s_persist_mutex);
    }
};

static esp_err_t begin_config_update(ConfigUpdate& update);
static esp_err_t finish_config_update(ConfigUpdate& update);
static esp_err_t cancel_config_update(ConfigUpdate& update, esp_err_t err);

static esp_err_t ensure_config_mutex()
{
    if (!s_config_mutex) {
        s_config_mutex = xSemaphoreCreateMutex();
        if (!s_config_mutex) return ESP_ERR_NO_MEM;
    }
    if (!s_persist_mutex) {
        s_persist_mutex = xSemaphoreCreateMutex();
        if (!s_persist_mutex) return ESP_ERR_NO_MEM;
    }
    return ESP_OK;
}

static IdfConfig config_snapshot()
{
    if (ensure_config_mutex() != ESP_OK) return IdfConfig();
    std::unique_ptr<IdfConfig> copy(new (std::nothrow) IdfConfig);
    if (!copy) return IdfConfig();
    xSemaphoreTake(s_config_mutex, portMAX_DELAY);
    *copy = s_config;
    xSemaphoreGive(s_config_mutex);
    return std::move(*copy);
}

static esp_err_t replace_config(IdfConfig& next)
{
    esp_err_t err = ensure_config_mutex();
    if (err != ESP_OK) return err;
    xSemaphoreTake(s_config_mutex, portMAX_DELAY);
    using std::swap;
    static_assert(noexcept(swap(s_config, next)), "IdfConfig publication must not allocate");
    swap(s_config, next);
    xSemaphoreGive(s_config_mutex);
    return ESP_OK;
}

static std::string channel_default_name(int idx)
{
    char buf[20];
    snprintf(buf, sizeof(buf), "Channel %d", idx + 1);
    return std::string(buf);
}

static bool is_blank(const std::string& value)
{
    return value.find_first_not_of(" \t\r\n") == std::string::npos;
}

static constexpr bool wifi_tx_power_valid(uint8_t power)
{
    return power == 8 || power == 20 || power == 28 || power == 34 || power == 44 ||
           power == 52 || power == 56 || power == 60 || power == 66 || power == 72 || power == 80;
}
static_assert(wifi_tx_power_valid(34) && wifi_tx_power_valid(80) && !wifi_tx_power_valid(40),
              "WiFi power levels must match the ESP-IDF mapping");

static std::string trim_copy(const std::string& value)
{
    size_t start = value.find_first_not_of(" \t\r\n");
    if (start == std::string::npos) return {};
    size_t end = value.find_last_not_of(" \t\r\n");
    return value.substr(start, end - start + 1);
}

static std::string cfg_escape(const std::string& value)
{
    std::string out;
    out.reserve(value.size() + 8);
    for (char ch : value) {
        if (ch == '\\') out += "\\\\";
        else if (ch == '\n') out += "\\n";
        else if (ch == '\r') out += "\\r";
        else out += ch;
    }
    return out;
}

static std::string cfg_unescape(const std::string& value)
{
    std::string out;
    out.reserve(value.size());
    for (size_t i = 0; i < value.size(); ++i) {
        char ch = value[i];
        if (ch == '\\' && i + 1 < value.size()) {
            char next = value[i + 1];
            if (next == 'n') { out += '\n'; ++i; }
            else if (next == 'r') { out += '\r'; ++i; }
            else if (next == '\\') { out += '\\'; ++i; }
            else out += ch;
        } else {
            out += ch;
        }
    }
    return out;
}

static bool bool_from_text(const std::string& value)
{
    return value == "1" || value == "true" || value == "on" || value == "yes";
}

static bool parse_int_strict(const std::string& value, int& out)
{
    const char* start = value.c_str();
    while (isspace(static_cast<unsigned char>(*start))) ++start;
    if (*start == '\0') return false;
    errno = 0;
    char* end = nullptr;
    long parsed = strtol(start, &end, 10);
    if (end == start || errno == ERANGE || parsed < INT_MIN || parsed > INT_MAX) return false;
    while (isspace(static_cast<unsigned char>(*end))) ++end;
    if (*end != '\0') return false;
    out = static_cast<int>(parsed);
    return true;
}

static bool parse_u32_strict(const std::string& value, uint32_t& out)
{
    const char* p = value.c_str();
    while (isspace(static_cast<unsigned char>(*p))) ++p;
    if (!isdigit(static_cast<unsigned char>(*p))) return false;
    uint64_t parsed = 0;
    while (isdigit(static_cast<unsigned char>(*p))) {
        parsed = parsed * 10ULL + static_cast<unsigned>(*p - '0');
        if (parsed > 0xffffffffULL) return false;
        ++p;
    }
    while (isspace(static_cast<unsigned char>(*p))) ++p;
    if (*p != '\0') return false;
    out = static_cast<uint32_t>(parsed);
    return true;
}

static void import_int_field(int& target, const std::string& value)
{
    int parsed = 0;
    if (parse_int_strict(value, parsed)) target = parsed;
}

static void import_u8_field(uint8_t& target, const std::string& value)
{
    int parsed = 0;
    if (parse_int_strict(value, parsed) && parsed >= 0 && parsed <= 255) {
        target = static_cast<uint8_t>(parsed);
    }
}

static void import_u32_field(uint32_t& target, const std::string& value)
{
    uint32_t parsed = 0;
    if (parse_u32_strict(value, parsed)) target = parsed;
}

static void append_kv(std::string& out, const char* key, const std::string& value)
{
    out += key;
    out += "=";
    out += cfg_escape(value);
    out += "\n";
}

static void append_kv_i(std::string& out, const char* key, int value)
{
    char buf[32];
    snprintf(buf, sizeof(buf), "%d", value);
    append_kv(out, key, buf);
}

static void append_kv_u32(std::string& out, const char* key, uint32_t value)
{
    char buf[32];
    snprintf(buf, sizeof(buf), "%lu", static_cast<unsigned long>(value));
    append_kv(out, key, buf);
}

static const char* redact_secret(const std::string& value)
{
    return value.empty() ? "" : "__REDACTED__";
}

static bool is_redacted_secret(const std::string& value)
{
    return value == "__REDACTED__";
}

// POSIX ERE does not support Perl-style \d, \w, or \s. Translate saved legacy
// rules to POSIX classes before compilation. Validation and runtime matching
// share this translation to keep their behavior consistent.
std::string idf_config_translate_perl_classes(const std::string& pattern)
{
    std::string out;
    out.reserve(pattern.size() + 16);
    bool in_bracket = false;
    for (size_t i = 0; i < pattern.size(); ++i) {
        char ch = pattern[i];
        if (ch == '[' && !in_bracket) { in_bracket = true; out += ch; continue; }
        if (ch == ']' && in_bracket) { in_bracket = false; out += ch; continue; }
        if (ch != '\\' || i + 1 >= pattern.size()) { out += ch; continue; }
        char next = pattern[i + 1];
        const char* body = nullptr;
        const char* neg = nullptr;
        switch (next) {
            case 'd': body = "0-9"; break;
            case 'D': neg = "0-9"; break;
            case 'w': body = "A-Za-z0-9_"; break;
            case 'W': neg = "A-Za-z0-9_"; break;
            case 's': body = " \t\r\n\f\v"; break;
            case 'S': neg = " \t\r\n\f\v"; break;
            default: out += ch; out += next; ++i; continue;
        }
        if (in_bracket) {
            if (body) { out += body; ++i; }
            else { out += ch; out += next; ++i; }
        } else {
            out += '[';
            if (neg) { out += '^'; out += neg; }
            else out += body;
            out += ']';
            ++i;
        }
    }
    return out;
}

esp_err_t idf_config_validate_forward_rules(const std::string& rules, std::string* message) try
{
    size_t pos = 0;
    int line_no = 0;
    while (pos < rules.size()) {
        size_t end = rules.find('\n', pos);
        if (end == std::string::npos) end = rules.size();
        std::string line = trim_copy(rules.substr(pos, end - pos));
        pos = end + (end < rules.size() ? 1 : 0);
        ++line_no;
        if (line.empty()) continue;

        size_t t1 = line.find('\t');
        size_t t2 = t1 == std::string::npos ? std::string::npos : line.find('\t', t1 + 1);
        if (t1 == std::string::npos || t2 == std::string::npos) continue;
        size_t t3 = line.find('\t', t2 + 1);
        std::string type = line.substr(0, t1);
        std::string pat = line.substr(t1 + 1, t2 - t1 - 1);
        std::string enabled = t3 == std::string::npos ? "1" : trim_copy(line.substr(t3 + 1));
        if (enabled == "0" || pat.empty() || type == "kw") continue;
        if (type != "from" && type != "re") continue;

        std::string posix = idf_config_translate_perl_classes(pat);
        regex_t re = {};
        int rc = regcomp(&re, posix.c_str(), REG_EXTENDED | REG_ICASE | REG_NOSUB);
        if (rc != 0) {
            if (message) {
                char errbuf[96] = {};
                regerror(rc, &re, errbuf, sizeof(errbuf));
                *message = "Invalid regex on line " + std::to_string(line_no) + ": " + errbuf;
            }
            return ESP_ERR_INVALID_ARG;
        }
        regfree(&re);
    }
    if (message) message->clear();
    return ESP_OK;
}
catch (const std::bad_alloc&) { return ESP_ERR_NO_MEM; }

esp_err_t idf_config_load(void)
{
    try {
        esp_err_t mutex_err = ensure_config_mutex();
        if (mutex_err != ESP_OK) return mutex_err;
        std::unique_ptr<IdfConfig> loaded(new IdfConfig);
        IdfConfigLoadStatus status = IdfConfigLoadStatus::Unknown;
        esp_err_t err = idf_config_storage_load(*loaded, &status);
        if (err != ESP_OK) {
            s_config_load_status = status;
            ESP_LOGE(TAG, "config load failed: %s", esp_err_to_name(err));
            idf_logf("config load failed (%s)", esp_err_to_name(err));
            return err;
        }
        mutex_err = replace_config(*loaded);
        if (mutex_err != ESP_OK) return mutex_err;
        s_config_load_status = status;
        ESP_LOGI(TAG, "config loaded (status=%u)", static_cast<unsigned>(status));
        idf_logf("config loaded (status=%u)", static_cast<unsigned>(status));
        return ESP_OK;
    } catch (const std::bad_alloc&) {
        s_config_load_status = IdfConfigLoadStatus::StorageError;
        return ESP_ERR_NO_MEM;
    }
}

IdfConfigLoadStatus idf_config_last_load_status(void)
{
    return s_config_load_status;
}

std::string idf_config_export_text(bool full_export)
{
    std::unique_ptr<IdfConfig> c(new (std::nothrow) IdfConfig(idf_config_get()));
    if (!c) return {};
    std::string out;
    out.reserve(4096);

    // Export slot 0 with legacy keys for old firmware. Other slots use wifiNSsid/Pass.
    append_kv(out, "wifiSsid", c->wifiNetworks[0].ssid);
    append_kv(out, "wifiPass", full_export ? c->wifiNetworks[0].pass : redact_secret(c->wifiNetworks[0].pass));
    for (int i = 1; i < IDF_MAX_WIFI_NETWORKS; ++i) {
        char key[16];
        snprintf(key, sizeof(key), "wifi%dSsid", i);
        append_kv(out, key, c->wifiNetworks[i].ssid);
        snprintf(key, sizeof(key), "wifi%dPass", i);
        append_kv(out, key, full_export ? c->wifiNetworks[i].pass : redact_secret(c->wifiNetworks[i].pass));
    }
    append_kv_i(out, "wifiTxPowerQuarterDbm", c->wifiTxPowerQuarterDbm);
    append_kv(out, "smtpServer", c->smtpServer);
    append_kv_i(out, "smtpPort", c->smtpPort);
    append_kv(out, "smtpUser", c->smtpUser);
    append_kv(out, "smtpPass", full_export ? c->smtpPass : redact_secret(c->smtpPass));
    append_kv(out, "smtpSendTo", c->smtpSendTo);
    append_kv(out, "adminPhone", c->adminPhone);
    append_kv(out, "webUser", c->webUser);
    append_kv(out, "webPass", full_export ? c->webPass : redact_secret(c->webPass));
    append_kv(out, "numBlkList", c->numberBlackList);
    append_kv(out, "fwdRules", c->forwardRules);
    append_kv_i(out, "emailEnabled", c->emailEnabled ? 1 : 0);
    append_kv_i(out, "pushEnabled", c->pushEnabled ? 1 : 0);

    append_kv_i(out, "tzOffsetMin", c->tzOffsetMin);
    append_kv(out, "ntpServer", c->ntpServer);
    append_kv(out, "mdnsHost", c->mdnsHost);
    append_kv_i(out, "rebootEnabled", c->rebootEnabled ? 1 : 0);
    append_kv_i(out, "rebootHour", c->rebootHour);
    append_kv_i(out, "hbEnabled", c->hbEnabled ? 1 : 0);
    append_kv_i(out, "hbHour", c->hbHour);
    append_kv_i(out, "smsHealthEnabled", c->smsHealthEnabled ? 1 : 0);
    append_kv_i(out, "smsHealthHour", c->smsHealthHour);
    append_kv_i(out, "smsHealthNotify", c->smsHealthNotify ? 1 : 0);

    append_kv_i(out, "kaEnabled", c->kaEnabled ? 1 : 0);
    append_kv_i(out, "kaIntervalDays", c->kaIntervalDays);
    append_kv_i(out, "kaAction", c->kaAction);
    append_kv(out, "kaTarget", c->kaTarget);
    append_kv(out, "kaUrl", c->kaUrl);
    append_kv(out, "kaProfile", c->kaProfile);
    append_kv_u32(out, "kaLastTime", c->kaLastTime);
    append_kv_i(out, "kaTrafficKB", c->kaTrafficKB);

    append_kv_i(out, "netLedEnabled", c->netLedEnabled ? 1 : 0);
    append_kv_i(out, "callNotifyEnabled", c->callNotifyEnabled ? 1 : 0);
    append_kv_i(out, "dataEnabled", c->dataEnabled ? 1 : 0);
    append_kv_i(out, "roamingEnabled", c->roamingEnabled ? 1 : 0);
    append_kv(out, "apn", c->apn);
    append_kv(out, "operatorPlmn", c->operatorPlmn);
    append_kv(out, "phoneNumber", c->phoneNumber);
    for (int i = 0; i < IDF_MAX_SIM_CREDENTIALS; ++i) {
        char key[20];
        const IdfSimCredential& item = c->simCredentials[i];
        snprintf(key, sizeof(key), "sim%dIccid", i); append_kv(out, key, item.iccid);
        snprintf(key, sizeof(key), "sim%dPin", i); append_kv(out, key, full_export ? item.pin : redact_secret(item.pin));
        snprintf(key, sizeof(key), "sim%dPuk", i); append_kv(out, key, full_export ? item.puk : redact_secret(item.puk));
        snprintf(key, sizeof(key), "sim%dPinMax", i); append_kv_i(out, key, item.pinMaxAttempts);
        snprintf(key, sizeof(key), "sim%dPukMax", i); append_kv_i(out, key, item.pukMaxAttempts);
        snprintf(key, sizeof(key), "sim%dPinFail", i); append_kv_i(out, key, item.pinFailedAttempts);
        snprintf(key, sizeof(key), "sim%dPukFail", i); append_kv_i(out, key, item.pukFailedAttempts);
    }

    for (int i = 0; i < IDF_MAX_PUSH_CHANNELS; ++i) {
        char key[24];
        const IdfPushChannel& ch = c->pushChannels[i];
        snprintf(key, sizeof(key), "push%den", i);
        append_kv_i(out, key, ch.enabled ? 1 : 0);
        snprintf(key, sizeof(key), "push%dtype", i);
        append_kv_i(out, key, ch.type);
        snprintf(key, sizeof(key), "push%durl", i);
        append_kv(out, key, full_export ? ch.url : redact_secret(ch.url));
        snprintf(key, sizeof(key), "push%dname", i);
        append_kv(out, key, ch.name);
        snprintf(key, sizeof(key), "push%dk1", i);
        append_kv(out, key, full_export ? ch.key1 : redact_secret(ch.key1));
        snprintf(key, sizeof(key), "push%dk2", i);
        append_kv(out, key, full_export ? ch.key2 : redact_secret(ch.key2));
        snprintf(key, sizeof(key), "push%dbody", i);
        append_kv(out, key, full_export ? ch.customBody : redact_secret(ch.customBody));
    }

    for (int i = 0; i < IDF_MAX_SCHED_TASKS; ++i) {
        char key[24];
        const IdfSchedTask& t = c->schedTasks[i];
        snprintf(key, sizeof(key), "st%dEn", i);
        append_kv_i(out, key, t.enabled ? 1 : 0);
        snprintf(key, sizeof(key), "st%dName", i);
        append_kv(out, key, t.name);
        snprintf(key, sizeof(key), "st%dProf", i);
        append_kv(out, key, t.profile);
        snprintf(key, sizeof(key), "st%dBack", i);
        append_kv_i(out, key, t.switchBack ? 1 : 0);
        snprintf(key, sizeof(key), "st%dDays", i);
        append_kv_i(out, key, t.intervalDays);
        snprintf(key, sizeof(key), "st%dAct", i);
        append_kv_i(out, key, t.action);
        snprintf(key, sizeof(key), "st%dTgt", i);
        append_kv(out, key, t.target);
        snprintf(key, sizeof(key), "st%dPay", i);
        append_kv(out, key, t.payload);
        snprintf(key, sizeof(key), "st%dLast", i);
        append_kv_u32(out, key, t.lastRun);
    }
    return out;
}

static void apply_import_key(IdfConfig& c, const std::string& key, const std::string& value)
{
    if (key == "wifiSsid") c.wifiNetworks[0].ssid = value;
    else if (key == "wifiPass" && !is_redacted_secret(value)) c.wifiNetworks[0].pass = value;
    else if (key.size() == 9 && key.rfind("wifi", 0) == 0 &&
             isdigit(static_cast<unsigned char>(key[4]))) {
        // wifi1Ssid / wifi1Pass ... Keep saved passwords when a redacted export omits them.
        int idx = key[4] - '0';
        if (idx < 1 || idx >= IDF_MAX_WIFI_NETWORKS) return;
        std::string suffix = key.substr(5);
        if (suffix == "Ssid") c.wifiNetworks[idx].ssid = value;
        else if (suffix == "Pass" && !is_redacted_secret(value)) c.wifiNetworks[idx].pass = value;
    }
    else if (key == "wifiTxPowerQuarterDbm") import_u8_field(c.wifiTxPowerQuarterDbm, value);
    else if (key == "smtpServer") c.smtpServer = value;
    else if (key == "smtpPort") import_int_field(c.smtpPort, value);
    else if (key == "smtpUser") c.smtpUser = value;
    else if (key == "smtpPass" && !is_redacted_secret(value)) c.smtpPass = value;
    else if (key == "smtpSendTo") c.smtpSendTo = value;
    else if (key == "adminPhone") c.adminPhone = value;
    else if (key == "webUser" && !is_blank(value)) c.webUser = value;
    else if (key == "webPass" && !is_blank(value) && !is_redacted_secret(value)) c.webPass = value;
    else if (key == "numBlkList" || key == "numberBlackList") c.numberBlackList = value;
    else if (key == "fwdRules" || key == "forwardRules") c.forwardRules = value;
    else if (key == "emailEnabled") c.emailEnabled = bool_from_text(value);
    else if (key == "pushEnabled") c.pushEnabled = bool_from_text(value);
    else if (key == "tzOffsetMin") import_int_field(c.tzOffsetMin, value);
    else if (key == "ntpServer") c.ntpServer = value;
    else if (key == "mdnsHost") c.mdnsHost = value;
    else if (key == "rebootEnabled") c.rebootEnabled = bool_from_text(value);
    else if (key == "rebootHour") import_int_field(c.rebootHour, value);
    else if (key == "hbEnabled") c.hbEnabled = bool_from_text(value);
    else if (key == "hbHour") import_int_field(c.hbHour, value);
    else if (key == "smsHealthEnabled") c.smsHealthEnabled = bool_from_text(value);
    else if (key == "smsHealthHour") import_int_field(c.smsHealthHour, value);
    else if (key == "smsHealthNotify") c.smsHealthNotify = bool_from_text(value);
    else if (key == "kaEnabled") c.kaEnabled = bool_from_text(value);
    else if (key == "kaIntervalDays") import_int_field(c.kaIntervalDays, value);
    else if (key == "kaAction") import_u8_field(c.kaAction, value);
    else if (key == "kaTarget") c.kaTarget = value;
    else if (key == "kaUrl") c.kaUrl = value.empty() ? IDF_KEEPALIVE_DEFAULT_URL : value;
    else if (key == "kaProfile") c.kaProfile = value;
    else if (key == "kaLastTime") import_u32_field(c.kaLastTime, value);
    else if (key == "kaTrafficKB") import_int_field(c.kaTrafficKB, value);
    else if (key == "netLedEnabled") c.netLedEnabled = bool_from_text(value);
    else if (key == "callNotifyEnabled") c.callNotifyEnabled = bool_from_text(value);
    else if (key == "dataEnabled") c.dataEnabled = bool_from_text(value);
    else if (key == "roamingEnabled") c.roamingEnabled = bool_from_text(value);
    else if (key == "apn") c.apn = value;
    else if (key == "operatorPlmn") c.operatorPlmn = value;
    else if (key == "phoneNumber") c.phoneNumber = value;
    else if (key.rfind("sim", 0) == 0 && key.size() > 4 && isdigit(static_cast<unsigned char>(key[3]))) {
        int idx = key[3] - '0';
        if (idx < 0 || idx >= IDF_MAX_SIM_CREDENTIALS) return;
        std::string suffix = key.substr(4);
        IdfSimCredential& item = c.simCredentials[idx];
        if (suffix == "Iccid") item.iccid = value;
        else if (suffix == "Pin" && !is_redacted_secret(value)) item.pin = value;
        else if (suffix == "Puk" && !is_redacted_secret(value)) item.puk = value;
        else if (suffix == "PinMax") import_u8_field(item.pinMaxAttempts, value);
        else if (suffix == "PukMax") import_u8_field(item.pukMaxAttempts, value);
        else if (suffix == "PinFail") import_u8_field(item.pinFailedAttempts, value);
        else if (suffix == "PukFail") import_u8_field(item.pukFailedAttempts, value);
    }
    else if (key.rfind("st", 0) == 0 && key.size() > 3 && isdigit(static_cast<unsigned char>(key[2]))) {
        int idx = key[2] - '0';
        if (idx < 0 || idx >= IDF_MAX_SCHED_TASKS) return;
        std::string suffix = key.substr(3);
        IdfSchedTask& t = c.schedTasks[idx];
        if (suffix == "En") t.enabled = bool_from_text(value);
        else if (suffix == "Name") t.name = value;
        else if (suffix == "Prof") t.profile = value;
        else if (suffix == "Back") t.switchBack = bool_from_text(value);
        else if (suffix == "Days") import_int_field(t.intervalDays, value);
        else if (suffix == "Act") import_u8_field(t.action, value);
        else if (suffix == "Tgt") t.target = value;
        else if (suffix == "Pay") t.payload = value;
        else if (suffix == "Last") import_u32_field(t.lastRun, value);
    }
    else if (key.rfind("push", 0) == 0) {
        size_t pos = 4;
        int idx = 0;
        bool has_digit = false;
        while (pos < key.size() && isdigit(static_cast<unsigned char>(key[pos]))) {
            has_digit = true;
            idx = idx * 10 + (key[pos] - '0');
            ++pos;
        }
        if (!has_digit || idx < 0 || idx >= IDF_MAX_PUSH_CHANNELS) return;
        std::string suffix = key.substr(pos);
        IdfPushChannel& ch = c.pushChannels[idx];
        if (suffix == "en") ch.enabled = bool_from_text(value);
        else if (suffix == "type") import_u8_field(ch.type, value);
        else if (suffix == "url" && !is_redacted_secret(value)) ch.url = value;
        else if (suffix == "name") ch.name = value.empty() ? channel_default_name(idx) : value;
        else if (suffix == "k1" && !is_redacted_secret(value)) ch.key1 = value;
        else if (suffix == "k2" && !is_redacted_secret(value)) ch.key2 = value;
        else if (suffix == "body" && !is_redacted_secret(value)) ch.customBody = value;
    }
}

esp_err_t idf_config_import_text(const std::string& text, int* applied_count) try
{
    if (text.empty()) return ESP_ERR_INVALID_ARG;
    ConfigUpdate update;
    esp_err_t err = begin_config_update(update);
    if (err != ESP_OK) return err;
    IdfConfig& next = *update.next;
    int applied = 0;
    size_t pos = 0;
    while (pos <= text.size()) {
        size_t end = text.find('\n', pos);
        if (end == std::string::npos) end = text.size();
        std::string line = text.substr(pos, end - pos);
        if (!line.empty() && line.back() == '\r') line.pop_back();
        size_t eq = line.find('=');
        if (eq != std::string::npos && eq > 0) {
            std::string key = line.substr(0, eq);
            std::string value = cfg_unescape(line.substr(eq + 1));
            key.erase(0, key.find_first_not_of(" \t\r\n"));
            size_t keep = key.find_last_not_of(" \t\r\n");
            if (keep != std::string::npos) key.erase(keep + 1);
            if (!key.empty()) {
                apply_import_key(next, key, value);
                ++applied;
            }
        }
        if (end == text.size()) break;
        pos = end + 1;
    }

    next.wifiFromFallback = false;
    err = finish_config_update(update);
    if (err == ESP_OK && applied_count) *applied_count = applied;
    return err;
}
catch (const std::bad_alloc&) { return ESP_ERR_NO_MEM; }

esp_err_t idf_config_export_portable(uint8_t* output, size_t capacity, size_t* written)
{
    if (written) *written = 0;
    if (!output || !written) return ESP_ERR_INVALID_ARG;
    esp_err_t err = ensure_config_mutex();
    if (err != ESP_OK) return err;
    if (xSemaphoreTake(s_config_mutex, portMAX_DELAY) != pdTRUE) return ESP_ERR_TIMEOUT;
    try {
        err = idf_config_storage_encode_portable(s_config, output, capacity, written);
    } catch (const std::bad_alloc&) {
        err = ESP_ERR_NO_MEM;
        *written = 0;
    }
    xSemaphoreGive(s_config_mutex);
    return err;
}

esp_err_t idf_config_restore_portable(const uint8_t* bytes, size_t length,
                                      IdfPortableConfigStatus* status)
{
    if (status) *status = IdfPortableConfigStatus::Invalid;
    if (!bytes || length == 0) return ESP_ERR_INVALID_ARG;
    if (status) *status = IdfPortableConfigStatus::Ok;

    ConfigUpdate update;
    esp_err_t err = begin_config_update(update);
    if (err != ESP_OK) return err;
    try {
        // Keep the decode target off the worker stack and publish it only after validation and persistence.
        std::unique_ptr<IdfConfig> decoded(new IdfConfig);
        const IdfPortableConfigStatus decoded_status =
            idf_config_storage_decode_portable(bytes, length, *update.base, *decoded);
        if (status) *status = decoded_status;
        if (decoded_status == IdfPortableConfigStatus::UnsupportedVersion) {
            return cancel_config_update(update, ESP_ERR_NOT_SUPPORTED);
        }
        if (decoded_status != IdfPortableConfigStatus::Ok) {
            return cancel_config_update(update, ESP_ERR_INVALID_ARG);
        }

        *update.next = std::move(*decoded);
        return finish_config_update(update);
    } catch (const std::bad_alloc&) {
        return cancel_config_update(update, ESP_ERR_NO_MEM);
    }
}

esp_err_t idf_config_factory_reset(void) try
{
    ConfigUpdate update;
    esp_err_t err = begin_config_update(update);
    if (err != ESP_OK) return err;
    idf_config_storage_factory_reset(*update.next);
    update.factory_reset = true;
    err = finish_config_update(update);
    if (err == ESP_OK) idf_log_line("config reset to factory defaults");
    return err;
}
catch (const std::bad_alloc&) { return ESP_ERR_NO_MEM; }

esp_err_t idf_config_set_keepalive_last(uint32_t epoch) try
{
    ConfigUpdate update;
    esp_err_t err = begin_config_update(update);
    if (err != ESP_OK) return err;
    update.next->kaLastTime = epoch;
    return finish_config_update(update);
}
catch (const std::bad_alloc&) { return ESP_ERR_NO_MEM; }

esp_err_t idf_config_set_sched_last(int index, uint32_t epoch) try
{
    if (index < 0 || index >= IDF_MAX_SCHED_TASKS) return ESP_ERR_INVALID_ARG;
    ConfigUpdate update;
    esp_err_t err = begin_config_update(update);
    if (err != ESP_OK) return err;
    update.next->schedTasks[index].lastRun = epoch;
    return finish_config_update(update);
}
catch (const std::bad_alloc&) { return ESP_ERR_NO_MEM; }

esp_err_t idf_config_set_net_led_enabled(bool enabled) try
{
    ConfigUpdate update;
    esp_err_t err = begin_config_update(update);
    if (err != ESP_OK) return err;
    update.next->netLedEnabled = enabled;
    return finish_config_update(update);
}
catch (const std::bad_alloc&) { return ESP_ERR_NO_MEM; }

esp_err_t idf_config_set_call_notify_enabled(bool enabled) try
{
    ConfigUpdate update;
    esp_err_t err = begin_config_update(update);
    if (err != ESP_OK) return err;
    update.next->callNotifyEnabled = enabled;
    return finish_config_update(update);
}
catch (const std::bad_alloc&) { return ESP_ERR_NO_MEM; }

static void merge_runtime_markers(IdfConfig& next, const IdfConfig& base)
{
    // kaLast/stXLast track runtime progress. Preserve current RAM values unless
    // this update changes them, so a slow NVS save cannot revert scheduler progress.
    xSemaphoreTake(s_config_mutex, portMAX_DELAY);
    if (next.kaLastTime == base.kaLastTime) next.kaLastTime = s_config.kaLastTime;
    for (int i = 0; i < IDF_MAX_SCHED_TASKS; ++i) {
        if (next.schedTasks[i].lastRun == base.schedTasks[i].lastRun) {
            next.schedTasks[i].lastRun = s_config.schedTasks[i].lastRun;
        }
    }
    xSemaphoreGive(s_config_mutex);
}

static void merge_legacy_mirrors(IdfConfig& next, const IdfConfig& base)
{
    // Existing Web/modem callers still edit these compatibility mirrors.  A
    // candidate save promotes only fields changed by that caller; v5 stores
    // the canonical hostname, heartbeat, and account array exactly once.
    if (next.hostname == base.hostname && next.mdnsHost != base.mdnsHost) next.hostname = next.mdnsHost;
    if (next.heartbeatEnable == base.heartbeatEnable && next.hbEnabled != base.hbEnabled) {
        next.heartbeatEnable = next.hbEnabled;
    }
    if (next.webAccounts[0].username == base.webAccounts[0].username && next.webUser != base.webUser) {
        next.webAccounts[0].username = next.webUser;
    }
    if (next.webAccounts[0].password == base.webAccounts[0].password && next.webPass != base.webPass) {
        next.webAccounts[0].password = next.webPass;
    }
}

static esp_err_t begin_config_update(ConfigUpdate& update)
{
    esp_err_t err = ensure_config_mutex();
    if (err != ESP_OK) return err;
    if (xSemaphoreTake(s_persist_mutex, portMAX_DELAY) != pdTRUE) return ESP_ERR_TIMEOUT;
    update.locked = true;
    try {
        update.base.reset(new IdfConfig);
        update.next.reset(new IdfConfig);
        xSemaphoreTake(s_config_mutex, portMAX_DELAY);
        try {
            *update.base = s_config;
            *update.next = s_config;
        } catch (...) {
            xSemaphoreGive(s_config_mutex);
            throw;
        }
        xSemaphoreGive(s_config_mutex);
        return ESP_OK;
    } catch (const std::bad_alloc&) {
        update.base.reset();
        update.next.reset();
        return cancel_config_update(update, ESP_ERR_NO_MEM);
    }
}

static esp_err_t finish_config_update(ConfigUpdate& update)
{
    if (!update.locked || !update.base || !update.next) return ESP_ERR_INVALID_STATE;
    try {
        if (!update.factory_reset) {
            merge_legacy_mirrors(*update.next, *update.base);
            merge_runtime_markers(*update.next, *update.base);
        }
        esp_err_t err = idf_config_storage_save(*update.next);
        if (err == ESP_OK) {
            update.next->mdnsHost = update.next->hostname;
            update.next->hbEnabled = update.next->heartbeatEnable;
            update.next->webUser = update.next->webAccounts[0].username;
            update.next->webPass = update.next->webAccounts[0].password;
            err = replace_config(*update.next);
        }
        xSemaphoreGive(s_persist_mutex);
        update.locked = false;
        return err;
    } catch (const std::bad_alloc&) {
        return cancel_config_update(update, ESP_ERR_NO_MEM);
    }
}

static esp_err_t cancel_config_update(ConfigUpdate& update, esp_err_t err)
{
    if (update.locked) {
        xSemaphoreGive(s_persist_mutex);
        update.locked = false;
    }
    return err;
}

esp_err_t idf_config_save_wifi(const std::string& ssid, const std::string& pass) try
{
    {
        if (ssid.empty() || ssid.size() > MAX_WIFI_SSID_BYTES ||
            (!pass.empty() && (pass.size() < 8 || pass.size() > MAX_WIFI_PASSWORD_BYTES))) {
            return ESP_ERR_INVALID_ARG;
        }
        ConfigUpdate update;
        esp_err_t err = begin_config_update(update);
        if (err != ESP_OK) return err;
        IdfConfig& next = *update.next;
        int shift_from = IDF_MAX_WIFI_NETWORKS - 1;
        for (int i = 0; i < IDF_MAX_WIFI_NETWORKS; ++i) {
            if (next.wifiNetworks[i].ssid == ssid) { shift_from = i; break; }
        }
        for (int i = shift_from; i > 0; --i) next.wifiNetworks[i] = next.wifiNetworks[i - 1];
        next.wifiNetworks[0] = {ssid, pass};
        next.wifiFromFallback = false;
        return finish_config_update(update);
    }
}
catch (const std::bad_alloc&) { return ESP_ERR_NO_MEM; }

esp_err_t idf_config_save_wifi(const char* ssid, size_t ssid_length,
                               const char* pass, size_t pass_length) try
{
    if (!ssid || !pass || ssid_length == 0 || ssid_length > MAX_WIFI_SSID_BYTES ||
        (pass_length != 0 && (pass_length < 8 || pass_length > MAX_WIFI_PASSWORD_BYTES))) {
        return ESP_ERR_INVALID_ARG;
    }
    return idf_config_save_wifi(std::string(ssid, ssid_length), std::string(pass, pass_length));
}
catch (const std::bad_alloc&) { return ESP_ERR_NO_MEM; }

esp_err_t idf_config_note_wifi_connected(const std::string& ssid, const std::string& pass) try
{
    if (ssid.empty() || ssid.size() > 32 || pass.size() > 64) return ESP_ERR_INVALID_ARG;
    esp_err_t err = ensure_config_mutex();
    if (err != ESP_OK) return err;

    // The list uses most-recently-used order. Slot 0 returns without a write.
    // Move another saved network to slot 0. The last slot is the LRU entry.
    // Persist only a changed or new network. NVS skips unchanged values.
    int found = -1;
    xSemaphoreTake(s_config_mutex, portMAX_DELAY);
    for (int i = 0; i < IDF_MAX_WIFI_NETWORKS; ++i) {
        if (s_config.wifiNetworks[i].ssid == ssid && s_config.wifiNetworks[i].pass == pass) {
            found = i;
            break;
        }
    }
    xSemaphoreGive(s_config_mutex);
    if (found == 0) return ESP_OK;

    err = idf_config_save_wifi(ssid, pass);
    if (err == ESP_OK && found < 0) idf_logf("new network added to saved WiFi: %s", ssid.c_str());
    return err;
}
catch (const std::bad_alloc&) { return ESP_ERR_NO_MEM; }

esp_err_t idf_config_save_wifi_networks(const IdfWifiNetwork nets_in[IDF_MAX_WIFI_NETWORKS],
                                         bool preserve_blank_pass, uint8_t wifi_tx_power_quarter_dbm) try
{
    {
        if (!wifi_tx_power_valid(wifi_tx_power_quarter_dbm)) return ESP_ERR_INVALID_ARG;
        ConfigUpdate update;
        esp_err_t err = begin_config_update(update);
        if (err != ESP_OK) return err;
        IdfConfig& base = *update.base;
        IdfConfig& next = *update.next;
        for (int i = 0; i < IDF_MAX_WIFI_NETWORKS; ++i) next.wifiNetworks[i] = IdfWifiNetwork();
        int w = 0;
        for (int i = 0; i < IDF_MAX_WIFI_NETWORKS && w < IDF_MAX_WIFI_NETWORKS; ++i) {
            if (is_blank(nets_in[i].ssid)) continue;
            if (nets_in[i].ssid.size() > MAX_WIFI_SSID_BYTES ||
                (!nets_in[i].pass.empty() &&
                 (nets_in[i].pass.size() < 8 || nets_in[i].pass.size() > MAX_WIFI_PASSWORD_BYTES))) {
                return cancel_config_update(update, ESP_ERR_INVALID_ARG);
            }
            bool duplicate = false;
            for (int j = 0; j < w; ++j) duplicate = duplicate || next.wifiNetworks[j].ssid == nets_in[i].ssid;
            if (duplicate) continue;
            next.wifiNetworks[w] = nets_in[i];
            if (preserve_blank_pass && next.wifiNetworks[w].pass.empty()) {
                const auto current = std::find_if(
                    std::begin(base.wifiNetworks), std::end(base.wifiNetworks), [&](const auto& item) {
                        return item.ssid == next.wifiNetworks[w].ssid;
                    });
                if (current != std::end(base.wifiNetworks)) {
                    next.wifiNetworks[w].pass = current->pass;
                }
            }
            ++w;
        }
        next.wifiTxPowerQuarterDbm = wifi_tx_power_quarter_dbm;
        if (w > 0) next.wifiFromFallback = false;
        return finish_config_update(update);
    }
}
catch (const std::bad_alloc&) { return ESP_ERR_NO_MEM; }

esp_err_t idf_config_save_wifi_profile(int index, const std::string& ssid,
                                       const std::string& password, bool open,
                                       bool retain_password) try
{
    if (index < 0 || index >= IDF_MAX_WIFI_NETWORKS || ssid.size() > MAX_WIFI_SSID_BYTES) {
        return ESP_ERR_INVALID_ARG;
    }
    if (!ssid.empty() && !open && !password.empty() &&
        (password.size() < 8 || password.size() > MAX_WIFI_PASSWORD_BYTES)) {
        return ESP_ERR_INVALID_ARG;
    }

    ConfigUpdate update;
    esp_err_t err = begin_config_update(update);
    if (err != ESP_OK) return err;
    if (ssid.empty()) {
        update.next->wifiNetworks[index] = IdfWifiNetwork();
    } else if (open) {
        update.next->wifiNetworks[index] = {ssid, std::string()};
    } else if (!password.empty()) {
        update.next->wifiNetworks[index] = {ssid, password};
    } else if (retain_password && update.base->wifiNetworks[index].ssid == ssid &&
               !update.base->wifiNetworks[index].pass.empty()) {
        update.next->wifiNetworks[index] = update.base->wifiNetworks[index];
    } else {
        return cancel_config_update(update, ESP_ERR_INVALID_ARG);
    }
    update.next->wifiFromFallback = false;
    return finish_config_update(update);
}
catch (const std::bad_alloc&) { return ESP_ERR_NO_MEM; }

esp_err_t idf_config_save_account(const std::string& user, const std::string& pass) try
{
    {
        if (user.size() > MAX_WEB_USERNAME_BYTES || pass.size() > MAX_WEB_PASSWORD_BYTES) {
            return ESP_ERR_INVALID_ARG;
        }
        ConfigUpdate update;
        esp_err_t err = begin_config_update(update);
        if (err != ESP_OK) return err;
        IdfConfig& base = *update.base;
        IdfConfig& next = *update.next;
        next.webAccounts[0].username = user.empty() ? base.webAccounts[0].username : user;
        next.webAccounts[0].password = pass.empty() ? base.webAccounts[0].password : pass;
        if (next.webAccounts[0].username.empty() || next.webAccounts[0].password.empty()) {
            return cancel_config_update(update, ESP_ERR_INVALID_ARG);
        }
        return finish_config_update(update);
    }
}
catch (const std::bad_alloc&) { return ESP_ERR_NO_MEM; }

esp_err_t idf_config_save_accounts(const IdfWebAccount accounts[IDF_MAX_WEB_ACCOUNTS],
                                   bool preserve_blank_password) try
{
    if (!accounts) return ESP_ERR_INVALID_ARG;
    for (int i = 0; i < IDF_MAX_WEB_ACCOUNTS; ++i) {
        if (accounts[i].username.size() > MAX_WEB_USERNAME_BYTES ||
            accounts[i].password.size() > MAX_WEB_PASSWORD_BYTES) {
            return ESP_ERR_INVALID_ARG;
        }
    }

    ConfigUpdate update;
    esp_err_t err = begin_config_update(update);
    if (err != ESP_OK) return err;
    for (int i = 0; i < IDF_MAX_WEB_ACCOUNTS; ++i) {
        update.next->webAccounts[i] = accounts[i];
        if (!update.next->webAccounts[i].username.empty() &&
            update.next->webAccounts[i].password.empty() && preserve_blank_password) {
            update.next->webAccounts[i].password = update.base->webAccounts[i].password;
        }
    }
    const bool usable = std::any_of(
        std::begin(update.next->webAccounts), std::end(update.next->webAccounts),
        [](const IdfWebAccount& account) {
            return !account.username.empty() && !account.password.empty();
        });
    if (!usable) return cancel_config_update(update, ESP_ERR_INVALID_ARG);
    return finish_config_update(update);
}
catch (const std::bad_alloc&) { return ESP_ERR_NO_MEM; }

esp_err_t idf_config_save_identity(const std::string& device_name, const std::string& hostname) try
{
    if (device_name.empty() || device_name.size() > MAX_DEVICE_NAME_BYTES || hostname.empty() ||
        hostname.size() > MAX_HOSTNAME_LENGTH || hostname.front() == '-' || hostname.back() == '-') {
        return ESP_ERR_INVALID_ARG;
    }
    if (!std::all_of(hostname.begin(), hostname.end(), [](unsigned char ch) {
            return (ch >= 'a' && ch <= 'z') || (ch >= '0' && ch <= '9') || ch == '-';
        })) return ESP_ERR_INVALID_ARG;
    ConfigUpdate update;
    esp_err_t err = begin_config_update(update);
    if (err != ESP_OK) return err;
    update.next->deviceName = device_name;
    update.next->hostname = hostname;
    update.next->mdnsHost = hostname;
    return finish_config_update(update);
}
catch (const std::bad_alloc&) { return ESP_ERR_NO_MEM; }

esp_err_t idf_config_save_notification_locale(const std::string& locale) try
{
    if (locale != NOTIFICATION_LOCALE_ZH_TW && locale != NOTIFICATION_LOCALE_ZH_CN &&
        locale != NOTIFICATION_LOCALE_EN) {
        return ESP_ERR_INVALID_ARG;
    }
    ConfigUpdate update;
    esp_err_t err = begin_config_update(update);
    if (err != ESP_OK) return err;
    update.next->notificationLocale = locale;
    return finish_config_update(update);
}
catch (const std::bad_alloc&) { return ESP_ERR_NO_MEM; }

esp_err_t idf_config_save_network_mode(int network_mode) try
{
    if (network_mode < NETWORK_MODE_WIFI_ONLY || network_mode > NETWORK_MODE_MIX) {
        return ESP_ERR_INVALID_ARG;
    }
    ConfigUpdate update;
    esp_err_t err = begin_config_update(update);
    if (err != ESP_OK) return err;
    update.next->networkMode = network_mode;
    return finish_config_update(update);
}
catch (const std::bad_alloc&) { return ESP_ERR_NO_MEM; }

esp_err_t idf_config_save_heartbeat(bool enabled, int interval_hours) try
{
    if (interval_hours < MIN_HEARTBEAT_INTERVAL_HOURS || interval_hours > MAX_HEARTBEAT_INTERVAL_HOURS) {
        return ESP_ERR_INVALID_ARG;
    }
    ConfigUpdate update;
    esp_err_t err = begin_config_update(update);
    if (err != ESP_OK) return err;
    update.next->heartbeatEnable = enabled;
    update.next->hbEnabled = enabled;
    update.next->heartbeatInterval = interval_hours;
    return finish_config_update(update);
}
catch (const std::bad_alloc&) { return ESP_ERR_NO_MEM; }

esp_err_t idf_config_save_time(int tz_offset_min, const std::string& ntp_server) try
{
    {
        if (tz_offset_min < -720 || tz_offset_min > 840 || ntp_server.size() > MAX_NTP_SERVER_BYTES) {
            return ESP_ERR_INVALID_ARG;
        }
        ConfigUpdate update;
        esp_err_t err = begin_config_update(update);
        if (err != ESP_OK) return err;
        update.next->tzOffsetMin = tz_offset_min;
        update.next->ntpServer = ntp_server;
        return finish_config_update(update);
    }
}
catch (const std::bad_alloc&) { return ESP_ERR_NO_MEM; }

esp_err_t idf_config_save_mdns_host(const std::string& host) try
{
    {
        if (host.empty() || host.size() > MAX_HOSTNAME_LENGTH) return ESP_ERR_INVALID_ARG;
        ConfigUpdate update;
        esp_err_t err = begin_config_update(update);
        if (err != ESP_OK) return err;
        update.next->hostname = host;
        update.next->mdnsHost = host;
        return finish_config_update(update);
    }
}
catch (const std::bad_alloc&) { return ESP_ERR_NO_MEM; }

esp_err_t idf_config_save_email(bool enabled, const std::string& server, int port,
                                const std::string& user, const std::string& pass,
                                const std::string& send_to, bool preserve_blank_pass) try
{
    {
        if (port < 1 || port > 65535 || server.size() > MAX_SMTP_SERVER_BYTES ||
            user.size() > MAX_SMTP_USER_BYTES || pass.size() > MAX_SMTP_PASSWORD_BYTES ||
            send_to.size() > MAX_SMTP_RECIPIENT_BYTES) return ESP_ERR_INVALID_ARG;
        ConfigUpdate update;
        esp_err_t err = begin_config_update(update);
        if (err != ESP_OK) return err;
        update.next->smtpServer = server;
        update.next->smtpPort = port;
        update.next->smtpUser = user;
        update.next->smtpPass = preserve_blank_pass && pass.empty() ? update.base->smtpPass : pass;
        update.next->smtpSendTo = send_to;
        update.next->emailEnabled = enabled;
        return finish_config_update(update);
    }
}
catch (const std::bad_alloc&) { return ESP_ERR_NO_MEM; }

esp_err_t idf_config_save_push(bool enabled, const IdfPushChannel channels[IDF_MAX_PUSH_CHANNELS]) try
{
    {
        ConfigUpdate update;
        esp_err_t err = begin_config_update(update);
        if (err != ESP_OK) return err;
        update.next->pushEnabled = enabled;
        for (int i = 0; i < IDF_MAX_PUSH_CHANNELS; ++i) update.next->pushChannels[i] = channels[i];
        return finish_config_update(update);
    }
}
catch (const std::bad_alloc&) { return ESP_ERR_NO_MEM; }

esp_err_t idf_config_save_filter(const std::string& admin_phone, const std::string& number_blacklist) try
{
    {
        if (admin_phone.size() > MAX_ADMIN_PHONE_BYTES || number_blacklist.size() > MAX_BLACKLIST_BYTES) {
            return ESP_ERR_INVALID_ARG;
        }
        ConfigUpdate update;
        esp_err_t err = begin_config_update(update);
        if (err != ESP_OK) return err;
        update.next->adminPhone = admin_phone;
        update.next->numberBlackList = number_blacklist;
        return finish_config_update(update);
    }
}
catch (const std::bad_alloc&) { return ESP_ERR_NO_MEM; }

esp_err_t idf_config_save_forward_rules(const std::string& rules) try
{
    {
        if (rules.size() > MAX_FORWARD_RULES_BYTES || idf_config_validate_forward_rules(rules, nullptr) != ESP_OK) {
            return ESP_ERR_INVALID_ARG;
        }
        ConfigUpdate update;
        esp_err_t err = begin_config_update(update);
        if (err != ESP_OK) return err;
        update.next->forwardRules = rules;
        return finish_config_update(update);
    }
}
catch (const std::bad_alloc&) { return ESP_ERR_NO_MEM; }

esp_err_t idf_config_save_keepalive(bool enabled, int interval_days, uint8_t action,
                                    const std::string& target, const std::string& url,
                                    const std::string& profile, int traffic_kb) try
{
    {
        if (interval_days < 1 || interval_days > 3650 || action > 3 ||
            traffic_kb < MIN_KEEPALIVE_TRAFFIC_KB || traffic_kb > MAX_KEEPALIVE_TRAFFIC_KB ||
            target.size() > MAX_KEEPALIVE_TARGET_BYTES ||
            url.size() > MAX_KEEPALIVE_URL_BYTES || profile.size() > MAX_KEEPALIVE_PROFILE_BYTES) {
            return ESP_ERR_INVALID_ARG;
        }
        ConfigUpdate update;
        esp_err_t err = begin_config_update(update);
        if (err != ESP_OK) return err;
        update.next->kaEnabled = enabled;
        update.next->kaIntervalDays = interval_days;
        update.next->kaAction = action;
        update.next->kaTarget = target;
        update.next->kaUrl = url.empty() ? std::string(IDF_KEEPALIVE_DEFAULT_URL) : url;
        update.next->kaProfile = profile;
        update.next->kaTrafficKB = traffic_kb;
        return finish_config_update(update);
    }
}
catch (const std::bad_alloc&) { return ESP_ERR_NO_MEM; }

esp_err_t idf_config_save_system_schedule(bool reboot_enabled, int reboot_hour,
                                          bool hb_enabled, int hb_hour,
                                          bool sms_health_enabled, int sms_health_hour,
                                          bool sms_health_notify) try
{
    {
        if (reboot_hour < 0 || reboot_hour > 23 || hb_hour < 0 || hb_hour > 23 ||
            sms_health_hour < 0 || sms_health_hour > 23) return ESP_ERR_INVALID_ARG;
        ConfigUpdate update;
        esp_err_t err = begin_config_update(update);
        if (err != ESP_OK) return err;
        update.next->rebootEnabled = reboot_enabled;
        update.next->rebootHour = reboot_hour;
        update.next->hbEnabled = hb_enabled;
        update.next->heartbeatEnable = hb_enabled;
        update.next->hbHour = hb_hour;
        update.next->smsHealthEnabled = sms_health_enabled;
        update.next->smsHealthHour = sms_health_hour;
        update.next->smsHealthNotify = sms_health_notify;
        return finish_config_update(update);
    }
}
catch (const std::bad_alloc&) { return ESP_ERR_NO_MEM; }

esp_err_t idf_config_save_sched_tasks(const IdfSchedTask tasks[IDF_MAX_SCHED_TASKS]) try
{
    {
        ConfigUpdate update;
        esp_err_t err = begin_config_update(update);
        if (err != ESP_OK) return err;
        for (int i = 0; i < IDF_MAX_SCHED_TASKS; ++i) {
            update.next->schedTasks[i] = tasks[i];
            update.next->schedTasks[i].lastRun = update.base->schedTasks[i].lastRun;
        }
        return finish_config_update(update);
    }
}
catch (const std::bad_alloc&) { return ESP_ERR_NO_MEM; }

esp_err_t idf_config_save_sim(bool data_enabled, bool roaming_enabled, const std::string& apn,
                              const std::string& operator_plmn, const std::string& phone_number,
                              const IdfSimCredential credentials[IDF_MAX_SIM_CREDENTIALS]) try
{
    {
        if (apn.size() > MAX_APN_BYTES || operator_plmn.size() > MAX_OPERATOR_PLMN_BYTES ||
            phone_number.size() > MAX_PHONE_NUMBER_BYTES) return ESP_ERR_INVALID_ARG;
        ConfigUpdate update;
        esp_err_t err = begin_config_update(update);
        if (err != ESP_OK) return err;
        update.next->dataEnabled = data_enabled;
        update.next->roamingEnabled = roaming_enabled;
        update.next->apn = apn;
        update.next->operatorPlmn = operator_plmn;
        update.next->phoneNumber = phone_number;
        for (int i = 0; i < IDF_MAX_SIM_CREDENTIALS; ++i) {
            update.next->simCredentials[i] = credentials[i];
            const IdfSimCredential& previous = update.base->simCredentials[i];
            if (update.next->simCredentials[i].iccid == previous.iccid) {
                if (update.next->simCredentials[i].pin.empty()) update.next->simCredentials[i].pin = previous.pin;
                if (update.next->simCredentials[i].puk.empty()) update.next->simCredentials[i].puk = previous.puk;
                if (update.next->simCredentials[i].pinFailedAttempts == UINT8_MAX) {
                    update.next->simCredentials[i].pinFailedAttempts = 0;
                } else if (update.next->simCredentials[i].pin == previous.pin) {
                    update.next->simCredentials[i].pinFailedAttempts = previous.pinFailedAttempts;
                }
                if (update.next->simCredentials[i].pukFailedAttempts == UINT8_MAX) {
                    update.next->simCredentials[i].pukFailedAttempts = 0;
                } else if (update.next->simCredentials[i].puk == previous.puk) {
                    update.next->simCredentials[i].pukFailedAttempts = previous.pukFailedAttempts;
                }
            }
        }
        return finish_config_update(update);
    }
}
catch (const std::bad_alloc&) { return ESP_ERR_NO_MEM; }

esp_err_t idf_config_record_sim_unlock_result(const std::string& iccid, bool puk, bool success) try
{
    {
        ConfigUpdate update;
        esp_err_t err = begin_config_update(update);
        if (err != ESP_OK) return err;
        int index = -1;
        for (int i = 0; i < IDF_MAX_SIM_CREDENTIALS; ++i) {
            if (update.next->simCredentials[i].iccid == iccid) {
                index = i;
                break;
            }
        }
        if (index < 0) return cancel_config_update(update, ESP_ERR_NOT_FOUND);
        IdfSimCredential& credential = update.next->simCredentials[index];
        if (puk) {
            credential.pukFailedAttempts = success
                                               ? 0
                                               : std::min<uint8_t>(static_cast<uint8_t>(credential.pukFailedAttempts + 1),
                                                                   credential.pukMaxAttempts);
        } else {
            credential.pinFailedAttempts = success
                                               ? 0
                                               : std::min<uint8_t>(static_cast<uint8_t>(credential.pinFailedAttempts + 1),
                                                                   credential.pinMaxAttempts);
        }
        return finish_config_update(update);
    }
}
catch (const std::bad_alloc&) { return ESP_ERR_NO_MEM; }

IdfConfig idf_config_get(void)
{
    return config_snapshot();
}

static bool email_configured_locked()
{
    return !s_config.smtpServer.empty() && !s_config.smtpUser.empty() &&
           !s_config.smtpPass.empty() && !s_config.smtpSendTo.empty();
}

static int enabled_push_count_locked()
{
    return static_cast<int>(std::count_if(
        std::begin(s_config.pushChannels), std::end(s_config.pushChannels),
        [](const auto& channel) { return channel.enabled; }));
}

IdfConfigStatusView idf_config_get_status_view(void)
{
    IdfConfigStatusView view;
    if (ensure_config_mutex() != ESP_OK) return view;
    xSemaphoreTake(s_config_mutex, portMAX_DELAY);
    view.tzOffsetMin = s_config.tzOffsetMin;
    view.dataEnabled = s_config.dataEnabled;
    view.emailEnabled = s_config.emailEnabled;
    view.pushEnabled = s_config.pushEnabled;
    view.adminPhone = s_config.adminPhone;
    view.phoneNumber = s_config.phoneNumber;
    view.apn = s_config.apn;
    // Derive all /status values under one lock for a consistent snapshot.
    view.emailConfigured = email_configured_locked();
    view.pushEnabledCount = enabled_push_count_locked();
    xSemaphoreGive(s_config_mutex);
    return view;
}

IdfConfigWebView idf_config_get_web_view(void)
{
    IdfConfigWebView view;
    if (ensure_config_mutex() != ESP_OK) return view;
    xSemaphoreTake(s_config_mutex, portMAX_DELAY);
    view.deviceName = s_config.deviceName;
    view.hostname = s_config.hostname;
    view.notificationLocale = s_config.notificationLocale;
    view.webUser = s_config.webUser;
    view.webPass = s_config.webPass;
    view.smtpServer = s_config.smtpServer;
    view.smtpPort = s_config.smtpPort;
    view.smtpUser = s_config.smtpUser;
    view.smtpPass = s_config.smtpPass;
    view.smtpSendTo = s_config.smtpSendTo;
    view.adminPhone = s_config.adminPhone;
    view.numberBlackList = s_config.numberBlackList;
    view.forwardRules = s_config.forwardRules;
    view.emailEnabled = s_config.emailEnabled;
    view.pushEnabled = s_config.pushEnabled;
    view.networkMode = s_config.networkMode;
    view.heartbeatEnable = s_config.heartbeatEnable;
    view.heartbeatInterval = s_config.heartbeatInterval;
    view.ntpServer = s_config.ntpServer;
    view.mdnsHost = s_config.mdnsHost;
    view.tzOffsetMin = s_config.tzOffsetMin;
    view.rebootEnabled = s_config.rebootEnabled;
    view.rebootHour = s_config.rebootHour;
    view.hbEnabled = s_config.hbEnabled;
    view.hbHour = s_config.hbHour;
    view.smsHealthEnabled = s_config.smsHealthEnabled;
    view.smsHealthHour = s_config.smsHealthHour;
    view.smsHealthNotify = s_config.smsHealthNotify;
    view.dataEnabled = s_config.dataEnabled;
    view.roamingEnabled = s_config.roamingEnabled;
    view.apn = s_config.apn;
    view.phoneNumber = s_config.phoneNumber;
    view.operatorPlmn = s_config.operatorPlmn;
    view.kaEnabled = s_config.kaEnabled;
    view.kaIntervalDays = s_config.kaIntervalDays;
    view.kaTrafficKB = s_config.kaTrafficKB;
    view.kaProfile = s_config.kaProfile;
    view.netLedEnabled = s_config.netLedEnabled;
    view.callNotifyEnabled = s_config.callNotifyEnabled;
    view.wifiTxPowerQuarterDbm = s_config.wifiTxPowerQuarterDbm;
    for (int i = 0; i < IDF_MAX_WIFI_NETWORKS; ++i) {
        view.wifiNetworks[i].ssid = s_config.wifiNetworks[i].ssid;
        view.wifiNetworks[i].passSet = !s_config.wifiNetworks[i].pass.empty();
    }
    for (int i = 0; i < IDF_MAX_SIM_CREDENTIALS; ++i) {
        const IdfSimCredential& item = s_config.simCredentials[i];
        view.simCredentials[i].iccid = item.iccid;
        view.simCredentials[i].pinSet = !item.pin.empty();
        view.simCredentials[i].pukSet = !item.puk.empty();
        view.simCredentials[i].pinMaxAttempts = item.pinMaxAttempts;
        view.simCredentials[i].pukMaxAttempts = item.pukMaxAttempts;
        view.simCredentials[i].pinFailedAttempts = item.pinFailedAttempts;
        view.simCredentials[i].pukFailedAttempts = item.pukFailedAttempts;
    }
    for (int i = 0; i < IDF_MAX_WEB_ACCOUNTS; ++i) {
        view.webAccounts[i].username = s_config.webAccounts[i].username;
        view.webAccounts[i].passwordSet = !s_config.webAccounts[i].password.empty();
    }
    view.emailConfigured = email_configured_locked();
    for (int i = 0; i < IDF_MAX_PUSH_CHANNELS; ++i) {
        view.pushChannels[i] = s_config.pushChannels[i];
        view.pushUrlSet[i] = !s_config.pushChannels[i].url.empty();
        view.pushCustomBodySet[i] = !s_config.pushChannels[i].customBody.empty();
        view.pushKey1Set[i] = !s_config.pushChannels[i].key1.empty();
        view.pushKey2Set[i] = !s_config.pushChannels[i].key2.empty();
    }
    view.pushEnabledCount = enabled_push_count_locked();
    xSemaphoreGive(s_config_mutex);
    return view;
}

IdfKeepaliveRunView idf_config_get_keepalive_run_view(void)
{
    IdfKeepaliveRunView view;
    if (ensure_config_mutex() != ESP_OK) return view;
    xSemaphoreTake(s_config_mutex, portMAX_DELAY);
    view.kaEnabled = s_config.kaEnabled;
    view.kaIntervalDays = s_config.kaIntervalDays;
    view.kaAction = s_config.kaAction;
    view.kaTarget = s_config.kaTarget;
    view.kaUrl = s_config.kaUrl;
    view.kaProfile = s_config.kaProfile;
    view.kaLastTime = s_config.kaLastTime;
    view.kaTrafficKB = s_config.kaTrafficKB;
    view.tzOffsetMin = s_config.tzOffsetMin;
    view.emailEnabled = s_config.emailEnabled;
    view.dataEnabled = s_config.dataEnabled;
    view.apn = s_config.apn;
    xSemaphoreGive(s_config_mutex);
    return view;
}

IdfSchedRunView idf_config_get_sched_run_view(int index)
{
    IdfSchedRunView view;
    if (index < 0 || index >= IDF_MAX_SCHED_TASKS) return view;
    if (ensure_config_mutex() != ESP_OK) return view;
    xSemaphoreTake(s_config_mutex, portMAX_DELAY);
    view.valid = true;
    view.task = s_config.schedTasks[index];
    view.kaUrl = s_config.kaUrl;
    view.tzOffsetMin = s_config.tzOffsetMin;
    view.emailEnabled = s_config.emailEnabled;
    view.emailConfigured = email_configured_locked();
    view.dataEnabled = s_config.dataEnabled;
    view.apn = s_config.apn;
    xSemaphoreGive(s_config_mutex);
    return view;
}

IdfSimSettingsView idf_config_get_sim_settings_view(void)
{
    IdfSimSettingsView view;
    if (ensure_config_mutex() != ESP_OK) return view;
    xSemaphoreTake(s_config_mutex, portMAX_DELAY);
    view.dataEnabled = s_config.dataEnabled;
    view.roamingEnabled = s_config.roamingEnabled;
    view.apn = s_config.apn;
    view.operatorPlmn = s_config.operatorPlmn;
    for (int i = 0; i < IDF_MAX_SIM_CREDENTIALS; ++i) view.credentials[i] = s_config.simCredentials[i];
    xSemaphoreGive(s_config_mutex);
    return view;
}

IdfSimUnlockView idf_config_get_sim_unlock_view(const std::string& iccid)
{
    IdfSimUnlockView view;
    if (ensure_config_mutex() != ESP_OK) return view;
    xSemaphoreTake(s_config_mutex, portMAX_DELAY);
    const auto item = std::find_if(
        std::begin(s_config.simCredentials), std::end(s_config.simCredentials),
        [&iccid](const auto& credential) { return credential.iccid == iccid; });
    if (item != std::end(s_config.simCredentials)) {
        view.found = true;
        view.credential = *item;
    }
    xSemaphoreGive(s_config_mutex);
    return view;
}

IdfSmsProcessView idf_config_get_sms_process_view(void)
{
    IdfSmsProcessView view;
    if (ensure_config_mutex() != ESP_OK) return view;
    xSemaphoreTake(s_config_mutex, portMAX_DELAY);
    view.adminPhone = s_config.adminPhone;
    view.numberBlackList = s_config.numberBlackList;
    view.tzOffsetMin = s_config.tzOffsetMin;
    xSemaphoreGive(s_config_mutex);
    return view;
}

IdfPushForwardView idf_config_get_push_forward_view(void)
{
    IdfPushForwardView view;
    if (ensure_config_mutex() != ESP_OK) return view;
    xSemaphoreTake(s_config_mutex, portMAX_DELAY);
    view.deviceName = s_config.deviceName;
    view.hostname = s_config.hostname;
    view.notificationLocale = s_config.notificationLocale;
    view.networkMode = s_config.networkMode;
    view.heartbeatEnable = s_config.heartbeatEnable;
    view.heartbeatInterval = s_config.heartbeatInterval;
    view.forwardRules = s_config.forwardRules;
    view.pushEnabled = s_config.pushEnabled;
    view.emailEnabled = s_config.emailEnabled;
    view.emailConfigured = email_configured_locked();
    for (int i = 0; i < IDF_MAX_PUSH_CHANNELS; ++i) view.pushChannels[i] = s_config.pushChannels[i];
    xSemaphoreGive(s_config_mutex);
    return view;
}

IdfPushNotifyView idf_config_get_push_notify_view(void)
{
    IdfPushNotifyView view;
    if (ensure_config_mutex() != ESP_OK) return view;
    xSemaphoreTake(s_config_mutex, portMAX_DELAY);
    view.deviceName = s_config.deviceName;
    view.hostname = s_config.hostname;
    view.notificationLocale = s_config.notificationLocale;
    view.networkMode = s_config.networkMode;
    view.heartbeatEnable = s_config.heartbeatEnable;
    view.heartbeatInterval = s_config.heartbeatInterval;
    view.pushEnabled = s_config.pushEnabled;
    view.tzOffsetMin = s_config.tzOffsetMin;
    for (int i = 0; i < IDF_MAX_PUSH_CHANNELS; ++i) view.pushChannels[i] = s_config.pushChannels[i];
    xSemaphoreGive(s_config_mutex);
    return view;
}

IdfEmailSettingsView idf_config_get_email_settings_view(void)
{
    IdfEmailSettingsView view;
    if (ensure_config_mutex() != ESP_OK) return view;
    xSemaphoreTake(s_config_mutex, portMAX_DELAY);
    view.emailEnabled = s_config.emailEnabled;
    view.emailConfigured = email_configured_locked();
    view.smtpServer = s_config.smtpServer;
    view.smtpPort = s_config.smtpPort;
    view.smtpUser = s_config.smtpUser;
    view.smtpPass = s_config.smtpPass;
    view.smtpSendTo = s_config.smtpSendTo;
    xSemaphoreGive(s_config_mutex);
    return view;
}

IdfSchedulerView idf_config_get_scheduler_view(void)
{
    IdfSchedulerView view;
    if (ensure_config_mutex() != ESP_OK) return view;
    xSemaphoreTake(s_config_mutex, portMAX_DELAY);
    view.kaEnabled = s_config.kaEnabled;
    view.kaIntervalDays = s_config.kaIntervalDays;
    view.kaAction = s_config.kaAction;
    view.kaTrafficKB = s_config.kaTrafficKB;
    view.kaLastTime = s_config.kaLastTime;
    view.tzOffsetMin = s_config.tzOffsetMin;
    view.rebootEnabled = s_config.rebootEnabled;
    view.rebootHour = s_config.rebootHour;
    view.hbEnabled = s_config.hbEnabled;
    view.hbHour = s_config.hbHour;
    view.smsHealthEnabled = s_config.smsHealthEnabled;
    view.smsHealthHour = s_config.smsHealthHour;
    view.smsHealthNotify = s_config.smsHealthNotify;
    view.emailEnabled = s_config.emailEnabled;
    for (int i = 0; i < IDF_MAX_SCHED_TASKS; ++i) view.schedTasks[i] = s_config.schedTasks[i];
    xSemaphoreGive(s_config_mutex);
    return view;
}

bool idf_config_get_push_channel(uint8_t channel, IdfPushChannel& out)
{
    if (channel >= IDF_MAX_PUSH_CHANNELS) return false;
    if (ensure_config_mutex() != ESP_OK) return false;
    xSemaphoreTake(s_config_mutex, portMAX_DELAY);
    out = s_config.pushChannels[channel];
    xSemaphoreGive(s_config_mutex);
    return true;
}

// Read small fields under the lock. A full snapshot copies 42 std::string values
// and causes repeated heap allocation and fragmentation on each HTTP request.
std::vector<IdfWifiNetwork> idf_config_get_wifi_networks(void)
{
    std::vector<IdfWifiNetwork> nets;
    if (ensure_config_mutex() != ESP_OK) return nets;
    nets.reserve(IDF_MAX_WIFI_NETWORKS);
    xSemaphoreTake(s_config_mutex, portMAX_DELAY);
    for (int i = 0; i < IDF_MAX_WIFI_NETWORKS; ++i) {
        if (!s_config.wifiNetworks[i].ssid.empty()) nets.push_back(s_config.wifiNetworks[i]);
    }
    xSemaphoreGive(s_config_mutex);
    return nets;
}

int idf_config_wifi_network_count(void)
{
    if (ensure_config_mutex() != ESP_OK) return 0;
    xSemaphoreTake(s_config_mutex, portMAX_DELAY);
    int count = 0;
    for (int i = 0; i < IDF_MAX_WIFI_NETWORKS; ++i) {
        if (!s_config.wifiNetworks[i].ssid.empty()) ++count;
    }
    xSemaphoreGive(s_config_mutex);
    return count;
}

bool idf_config_net_led_enabled(void)
{
    if (ensure_config_mutex() != ESP_OK) return true;
    xSemaphoreTake(s_config_mutex, portMAX_DELAY);
    bool on = s_config.netLedEnabled;
    xSemaphoreGive(s_config_mutex);
    return on;
}

bool idf_config_call_notify_enabled(void)
{
    if (ensure_config_mutex() != ESP_OK) return true;
    xSemaphoreTake(s_config_mutex, portMAX_DELAY);
    bool on = s_config.callNotifyEnabled;
    xSemaphoreGive(s_config_mutex);
    return on;
}

// SNTP and system event callbacks have small stacks (about 3.5 KB and 4 KB).
// Copy only the required fields under the lock. A full IdfConfig copy can overflow
// these stacks when the scheduled task count increases.
int idf_config_get_tz_offset(void)
{
    if (ensure_config_mutex() != ESP_OK) return 480;
    xSemaphoreTake(s_config_mutex, portMAX_DELAY);
    int tz = s_config.tzOffsetMin;
    xSemaphoreGive(s_config_mutex);
    return tz;
}

std::string idf_config_get_ntp_server(void)
{
    if (ensure_config_mutex() != ESP_OK) return std::string();
    xSemaphoreTake(s_config_mutex, portMAX_DELAY);
    std::string server = s_config.ntpServer;
    xSemaphoreGive(s_config_mutex);
    return server;
}

void idf_config_copy_mdns_host(char* out, size_t cap)
{
    if (!out || cap == 0) return;
    out[0] = '\0';
    if (ensure_config_mutex() != ESP_OK) {
        snprintf(out, cap, "sms");
        return;
    }
    xSemaphoreTake(s_config_mutex, portMAX_DELAY);
    snprintf(out, cap, "%s", s_config.mdnsHost.c_str());
    xSemaphoreGive(s_config_mutex);
    if (out[0] == '\0') snprintf(out, cap, "sms");
}

bool idf_config_email_configured(void)
{
    if (ensure_config_mutex() != ESP_OK) return false;
    xSemaphoreTake(s_config_mutex, portMAX_DELAY);
    bool ok = email_configured_locked();
    xSemaphoreGive(s_config_mutex);
    return ok;
}

// Accumulate byte differences without an early return to limit timing leakage.
static bool timing_safe_equals(const std::string& expected, const char* actual)
{
    size_t actual_len = strlen(actual);
    size_t compared = std::max(expected.size(), actual_len);
    unsigned char diff = (expected.size() == actual_len) ? 0 : 1;
    for (size_t i = 0; i < compared; ++i) {
        unsigned char expected_byte = i < expected.size() ? static_cast<unsigned char>(expected[i]) : 0;
        unsigned char actual_byte = i < actual_len ? static_cast<unsigned char>(actual[i]) : 0;
        diff |= expected_byte ^ actual_byte;
    }
    return diff == 0;
}

bool idf_config_check_web_auth(const char* user, const char* pass)
{
    if (!user || !pass) return false;
    if (ensure_config_mutex() != ESP_OK) return false;
    xSemaphoreTake(s_config_mutex, portMAX_DELAY);
    bool authenticated = false;
    for (const auto& account : s_config.webAccounts) {
        const bool user_ok = timing_safe_equals(account.username, user);
        const bool pass_ok = timing_safe_equals(account.password, pass);
        const bool usable = !account.username.empty() && !account.password.empty();
        // Bitwise bool operators keep every account comparison on the path;
        // empty compatibility slots must never authenticate an empty pair.
        authenticated = authenticated | (usable & user_ok & pass_ok);
    }
    xSemaphoreGive(s_config_mutex);
    return authenticated;
}
