#include "idf_modem_imei.h"

#include <atomic>
#include <cassert>
#include <cstdint>
#include <ctime>
#include <string>
#include <sys/time.h>
#include <utility>
#include <vector>

using esp_err_t = int;
using TickType_t = uint32_t;
constexpr int ESP_OK = 0, ESP_FAIL = -1;
#define pdMS_TO_TICKS(ms) static_cast<TickType_t>(ms)

static int64_t now_us = 1000000;
static time_t epoch = 0;
static bool idle = true, esim_active = false, sntp_during_query = false;
static int registration = 1;
[[maybe_unused]] static bool s_uart_wait_cmt_pdu = false;
[[maybe_unused]] static int64_t s_uart_wait_cmt_until_us = 0;
static std::atomic<int> s_status_sample_requests{0};
static std::vector<time_t> writes;
static std::vector<std::string> commands;
static std::string response;
static unsigned writes_at_first_sample = 0;
static bool sample_seen = false;
static int setter_result = 0;

[[maybe_unused]] static time_t fake_time(time_t*) { return epoch; }
[[maybe_unused]] static int fake_settimeofday(const timeval* value, const void*)
{
    assert(value->tv_usec == 0);
    writes.push_back(value->tv_sec);
    if (setter_result == 0) epoch = value->tv_sec;
    return setter_result;
}
[[maybe_unused]] static int64_t esp_timer_get_time() { return now_us; }
[[maybe_unused]] static bool at_channel_idle_now() { return idle && !esim_active; }
struct Status { int ceregStat; };
[[maybe_unused]] static Status idf_modem_get_status() { return {registration}; }
[[maybe_unused]] static std::string idf_util_trim_copy(const std::string& value)
{
    const size_t start = value.find_first_not_of(" \t\r\n");
    return start == std::string::npos ? std::string() :
        value.substr(start, value.find_last_not_of(" \t\r\n") - start + 1);
}
static int at_final_result(const std::string&);
static esp_err_t idf_modem_send_at(const std::string& command, uint32_t timeout, std::string& out)
{
    assert(command == "AT+CCLK?" && timeout == 1000);
    commands.push_back(command);
    out = response;
    if (sntp_during_query) epoch = 1788652999;
    return at_final_result(out) > 0 ? ESP_OK : ESP_FAIL;
}
#define time fake_time
#define settimeofday fake_settimeofday
#include "clock_runtime.inc"
#undef settimeofday
#undef time

struct IdfSimSettingsView {};
static void retry_sms_storage_if_pending() {}
static void apply_startup_data_mode(int) {}
static IdfSimSettingsView idf_config_get_sim_settings_view() { return {}; }
static void apply_operator_if_configured(IdfSimSettingsView, int) {}
static void enforce_roaming_data_policy(IdfSimSettingsView, int) {}
static void sample_signal_once()
{
    if (!sample_seen) writes_at_first_sample = writes.size();
    sample_seen = true;
}
static void sample_signal_detail_once() {}
static void sample_identity_once(bool, bool) {}
static bool startup_sampling_done() { return true; }
static void set_phase(const char*) {}
static void vTaskDelay(TickType_t ticks) { now_us += ticks * 1000; }
static bool process_data_mode_retry() { return false; }
#include "clock_owner.inc"

static std::string frame(const std::string& value)
{
    return "AT+CCLK?\r\n+CCLK: \"" + value + "\"\r\nOK\r\n";
}
static void fresh_attempt(const std::string& value)
{
    epoch = 0;
    now_us += 60000000;
    response = value;
    initial_owner_pass(registration);
}

int main(int argc, char** argv)
{
    (void)&send_ok;
    assert(argc == 2);
    const std::string scenario = argv[1];
    if (scenario == "valid") {
        for (const auto& item : std::vector<std::pair<std::string, time_t>>{
                {"26/09/06,08:00:00+32", 1788652800},
                {"24/02/29,12:34:56-12", 1709220896},
                {"69/12/31,23:59:59+00", 3155759999}}) {
            fresh_attempt(frame(item.first));
            assert(!writes.empty() && writes.back() == item.second && epoch == item.second);
        }
        assert(commands.size() == 3 && writes_at_first_sample == 1);
        fresh_attempt("+CEREG: 1\r\n+CCLK: \"26/09/06,08:00:00+32\"\r\n"
                      "OK\r\n+CMT: ,16\r\n00110000000000000000000000000000\r\n");
        assert(writes.size() == 4 && writes.back() == 1788652800);
    } else if (scenario == "invalid") {
        for (const char* value : {
                "23/02/29,12:00:00+00", "24/04/31,12:00:00+00", "24/00/01,00:00:00+00",
                "24/01/00,00:00:00+00", "24/13/01,00:00:00+00", "24/01/01,24:00:00+00",
                "24/01/01,00:60:00+00", "24/01/01,00:00:60+00", "26/09/06,08:00:00",
                "26/09/06,08:00:00+97", "26/09/06,08:00:00-97", "26/09/06,08:00:00x32",
                "26/09/06,08:00:00+3x", "70/01/01,00:00:00+00", "99/01/01,00:00:00+00",
                "23/01/01,00:00:00+00"}) {
            fresh_attempt(frame(value));
            assert(writes.empty() && epoch == 0);
        }
        const std::string payload = "+CCLK: \"26/09/06,08:00:00+32\"\r\n";
        for (const auto& value : std::vector<std::string>{
                "OK\r\n" + payload, "AT+CSQ\r\n" + payload + "OK\r\n",
                payload + "ERROR\r\n", payload + "OK\r\nERROR\r\n",
                payload + payload + "OK\r\n", payload, payload + "OK\r\nOK\r\n"}) {
            fresh_attempt(value);
            assert(writes.empty() && epoch == 0);
        }
    } else if (scenario == "gates") {
        response = frame("26/09/06,08:00:00+32");
        epoch = 1788652999;
        initial_owner_pass(registration);
        assert(commands.empty() && writes.empty());
        epoch = 0;
        registration = 5;
        initial_owner_pass(registration);
        registration = 11;
        periodic_owner_pass();
        registration = 1;
        idle = false;
        periodic_owner_pass();
        idle = true;
        esim_active = true;
        periodic_owner_pass();
        esim_active = false;
        s_uart_wait_cmt_pdu = true;
        s_uart_wait_cmt_until_us = now_us + 3000000;
        periodic_owner_pass();
        assert(commands.empty() && writes.empty());
        s_uart_wait_cmt_pdu = false;
        response = "ERROR\r\n";
        periodic_owner_pass();
        assert(commands.size() == 1 && writes.empty());
        now_us += 59999999;
        periodic_owner_pass();
        assert(commands.size() == 1);
        ++now_us;
        response = frame("26/09/06,08:00:00+32");
        setter_result = -1;
        periodic_owner_pass();
        assert(commands.size() == 2 && writes.size() == 1 && epoch == 0);
        now_us += 60000000;
        setter_result = 0;
        periodic_owner_pass();
        assert(commands.size() == 3 && writes.size() == 2 && epoch == 1788652800);
        now_us += 60000000;
        periodic_owner_pass();
        assert(commands.size() == 3 && writes.size() == 2);
    } else {
        assert(scenario == "race");
        response = frame("26/09/06,08:00:00+32");
        sntp_during_query = true;
        initial_owner_pass(registration);
        assert(commands.size() == 1 && writes.empty() && epoch == 1788652999);
        now_us += 60000000;
        periodic_owner_pass();
        assert(commands.size() == 1 && writes.empty());
    }
}
