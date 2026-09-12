#include "idf_modem_imei.h"
#include "idf_modem_registration.h"

#include <algorithm>
#include <atomic>
#include <cassert>
#include <cctype>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <deque>
#include <string>
#include <vector>

using esp_err_t = int;
using TickType_t = uint32_t;
constexpr int ESP_OK = 0, ESP_FAIL = -1, ESP_ERR_TIMEOUT = 1, pdTRUE = 1;
#define pdMS_TO_TICKS(ms) static_cast<TickType_t>(ms)

static uint64_t now_ms = 100000;
static TickType_t xTaskGetTickCount() { return static_cast<TickType_t>(now_ms); }
static int64_t esp_timer_get_time() { return static_cast<int64_t>(now_ms * 1000); }
static void vTaskDelay(TickType_t ticks) { now_ms += ticks; }
#include "sim_types.inc"

static IdfModemStatus s_status;
static int s_status_mutex = 1;
static int xSemaphoreTake(int, TickType_t) { return pdTRUE; }
static void xSemaphoreGive(int) {}
static std::string s_last_pin_attempt_key;
static std::atomic<int> s_sim_unlock_request{0}, s_status_sample_requests{0};
static std::atomic<int64_t> s_last_web_poll_us{0};
static bool idle = true, esim_active = false, complete_identity = false;
static bool identity_progress = false;
static std::string cpin = "unknown", vendor_iccid, vendor_reply, crsm, selected_iccid;
static bool accept_pin = false, credential_found = false;
static esp_err_t pin_result = ESP_FAIL;
static IdfSimCredential credential;
static unsigned failed_pin_records = 0, successful_pin_records = 0;
static std::vector<std::string> commands, recovery_events;
static std::vector<uint64_t> identity_samples;
static std::string sampled_iccid;
static std::string cached_iccid;

static std::string idf_util_trim_copy(const std::string& input)
{
    const size_t first = input.find_first_not_of(" \r\n\t");
    return first == std::string::npos ? std::string() :
        input.substr(first, input.find_last_not_of(" \r\n\t") - first + 1);
}
static void idf_log_line(const char*) {}
[[maybe_unused]] static void save_identity_cache(const std::string&, const std::string& iccid)
{
    cached_iccid = iccid;
}
static IdfSimUnlockView idf_config_get_sim_unlock_view(const std::string& iccid)
{
    selected_iccid = iccid;
    return {credential_found && iccid == credential.iccid, credential};
}
static void idf_config_record_sim_unlock_result(const std::string& iccid, bool puk, bool ok)
{
    assert(iccid == credential.iccid);
    assert(!puk);
    if (ok) ++successful_pin_records;
    else { ++failed_pin_records; ++credential.pinFailedAttempts; }
}
static int at_final_result(const std::string& response);
static esp_err_t idf_modem_send_at(const std::string& command, uint32_t timeout, std::string& out)
{
    commands.push_back(command);
    out = "OK\r\n";
    if (command == "AT+CPIN?") {
        if (cpin == "unknown") { out = "ERROR\r\n"; return ESP_FAIL; }
        out = "+CPIN: " + cpin + "\r\nOK\r\n";
    } else if (command == "AT+MCCID" || command == "AT+ICCID" || command == "AT+CCID") {
        assert(timeout == 1500);
        if (!vendor_reply.empty()) { out = vendor_reply; return at_final_result(out) > 0 ? ESP_OK : ESP_FAIL; }
        if (vendor_iccid.empty()) { out = "ERROR\r\n"; return ESP_FAIL; }
        out = "+ICCID: " + vendor_iccid + "\r\nOK\r\n";
    } else if (command == "AT+CRSM=176,12258,0,0,10") {
        assert(timeout == 2000);
        out = crsm;
        return at_final_result(out) > 0 ? ESP_OK : ESP_FAIL;
    } else if (command.rfind("AT+CPIN=", 0) == 0) {
        assert(timeout == 5000);
        if (accept_pin) cpin = "READY";
        else { out = "ERROR\r\n"; return pin_result; }
    } else {
        assert(command == "ATE0" || command == "AT+CMEE=1");
    }
    return ESP_OK;
}
#include "sim_runtime.inc"
#include "sim_sampling.inc"

static bool at_channel_idle_now() { return idle && !esim_active; }
static bool process_data_mode_retry() { return false; }
static void bootstrap_clock_once() {}
static bool startup_info_complete() { return complete_identity; }
static bool startup_sampling_done() { return s_status.signalFresh && s_status.identityFresh; }
static void sample_signal_once() { s_status.signalFresh = true; }
static void sample_signal_detail_once() {}
static bool sample_identity_once(bool, bool)
{
    identity_samples.push_back(now_ms);
    sampled_iccid = sample_iccid_slice();
    if (!sampled_iccid.empty()) s_status.iccid = sampled_iccid;
    s_status.identityFresh = true;
    return identity_progress;
}
static void invalidate_registration_state(const char*, bool)
{
    recovery_events.emplace_back("invalidated");
    s_status.ceregStat = -1;
}
static bool configure_sms_and_registration()
{
    assert(s_status.ceregStat == -1);
    recovery_events.emplace_back("sms");
    return true;
}
static void set_phase(const char* phase) { s_status.phase = phase; }
#include "sim_iteration.inc"

static void reset_fixture()
{
    now_ms = 100000;
    s_status = {};
    s_status.ceregStat = 1;
    s_last_pin_attempt_key.clear();
    s_sim_unlock_request = 0; s_status_sample_requests = 0; s_last_web_poll_us = 0;
    idle = true; esim_active = false; complete_identity = false; identity_progress = false;
    cpin = "unknown"; vendor_iccid.clear(); vendor_reply.clear(); crsm.clear(); selected_iccid.clear();
    accept_pin = false; credential_found = false; credential = {};
    pin_result = ESP_FAIL;
    failed_pin_records = 0; successful_pin_records = 0;
    commands.clear(); recovery_events.clear(); identity_samples.clear(); sampled_iccid.clear();
    cached_iccid.clear();
}

static unsigned command_count(const std::string& command)
{
    return static_cast<unsigned>(std::count(commands.begin(), commands.end(), command));
}

static void test_vendor_frames()
{
    reset_fixture();
    vendor_iccid = "8901234567890123456";
    assert(query_current_iccid() == "8901234567890123456");
    assert(commands == std::vector<std::string>{"AT+MCCID"});

    vendor_iccid.clear();
    for (const std::string frame : {
        "OK\r\n+ICCID: 8901234567890123456\r\n",
        "+ICCID: 8901234567890123456\r\nOK\r\nERROR\r\n",
        "AT+OTHER\r\n+ICCID: 8901234567890123456\r\nOK\r\n",
        "+ICCID: 8901234567890123456\r\nOK\r\nOK\r\n"}) {
        vendor_reply = frame;
        assert(query_current_iccid().empty());
    }
    vendor_reply = "AT+MCCID\r\n+ICCID: 8901234567890123456\r\nOK\r\n+CEREG: 1\r\n";
    assert(query_current_iccid() == "8901234567890123456");
}

static void test_iccid()
{
    reset_fixture();
    crsm = "+CRSM: 144,0,\"981032547698103254F6\"\r\nOK\r\n";
    assert(query_current_iccid() == "8901234567890123456");
    assert((commands == std::vector<std::string>{
        "AT+MCCID", "AT+ICCID", "AT+CCID", "AT+CRSM=176,12258,0,0,10"}));
    const uint64_t sampling_start = now_ms;
    assert(sample_iccid_slice() == "8901234567890123456");
    assert(now_ms - sampling_start == 390);

    for (const std::string frame : {
        "+CRSM: 145,0,\"98103254769810325476\"\r\nOK\r\n",
        "AT+CRSM=176,12258,0,0,10\r\n+CRSM: 144,0,\"98103254769810325476\"\r\nOK\r\n",
        "+CMT: ,16\r\n00112233445566778899AABBCCDDEEFF00\r\n"
        "+CRSM: 144,0,\"98103254769810325476\"\r\nOK\r\n+CEREG: 1\r\n"}) {
        crsm = frame;
        assert(query_current_iccid() == "89012345678901234567");
    }
    for (const std::string frame : {
        "OK\r\n+CRSM: 144,0,\"981032547698103254F6\"\r\n",
        "+CRSM: 144,0,\"981032547698103254F6\"\r\nOK\r\nERROR\r\n",
        "AT+OTHER\r\n+CRSM: 144,0,\"981032547698103254F6\"\r\nOK\r\n",
        "+CRSM: 144,0,\"981032547698103254F6\"\r\nOK\r\nOK\r\n",
        "+CRSM: 148,0,\"981032547698103254F6\"\r\nOK\r\n",
        "+CRSM: 144,1,\"981032547698103254F6\"\r\nOK\r\n",
        "+CRSM: 144,0,\"981032547698103254\"\r\nOK\r\n",
        "+CRSM: 144,0,\"981032547698103254A6\"\r\nOK\r\n",
        "+CRSM: 144,0,\"9F103254769810325476\"\r\nOK\r\n",
        "+CRSM: 144,0,\"981032547698103254F6\",1\r\nOK\r\n",
        "+CRSM: 144,0,\"981032547698103254F6\"\r\nERROR\r\n",
        "+CRSM: 144,0,\"981032547698103254F6\"\r\n+CRSM: 144,0,\"981032547698103254F6\"\r\nOK\r\n",
        "8901234567890123456\r\nOK\r\n"}) {
        crsm = frame;
        assert(query_current_iccid().empty());
    }

    reset_fixture();
    cpin = "SIM PIN";
    crsm = "+CRSM: 144,0,\"981032547698103254F6\"\r\nOK\r\n";
    credential_found = true; credential.iccid = "8901234567890123456"; credential.pin = "1234";
    accept_pin = true;
    assert(try_unlock_sim(false));
    assert(selected_iccid == credential.iccid && successful_pin_records == 1);
    assert(command_count("AT+CPIN=\"1234\"") == 1);

    reset_fixture();
    cpin = "SIM PIN";
    crsm = "+CRSM: 144,1,\"981032547698103254F6\"\r\nOK\r\n";
    credential_found = true; credential.iccid = "8901234567890123456"; credential.pin = "1234";
    assert(!try_unlock_sim(false));
    assert(selected_iccid.empty() && command_count("AT+CPIN=\"1234\"") == 0);
}

static void test_ready_iccid()
{
    reset_fixture();
    cpin = "READY";
    s_status.ceregStat = 0;
    vendor_iccid = "8901234567890123456";
    assert(try_unlock_sim(false));
    assert(s_status.simState == "ready" && s_status.iccid == vendor_iccid &&
           cached_iccid == vendor_iccid);
    assert(command_count("AT+CPIN=\"1234\"") == 0);

    reset_fixture();
    cpin = "READY";
    s_status.iccid = "8901234567890123456";
    assert(try_unlock_sim(false));
    assert(s_status.iccid == "8901234567890123456");
    assert(command_count("AT+MCCID") == 0 && command_count("AT+ICCID") == 0 &&
           command_count("AT+CCID") == 0 && command_count("AT+CRSM=176,12258,0,0,10") == 0);
    assert(command_count("AT+CPIN=\"1234\"") == 0);

    reset_fixture();
    cpin = "READY";
    assert(try_unlock_sim(false));
    assert(s_status.simState == "ready" && s_status.iccid.empty() && cached_iccid.empty());
    assert(command_count("AT+CPIN=\"1234\"") == 0);
}

static void test_retry()
{
    reset_fixture();
    OwnerIteration owner;
    now_ms += 29999; owner.step();
    assert(commands.empty());
    ++now_ms; cpin = "READY"; owner.step();
    assert(owner.sim_ready);
    assert((recovery_events == std::vector<std::string>{"invalidated", "sms"}));
    assert(!owner.registered && !owner.post_register_done && s_status.phase == "registering");

    reset_fixture();
    OwnerIteration missing_sim;
    for (uint32_t delay : {30000U, 60000U, 120000U, 300000U, 600000U, 600000U}) {
        const unsigned before = command_count("AT+CPIN?");
        now_ms += delay - 1; missing_sim.step();
        assert(command_count("AT+CPIN?") == before);
        ++now_ms; missing_sim.step();
        assert(command_count("AT+CPIN?") == before + 1 && !missing_sim.sim_ready);
    }
    missing_sim.step(true);
    const unsigned before_reset_retry = command_count("AT+CPIN?");
    now_ms += 29999; missing_sim.step();
    assert(command_count("AT+CPIN?") == before_reset_retry);
    ++now_ms; missing_sim.step();
    assert(command_count("AT+CPIN?") == before_reset_retry + 1);

    reset_fixture();
    OwnerIteration missing_identity;
    missing_identity.sim_ready = true;
    missing_identity.registered = true;
    missing_identity.post_register_done = true;
    s_status.iccid = "8901234567890123456";
    for (uint32_t delay : {30000U, 60000U, 120000U, 300000U, 600000U, 600000U}) {
        const auto samples = identity_samples.size();
        now_ms += delay - 1; missing_identity.step();
        assert(identity_samples.size() == samples);
        ++now_ms; missing_identity.step();
        assert(identity_samples.size() == samples + 1);
    }
    identity_progress = true;
    now_ms += 600000; missing_identity.step();
    assert(identity_samples.size() == 7);
    identity_progress = false;
    now_ms += 29999; missing_identity.step();
    assert(identity_samples.size() == 7);
    ++now_ms; missing_identity.step();
    assert(identity_samples.size() == 8);
    s_status_sample_requests = 1; idle = false;
    missing_identity.step();
    assert(s_status_sample_requests == 1 && identity_samples.size() == 8);
    idle = true; missing_identity.step();
    assert(s_status_sample_requests == 0 && identity_samples.size() == 9);
    now_ms += 30000; missing_identity.step();
    assert(identity_samples.size() == 10);
    complete_identity = true;
    now_ms += 600000; missing_identity.step();
    assert(identity_samples.size() == 10);

    reset_fixture();
    OwnerIteration busy;
    now_ms += 30000; cpin = "READY";
    idle = false; busy.step();
    idle = true; esim_active = true; busy.step();
    assert(commands.empty() && !busy.sim_ready);
    esim_active = false; busy.step();
    assert(busy.sim_ready && command_count("AT+CPIN?") == 1);

    reset_fixture();
    OwnerIteration unregistered;
    unregistered.sim_ready = true;
    s_status.ceregStat = 11;
    now_ms += 30000; unregistered.step();
    assert(commands.empty() && identity_samples.empty());
    s_status.ceregStat = 1; unregistered.step();
    assert(identity_samples.size() == 1);

    reset_fixture();
    now_ms = UINT32_MAX - 15000ULL;
    OwnerIteration tick_wrap;
    cpin = "READY";
    now_ms += 29999; tick_wrap.step();
    assert(commands.empty());
    ++now_ms; tick_wrap.step();
    assert(tick_wrap.sim_ready);

    reset_fixture();
    OwnerIteration locked;
    cpin = "SIM PIN"; vendor_iccid = "8901234567890123456";
    credential_found = true; credential.iccid = vendor_iccid; credential.pin = "1234";
    now_ms += 30000; locked.step();
    now_ms += 60000; locked.step();
    assert(command_count("AT+CPIN=\"1234\"") == 1 && failed_pin_records == 1);
    cpin = "SIM PUK"; credential.puk = "12345678";
    now_ms += 120000; locked.step();
    assert(command_count("AT+CPIN=\"12345678\",\"1234\"") == 0);

    reset_fixture();
    OwnerIteration timed_out_pin;
    cpin = "SIM PIN"; vendor_iccid = "8901234567890123456";
    credential_found = true; credential.iccid = vendor_iccid; credential.pin = "1234";
    credential.pinMaxAttempts = 3; pin_result = ESP_ERR_TIMEOUT;
    now_ms += 30000; timed_out_pin.step();
    now_ms += 60000; timed_out_pin.step();
    assert(command_count("AT+CPIN=\"1234\"") == 1 && failed_pin_records == 0);
}

int main(int argc, char** argv)
{
    assert(argc == 2);
    if (std::string(argv[1]) == "vendor") test_vendor_frames();
    else if (std::string(argv[1]) == "iccid") test_iccid();
    else if (std::string(argv[1]) == "ready") test_ready_iccid();
    else { assert(std::string(argv[1]) == "retry"); test_retry(); }
}
