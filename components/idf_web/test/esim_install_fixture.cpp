#include <algorithm>
#include <cassert>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <functional>
#include <iostream>
#include <new>
#include <string>
#include <vector>
#include "idf_web_core.h"
#include "idf_util.h"
#include "idf_esim.h"
#include "idf_lpa_activation_code.h"
#include "idf_lpa_install.h"

using TickType_t = uint32_t;
constexpr TickType_t portMAX_DELAY = UINT32_MAX;
constexpr int pdPASS = 1;
constexpr int HTTP_GET = 0, HTTP_POST = 1;
static TickType_t pdMS_TO_TICKS(uint32_t ms) { return ms; }
struct httpd_req_t {
    int method = HTTP_POST;
    const char* uri = "/api/esim";
    size_t content_len = 0;
    std::string input, output;
    int status = 200;
    bool authenticated = true, csrf = true;
};

// STRUCTS

static WebAsyncJob s_esim_job;
static EsimWebCache s_esim_cache;
static uint32_t s_next_esim_job_id = 1;
static std::string s_esim_confirmation_code;
static int64_t s_esim_confirmation_deadline_us = 0;
static bool s_esim_confirmation_received = false;
static bool s_esim_confirmation_accepted = false;
static int64_t clock_us = 0;
static bool locked = false, admitted = false;
static bool require_confirmation = true, notification_pending = true, uncertain = false;
static unsigned install_calls = 0, enable_calls = 0;
static void (*task_fn)(void*) = nullptr;
static void* task_arg = nullptr;
static std::function<void()> on_delay;

static int64_t esp_timer_get_time() { return clock_us; }
static bool cell_job_lock(TickType_t = 300) {
    assert(!locked);
    if (task_fn) return false;
    locked = true; return true;
}
static void cell_job_unlock() { assert(locked); locked = false; }
static bool try_shared_admission(bool) { if (admitted) return false; admitted = true; return true; }
static void release_shared_admission() { assert(admitted); admitted = false; }
static bool backup_transfer_active() { return false; }
static bool ota_active() { return false; }
static bool device_restart_pending() { return false; }
static bool restore_restart_pending() { return false; }
static bool api_jobs_active() { return false; }
static bool idf_push_test_active() { return false; }
static bool cellular_job_active_locked() { return s_esim_job.running || s_esim_job.queued; }
static unsigned esp_random() { static unsigned value = 0; return ++value; }
static void idf_logf(const char*, ...) {}
static int xTaskCreate(void (*fn)(void*), const char*, unsigned, void* arg, unsigned, void*) {
    assert(!task_fn); task_fn = fn; task_arg = arg; return pdPASS;
}
static void vTaskDelete(void*) {}
static void vTaskDelay(TickType_t ticks) {
    assert(!locked);
    clock_us += static_cast<int64_t>(ticks) * 1000;
    if (on_delay) { auto run = std::move(on_delay); on_delay = {}; run(); }
}
struct EsimFixtureModemStatus { bool atReady = true, modemReady = true; };
static EsimFixtureModemStatus idf_modem_get_status() { return {}; }
static bool idf_modem_at_idle() { return true; }
static void idf_modem_invalidate_sim_identity() { ++enable_calls; }
esp_err_t idf_esim_list_profiles(std::vector<IdfEsimProfile>& out, std::string& eid, std::string&) {
    assert(!locked); out = {{"private-card", "", "disabled", "Installed profile", "", "", "operational"}};
    eid = "private-eid"; return ESP_OK;
}
esp_err_t idf_esim_get_eid(std::string&, std::string&) { return ESP_FAIL; }
esp_err_t idf_esim_enable_profile(const std::string&, std::string&) { ++enable_calls; return ESP_OK; }
esp_err_t idf_esim_disable_profile(const std::string&, std::string&) { ++enable_calls; return ESP_OK; }
esp_err_t idf_esim_delete_profile(const std::string&, std::string&) { return ESP_FAIL; }
esp_err_t idf_esim_set_nickname(const std::string&, const std::string&, std::string&) { return ESP_FAIL; }
esp_err_t idf_esim_switch_profile(const std::string&, std::string&) { ++enable_calls; return ESP_OK; }
esp_err_t idf_lpa_install_profile(std::string_view code, IdfLpaConfirmationCallback confirm,
    IdfLpaProgressCallback progress, void* context, IdfLpaInstallResult& result) {
    assert(!locked && admitted);
    assert(code == "LPA:1$example.invalid$INSTALL-SECRET");
    ++install_calls;
    progress(context, IdfLpaInstallStage::authenticating);
    {
        std::string confirmation;
        bool accepted = false;
        LpaRspProfileMetadata metadata;
        metadata.profile_name = "Installed profile";
        metadata.service_provider_name = "Example carrier";
        const int64_t began = clock_us;
        if (confirm(context, metadata, require_confirmation, 100, accepted, confirmation) != ESP_OK) {
            assert(confirmation.empty()); assert(clock_us - began == 100000);
            result.error = IdfLpaInstallError::confirmation_timeout; return ESP_ERR_TIMEOUT;
        }
        if (!accepted) { assert(confirmation.empty()); result.error = IdfLpaInstallError::postponed; return ESP_FAIL; }
        assert(confirmation == (require_confirmation ? "private-secret" : ""));
        idf_web_secure_clear(confirmation);
    }
    if (uncertain) { result.error = IdfLpaInstallError::installation_uncertain; return ESP_FAIL; }
    progress(context, IdfLpaInstallStage::downloading);
    result.installed = true; result.notification_pending = notification_pending;
    return ESP_OK;
}
static void set_json_no_cache(httpd_req_t*) {}
static int httpd_resp_set_status(httpd_req_t* req, const char* value) { req->status = std::atoi(value); return ESP_OK; }
static int httpd_resp_set_hdr(httpd_req_t*, const char*, const char*) { return ESP_OK; }
static int httpd_resp_send(httpd_req_t* req, const char* value, size_t size) { req->output.assign(value, size); return ESP_OK; }
static int httpd_resp_sendstr(httpd_req_t* req, const char* value) { req->output = value; return ESP_OK; }
static bool reject_oversized_body(httpd_req_t*) { return false; }
static bool check_auth_strict(httpd_req_t* req) { if (!req->authenticated) req->status = 401; return req->authenticated; }
static bool check_csrf(httpd_req_t* req) { if (!req->csrf) req->status = 403; return req->csrf; }
static int read_body(httpd_req_t* req, std::string& out, size_t max) {
    if (req->input.size() > max) { req->status = 413; return ESP_FAIL; }
    out = req->input; return ESP_OK;
}

#define IdfModemStatus EsimFixtureModemStatus
// FUNCTIONS
#undef IdfModemStatus

static httpd_req_t request(std::string input = {}) {
    httpd_req_t req; req.input = std::move(input); req.content_len = req.input.size();
    if (req.input.empty()) req.method = HTTP_GET;
    handle_api_esim(&req); return req;
}
static void run_task() {
    assert(task_fn); auto fn = task_fn; auto arg = task_arg; task_fn = nullptr; task_arg = nullptr; fn(arg);
    assert(!locked && !admitted && s_esim_confirmation_code.empty());
}

int main() {
    const std::string start = "action=install&activationCode=LPA%3A1%24example.invalid%24INSTALL-SECRET";
    httpd_req_t unauthorized; unauthorized.input = start; unauthorized.content_len = start.size(); unauthorized.authenticated = false;
    handle_api_esim(&unauthorized); assert(unauthorized.status == 401 && !task_fn);
    unauthorized.authenticated = true; unauthorized.csrf = false;
    handle_api_esim(&unauthorized); assert(unauthorized.status == 403 && !task_fn);
    for (const std::string& invalid : {start + "&nickname=", start + "&action=install", start + "&=discarded", std::string("action=install&activationCode=bad")}) {
        assert(request(invalid).status == 400 && !task_fn);
    }
    auto accepted = request(start);
    assert(accepted.status == 202 && task_fn && admitted);
    assert(accepted.output.find("\"jobId\":1") != std::string::npos);
    assert(accepted.output.find("INSTALL-SECRET") == std::string::npos);
    assert(request(start).status == 409);
    on_delay = [] {
        assert(s_esim_job.confirmationRequired && admitted && !locked);
        assert(s_esim_job.profileName == "Installed profile" && s_esim_job.providerName == "Example carrier");
        assert(request("action=confirm&jobId=2&accepted=true&confirmationCode=private-secret").status == 409);
        assert(request("action=confirm&jobId=1&accepted=true").status == 400);
        assert(request("action=confirm&jobId=1&accepted=false&confirmationCode=private-secret").status == 400);
        assert(request("action=confirm&jobId=1&accepted=true&confirmationCode=private-secret&handle=").status == 400);
        assert(request("action=confirm&jobId=1&accepted=true&confirmationCode=private-secret").status == 202);
        assert(request("action=confirm&jobId=1&accepted=true&confirmationCode=private-secret").status == 409);
    };
    run_task();
    assert(install_calls == 1 && enable_calls == 0 && s_esim_job.success);
    assert(!s_esim_job.confirmationRequired);
    std::cout << request().output << '\n';
    assert(request(start).status == 202);
    run_task();
    assert(!s_esim_job.success && !s_esim_job.confirmationRequired);
    assert(request("action=confirm&jobId=2&accepted=true&confirmationCode=private-secret").status == 409);
    require_confirmation = false; uncertain = true;
    assert(request(start).status == 202);
    on_delay = [] {
        assert(!s_esim_job.confirmationRequired && s_esim_job.stage == "awaiting_confirmation");
        assert(request("action=confirm&jobId=3&accepted=true&confirmationCode=unrequested").status == 400);
        assert(request("action=confirm&jobId=3&accepted=true").status == 202);
    };
    run_task();
    assert(!s_esim_job.success && std::string(modern_esim_job_code(s_esim_job)) == "ACTION_ESIM_INSTALLATION_UNCERTAIN");
    assert(request(start).status == 202);
    on_delay = [] { assert(request("action=confirm&jobId=4&accepted=false").status == 202); };
    run_task();
    assert(!s_esim_job.success && std::string(modern_esim_job_code(s_esim_job)) == "ACTION_ESIM_POSTPONED");
    assert(s_esim_job.profileName.empty() && s_esim_job.providerName.empty());
    assert(enable_calls == 0);
}
