#pragma once

#include <stdint.h>

#include <string>

#include "esp_err.h"
#include "idf_config.h"

struct IdfModemStatus {
    bool started = false;
    bool atReady = false;
    bool modemReady = false;
    bool signalFresh = false;
    bool identityFresh = false;
    std::string phase = "off";
    int ceregStat = -1;
    int csq = -1;
    int ber = 99;
    int rsrp = 999;
    int rsrq = 999;
    int sinr = 999;
    std::string mfr;
    std::string model;
    std::string fwver;
    std::string imei;
    std::string iccid;
    std::string imsi;
    std::string operatorName;
    std::string apnSim;
    std::string cellIp;
    std::string phone;
    std::string simState = "unknown";
    bool simCredentialMatched = false;
    std::string simUnlockMessage;
};

struct IdfCellularHttpResult {
    bool ok = false;
    int httpStatus = -1;
    uint32_t bytesRead = 0;
    uint32_t expectedBytes = 0;
    int mhttpError = 0;
    std::string cellIp;
    std::string message;
};

// The MHTTP body is streamed over the 115200-baud UART and has a 90-second
// download deadline. Keep the configurable schema range broad, but refuse a
// keepalive threshold above this conservative runtime limit before activation.
static constexpr uint32_t IDF_MODEM_KEEPALIVE_MAX_RUNTIME_KB = 512;
static constexpr uint32_t IDF_MODEM_KEEPALIVE_MAX_RUNTIME_BYTES =
    IDF_MODEM_KEEPALIVE_MAX_RUNTIME_KB * 1024UL;

struct IdfCellularHttpConfig {
    bool dataEnabled = false;
    std::string apn;
    uint32_t minPayloadBytes = 48UL * 1024UL;
};

// Return immediately when the fixed command slots are full. ESP_ERR_TIMEOUT means an enqueued command timed out.
static constexpr esp_err_t IDF_MODEM_ERR_BUSY = static_cast<esp_err_t>(0x7201);

esp_err_t idf_modem_start(const IdfConfig& config);
esp_err_t idf_modem_send_at(const std::string& cmd, uint32_t timeout_ms, std::string& response);
esp_err_t idf_modem_send_at_until(const std::string& cmd, const char* token, uint32_t timeout_ms, std::string& response);
esp_err_t idf_modem_send_pdu(const std::string& cmgs_cmd, const char* pdu, uint32_t timeout_ms, std::string& response);
esp_err_t idf_modem_cellular_http_get(const std::string& url, const IdfCellularHttpConfig& config, IdfCellularHttpResult& result);
esp_err_t idf_modem_request_reset(bool hard_reset);
// Ask the modem task to recheck the SIM lock. allow_puk permits one user-confirmed PUK attempt.
esp_err_t idf_modem_request_sim_unlock(bool allow_puk);
bool idf_modem_take_urc(std::string& out);
// Wait for buffered URC data or an external wake-up. Return false on timeout.
bool idf_modem_wait_event(uint32_t timeout_ms);
// Wake the SMS task after a buffered URC or queued Web SMS.
void idf_modem_signal_event(void);
IdfModemStatus idf_modem_get_status(void);
// Report whether the AT channel is idle so Web routes can avoid blocking httpd.
bool idf_modem_at_idle(void);
// Open a short identity and signal sampling window after an explicit Web refresh.
void idf_modem_request_status_sample(void);
// Reassert SMS storage selection (CPMS MT, ME, then SM) with CMGF and CNMI.
// This repairs the default storage state after an unobserved modem reset.
void idf_modem_reassert_sms_storage(void);
// Check registration, PDU mode, CNMI, and SMS storage each day. Repair invalid settings.
// This checks only the local SMS stack, not carrier delivery.
bool idf_modem_sms_health_check(std::string& summary);
// Pause background modem and SMS commands during an eSIM APDU session.
void idf_modem_begin_esim_operation(void);
void idf_modem_end_esim_operation(void);
bool idf_modem_esim_operation_active(void);
// Clear cached SIM identity after an eSIM profile change and request a new sample.
void idf_modem_invalidate_sim_identity(void);
// Register a SIM identity change hook for hot swaps and eSIM changes.
// The hook can run in the modem task and must not block.
void idf_modem_set_sim_identity_hook(void (*hook)(void));
// Pull EN low before a planned ESP restart to fully power off the modem.
// Use the warm-start path only after an unexpected reset such as a crash or watchdog.
void idf_modem_power_off_for_restart(void);
