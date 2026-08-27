#pragma once

#include <stdint.h>
#include <stddef.h>

#include <string>

#include "esp_err.h"
#include "idf_config.h"
#include "idf_modem_https.h"

#ifndef SMS_USB_RECOVERY
#define SMS_USB_RECOVERY 0
#endif

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

// Keep the legacy cellular traffic limit for configuration compatibility; the HTTP API is unsupported.
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

enum class IdfModemUsbQueryBusyReason : uint8_t {
    unknown = 0,
    gate_closed = 1,
    mutex_timeout = 2,
    slots_full = 3,
    queue_full = 4,
};

#if SMS_USB_RECOVERY
static constexpr uint8_t IDF_MODEM_USB_QUERY_ATI = 0x01;
static constexpr uint8_t IDF_MODEM_USB_QUERY_CPIN = 0x02;
static constexpr uint8_t IDF_MODEM_USB_QUERY_CEREG = 0x03;
static constexpr uint8_t IDF_MODEM_USB_QUERY_COPS = 0x04;
static constexpr uint8_t IDF_MODEM_USB_QUERY_CGATT = 0x05;
static constexpr uint8_t IDF_MODEM_USB_QUERY_CGACT = 0x06;
static constexpr uint8_t IDF_MODEM_USB_QUERY_CGPADDR = 0x07;
static constexpr uint8_t IDF_MODEM_USB_QUERY_ICCID = 0x08;
static constexpr uint8_t IDF_MODEM_USB_QUERY_CSQ = 0x09;
static constexpr uint8_t IDF_MODEM_USB_QUERY_CESQ = 0x0A;
static constexpr uint8_t IDF_MODEM_USB_QUERY_CFUN = 0x0B;
static constexpr uint8_t IDF_MODEM_USB_QUERY_CREG = 0x0C;
static constexpr uint8_t IDF_MODEM_USB_QUERY_CGREG = 0x0D;
static constexpr uint8_t IDF_MODEM_USB_QUERY_CEER = 0x0E;
static constexpr uint8_t IDF_MODEM_USB_QUERY_CIMI = 0x0F;
static constexpr uint8_t IDF_MODEM_USB_QUERY_CPOL = 0x10;
static constexpr uint8_t IDF_MODEM_USB_QUERY_CGDCONT = 0x11;
static constexpr size_t IDF_MODEM_USB_QUERY_MAX_RESPONSE = 96;
static constexpr uint32_t IDF_MODEM_USB_QUERY_TIMEOUT_MS = 1500;
static constexpr uint32_t IDF_MODEM_USB_QUERY_CPOL_TIMEOUT_MS = 5000;
#endif

esp_err_t idf_modem_start(const IdfConfig& config);
esp_err_t idf_modem_send_at(const std::string& cmd, uint32_t timeout_ms, std::string& response);
esp_err_t idf_modem_send_at_until(const std::string& cmd, const char* token, uint32_t timeout_ms, std::string& response);
esp_err_t idf_modem_send_pdu(const std::string& cmgs_cmd, const char* pdu, uint32_t timeout_ms, std::string& response);
#if SMS_USB_RECOVERY
esp_err_t idf_modem_usb_query(uint8_t query_id, std::string& response,
                              uint8_t* busy_reason = nullptr);
#endif
esp_err_t idf_modem_cellular_http_get(const std::string& url, const IdfCellularHttpConfig& config, IdfCellularHttpResult& result);
esp_err_t idf_modem_https_post(const IdfModemHttpsPostRequest& request,
                               IdfModemHttpsPostResult& result);
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
