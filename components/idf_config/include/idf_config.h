#pragma once

#include <stddef.h>
#include <stdint.h>

#include <string>
#include <utility>
#include <vector>

#include "esp_err.h"
#include "firmware_version_generated.h"

static constexpr int IDF_MAX_PUSH_CHANNELS = 5;
static constexpr int IDF_MAX_WEB_ACCOUNTS = 10;
static constexpr const char* IDF_FW_VERSION = FIRMWARE_DISPLAY_VERSION;
static constexpr const char* IDF_DEFAULT_WEB_USER = "admin";
static constexpr const char* IDF_DEFAULT_WEB_PASS = "admin123";
static constexpr const char* IDF_KEEPALIVE_DEFAULT_URL = "http://gg.incrafttime.top/api/payload?size=64342";

static constexpr int IDF_MAX_SCHED_TASKS = 6;

// Scan before connection and select the strongest saved network in range.
// Slot 0 stores the latest provisioned network for legacy compatibility.
static constexpr int IDF_MAX_WIFI_NETWORKS = 5;
static constexpr int IDF_MAX_SIM_CREDENTIALS = 5;

struct IdfSimCredential {
    std::string iccid;
    std::string pin;
    std::string puk;
    uint8_t pinMaxAttempts = 1;
    uint8_t pukMaxAttempts = 1;
    uint8_t pinFailedAttempts = 0;
    uint8_t pukFailedAttempts = 0;
};

struct IdfWifiNetwork {
    std::string ssid;
    std::string pass;
};

struct IdfWebAccount {
    std::string username;
    std::string password;
};

// A scheduled task can select an eSIM profile, run an action, and switch back.
struct IdfSchedTask {
    bool enabled = false;
    std::string name;        // Display name
    std::string profile;     // Target eSIM profile (ICCID or alias). Empty uses the current SIM.
    bool switchBack = true;  // Restore the previously active profile after the task
    int intervalDays = 30;   // Interval in days
    uint8_t action = 0;      // 0=push alert, 1=cellular HTTP unsupported, 2=SMS, 3=USSD
    std::string target;      // Reserved HTTP target, phone number, or USSD code
    std::string payload;     // Push or SMS content
    uint32_t lastRun = 0;    // Base epoch. Zero means unset.
};

struct IdfPushChannel {
    bool enabled = false;
    uint8_t type = 1;
    std::string name;
    std::string url;
    std::string key1;
    std::string key2;
    std::string titleTemplate;
    std::string bodyTemplate;
    std::string customBody;
    bool cellularEnabled = true;
    std::string cellularUrl;
};

struct IdfConfig {
    // v5 local identity and notification locale. webUser/webPass mirror account 0
    // for legacy callers and are not persisted.
    std::string deviceName = "SMS Forwarder";
    std::string hostname = "sms";
    std::string notificationLocale = "zh-TW";

    // Slot 0 uses legacy keys wifiSsid/wifiPass. Other slots use wifiNSsid/wifiNPass.
    // Old firmware can read the latest provisioned network after an OTA rollback.
    IdfWifiNetwork wifiNetworks[IDF_MAX_WIFI_NETWORKS];
    bool wifiFromFallback = false;
    uint8_t wifiTxPowerQuarterDbm = 34;  // ESP-IDF unit is 0.25 dBm. 34 = 8.5 dBm.

    IdfWebAccount webAccounts[IDF_MAX_WEB_ACCOUNTS];
    int networkMode = 0;
    bool heartbeatEnable = true;
    int heartbeatInterval = 6;

    std::string smtpServer;
    int smtpPort = 465;
    std::string smtpUser;
    std::string smtpPass;
    std::string smtpSendTo;
    std::string adminPhone;
    bool emailEnabled = true;
    bool pushEnabled = true;

    std::string webUser = IDF_DEFAULT_WEB_USER;
    std::string webPass = IDF_DEFAULT_WEB_PASS;
    std::string numberBlackList;
    std::string forwardRules;

    bool kaEnabled = false;
    int kaIntervalDays = 175;
    uint8_t kaAction = 1;
    std::string kaTarget;
    std::string kaUrl = IDF_KEEPALIVE_DEFAULT_URL;
    std::string kaProfile;
    uint32_t kaLastTime = 0;
    int kaTrafficKB = 1;

    int tzOffsetMin = 480;
    std::string ntpServer = "ntp.aliyun.com";
    std::string mdnsHost = "sms";  // Host for <host>.local. Rename it for multi-device deployments.
    bool rebootEnabled = false;
    int rebootHour = 4;
    bool hbEnabled = false;
    int hbHour = 9;
    bool smsHealthEnabled = false;
    int smsHealthHour = 10;
    bool smsHealthNotify = true;

    bool netLedEnabled = true;  // Persist the modem NET LED setting (AT+MNETLIGHT).
    bool callNotifyEnabled = true;  // Send caller ID through the SMS notification channels.
    bool dataEnabled = false;
    bool roamingEnabled = false;  // Disable cellular data while roaming when false.
    std::string apn;
    std::string operatorPlmn;
    std::string phoneNumber;
    IdfSimCredential simCredentials[IDF_MAX_SIM_CREDENTIALS];

    IdfPushChannel pushChannels[IDF_MAX_PUSH_CHANNELS];
    IdfSchedTask schedTasks[IDF_MAX_SCHED_TASKS];
};

using IdfFormFields = std::vector<std::pair<std::string, std::string>>;

enum class IdfConfigLoadStatus : uint8_t {
    Unknown = 0,
    Loaded = 1,
    Migrated = 2,
    FirstBoot = 3,
    StorageError = 4,
    UnsupportedSchema = 5,
};

enum class IdfPortableConfigStatus : uint8_t {
    Ok = 0,
    Invalid = 1,
    UnsupportedVersion = 2,
};

esp_err_t idf_config_load(void);
IdfConfigLoadStatus idf_config_last_load_status(void);
// Monotonic for this boot. It changes only after a complete config is durably
// saved and published (or loaded and published at boot).
uint64_t idf_config_generation(void);
// Put a new or updated network in slot 0. Remove the oldest entry if the list is full.
esp_err_t idf_config_save_wifi(const std::string& ssid, const std::string& pass);
esp_err_t idf_config_save_wifi(const char* ssid, size_t ssid_length,
                               const char* pass, size_t pass_length);
// Save the Web WiFi list. If preserve_blank_pass is true, blank passwords remain unchanged.
esp_err_t idf_config_save_wifi_networks(const IdfWifiNetwork nets[IDF_MAX_WIFI_NETWORKS],
                                        bool preserve_blank_pass, uint8_t wifi_tx_power_quarter_dbm);
// Atomically update one Web-managed slot without reordering the list.  Empty
// SSID clears the slot; open networks clear the password; a blank retained
// password is valid only when the SSID is unchanged.
esp_err_t idf_config_save_wifi_profile(int index, const std::string& ssid,
                                       const std::string& password, bool open,
                                       bool retain_password);
// Keep connected networks in most-recently-used order. Slot 0 returns without a write.
// Move another saved network to slot 0. Insert new or changed networks in slot 0.
// Remove the least-recently-used network when the list is full.
esp_err_t idf_config_note_wifi_connected(const std::string& ssid, const std::string& pass);
esp_err_t idf_config_save_account(const std::string& user, const std::string& pass);
// Atomically replace all ten web accounts.  An empty username disables that
// slot; when preserve_blank_password is true, an empty password retains the
// slot's current password for a non-empty username.  At least one complete
// account must remain usable.
esp_err_t idf_config_save_accounts(const IdfWebAccount accounts[IDF_MAX_WEB_ACCOUNTS],
                                   bool preserve_blank_password);
esp_err_t idf_config_save_identity(const std::string& device_name, const std::string& hostname);
esp_err_t idf_config_save_notification_locale(const std::string& locale);
esp_err_t idf_config_save_network_mode(int network_mode);
esp_err_t idf_config_save_heartbeat(bool enabled, int interval_hours);
esp_err_t idf_config_save_time(int tz_offset_min, const std::string& ntp_server);
esp_err_t idf_config_save_mdns_host(const std::string& host);
esp_err_t idf_config_save_email(bool enabled, const std::string& server, int port,
                                const std::string& user, const std::string& pass,
                                const std::string& send_to, bool preserve_blank_pass);
esp_err_t idf_config_save_push(bool enabled, const IdfPushChannel channels[IDF_MAX_PUSH_CHANNELS]);
esp_err_t idf_config_save_filter(const std::string& admin_phone, const std::string& number_blacklist);
esp_err_t idf_config_validate_forward_rules(const std::string& rules, std::string* message);
// Translate Perl-style \d, \w, and \s to POSIX classes for validation and matching.
std::string idf_config_translate_perl_classes(const std::string& pattern);
esp_err_t idf_config_save_forward_rules(const std::string& rules);
esp_err_t idf_config_save_keepalive(bool enabled, int interval_days, uint8_t action,
                                    const std::string& target, const std::string& url,
                                    const std::string& profile, int traffic_kb = 1);
esp_err_t idf_config_save_system_schedule(bool reboot_enabled, int reboot_hour,
                                          bool hb_enabled, int hb_hour,
                                          bool sms_health_enabled, int sms_health_hour,
                                          bool sms_health_notify);
esp_err_t idf_config_save_sched_tasks(const IdfSchedTask tasks[IDF_MAX_SCHED_TASKS]);
esp_err_t idf_config_save_sim(bool data_enabled, bool roaming_enabled, const std::string& apn,
                              const std::string& operator_plmn, const std::string& phone_number,
                              const IdfSimCredential credentials[IDF_MAX_SIM_CREDENTIALS]);
esp_err_t idf_config_record_sim_unlock_result(const std::string& iccid, bool puk, bool success);
std::string idf_config_export_text(bool full_export);
esp_err_t idf_config_import_text(const std::string& text, int* applied_count);
esp_err_t idf_config_export_portable(uint8_t* output, size_t capacity, size_t* written);
esp_err_t idf_config_restore_portable(const uint8_t* bytes, size_t length,
                                      IdfPortableConfigStatus* status);
esp_err_t idf_config_factory_reset(void);
esp_err_t idf_config_set_keepalive_last(uint32_t epoch);
esp_err_t idf_config_set_sched_last(int index, uint32_t epoch);
esp_err_t idf_config_set_net_led_enabled(bool enabled);
esp_err_t idf_config_set_call_notify_enabled(bool enabled);

// A narrow /status snapshot avoids a full config copy every two seconds.
struct IdfConfigStatusView {
    int tzOffsetMin = 480;
    bool dataEnabled = false;
    bool emailEnabled = true;
    bool pushEnabled = true;
    bool emailConfigured = false;
    int pushEnabledCount = 0;
    std::string adminPhone;
    std::string phoneNumber;
    std::string apn;
};

// The Web WiFi view exposes each SSID and password-presence flag, not passwords.
struct IdfWifiNetworkView {
    std::string ssid;
    bool passSet = false;
};

struct IdfWebAccountView {
    std::string username;
    bool passwordSet = false;
};

struct IdfSimCredentialView {
    std::string iccid;
    bool pinSet = false;
    bool pukSet = false;
    uint8_t pinMaxAttempts = 1;
    uint8_t pukMaxAttempts = 1;
    uint8_t pinFailedAttempts = 0;
    uint8_t pukFailedAttempts = 0;
};

// The /config.json snapshot omits scheduled tasks to avoid a full deep copy.
struct IdfConfigWebView {
    std::string deviceName;
    std::string hostname;
    std::string notificationLocale;
    std::string webUser = IDF_DEFAULT_WEB_USER;
    std::string webPass = IDF_DEFAULT_WEB_PASS;
    std::string smtpServer;
    int smtpPort = 465;
    std::string smtpUser;
    std::string smtpPass;
    std::string smtpSendTo;
    std::string adminPhone;
    std::string numberBlackList;
    std::string forwardRules;
    bool emailEnabled = true;
    bool emailConfigured = false;
    bool pushEnabled = true;
    int pushEnabledCount = 0;
    int networkMode = 0;
    bool heartbeatEnable = true;
    int heartbeatInterval = 6;
    std::string ntpServer = "ntp.aliyun.com";
    std::string mdnsHost = "sms";
    int tzOffsetMin = 480;
    bool rebootEnabled = false;
    int rebootHour = 4;
    bool hbEnabled = false;
    int hbHour = 9;
    bool smsHealthEnabled = false;
    int smsHealthHour = 10;
    bool smsHealthNotify = true;
    bool dataEnabled = false;
    bool roamingEnabled = false;
    std::string apn;
    std::string phoneNumber;
    std::string operatorPlmn;
    bool kaEnabled = false;
    int kaIntervalDays = 175;
    int kaTrafficKB = 1;
    std::string kaProfile;
    bool netLedEnabled = true;
    bool callNotifyEnabled = true;
    uint8_t wifiTxPowerQuarterDbm = 34;
    IdfWifiNetworkView wifiNetworks[IDF_MAX_WIFI_NETWORKS];
    IdfWebAccountView webAccounts[IDF_MAX_WEB_ACCOUNTS];
    IdfSimCredentialView simCredentials[IDF_MAX_SIM_CREDENTIALS];
    IdfPushChannel pushChannels[IDF_MAX_PUSH_CHANNELS];
    // Secret-bearing members above remain for the legacy form parser; API
    // responses must use these presence bits and blank the corresponding
    // values before serialization.
    bool pushUrlSet[IDF_MAX_PUSH_CHANNELS] = {};
    bool pushCellularUrlSet[IDF_MAX_PUSH_CHANNELS] = {};
    bool pushCustomBodySet[IDF_MAX_PUSH_CHANNELS] = {};
    bool pushKey1Set[IDF_MAX_PUSH_CHANNELS] = {};
    bool pushKey2Set[IDF_MAX_PUSH_CHANNELS] = {};
};

// This keep-alive snapshot copies only the fields required by the task.
struct IdfKeepaliveRunView {
    bool kaEnabled = false;
    int kaIntervalDays = 175;
    uint8_t kaAction = 1;
    std::string kaTarget;
    std::string kaUrl = IDF_KEEPALIVE_DEFAULT_URL;
    std::string kaProfile;
    uint32_t kaLastTime = 0;
    int kaTrafficKB = 1;
    int tzOffsetMin = 480;
    bool emailEnabled = true;
    bool dataEnabled = false;
    std::string apn;
};

// Manual and scheduled runs copy only the selected task slot.
struct IdfSchedRunView {
    bool valid = false;
    IdfSchedTask task;
    std::string kaUrl = IDF_KEEPALIVE_DEFAULT_URL;
    int tzOffsetMin = 480;
    bool emailEnabled = true;
    bool emailConfigured = false;
    bool dataEnabled = false;
    std::string apn;
};

struct IdfSimSettingsView {
    bool dataEnabled = false;
    bool roamingEnabled = false;
    std::string apn;
    std::string operatorPlmn;
    IdfSimCredential credentials[IDF_MAX_SIM_CREDENTIALS];
};

struct IdfSimUnlockView {
    bool found = false;
    IdfSimCredential credential;
};

struct IdfSmsProcessView {
    std::string adminPhone;
    std::string numberBlackList;
    int tzOffsetMin = 480;
};

struct IdfPushForwardView {
    std::string deviceName;
    std::string hostname;
    std::string notificationLocale;
    int networkMode = 0;
    bool heartbeatEnable = true;
    int heartbeatInterval = 6;
    std::string forwardRules;
    bool pushEnabled = true;
    bool emailEnabled = true;
    bool emailConfigured = false;
    IdfPushChannel pushChannels[IDF_MAX_PUSH_CHANNELS];
};

struct IdfPushNotifyView {
    std::string deviceName;
    std::string hostname;
    std::string notificationLocale;
    int networkMode = 0;
    bool heartbeatEnable = true;
    int heartbeatInterval = 6;
    bool pushEnabled = true;
    int tzOffsetMin = 480;
    IdfPushChannel pushChannels[IDF_MAX_PUSH_CHANNELS];
};

struct IdfEmailSettingsView {
    bool emailEnabled = true;
    bool emailConfigured = false;
    std::string smtpServer;
    int smtpPort = 465;
    std::string smtpUser;
    std::string smtpPass;
    std::string smtpSendTo;
};

struct IdfSchedulerView {
    bool kaEnabled = false;
    int kaIntervalDays = 175;
    uint8_t kaAction = 1;
    int kaTrafficKB = 1;
    uint32_t kaLastTime = 0;
    int tzOffsetMin = 480;
    bool rebootEnabled = false;
    int rebootHour = 4;
    bool hbEnabled = false;
    int hbHour = 9;
    bool smsHealthEnabled = false;
    int smsHealthHour = 10;
    bool smsHealthNotify = true;
    bool emailEnabled = true;
    IdfSchedTask schedTasks[IDF_MAX_SCHED_TASKS];
};

IdfConfig idf_config_get(void);
IdfConfigStatusView idf_config_get_status_view(void);
IdfConfigWebView idf_config_get_web_view(void);
IdfKeepaliveRunView idf_config_get_keepalive_run_view(void);
IdfSchedRunView idf_config_get_sched_run_view(int index);
IdfSimSettingsView idf_config_get_sim_settings_view(void);
IdfSimUnlockView idf_config_get_sim_unlock_view(const std::string& iccid);
IdfSmsProcessView idf_config_get_sms_process_view(void);
IdfPushForwardView idf_config_get_push_forward_view(void);
IdfPushNotifyView idf_config_get_push_notify_view(void);
IdfEmailSettingsView idf_config_get_email_settings_view(void);
IdfSchedulerView idf_config_get_scheduler_view(void);
bool idf_config_get_push_channel(uint8_t channel, IdfPushChannel& out);
bool idf_config_email_configured(void);
// Compare Web credentials under the lock to avoid a full config copy per request.
bool idf_config_check_web_auth(const char* user, const char* pass);
// Read this modem flag under the lock to avoid a full config copy on its task stack.
bool idf_config_net_led_enabled(void);
bool idf_config_call_notify_enabled(void);
// Narrow timezone and NTP accessors avoid a full config copy on small task stacks.
int idf_config_get_tz_offset(void);
std::string idf_config_get_ntp_server(void);
// Copy the mDNS host to a fixed buffer for the 3 KB response task.
// This avoids a full config copy and a std::string allocation each second.
void idf_config_copy_mdns_host(char* out, size_t cap);
// Return non-empty WiFi slots to the selector. The 15-second watchdog reads only the count.
std::vector<IdfWifiNetwork> idf_config_get_wifi_networks(void);
int idf_config_wifi_network_count(void);
