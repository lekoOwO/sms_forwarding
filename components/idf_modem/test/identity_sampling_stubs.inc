static IdfModemStatus status;
static bool s_identity_static_attempted = false, s_identity_network_attempted = false;
static std::vector<std::string> commands;
static IdfModemStatus idf_modem_get_status() { return status; }
static bool send_ok(const char* command, int, std::string* response)
{
    commands.emplace_back(command);
    *response = command;
    return true;
}
static std::string first_payload_line(const std::string& response, const char*) { return response; }
static bool is_imei_text(const std::string& value) { return value.size() == 15; }
static bool idf_modem_parse_imei_frame(const std::string&, const char*, std::string& out)
{ out = "123456789012345"; return true; }
static std::string query_current_iccid(int) { return "8900000000000000000"; }
static std::string first_digits_line(const std::string&, int, int) { return "001010000000001"; }
static std::string first_digit_run(const std::string&, int, int) { return {}; }
static std::string parse_cops(const std::string&) { return {}; }
static std::string parse_apn(const std::string&) { return {}; }
static std::string parse_cnum_phone(const std::string&) { return {}; }
static void update_status(const IdfModemStatus& patch, bool, bool)
{
    status.mfr = patch.mfr; status.model = patch.model; status.fwver = patch.fwver;
    status.imei = patch.imei; status.iccid = patch.iccid; status.imsi = patch.imsi;
}
static void save_identity_cache(const std::string&, const std::string&) {}
static std::string mask_identity(const std::string&) { return {}; }
static void idf_logf(const char*, ...) {}
static void vTaskDelay(int) {}
#define pdMS_TO_TICKS(ms) (ms)
#define ESP_LOGI(...) ((void)0)
