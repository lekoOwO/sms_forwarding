#include <cassert>
#include <cstdint>
#include <string>
#include <vector>

struct IdfSimSettingsView {
    bool dataEnabled = false;
    std::string apn;
};

struct IdfModemStatus {
    int ceregStat = 1;
    std::string cellIp;
};

static IdfModemStatus status;
static bool cgact_ok = true;
static bool ip_available = false;
static std::vector<std::string> commands;

static IdfModemStatus idf_modem_get_status() { return status; }
static bool idf_modem_data_activation_allowed(int cereg_stat) { return cereg_stat == 1; }

static std::string idf_util_trim_copy(const std::string& value)
{
    const size_t first = value.find_first_not_of(" \r\n\t");
    return first == std::string::npos
               ? std::string()
               : value.substr(first, value.find_last_not_of(" \r\n\t") - first + 1);
}

static bool apn_valid_for_at(const std::string& apn)
{
    return apn.size() <= 96 && apn.find('"') == std::string::npos &&
           apn.find('\r') == std::string::npos && apn.find('\n') == std::string::npos;
}

static void idf_log_line(const char*) {}

static bool send_ok(const char* command, uint32_t, std::string* response)
{
    commands.emplace_back(command);
    if (response) *response = "OK\r\n";
    if (std::string(command) == "AT+CGACT=1,1") return cgact_ok;
    return true;
}

static void set_status_cell_ip(const std::string& ip) { status.cellIp = ip; }

static bool sample_cell_ip_once()
{
    commands.emplace_back("AT+CGPADDR=1");
    if (!ip_available) {
        status.cellIp.clear();
        return false;
    }
    status.cellIp = "192.0.2.44";
    return true;
}

#include "data_mode_runtime.inc"

static void reset_fixture()
{
    status = {};
    status.ceregStat = 1;
    cgact_ok = true;
    ip_available = false;
    commands.clear();
}

int main()
{
    IdfSimSettingsView cfg;
    cfg.dataEnabled = true;
    cfg.apn = "fixture";

    reset_fixture();
    cgact_ok = false;
    ip_available = true;
    assert(apply_configured_data_mode_once(cfg, 6000, 2500));
    assert(status.cellIp == "192.0.2.44");
    assert((commands == std::vector<std::string>{
        "AT+CGDCONT=1,\"IP\",\"fixture\"", "AT+CGACT=1,1", "AT+CGPADDR=1"}));

    reset_fixture();
    cgact_ok = true;
    ip_available = false;
    assert(!apply_configured_data_mode_once(cfg, 6000, 2500));
    assert(status.cellIp.empty());
    assert(commands.back() == "AT+CGPADDR=1");

    reset_fixture();
    cfg.dataEnabled = false;
    status.cellIp = "192.0.2.44";
    assert(apply_configured_data_mode_once(cfg, 6000, 2500));
    assert(status.cellIp.empty());
    assert(commands == std::vector<std::string>{"AT+CGACT=0,1"});
}
