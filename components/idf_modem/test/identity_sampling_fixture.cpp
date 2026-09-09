#include "idf_modem_registration.h"
#include <cassert>
#include <vector>
#include "identity_runtime.inc"

int main()
{
    // 漫遊已註冊時可取得靜態身分，但不能啟用資料或修改選網設定。
    status.ceregStat = 5;
    assert(sample_identity_once(false, true));
    assert(!status.mfr.empty() && !status.model.empty() && !status.fwver.empty());
    assert(!status.imei.empty() && !status.iccid.empty() && !status.imsi.empty());
    assert(std::find(commands.begin(), commands.end(), "AT+CIMI") != commands.end());
    assert(std::find(commands.begin(), commands.end(), "AT+COPS?") != commands.end());
    assert(std::none_of(commands.begin(), commands.end(), [](const std::string& command) {
        return command.find("AT+COPS=") == 0 || command.find("AT+CGACT=") == 0;
    }));
    assert(!idf_modem_data_activation_allowed(5));
    for (int stat : {-1, 0, 2, 3, 4, 11}) {
        status = {}; status.ceregStat = stat; commands.clear();
        assert(!sample_identity_once(false, true));
        assert(commands.empty());
    }
    status = {}; status.ceregStat = 1; commands.clear();
    assert(sample_identity_once(false, true));
    assert(std::find(commands.begin(), commands.end(), "AT+COPS=3,0") != commands.end());
}
