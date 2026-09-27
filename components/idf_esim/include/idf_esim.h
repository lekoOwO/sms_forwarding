#pragma once

#include <string>
#include <vector>

#include "esp_err.h"

struct IdfEsimProfile {
    std::string iccid;
    std::string isdpAid;
    std::string state;
    std::string nickname;
    std::string serviceProvider;
    std::string profileName;
    std::string profileClass;
};

// Register the card-identity hook that invalidates the EID cache after a SIM hot swap. app_main calls this once.
void idf_esim_init(void);
esp_err_t idf_esim_get_eid(std::string& eid, std::string& message);
esp_err_t idf_esim_list_profiles(std::vector<IdfEsimProfile>& profiles,
                                 std::string& eid,
                                 std::string& message);
// Enable, disable, and switch through SGP.22 without refreshFlag. Success requests a soft modem restart to reset the UICC.
// The new profile takes effect after modem attachment (issue #17). Callers do not need another refresh.
esp_err_t idf_esim_enable_profile(const std::string& identifier, std::string& message);
esp_err_t idf_esim_disable_profile(const std::string& identifier, std::string& message);
esp_err_t idf_esim_delete_profile(const std::string& identifier,
                                  std::string& message);
esp_err_t idf_esim_set_nickname(const std::string& identifier,
                                const std::string& nickname,
                                std::string& message);
esp_err_t idf_esim_switch_profile(const std::string& identifier, std::string& message);
std::string idf_esim_mask_profile_id(const std::string& identifier);
// Match a profile against a user identifier: ICCID, ISD-P AID, nickname, name, or carrier name. Ignore case.
bool idf_esim_profile_matches(const IdfEsimProfile& profile, const std::string& identifier);
