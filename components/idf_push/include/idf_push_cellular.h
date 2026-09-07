#pragma once

#include <string>

#include "idf_config.h"
#include "config_schema_generated.h"

struct IdfPushCellularTarget {
    std::string effectiveUrl;
    std::string canonicalOrigin;
};

bool idf_push_prepare_cellular_target(const IdfPushChannel& channel,
                                      IdfPushCellularTarget& target);
