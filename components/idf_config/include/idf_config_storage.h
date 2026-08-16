#pragma once

#include "idf_config.h"

// The storage boundary owns the versioned CFG2 codec and the two-slot appcfg
// transaction.  Callers update a complete candidate and publish it only after
// the blob and its commit marker have both been read back successfully.
esp_err_t idf_config_storage_load(IdfConfig& out, IdfConfigLoadStatus* status);
esp_err_t idf_config_storage_save(const IdfConfig& candidate);
// Populate the exact storage defaults used for first boot and factory reset.
void idf_config_storage_factory_reset(IdfConfig& out);
