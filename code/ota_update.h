#pragma once

#include <Arduino.h>

#define OTA_CHUNK_SIZE 8192

void initOtaUpdate();
void handleOtaStart();
void handleOtaChunk();
void handleOtaFinish();
void runOtaFinish();
void otaTick();
bool otaUploadActive();
bool deviceRestartPending();
void scheduleDeviceRestart(uint32_t delayMs = 2000);
void otaConfirmHealthy(bool healthy);
