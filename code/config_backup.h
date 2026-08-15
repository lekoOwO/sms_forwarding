#pragma once

void initConfigBackup();
void handleConfigExportStart();
void handleConfigExportDownload();
void handleConfigRestoreStart();
void handleConfigRestoreChunk();
void handleConfigRestoreFinish();
bool configTransferActive();
void configBackupTick();
