#ifndef WEB_HANDLERS_H
#define WEB_HANDLERS_H

#include "globals.h"

#define LOG_BUF_SIZE 64
#define LOG_BYTE_BUDGET (24 * 1024)
#define MAX_ACTIVE_WEB_JOBS 3
#define MAX_REQUEST_CHUNK_BYTES 8192

typedef void (*WebJobHandler)();

extern String logBuffer[LOG_BUF_SIZE];
extern int logBufIdx;
extern int logBufCount;

void logCapture(const String& msg);
void logCapture(const char* msg);
void logCaptureF(const char* fmt, ...);
void logCaptureLn(const String& msg);
void logCaptureLn(const char* msg);

void initWebRuntime();
void lockRuntimeConfig();
void unlockRuntimeConfig();
bool startManagementHttpTask();
void processWebJobs();
bool webJobsActive();
bool webJobExecuting();
String webJobArg(const String& name);
bool enqueueWebJob(const char* type, WebJobHandler handler,
                   const String& argName1 = "", const String& argValue1 = "",
                   const String& argName2 = "", const String& argValue2 = "");
void sendQueuedActionResult(int status, bool success, const char* code,
                            const String& detail = "");
uint32_t deferCurrentWebJob();
void completeDeferredWebJob(uint32_t id, bool success, const String& resultJson);
void resumeDeferredWebJob(uint32_t id, WebJobHandler handler);
bool checkAuth();
bool checkCsrf();
bool decodeBase64RequestChunk(size_t capacity, uint8_t*& output, size_t& outputLength);
void handleRoot();
void handleConfig();
void handleSave();
void handleQuery();
void handleFlightMode();
void handleATCommand();
void handleSendSms();
void handlePing();
void handleLog();
void handleModem();
void handleWifi();
void handleJob();

#endif
