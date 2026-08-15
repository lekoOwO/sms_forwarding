#include "web_handlers.h"
#include <ArduinoJson.h>
#include <esp_random.h>
#include <mbedtls/base64.h>
#include "config_backup.h"
#include "config.h"
#include "modem.h"
#include "notification_locale.h"
#include "ota_update.h"
#include "push.h"
#include "utf8_validation.h"
#include "web_bundle.h"
#include "wifi_config.h"

// ---- Log ring buffer ----
String logBuffer[LOG_BUF_SIZE];
int logBufIdx = 0;
int logBufCount = 0;
static uint32_t logIds[LOG_BUF_SIZE];
static size_t logBytes = 0;
static uint32_t nextLogId = 1;
static String _logLine;  // logCapture writes here; logCaptureLn commits the complete line.
static SemaphoreHandle_t logMutex;
static SemaphoreHandle_t logLineMutex;

enum WebJobState : uint8_t { WEB_JOB_EMPTY, WEB_JOB_QUEUED, WEB_JOB_RUNNING, WEB_JOB_DONE };

struct WebJob {
  uint32_t id = 0;
  uint32_t completedAt = 0;
  WebJobState state = WEB_JOB_EMPTY;
  bool success = false;
  bool deferred = false;
  String type;
  WebJobHandler handler = nullptr;
  String argNames[48];
  String argValues[48];
  String resultJson;
};

static constexpr size_t WEB_JOB_SLOTS = 6;
static constexpr size_t WEB_JOB_ARG_SLOTS = 48;
static WebJob webJobs[WEB_JOB_SLOTS];
static SemaphoreHandle_t jobMutex;
static SemaphoreHandle_t configMutex;
static volatile int executingJob = -1;
static TaskHandle_t jobTaskHandle;
static uint32_t nextJobId = 1;
static String csrfToken;

struct AuthAttempt {
  IPAddress ip;
  uint32_t windowStart = 0;
  uint32_t blockedUntil = 0;
  uint8_t failures = 0;
  bool used = false;
};

static AuthAttempt authAttempts[4];
static constexpr uint32_t AUTH_WINDOW_MS = 60000;
static constexpr uint32_t AUTH_BLOCK_MS = 60000;
static constexpr uint8_t AUTH_FAILURE_LIMIT = 5;

static bool constantTimeEqual(const String& left, const String& right) {
  size_t length = left.length() > right.length() ? left.length() : right.length();
  uint8_t difference = static_cast<uint8_t>(left.length() ^ right.length());
  for (size_t i = 0; i < length; ++i) {
    uint8_t a = i < left.length() ? left[i] : 0;
    uint8_t b = i < right.length() ? right[i] : 0;
    difference |= a ^ b;
  }
  return difference == 0;
}

void initWebRuntime() {
  if (!logMutex) logMutex = xSemaphoreCreateMutex();
  if (!logLineMutex) logLineMutex = xSemaphoreCreateMutex();
  if (!jobMutex) jobMutex = xSemaphoreCreateMutex();
  if (!configMutex) configMutex = xSemaphoreCreateMutex();
  uint8_t random[16];
  esp_fill_random(random, sizeof(random));
  static const char hex[] = "0123456789abcdef";
  csrfToken = "";
  csrfToken.reserve(sizeof(random) * 2);
  for (uint8_t byte : random) {
    csrfToken += hex[byte >> 4];
    csrfToken += hex[byte & 0x0f];
  }
  memset(random, 0, sizeof(random));
}

void lockRuntimeConfig() {
  xSemaphoreTake(configMutex, portMAX_DELAY);
}

void unlockRuntimeConfig() {
  xSemaphoreGive(configMutex);
}

static String requestArg(const String& name) {
  if (webJobExecuting()) {
    int index = executingJob;
    for (size_t i = 0; i < WEB_JOB_ARG_SLOTS; ++i) {
      if (webJobs[index].argNames[i] == name) return webJobs[index].argValues[i];
    }
    return "";
  }
  return server.arg(name);
}

String webJobArg(const String& name) {
  return requestArg(name);
}

static bool requestHasArg(const String& name) {
  if (webJobExecuting()) {
    int index = executingJob;
    for (size_t i = 0; i < WEB_JOB_ARG_SLOTS; ++i) {
      if (webJobs[index].argNames[i] == name) return true;
    }
    return false;
  }
  return server.hasArg(name);
}

bool webJobExecuting() {
  return executingJob >= 0 && xTaskGetCurrentTaskHandle() == jobTaskHandle;
}

bool webJobsActive() {
  if (!jobMutex) return false;
  xSemaphoreTake(jobMutex, portMAX_DELAY);
  bool active = false;
  for (const WebJob& job : webJobs) {
    if (job.state == WEB_JOB_QUEUED || job.state == WEB_JOB_RUNNING) {
      active = true;
      break;
    }
  }
  xSemaphoreGive(jobMutex);
  return active;
}

static void httpTask(void*) {
  for (;;) {
    server.handleClient();
    vTaskDelay(pdMS_TO_TICKS(2));
  }
}

bool startManagementHttpTask() {
  return xTaskCreate(httpTask, "management-http", 6144, nullptr, 1, nullptr) == pdPASS;
}

static void _serialWrite(const char* msg, size_t length, bool newline = false) {
  size_t required = length + (newline ? 2 : 0);
  if ((size_t)Serial.availableForWrite() < required) return;
  Serial.write((const uint8_t*)msg, length);
  if (newline) Serial.write((const uint8_t*)"\r\n", 2);
}

static void _logAppend(const String& line) {
  if (!logMutex) return;
  xSemaphoreTake(logMutex, portMAX_DELAY);
  while (logBufCount > 0 && logBytes + line.length() > LOG_BYTE_BUDGET) {
    int oldest = (logBufIdx - logBufCount + LOG_BUF_SIZE) % LOG_BUF_SIZE;
    logBytes -= logBuffer[oldest].length();
    logBuffer[oldest] = "";
    logBufCount--;
  }
  if (logBufCount == LOG_BUF_SIZE) {
    logBytes -= logBuffer[logBufIdx].length();
  } else {
    logBufCount++;
  }
  logBuffer[logBufIdx] = line;
  logIds[logBufIdx] = nextLogId++;
  if (nextLogId == 0) nextLogId = 1;
  logBytes += line.length();
  logBufIdx = (logBufIdx + 1) % LOG_BUF_SIZE;
  xSemaphoreGive(logMutex);
}

static void _logCommit() {
  String line;
  xSemaphoreTake(logLineMutex, portMAX_DELAY);
  line = _logLine;
  _logLine = "";
  xSemaphoreGive(logLineMutex);
  if (line.length() > 0) _logAppend(line);
}

static void _logAppendFragment(const String& msg) {
  xSemaphoreTake(logLineMutex, portMAX_DELAY);
  if (_logLine.length() < LOG_LINE_MAX_LENGTH) {
    _logLine += msg.substring(0, LOG_LINE_MAX_LENGTH - _logLine.length());
  }
  xSemaphoreGive(logLineMutex);
}

static void _logAppendFragment(const char* msg) {
  _logAppendFragment(String(msg));
}

void logCapture(const String& msg) {
  _serialWrite(msg.c_str(), msg.length());
  _logAppendFragment(msg);
}

void logCapture(const char* msg) {
  _serialWrite(msg, strlen(msg));
  _logAppendFragment(msg);
}

void logCaptureF(const char* fmt, ...) {
  char buf[256];
  va_list args;
  va_start(args, fmt);
  vsnprintf(buf, sizeof(buf), fmt, args);
  va_end(args);
  _serialWrite(buf, strlen(buf));
  _logAppendFragment(buf);
  // Commit the line when the formatted string ends with \n.
  size_t len = strlen(buf);
  if (len > 0 && buf[len - 1] == '\n') {
    String line;
    xSemaphoreTake(logLineMutex, portMAX_DELAY);
    _logLine.trim();
    line = _logLine;
    _logLine = "";
    xSemaphoreGive(logLineMutex);
    if (line.length()) _logAppend(line);
  }
}

void logCaptureLn(const String& msg) {
  _serialWrite(msg.c_str(), msg.length(), true);
  String line;
  xSemaphoreTake(logLineMutex, portMAX_DELAY);
  if (_logLine.length() < LOG_LINE_MAX_LENGTH) {
    _logLine += msg.substring(0, LOG_LINE_MAX_LENGTH - _logLine.length());
  }
  line = _logLine;
  _logLine = "";
  xSemaphoreGive(logLineMutex);
  if (line.length()) _logAppend(line);
}

void logCaptureLn(const char* msg) {
  logCaptureLn(String(msg));
}

static void sendActionResult(int status, bool success, const char* code,
                             const String& detail = "");
static void sendActionResult(int status, bool success, const char* code,
                             JsonDocument& data, const String& detail = "");

static String actionResultJson(bool success, const char* code) {
  JsonDocument result;
  result["success"] = success;
  result["code"] = code;
  result["data"].to<JsonObject>();
  result["detail"] = "";
  String json;
  serializeJson(result, json);
  return json;
}

static void clearWebJobArgs(WebJob& job) {
  for (size_t i = 0; i < WEB_JOB_ARG_SLOTS; ++i) {
    if (job.argValues[i].length()) {
      memset(const_cast<char*>(job.argValues[i].c_str()), 0, job.argValues[i].length());
    }
    job.argNames[i] = "";
    job.argValues[i] = "";
  }
}

static void cancelQueuedJobsForRestart() {
  xSemaphoreTake(jobMutex, portMAX_DELAY);
  uint32_t completedAt = millis();
  for (WebJob& job : webJobs) {
    if (job.state != WEB_JOB_QUEUED) continue;
    job.success = false;
    job.deferred = false;
    job.state = WEB_JOB_DONE;
    job.completedAt = completedAt;
    job.handler = nullptr;
    job.resultJson = actionResultJson(false, "ACTION_BUSY");
    clearWebJobArgs(job);
  }
  xSemaphoreGive(jobMutex);
}

// Check HTTP Basic authentication.
bool checkAuth() {
  if (webJobExecuting()) return true;
  IPAddress remote = server.client().remoteIP();
  uint32_t now = millis();
  AuthAttempt* attempt = nullptr;
  AuthAttempt* replacement = &authAttempts[0];
  for (AuthAttempt& entry : authAttempts) {
    if (entry.used && entry.ip == remote) attempt = &entry;
    if (!entry.used || entry.windowStart < replacement->windowStart) replacement = &entry;
  }
  if (attempt && static_cast<int32_t>(attempt->blockedUntil - now) > 0) {
    server.sendHeader("Retry-After", String((attempt->blockedUntil - now + 999) / 1000));
    sendActionResult(429, false, "ACTION_AUTH_THROTTLED");
    return false;
  }
  for (int i = 0; i < MAX_WEB_ACCOUNTS; i++) {
    xSemaphoreTake(configMutex, portMAX_DELAY);
    const WebAccount& account = config.webAccounts[i];
    bool authenticated = account.username.length() > 0 && account.password.length() > 0 &&
                         server.authenticate(account.username.c_str(), account.password.c_str());
    xSemaphoreGive(configMutex);
    if (authenticated) {
      if (attempt) *attempt = AuthAttempt{};
      return true;
    }
  }
  if (!attempt) {
    attempt = replacement;
    *attempt = AuthAttempt{};
    attempt->used = true;
    attempt->ip = remote;
    attempt->windowStart = now;
  }
  if (now - attempt->windowStart > AUTH_WINDOW_MS) {
    attempt->windowStart = now;
    attempt->failures = 0;
  }
  if (++attempt->failures >= AUTH_FAILURE_LIMIT) attempt->blockedUntil = now + AUTH_BLOCK_MS;
  server.requestAuthentication(BASIC_AUTH, "SMS Forwarding", "Enter the administrator username and password");
  return false;
}

bool checkCsrf() {
  if (webJobExecuting()) return true;
  if (constantTimeEqual(server.header("X-CSRF-Token"), csrfToken)) return true;
  server.sendHeader("Cache-Control", "no-store");
  sendActionResult(403, false, "ACTION_CSRF_INVALID");
  return false;
}

bool decodeBase64RequestChunk(size_t capacity, uint8_t*& output, size_t& outputLength) {
  static uint8_t decoded[MAX_REQUEST_CHUNK_BYTES];
  const String encoded = server.arg("plain");
  const size_t encodedLimit = 4 * ((capacity + 2) / 3);
  if (capacity == 0 || capacity > sizeof(decoded) || encoded.length() == 0 ||
      encoded.length() > encodedLimit ||
      (encoded.length() & 3)) return false;
  bool padding = false;
  size_t paddingBytes = 0;
  for (size_t i = 0; i < encoded.length(); ++i) {
    const char c = encoded[i];
    if (c == '=') {
      padding = true;
      if (++paddingBytes > 2 || i + 2 < encoded.length()) return false;
    } else if (padding || !(isAlphaNumeric(c) || c == '+' || c == '/')) {
      return false;
    }
  }
  outputLength = 0;
  output = decoded;
  return mbedtls_base64_decode(decoded, capacity, &outputLength,
                               reinterpret_cast<const uint8_t*>(encoded.c_str()),
                               encoded.length()) == 0 && outputLength > 0;
}

static const size_t JSON_RESPONSE_MAX_LENGTH = 128 * 1024;

static void sendJsonFailure() {
  if (webJobExecuting()) {
    xSemaphoreTake(jobMutex, portMAX_DELAY);
    webJobs[executingJob].success = false;
    webJobs[executingJob].resultJson = actionResultJson(false, "ACTION_JSON_FAILED");
    xSemaphoreGive(jobMutex);
    return;
  }
  server.sendHeader("Cache-Control", "no-store");
  server.send_P(500, PSTR("application/json"),
                PSTR("{\"error\":\"JSON serialization failed\"}"));
}

static void sendJson(int status, JsonDocument& document) {
  size_t length = measureJson(document);
  String json;
  if (document.overflowed() || length > JSON_RESPONSE_MAX_LENGTH || !json.reserve(length) ||
      serializeJson(document, json) != length || json.length() != length ||
      !hasValidJsonEncoding(json.c_str())) {
    sendJsonFailure();
    return;
  }
  if (webJobExecuting()) {
    xSemaphoreTake(jobMutex, portMAX_DELAY);
    WebJob& job = webJobs[executingJob];
    job.success = status < 400 && document["success"].as<bool>();
    job.resultJson = json;
    xSemaphoreGive(jobMutex);
    return;
  }
  server.sendHeader("Cache-Control", "no-store");
  server.send(status, "application/json", json);
}

void sendQueuedActionResult(int status, bool success, const char* code,
                            const String& detail) {
  sendActionResult(status, success, code, detail);
}

bool enqueueWebJob(const char* type, WebJobHandler handler,
                   const String& argName1, const String& argValue1,
                   const String& argName2, const String& argValue2) {
  if (!jobMutex || !handler) return false;
  if (deviceRestartPending()) {
    sendActionResult(409, false, "ACTION_BUSY");
    return false;
  }
  if ((otaUploadActive() && strcmp(type, "ota") != 0) ||
      (configTransferActive() && strcmp(type, "config-restore") != 0 &&
       strcmp(type, "config-export") != 0)) {
    sendActionResult(409, false, "ACTION_OTA_BUSY");
    return false;
  }

  xSemaphoreTake(jobMutex, portMAX_DELAY);
  size_t active = 0;
  int emptySlot = -1;
  int oldestDoneSlot = -1;
  uint32_t now = millis();
  uint32_t oldestAge = 0;
  for (size_t i = 0; i < WEB_JOB_SLOTS; ++i) {
    if (webJobs[i].state == WEB_JOB_QUEUED || webJobs[i].state == WEB_JOB_RUNNING) active++;
    if (webJobs[i].state == WEB_JOB_EMPTY && emptySlot < 0) emptySlot = i;
    else if (webJobs[i].state == WEB_JOB_DONE) {
      uint32_t age = now - webJobs[i].completedAt;
      if (oldestDoneSlot < 0 || age > oldestAge) {
        oldestAge = age;
        oldestDoneSlot = i;
      }
    }
  }
  int slot = emptySlot >= 0 ? emptySlot : oldestDoneSlot;
  if (active >= MAX_ACTIVE_WEB_JOBS || slot < 0) {
    xSemaphoreGive(jobMutex);
    sendActionResult(429, false, "ACTION_JOB_QUEUE_FULL");
    return false;
  }
  WebJob& job = webJobs[slot];
  job.id = nextJobId++;
  if (job.id == 0) job.id = nextJobId++;
  job.completedAt = 0;
  job.state = WEB_JOB_QUEUED;
  job.success = false;
  job.deferred = false;
  job.type = type;
  job.handler = handler;
  if (argName1 == "*") {
    if (server.args() > WEB_JOB_ARG_SLOTS) {
      job.state = WEB_JOB_EMPTY;
      xSemaphoreGive(jobMutex);
      sendActionResult(400, false, "ACTION_TOO_MANY_FIELDS");
      return false;
    }
    for (int i = 0; i < server.args(); ++i) {
      job.argNames[i] = server.argName(i);
      job.argValues[i] = server.arg(i);
    }
  } else {
    job.argNames[0] = argName1;
    job.argValues[0] = argValue1;
    job.argNames[1] = argName2;
    job.argValues[1] = argValue2;
  }
  job.resultJson = "";
  uint32_t id = job.id;
  xSemaphoreGive(jobMutex);

  JsonDocument data;
  data["jobId"] = id;
  sendActionResult(202, true, "ACTION_JOB_ACCEPTED", data);
  return true;
}

void processWebJobs() {
  if (!jobMutex || executingJob >= 0) return;
  if (deviceRestartPending()) {
    cancelQueuedJobsForRestart();
    return;
  }
  xSemaphoreTake(jobMutex, portMAX_DELAY);
  int slot = -1;
  for (size_t i = 0; i < WEB_JOB_SLOTS; ++i) {
    if (webJobs[i].state == WEB_JOB_QUEUED) {
      slot = i;
      webJobs[i].state = WEB_JOB_RUNNING;
      break;
    }
  }
  xSemaphoreGive(jobMutex);
  if (slot < 0) return;

  executingJob = slot;
  jobTaskHandle = xTaskGetCurrentTaskHandle();
  webJobs[slot].handler();
  xSemaphoreTake(jobMutex, portMAX_DELAY);
  WebJob& job = webJobs[slot];
  if (!job.deferred && job.resultJson.length() == 0) {
    job.success = false;
    job.resultJson = actionResultJson(false, "ACTION_JOB_FAILED");
  }
  if (!job.deferred) {
    job.state = WEB_JOB_DONE;
    job.completedAt = millis();
  }
  job.handler = nullptr;
  clearWebJobArgs(job);
  executingJob = -1;
  xSemaphoreGive(jobMutex);
}

uint32_t deferCurrentWebJob() {
  if (!webJobExecuting()) return 0;
  xSemaphoreTake(jobMutex, portMAX_DELAY);
  WebJob& job = webJobs[executingJob];
  job.deferred = true;
  uint32_t id = job.id;
  xSemaphoreGive(jobMutex);
  return id;
}

void completeDeferredWebJob(uint32_t id, bool success, const String& resultJson) {
  xSemaphoreTake(jobMutex, portMAX_DELAY);
  for (WebJob& job : webJobs) {
    if (job.id != id || job.state != WEB_JOB_RUNNING || !job.deferred) continue;
    job.success = success;
    job.resultJson = resultJson;
    job.deferred = false;
    job.state = WEB_JOB_DONE;
    job.completedAt = millis();
    break;
  }
  xSemaphoreGive(jobMutex);
}

void resumeDeferredWebJob(uint32_t id, WebJobHandler handler) {
  xSemaphoreTake(jobMutex, portMAX_DELAY);
  for (WebJob& job : webJobs) {
    if (job.id != id || job.state != WEB_JOB_RUNNING || !job.deferred) continue;
    job.deferred = false;
    job.state = WEB_JOB_QUEUED;
    job.handler = handler;
    break;
  }
  xSemaphoreGive(jobMutex);
}

void handleJob() {
  if (!checkAuth()) return;
  uint32_t id = requestArg("id").toInt();
  JsonDocument response;
  bool found = false;
  xSemaphoreTake(jobMutex, portMAX_DELAY);
  for (const WebJob& job : webJobs) {
    if (job.state == WEB_JOB_EMPTY || job.id != id || id == 0) continue;
    found = true;
    response["id"] = job.id;
    response["type"] = job.type;
    response["state"] = job.state == WEB_JOB_QUEUED ? "queued" :
                        job.state == WEB_JOB_RUNNING ? "running" :
                        job.success ? "succeeded" : "failed";
    if (job.state == WEB_JOB_DONE) {
      JsonDocument result;
      if (!deserializeJson(result, job.resultJson)) response["result"].set(result.as<JsonVariantConst>());
    }
    break;
  }
  xSemaphoreGive(jobMutex);
  if (!found) {
    sendActionResult(404, false, "ACTION_JOB_NOT_FOUND");
    return;
  }
  sendJson(200, response);
}

static void sendActionResult(int status, bool success, const char* code,
                             const String& detail) {
  JsonDocument response;
  response["success"] = success;
  response["code"] = code;
  response["data"].to<JsonObject>();
  response["detail"] = detail;
  sendJson(status, response);
}

static void sendActionResult(int status, bool success, const char* code,
                             JsonDocument& data, const String& detail) {
  if (data.overflowed()) {
    sendJsonFailure();
    return;
  }
  JsonDocument response;
  response["success"] = success;
  response["code"] = code;
  response["data"].set(data.as<JsonVariantConst>());
  response["detail"] = detail;
  sendJson(status, response);
}

static void setStringOrNull(JsonObject& object, const char* key, const String& value) {
  if (value == "N/A") object[key] = nullptr;
  else object[key] = value;
}

static bool rejectInvalidOrTooLong(const String& value, size_t maxBytes, const String& field) {
  if (!isValidUtf8Text(value.c_str())) {
    sendActionResult(400, false, "ACTION_INPUT_INVALID", field);
    return true;
  }
  if (value.length() > maxBytes) {
    sendActionResult(400, false, "ACTION_INPUT_TOO_LONG", field);
    return true;
  }
  return false;
}

static bool rejectArgInvalidOrTooLong(const String& field, size_t maxBytes) {
  return requestHasArg(field) && rejectInvalidOrTooLong(requestArg(field), maxBytes, field);
}

static bool rejectModemBusy() {
  if (!modemIsBusy()) return false;
  sendActionResult(429, false, "ACTION_MODEM_BUSY");
  return true;
}

// Serve the frontend build directly from the application image.
void handleRoot() {
  if (!checkAuth()) return;
  server.sendHeader("Content-Security-Policy", "frame-ancestors 'none'");
  server.sendHeader("X-Frame-Options", "DENY");
  server.sendHeader("Cache-Control", "no-store");
  server.sendHeader("Content-Encoding", "gzip");
  server.sendHeader("Vary", "Accept-Encoding");
  server.send_P(200, "text/html; charset=utf-8",
                reinterpret_cast<const char*>(WEB_BUNDLE), WEB_BUNDLE_SIZE);
}

// Return the status and configuration needed to initialize the frontend. Passwords are omitted.
void handleConfig() {
  if (!checkAuth()) return;

  xSemaphoreTake(configMutex, portMAX_DELAY);

  bool emailOk = config.smtpServer.length() > 0 && config.smtpUser.length() > 0 &&
                 config.smtpPass.length() > 0 && config.smtpSendTo.length() > 0;
  int pushCount = 0;
  for (int i = 0; i < MAX_PUSH_CHANNELS; i++) {
    if (config.pushChannels[i].enabled) pushCount++;
  }

  JsonDocument json;
  JsonObject status = json["status"].to<JsonObject>();
  json["csrfToken"] = csrfToken;
  status["ip"] = WiFi.localIP().toString();
  status["wifiSsid"] = WiFi.SSID();
  status["freeHeapKb"] = ESP.getFreeHeap() / 1024;
  status["uptimeSeconds"] = millis() / 1000;
  status["modemReady"] = modemReady;
  status["emailConfigured"] = emailOk;
  status["enabledPushChannels"] = pushCount;

  JsonObject configJson = json["config"].to<JsonObject>();
  JsonArray webAccounts = configJson["webAccounts"].to<JsonArray>();
  for (int i = 0; i < MAX_WEB_ACCOUNTS; i++) {
    JsonObject account = webAccounts.add<JsonObject>();
    account["username"] = config.webAccounts[i].username;
    account["password"] = "";
  }
  configJson["smtpServer"] = config.smtpServer;
  configJson["deviceName"] = config.deviceName;
  configJson["hostname"] = config.hostname;
  configJson["notificationLocale"] = config.notificationLocale;
  configJson["smtpPort"] = config.smtpPort;
  configJson["smtpUser"] = config.smtpUser;
  configJson["smtpPass"] = "";
  configJson["smtpSendTo"] = config.smtpSendTo;
  configJson["adminPhone"] = config.adminPhone;
  configJson["numberBlackList"] = config.numberBlackList;
  JsonArray pushChannels = configJson["pushChannels"].to<JsonArray>();
  for (int i = 0; i < MAX_PUSH_CHANNELS; i++) {
    const PushChannel& channel = config.pushChannels[i];
    JsonObject channelJson = pushChannels.add<JsonObject>();
    channelJson["enabled"] = channel.enabled;
    channelJson["type"] = static_cast<int>(channel.type);
    channelJson["name"] = channel.name;
    channelJson["url"] = channel.url;
    channelJson["key1"] = channel.key1;
    channelJson["key2"] = channel.key2;
    channelJson["titleTemplate"] = channel.titleTemplate;
    channelJson["bodyTemplate"] = channel.bodyTemplate;
    channelJson["customBody"] = channel.customBody;
  }
  xSemaphoreGive(configMutex);
  sendJson(200, json);
}

// Handle flight mode control requests.
void handleFlightMode() {
  if (!checkAuth()) return;
  if (!webJobExecuting()) {
    if (!checkCsrf()) return;
    enqueueWebJob("flight", handleFlightMode, "*", "");
    return;
  }
  
  String action = requestArg("action");
  if (rejectInvalidOrTooLong(action, 32, "action")) return;
  if (rejectModemBusy()) return;
  bool success = false;
  JsonDocument data;
  JsonObject dataObject = data.to<JsonObject>();
  String detail = "";
  const char* code = "ACTION_UNKNOWN";
  
  if (action == "query") {
    // Query the current operating mode.
    logCaptureLn(String("Web UI queried flight mode: AT+CFUN?"));
    String resp = sendATCommand("AT+CFUN?", 2000);
    logCaptureLn(String("CFUN query response: " + resp));
    
    if (resp.indexOf("+CFUN:") >= 0) {
      success = true;
      int idx = resp.indexOf("+CFUN:");
      int mode = resp.substring(idx + 6).toInt();
      
      if (mode == 0) {
        code = "ACTION_FLIGHT_STATUS_OFF";
      } else if (mode == 1) {
        code = "ACTION_FLIGHT_STATUS_NORMAL";
      } else if (mode == 4) {
        code = "ACTION_FLIGHT_STATUS_ON";
      } else {
        code = "ACTION_FLIGHT_STATUS_UNKNOWN";
      }
      dataObject["mode"] = mode;
    } else {
      code = "ACTION_FLIGHT_FAILED";
      detail = resp;
    }
  }
  else if (action == "toggle") {
    // Query the current state first.
    String resp = sendATCommand("AT+CFUN?", 2000);
    logCaptureLn(String("CFUN query response: " + resp));
    
    if (resp.indexOf("+CFUN:") >= 0) {
      int idx = resp.indexOf("+CFUN:");
      int currentMode = resp.substring(idx + 6).toInt();
      
      // Toggle between mode 1 (normal) and mode 4 (flight mode).
      int newMode = (currentMode == 1) ? 4 : 1;
      String cmd = "AT+CFUN=" + String(newMode);
      
      logCaptureLn(String("Toggling flight mode: " + cmd));
      String setResp = sendATCommand(cmd.c_str(), 5000);
      logCaptureLn(String("CFUN set response: " + setResp));
      
      if (setResp.indexOf("OK") >= 0) {
        success = true;
        code = newMode == 4 ? "ACTION_FLIGHT_ENABLED" : "ACTION_FLIGHT_DISABLED";
      } else {
        code = "ACTION_FLIGHT_FAILED";
        detail = setResp;
      }
    } else {
      code = "ACTION_FLIGHT_FAILED";
      detail = resp;
    }
  }
  else if (action == "on") {
    // Force flight mode on.
    logCaptureLn(String("Web UI enabled flight mode: AT+CFUN=4"));
    String resp = sendATCommand("AT+CFUN=4", 5000);
    if (resp.indexOf("OK") >= 0) {
      success = true;
      code = "ACTION_FLIGHT_ENABLED";
    } else {
      code = "ACTION_FLIGHT_FAILED";
      detail = resp;
    }
  }
  else if (action == "off") {
    // Force flight mode off.
    logCaptureLn(String("Web UI disabled flight mode: AT+CFUN=1"));
    String resp = sendATCommand("AT+CFUN=1", 5000);
    if (resp.indexOf("OK") >= 0) {
      success = true;
      code = "ACTION_FLIGHT_DISABLED";
    } else {
      code = "ACTION_FLIGHT_FAILED";
      detail = resp;
    }
  }

  sendActionResult(200, success, code, data, detail);
}

// Handle AT command test requests.
void handleATCommand() {
  if (!checkAuth()) return;
  if (!webJobExecuting()) {
    if (!checkCsrf()) return;
    enqueueWebJob("at", handleATCommand, "*", "");
    return;
  }
  
  String cmd = requestArg("cmd");
  if (rejectInvalidOrTooLong(cmd, 256, "cmd")) return;
  if (cmd.length() > 0 && !modemCommandAllowed(cmd)) {
    sendActionResult(400, false, "ACTION_AT_REJECTED");
    return;
  }
  if (rejectModemBusy()) return;
  bool success = false;
  JsonDocument data;
  JsonObject dataObject = data.to<JsonObject>();
  const char* code = "ACTION_AT_REQUIRED";
  
  if (cmd.length() == 0) {
  } else {
    logCaptureLn(String("Web UI sent AT command: " + cmd));
    String resp = sendATCommand(cmd.c_str(), 5000);
    logCaptureLn(String("Modem response: " + resp));
    
    if (resp.length() > 0) {
      success = true;
      code = "ACTION_AT_OK";
      dataObject["raw"] = resp;
    } else {
      code = "ACTION_AT_TIMEOUT";
    }
  }

  sendActionResult(200, success, code, data);
}

// Handle modem information queries.
void handleQuery() {
  if (!checkAuth()) return;
  if (!webJobExecuting()) {
    enqueueWebJob("query", handleQuery, "*", "");
    return;
  }
  
  String type = requestArg("type");
  if (rejectInvalidOrTooLong(type, 32, "type")) return;
  if (type != "wifi" && rejectModemBusy()) return;
  bool success = false;
  JsonDocument data;
  JsonObject dataObject = data.to<JsonObject>();
  String detail = "";
  const char* code = "ACTION_QUERY_UNKNOWN";
  
  if (type == "ati") {
    // Query firmware information.
    String resp = sendATCommand("ATI", 2000);
    logCaptureLn(String("ATI response: " + resp));
    
    if (resp.indexOf("OK") >= 0) {
      success = true;
      code = "ACTION_QUERY_OK";
      // Parse the ATI response.
      String manufacturer = "N/A";
      String model = "N/A";
      String version = "N/A";
      
      // Parse the response line by line.
      int lineStart = 0;
      int lineNum = 0;
      for (int i = 0; i < resp.length(); i++) {
        if (resp.charAt(i) == '\n' || i == resp.length() - 1) {
          String line = resp.substring(lineStart, i);
          line.trim();
          if (line.length() > 0 && line != "ATI" && line != "OK") {
            lineNum++;
            if (lineNum == 1) manufacturer = line;
            else if (lineNum == 2) model = line;
            else if (lineNum == 3) version = line;
          }
          lineStart = i + 1;
        }
      }
      
      setStringOrNull(dataObject, "manufacturer", manufacturer);
      setStringOrNull(dataObject, "model", model);
      setStringOrNull(dataObject, "revision", version);
    } else {
      code = "ACTION_QUERY_FAILED";
      detail = resp;
    }
  }
  else if (type == "signal") {
    // Query signal quality.
    String resp = sendATCommand("AT+CESQ", 2000);
    logCaptureLn(String("CESQ response: " + resp));
    
    if (resp.indexOf("+CESQ:") >= 0) {
      success = true;
      code = "ACTION_QUERY_OK";
      // Parse +CESQ: <rxlev>,<ber>,<rscp>,<ecno>,<rsrq>,<rsrp>.
      int idx = resp.indexOf("+CESQ:");
      String params = resp.substring(idx + 6);
      int endIdx = params.indexOf('\r');
      if (endIdx < 0) endIdx = params.indexOf('\n');
      if (endIdx > 0) params = params.substring(0, endIdx);
      params.trim();
      
      // Split the parameters.
      String values[6];
      int valIdx = 0;
      int startPos = 0;
      for (int i = 0; i <= params.length() && valIdx < 6; i++) {
        if (i == params.length() || params.charAt(i) == ',') {
          values[valIdx] = params.substring(startPos, i);
          values[valIdx].trim();
          valIdx++;
          startPos = i + 1;
        }
      }
      
      // Convert RSRP to dBm (0-97 maps to -140 through -44 dBm; 99 means unknown).
      int rsrp = values[5].toInt();
      if (rsrp == 99 || rsrp == 255) {
        dataObject["rsrpDbm"] = nullptr;
      } else {
        dataObject["rsrpDbm"] = -140 + rsrp;
      }
      
      // Convert RSRQ (0-34 maps to -19.5 through -3 dB).
      int rsrq = values[4].toInt();
      if (rsrq == 99 || rsrq == 255) {
        dataObject["rsrqDb"] = nullptr;
      } else {
        dataObject["rsrqDb"] = -19.5 + rsrq * 0.5;
      }
      dataObject["cesq"] = params;
    } else {
      code = "ACTION_QUERY_FAILED";
      detail = resp;
    }
  }
  else if (type == "siminfo") {
    // Query SIM card information.
    success = true;
    code = "ACTION_QUERY_OK";
    
    // Query the IMSI.
    String resp = sendATCommand("AT+CIMI", 2000);
    String imsi = "N/A";
    if (resp.indexOf("OK") >= 0) {
      int start = resp.indexOf('\n');
      if (start >= 0) {
        int end = resp.indexOf('\n', start + 1);
        if (end < 0) end = resp.indexOf('\r', start + 1);
        if (end > start) {
          imsi = resp.substring(start + 1, end);
          imsi.trim();
          if (imsi == "OK" || imsi.length() < 10) imsi = "N/A";
        }
      }
    }
    // Query the ICCID.
    resp = sendATCommand("AT+ICCID", 2000);
    String iccid = "N/A";
    if (resp.indexOf("+ICCID:") >= 0) {
      int idx = resp.indexOf("+ICCID:");
      String tmp = resp.substring(idx + 7);
      int endIdx = tmp.indexOf('\r');
      if (endIdx < 0) endIdx = tmp.indexOf('\n');
      if (endIdx > 0) iccid = tmp.substring(0, endIdx);
      iccid.trim();
    }
    // Query this device's phone number when supported by the SIM card.
    resp = sendATCommand("AT+CNUM", 2000);
    String phoneNum = "N/A";
    if (resp.indexOf("+CNUM:") >= 0) {
      int idx = resp.indexOf(",\"");
      if (idx >= 0) {
        int endIdx = resp.indexOf("\"", idx + 2);
        if (endIdx > idx) {
          phoneNum = resp.substring(idx + 2, endIdx);
        }
      }
    }
    setStringOrNull(dataObject, "imsi", imsi);
    setStringOrNull(dataObject, "iccid", iccid);
    setStringOrNull(dataObject, "msisdn", phoneNum);
  }
  else if (type == "network") {
    // Query network status.
    success = true;
    code = "ACTION_QUERY_OK";
    
    // Query network registration status.
    String resp = sendATCommand("AT+CEREG?", 2000);
    int regStatus = modemParseCeregQueryStatus(resp);
    // Query the network operator.
    resp = sendATCommand("AT+COPS?", 2000);
    String oper = "N/A";
    if (resp.indexOf("+COPS:") >= 0) {
      int idx = resp.indexOf(",\"");
      if (idx >= 0) {
        int endIdx = resp.indexOf("\"", idx + 2);
        if (endIdx > idx) {
          oper = resp.substring(idx + 2, endIdx);
        }
      }
    }
    // Query PDP context activation status.
    resp = sendATCommand("AT+CGACT?", 2000);
    int pdpStatus = -1;
    int cgact = resp.indexOf("+CGACT:");
    while (cgact >= 0) {
      String line = resp.substring(cgact + 7);
      int lineEnd = line.indexOf('\n');
      if (lineEnd >= 0) line = line.substring(0, lineEnd);
      line.trim();
      int comma = line.indexOf(',');
      String cid = comma > 0 ? line.substring(0, comma) : "";
      String state = comma > 0 ? line.substring(comma + 1) : "";
      cid.trim();
      state.trim();
      bool valid = cid.length() > 0 && state.length() == 1 &&
                   (state == "0" || state == "1");
      for (size_t i = 0; valid && i < cid.length(); i++) valid = isDigit(cid[i]);
      if (valid) {
        if (cid == "1" && state == "1") {
          pdpStatus = 1;
          break;
        }
        pdpStatus = 0;
      }
      cgact = resp.indexOf("+CGACT:", cgact + 7);
    }
    // Query the APN.
    resp = sendATCommand("AT+CGDCONT?", 2000);
    String apn = "N/A";
    if (resp.indexOf("+CGDCONT:") >= 0) {
      int idx = resp.indexOf(",\"");
      if (idx >= 0) {
        idx = resp.indexOf(",\"", idx + 2);  // Skip the PDP type.
        if (idx >= 0) {
          int endIdx = resp.indexOf("\"", idx + 2);
          if (endIdx > idx) {
            apn = resp.substring(idx + 2, endIdx);
            if (apn.length() == 0) apn = "N/A";
          }
        }
      }
    }
    if (regStatus < 0) dataObject["registration"] = nullptr;
    else dataObject["registration"] = regStatus;
    setStringOrNull(dataObject, "operator", oper);
    if (pdpStatus < 0) dataObject["pdpActive"] = nullptr;
    else dataObject["pdpActive"] = pdpStatus == 1;
    setStringOrNull(dataObject, "apn", apn);
  }
  else if (type == "wifi") {
    // Query WiFi status.
    success = true;
    code = "ACTION_QUERY_OK";
    
    // SSID
    String ssid = WiFi.SSID();
    if (ssid.length() == 0) ssid = "N/A";
    // RSSI signal strength.
    int rssi = WiFi.RSSI();

    dataObject["wifiStatus"] = static_cast<int>(WiFi.status());
    setStringOrNull(dataObject, "ssid", ssid);
    dataObject["rssiDbm"] = rssi;
    dataObject["ip"] = WiFi.localIP().toString();
    dataObject["gateway"] = WiFi.gatewayIP().toString();
    dataObject["netmask"] = WiFi.subnetMask().toString();
    dataObject["dns"] = WiFi.dnsIP().toString();
    dataObject["mac"] = WiFi.macAddress();
    dataObject["bssid"] = WiFi.BSSIDstr();
    dataObject["channel"] = WiFi.channel();
  }

  sendActionResult(200, success, code, data, detail);
}

// Handle SMS send requests.
void handleSendSms() {
  if (!checkAuth()) return;
  if (!webJobExecuting()) {
    if (!checkCsrf()) return;
    enqueueWebJob("sms", handleSendSms, "*", "");
    return;
  }
  
  String phone = requestArg("phone");
  String content = requestArg("content");
  if (rejectInvalidOrTooLong(phone, 32, "phone") ||
      rejectInvalidOrTooLong(content, 2048, "content")) return;
  if (rejectModemBusy()) return;
  
  phone.trim();
  content.trim();
  
  bool success = false;
  const char* code = "ACTION_SMS_FAILED";
  
  if (phone.length() == 0) {
    code = "ACTION_SMS_PHONE_REQUIRED";
  } else if (content.length() == 0) {
    code = "ACTION_SMS_CONTENT_REQUIRED";
  } else {
    logCaptureLn(String("Web UI requested SMS send"));
    
    success = sendSMS(phone.c_str(), content.c_str());
    code = success ? "ACTION_SMS_SENT" : "ACTION_SMS_FAILED";
  }

  sendActionResult(200, success, code);
}

// Handle Ping requests.
void handlePing() {
  if (!checkAuth()) return;
  if (!webJobExecuting()) {
    if (!checkCsrf()) return;
    enqueueWebJob("ping", handlePing, "*", "");
    return;
  }
  if (rejectModemBusy()) return;

  String activateResponse;
  bool activated = modemSetDataActive(true, activateResponse);
  String response = activated
                      ? sendATCommandUntil("AT+MPING=\"8.8.8.8\",30,1", "+MPING:", 35000)
                      : activateResponse;

  String deactivateResponse;
  modemSetDataActive(false, deactivateResponse);

  int mping = response.indexOf("+MPING:");
  if (!activated || response.indexOf("ERROR") >= 0) {
    sendActionResult(200, false, "ACTION_PING_MODEM_ERROR", response);
    return;
  }
  if (mping < 0) {
    sendActionResult(200, false, "ACTION_PING_TIMEOUT");
    return;
  }

  String params = response.substring(mping + 7);
  int lineEnd = params.indexOf('\n');
  if (lineEnd >= 0) params = params.substring(0, lineEnd);
  params.trim();
  int firstComma = params.indexOf(',');
  int result = (firstComma < 0 ? params : params.substring(0, firstComma)).toInt();
  if (firstComma < 0 && result != 0 && result != 1) {
    sendActionResult(200, false, "ACTION_PING_UNREACHABLE", params);
    return;
  }

  JsonDocument data;
  JsonObject dataObject = data.to<JsonObject>();
  dataObject["ip"] = "8.8.8.8";
  if (firstComma >= 0) {
    String rest = params.substring(firstComma + 1);
    int ipEnd = rest.indexOf(',');
    if (ipEnd >= 0) {
      String ip = rest.substring(0, ipEnd);
      ip.replace("\"", "");
      rest = rest.substring(ipEnd + 1);
      int packetEnd = rest.indexOf(',');
      if (packetEnd >= 0) {
        rest = rest.substring(packetEnd + 1);
        int timeEnd = rest.indexOf(',');
        String latency = timeEnd < 0 ? rest : rest.substring(0, timeEnd);
        String ttl = timeEnd < 0 ? "" : rest.substring(timeEnd + 1);
        latency.trim();
        ttl.trim();
        dataObject["ip"] = ip;
        dataObject["latencyMs"] = latency.toInt();
        if (ttl.length()) dataObject["ttl"] = ttl.toInt();
        else dataObject["ttl"] = nullptr;
      }
    }
  }
  sendActionResult(200, true, "ACTION_PING_OK", data);
}

// Handle configuration save requests.
void handleSave() {
  if (!checkAuth()) return;
  if (!webJobExecuting()) {
    if (!checkCsrf()) return;
    enqueueWebJob("config-save", handleSave, "*", "");
    return;
  }

  xSemaphoreTake(configMutex, portMAX_DELAY);
  Config next = config;
  xSemaphoreGive(configMutex);
  String previousHostname = next.hostname;
  String previousSmtpServer = next.smtpServer;
  int previousSmtpPort = next.smtpPort;
  String previousSmtpUser = next.smtpUser;

  if (rejectArgInvalidOrTooLong("deviceName", MAX_DEVICE_NAME_BYTES) ||
      rejectArgInvalidOrTooLong("hostname", MAX_HOSTNAME_LENGTH) ||
      rejectArgInvalidOrTooLong("notificationLocale", MAX_NOTIFICATION_LOCALE_BYTES) ||
      rejectArgInvalidOrTooLong("smtpServer", 253) ||
      rejectArgInvalidOrTooLong("smtpPort", 32) ||
      rejectArgInvalidOrTooLong("smtpUser", 254) ||
      rejectArgInvalidOrTooLong("smtpPass", 256) ||
      rejectArgInvalidOrTooLong("smtpSendTo", 254) ||
      rejectArgInvalidOrTooLong("adminPhone", 32) ||
      rejectArgInvalidOrTooLong("numberBlackList", 1024)) return;

  for (int i = 0; i < MAX_PUSH_CHANNELS; i++) {
    String prefix = "push" + String(i);
    if (rejectArgInvalidOrTooLong(prefix + "en", 32) ||
        rejectArgInvalidOrTooLong(prefix + "type", 32) ||
        rejectArgInvalidOrTooLong(prefix + "url", 512) ||
        rejectArgInvalidOrTooLong(prefix + "name", 64) ||
        rejectArgInvalidOrTooLong(prefix + "key1", 256) ||
        rejectArgInvalidOrTooLong(prefix + "key2", 256) ||
        rejectArgInvalidOrTooLong(prefix + "title", MAX_TITLE_TEMPLATE_BYTES) ||
        rejectArgInvalidOrTooLong(prefix + "template", MAX_BODY_TEMPLATE_BYTES) ||
        rejectArgInvalidOrTooLong(prefix + "body", 2048)) return;
  }

  for (int i = 0; i < MAX_WEB_ACCOUNTS; i++) {
    String prefix = "account" + String(i);
    String userKey = prefix + "user";
    String passKey = prefix + "pass";
    if (rejectArgInvalidOrTooLong(userKey, 64) ||
        rejectArgInvalidOrTooLong(passKey, 96)) return;
    String username = requestHasArg(userKey) ? requestArg(userKey) : next.webAccounts[i].username;
    String password = requestHasArg(passKey) && requestArg(passKey).length() > 0
                        ? requestArg(passKey) : next.webAccounts[i].password;
    username.trim();
    if (username.length() == 0) password = "";
    if ((requestHasArg(userKey) || requestHasArg(passKey)) &&
        username.length() + password.length() + 1 > 180) {
      sendActionResult(400, false, "ACTION_INPUT_TOO_LONG",
                       requestHasArg(passKey) ? passKey : userKey);
      return;
    }
  }

  // Account form: a blank username disables the account; a blank password preserves it.
  for (int i = 0; i < MAX_WEB_ACCOUNTS; i++) {
    String prefix = "account" + String(i);
    String userKey = prefix + "user";
    String passKey = prefix + "pass";
    if (requestHasArg(userKey)) {
      next.webAccounts[i].username = requestArg(userKey);
      next.webAccounts[i].username.trim();
      if (next.webAccounts[i].username.length() == 0) next.webAccounts[i].password = "";
    }
    if (requestHasArg(passKey) && requestArg(passKey).length() > 0) {
      next.webAccounts[i].password = requestArg(passKey);
    }
    if (next.webAccounts[i].password.length() == 0) next.webAccounts[i].username = "";
  }
  bool hasWebAccount = false;
  for (int i = 0; i < MAX_WEB_ACCOUNTS; i++) {
    if (next.webAccounts[i].username.length() > 0 && next.webAccounts[i].password.length() > 0) {
      hasWebAccount = true;
      break;
    }
  }
  if (!hasWebAccount) {
    sendActionResult(400, false, "ACTION_CONFIG_ACCOUNT_REQUIRED");
    return;
  }

  // Email notification form: update only fields present in the request.
  if (requestHasArg("deviceName")) next.deviceName = requestArg("deviceName");
  if (requestHasArg("hostname")) next.hostname = requestArg("hostname");
  if (requestHasArg("notificationLocale")) next.notificationLocale = requestArg("notificationLocale");
  if (requestHasArg("smtpServer")) {
    next.smtpServer = requestArg("smtpServer");
  }
  if (requestHasArg("smtpPort")) {
    long smtpPort = requestArg("smtpPort").toInt();
    next.smtpPort = smtpPort > 0 && smtpPort <= 65535 ? smtpPort : 465;
  }
  if (requestHasArg("smtpUser")) {
    next.smtpUser = requestArg("smtpUser");
  }
  if (requestHasArg("smtpPass")) {
    next.smtpPass = requestArg("smtpPass");
  }
  if (requestHasArg("smtpSendTo")) {
    next.smtpSendTo = requestArg("smtpSendTo");
  }
  if (!requestHasArg("smtpPass") &&
      (next.smtpServer != previousSmtpServer || next.smtpPort != previousSmtpPort ||
       next.smtpUser != previousSmtpUser)) {
    next.smtpPass = "";
  }
  // Administrator and blacklist form: update only fields present in the request.
  if (requestHasArg("adminPhone")) {
    next.adminPhone = requestArg("adminPhone");
  }
  if (requestHasArg("numberBlackList")) {
    next.numberBlackList = requestArg("numberBlackList");
  }

  // Push channel configuration: update only when that channel's fields are present.
  for (int i = 0; i < MAX_PUSH_CHANNELS; i++) {
    String idx = String(i);
    String enKey = "push" + idx + "en";
    String typeKey = "push" + idx + "type";
    String urlKey = "push" + idx + "url";
    String nameKey = "push" + idx + "name";
    String k1Key = "push" + idx + "key1";
    String k2Key = "push" + idx + "key2";
    String titleKey = "push" + idx + "title";
    String templateKey = "push" + idx + "template";
    String bodyKey = "push" + idx + "body";
    // Update the entire channel when any of its fields are present.
    if (requestHasArg(enKey) || requestHasArg(typeKey) || requestHasArg(urlKey) ||
        requestHasArg(nameKey) || requestHasArg(k1Key) || requestHasArg(k2Key) ||
        requestHasArg(titleKey) || requestHasArg(templateKey) || requestHasArg(bodyKey)) {
      next.pushChannels[i].enabled = requestArg(enKey) == "on";
      next.pushChannels[i].type = (PushType)requestArg(typeKey).toInt();
      next.pushChannels[i].url = requestArg(urlKey);
      next.pushChannels[i].name = requestArg(nameKey);
      next.pushChannels[i].key1 = requestArg(k1Key);
      next.pushChannels[i].key2 = requestArg(k2Key);
      next.pushChannels[i].titleTemplate = requestArg(titleKey);
      next.pushChannels[i].bodyTemplate = requestArg(templateKey);
      next.pushChannels[i].customBody = requestArg(bodyKey);
      if (next.pushChannels[i].type == PUSH_TYPE_CUSTOM) {
        next.pushChannels[i].titleTemplate = "";
        next.pushChannels[i].bodyTemplate = "";
      } else {
        next.pushChannels[i].customBody = "";
      }
      if (next.pushChannels[i].name.length() == 0) {
        next.pushChannels[i].name = "Channel " + String(i + 1);
      }
    }
  }
  if (!isConfigSemanticallyValid(next)) {
    sendActionResult(400, false, "ACTION_CONFIG_INVALID");
    return;
  }
  
  if (!saveConfig(next)) {
    sendActionResult(500, false, "ACTION_CONFIG_SAVE_FAILED");
    return;
  }
  xSemaphoreTake(configMutex, portMAX_DELAY);
  config = next;
  configValid = isConfigValid();
  xSemaphoreGive(configMutex);
  
  sendActionResult(200, true, "ACTION_CONFIG_SAVED");
  
  // Send a startup notification when the configuration is valid.
  if (configValid) {
    logCaptureLn(String("Configuration valid; sending startup notification..."));
    String subject, body;
    buildSystemNotificationText(next.notificationLocale, SYSTEM_NOTIFICATION_CONFIG_UPDATED,
                                next.deviceName, getDeviceUrl(), subject, body);
    sendEmailNotification(subject.c_str(), body.c_str());
  }
  if (next.hostname != previousHostname) scheduleDeviceRestart();
}

// Handle log queries by returning the lines in the ring buffer.
void handleLog() {
  if (!checkAuth()) return;

  JsonDocument json;
  uint32_t cursor = requestArg("cursor").toInt();
  int limit = requestArg("limit").toInt();
  if (limit < 1 || limit > 50) limit = 50;
  uint32_t selectedIds[50];
  String selectedMessages[50];
  int selected = 0;
  bool hasMore = false;
  xSemaphoreTake(logMutex, portMAX_DELAY);
  int total = logBufCount;
  int start = (logBufIdx - total + LOG_BUF_SIZE) % LOG_BUF_SIZE;
  for (int i = total - 1; i >= 0; --i) {
    int pos = (start + i) % LOG_BUF_SIZE;
    if (cursor && logIds[pos] >= cursor) continue;
    if (selected >= limit) {
      hasMore = true;
      break;
    }
    selectedIds[selected] = logIds[pos];
    selectedMessages[selected] = logBuffer[pos];
    selected++;
  }
  xSemaphoreGive(logMutex);

  JsonArray entries = json["entries"].to<JsonArray>();
  for (int i = selected - 1; i >= 0; --i) {
    JsonObject entry = entries.add<JsonObject>();
    entry["id"] = selectedIds[i];
    entry["message"] = selectedMessages[i];
  }
  if (hasMore && selected) json["nextCursor"] = selectedIds[selected - 1];
  else json["nextCursor"] = nullptr;
  json["hasMore"] = hasMore;
  sendJson(200, json);
}

// Modem control commands.
void handleModem() {
  if (!checkAuth()) return;
  if (!webJobExecuting()) {
    if (!checkCsrf()) return;
    enqueueWebJob("modem", handleModem, "*", "");
    return;
  }

  if (rejectInvalidOrTooLong(requestArg("action"), 32, "action")) return;
  if (rejectModemBusy()) return;

  String action = requestArg("action");
  bool success = false;
  JsonDocument data;
  JsonObject dataObject = data.to<JsonObject>();
  String detail = "";
  const char* code = "ACTION_UNKNOWN";

  if (action == "restart") {
    // For an AT soft restart, respond before initialization to prevent browser retries.
    logCaptureLn(String("Web UI requested a modem soft restart..."));
    sendActionResult(200, true, "ACTION_MODEM_RESTARTING");
    String resp = sendATCommand("AT+CFUN=1,1", 15000);
    success = (resp.indexOf("OK") >= 0);
    logCaptureLn(String(success ? "Modem soft restart succeeded: " : "Soft restart failed: ") + resp);
    if (success) modemInit();
    return;
  }
  else if (action == "hardreset") {
    // Power-cycle through the EN pin; resetModule() calls modemInit().
    logCaptureLn(String("Web UI requested a modem hard restart..."));
    sendActionResult(200, true, "ACTION_MODEM_HARD_RESTARTING");
    resetModule();
    return;
  }
  else if (action == "signal") {
    logCaptureLn(String("Web UI queried signal strength: AT+CSQ"));
    String resp = sendATCommand("AT+CSQ", 3000);
    int csqIdx = resp.indexOf("+CSQ:");
    if (csqIdx >= 0) {
      String csqLine = resp.substring(csqIdx);
      csqLine = csqLine.substring(0, csqLine.indexOf('\n'));
      csqLine.trim();
      int commaIdx = csqLine.indexOf(',');
      if (commaIdx >= 0) {
        int rssi = csqLine.substring(csqLine.indexOf(':') + 1, commaIdx).toInt();
        int ber = csqLine.substring(commaIdx + 1).toInt();
        if (rssi == 99) dataObject["signalDbm"] = nullptr;
        else dataObject["signalDbm"] = -113 + rssi * 2;
        dataObject["rssi"] = rssi;
        dataObject["ber"] = ber;
        success = true;
        code = "ACTION_MODEM_OK";
      }
    }
    if (!success) {
      code = "ACTION_MODEM_FAILED";
      detail = resp;
    }
  }
  else if (action == "operator") {
    logCaptureLn(String("Web UI queried the network operator: AT+COPS?"));
    String resp = sendATCommand("AT+COPS?", 5000);
    int copsIdx = resp.indexOf("+COPS:");
    if (copsIdx >= 0) {
      String copsLine = resp.substring(copsIdx);
      copsLine = copsLine.substring(0, copsLine.indexOf('\n'));
      copsLine.trim();
      int q1 = copsLine.indexOf('"');
      int q2 = copsLine.indexOf('"', q1 + 1);
      if (q1 >= 0 && q2 >= 0) {
        dataObject["operator"] = copsLine.substring(q1 + 1, q2);
        success = true;
        code = "ACTION_MODEM_OK";
      } else {
        dataObject["operator"] = copsLine;
        success = true;
        code = "ACTION_MODEM_OK";
      }
    }
    if (!success) {
      code = "ACTION_MODEM_FAILED";
      detail = resp;
    }
  }
  else if (action == "imei") {
    logCaptureLn(String("Web UI queried the IMEI: AT+GSN"));
    String resp = sendATCommand("AT+GSN", 3000);
    resp.trim();
    int okIdx = resp.lastIndexOf("OK");
    if (okIdx > 0) resp = resp.substring(0, okIdx);
    int gsnIdx = resp.indexOf("AT+GSN");
    if (gsnIdx >= 0) resp = resp.substring(gsnIdx + 6);
    resp.trim();
    if (resp.length() > 0) {
      dataObject["imei"] = resp;
      success = true;
      code = "ACTION_MODEM_OK";
    } else {
      code = "ACTION_MODEM_FAILED";
    }
  }
  else {
    detail = action;
  }

  sendActionResult(200, success, code, data, detail);
}

// WiFi restart.
void handleWifi() {
  if (!checkAuth()) return;
  if (!webJobExecuting()) {
    if (!checkCsrf()) return;
    enqueueWebJob("wifi", handleWifi, "*", "");
    return;
  }

  if (rejectInvalidOrTooLong(requestArg("action"), 32, "action")) return;

  String action = requestArg("action");
  if (action == "restart") {
    logCaptureLn(String("Web UI requested a WiFi restart..."));
    sendActionResult(200, true, "ACTION_WIFI_RESTARTING");
    delay(500);
    WiFi.disconnect(true);
    WiFi.setSleep(false);
    WiFi.setAutoReconnect(true);
    WiFi.setScanMethod(WIFI_FAST_SCAN);
    WiFi.begin(WIFI_SSID, WIFI_PASS);
    logCaptureLn(String("Reconnecting to WiFi: " + String(WIFI_SSID)));
    unsigned long start = millis();
    while (WiFi.status() != WL_CONNECTED && millis() - start < 15000) {
      delay(50);
    }
    if (WiFi.status() == WL_CONNECTED) {
      logCaptureLn(String("WiFi reconnected, IP: " + WiFi.localIP().toString()));
    } else {
      logCaptureLn(String("WiFi reconnection failed; retrying in the background"));
    }
  } else {
    sendActionResult(200, false, "ACTION_UNKNOWN");
  }
}
