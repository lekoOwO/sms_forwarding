#include "globals.h"
#include <esp_ota_ops.h>
#include "wifi_config.h"
#include "config.h"
#include "config_backup.h"
#include "web_handlers.h"
#include "modem.h"
#include "notification_locale.h"
#include "ota_update.h"
#include "push.h"
#include "sms_process.h"

static volatile bool managementHttpEnabled = false;

extern "C" bool verifyRollbackLater() {
  return true;
}

void setup() {
  pinMode(LED_BUILTIN, OUTPUT);
  digitalWrite(LED_BUILTIN, HIGH);
  Serial.begin(115200);
  initWebRuntime();
  initConfigBackup();
  initOtaUpdate();
  // Keep startup delay short; the WiFi connection has its own timeout.
  delay(200);
  Serial1.begin(115200, SERIAL_8N1, RXD, TXD);
  Serial1.setRxBufferSize(SERIAL_BUFFER_SIZE);
  modemDrainInput();
  modemPowerCycle();
  modemDrainInput();
  initConcatBuffer();
  ConfigLoadStatus configLoadStatus = loadConfig();
  bool configStorageAvailable = configLoadStatus != CONFIG_LOAD_STORAGE_ERROR;
  configValid = configStorageAvailable && isConfigValid();

  // ---- WiFi connection tuning ----
  WiFi.mode(WIFI_STA);
  if (!WiFi.setHostname(config.hostname.c_str())) {
    logCaptureLn("Failed to apply WiFi hostname");
  }
  WiFi.setSleep(false);                    // Disable modem sleep for faster connection response.
  WiFi.setAutoReconnect(true);             // Reconnect automatically after disconnection.
  // Use a fast scan instead of scanning every channel, which waits too long on empty channels.
  // ESP32 remembers the channel after the first successful connection for faster startup.
  WiFi.setScanMethod(WIFI_FAST_SCAN);
  WiFi.setSortMethod(WIFI_CONNECT_AP_BY_SIGNAL);
  WiFi.begin(WIFI_SSID, WIFI_PASS);
  logCaptureLn(String("Connecting to WiFi: ") + String(WIFI_SSID));

  // Wait for the connection with a timeout; restart and retry on failure.
  unsigned long wifiStart = millis();
  const unsigned long WIFI_TIMEOUT = 20000; // 20-second timeout.
  while (WiFi.status() != WL_CONNECTED && millis() - wifiStart < WIFI_TIMEOUT) {
    blink_short(200);
  }

  if (WiFi.status() == WL_CONNECTED) {
    logCaptureLn(String("WiFi connected"));
    logCapture(String("IP address: "));
    logCaptureLn(WiFi.localIP().toString());
    logCapture(String("Signal strength (RSSI): "));
    logCaptureLn(String(WiFi.RSSI()) + " dBm");
  } else {
    logCaptureLn(String("⚠️ WiFi connection timed out; restarting to retry..."));
    delay(1000);
    ESP.restart();
  }

  if (configStorageAvailable) {
    const char* collectedHeaders[] = {"X-CSRF-Token"};
    server.collectHeaders(collectedHeaders, 1);
    server.on("/", handleRoot);
    server.on("/api/config", handleConfig);
    server.on("/api/config/export", HTTP_POST, handleConfigExportStart);
    server.on("/api/config/export", HTTP_GET, handleConfigExportDownload);
    server.on("/api/config/restore/start", HTTP_POST, handleConfigRestoreStart);
    server.on("/api/config/restore/chunk", HTTP_POST, handleConfigRestoreChunk);
    server.on("/api/config/restore/finish", HTTP_POST, handleConfigRestoreFinish);
    server.on("/api/jobs", HTTP_GET, handleJob);
    server.on("/api/ota/start", HTTP_POST, handleOtaStart);
    server.on("/api/ota/chunk", HTTP_POST, handleOtaChunk);
    server.on("/api/ota/finish", HTTP_POST, handleOtaFinish);
    server.on("/save", HTTP_POST, handleSave);
    server.on("/tools", handleRoot);
    server.on("/sms", handleRoot);
    server.on("/sendsms", HTTP_POST, handleSendSms);
    server.on("/ping", HTTP_POST, handlePing);
    server.on("/query", handleQuery);
    server.on("/flight", handleFlightMode);
    server.on("/at", handleATCommand);
    server.on("/log", handleLog);
    server.on("/modem", handleModem);
    server.on("/wifi", handleWifi);
    server.begin();
    managementHttpEnabled = startManagementHttpTask();
    logCaptureLn(managementHttpEnabled ? "HTTP server started" : "HTTP task failed to start");
  } else {
    logCaptureLn("Configuration storage failure: management HTTP disabled; recover via USB");
  }

  // ---- NTP time synchronization ----
  logCaptureLn(String("Synchronizing NTP time..."));
  configTime(0, 0, "ntp.ntsc.ac.cn", "ntp.aliyun.com", "pool.ntp.org");
  int ntpRetry = 0;
  while (time(nullptr) < 100000 && ntpRetry < 100) {
    delay(1);
    ntpRetry++;
  }
  if (time(nullptr) >= 100000) {
    timeSynced = true;
    logCaptureLn(String("NTP time synchronized"));
    time_t now = time(nullptr);
    logCapture(String("Current UTC timestamp: "));
    logCaptureLn(String(now));
  } else {
    logCaptureLn(String("NTP time synchronization failed; signed notifications paused until time is valid"));
  }

  ssl_client.setInsecure();
  digitalWrite(LED_BUILTIN, LOW);

  // ---- Startup notification (the web UI is ready before email is sent) ----
  if (configValid) {
    logCaptureLn(String("Configuration valid; sending startup notification..."));
    String subject, body;
    buildSystemNotificationText(config.notificationLocale, SYSTEM_NOTIFICATION_STARTED,
                                config.deviceName, getDeviceUrl(), subject, body);
    sendEmailNotification(subject.c_str(), body.c_str());
  }

  // ---- Modem initialization (slow, but the web UI is already available) ----
  modemInit();
  otaConfirmHealthy(configStorageAvailable && WiFi.status() == WL_CONNECTED && managementHttpEnabled);
}

void loop() {
  processWebJobs();
  otaTick();
  configBackupTick();
  if (managementHttpEnabled && !configValid) {
    if (millis() - lastPrintTime >= 1000) {
      lastPrintTime = millis();
      logCaptureLn(String("⚠️ Visit " + getDeviceUrl() + " to configure system settings"));
    }
  }
  checkConcatTimeout();
#if ENABLE_MODEM_USB_RAW_BRIDGE
  if (!modemIsBusy() && Serial.available()) Serial1.write(Serial.read());
#endif
  modemPoll();
  checkSerial1URC();
}
