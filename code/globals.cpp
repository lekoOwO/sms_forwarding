#include "globals.h"

#include "web_handlers.h"
#include "wifi_config.h"

Config config;
Preferences preferences;
PDU pdu = PDU(4096);
WiFiClientSecure ssl_client;
SMTPClient smtp(ssl_client);
WebServer server(80);
bool configValid = false;
bool timeSynced = false;
bool modemReady = false;
unsigned long lastPrintTime = 0;
ConcatSms concatBuffer[MAX_CONCAT_MESSAGES];
static bool apActive = false;
static String apSsid;

static bool tryWifiProfile(const String& ssid, const String& password, uint32_t timeoutMs) {
  WiFi.disconnect(false, false);
  WiFi.setMinSecurity(password.length() > 0 ? WIFI_AUTH_WPA2_PSK : WIFI_AUTH_OPEN);
  WiFi.begin(ssid.c_str(), password.length() > 0 ? password.c_str() : nullptr);
  uint32_t started = millis();
  while (WiFi.status() != WL_CONNECTED && millis() - started < timeoutMs) {
    delay(50);
  }
  return WiFi.status() == WL_CONNECTED;
}

bool connectWifi(uint32_t timeoutMs) {
  WiFi.disconnect(false, false);
  WiFi.mode(apActive ? WIFI_AP_STA : WIFI_STA);
  if (!WiFi.setHostname(config.hostname.c_str())) logCaptureLn("Failed to apply WiFi hostname");
  WiFi.setSleep(false);
  WiFi.setAutoReconnect(true);
  WiFi.setScanMethod(WIFI_FAST_SCAN);
  WiFi.setSortMethod(WIFI_CONNECT_AP_BY_SIGNAL);

  int configuredCount = 0;
  for (int i = 0; i < MAX_WIFI_PROFILES; ++i) {
    if (config.wifiProfiles[i].ssid.length() > 0) configuredCount++;
  }

  uint32_t started = millis();
  if (configuredCount > 0) {
    logCaptureF("Connecting to %d configured WiFi profile(s)\n", configuredCount);
    int attempted = 0;
    for (int i = 0; i < MAX_WIFI_PROFILES; ++i) {
      const WifiProfile& profile = config.wifiProfiles[i];
      if (profile.ssid.length() == 0) continue;
      uint32_t elapsed = millis() - started;
      if (elapsed >= timeoutMs) break;
      uint32_t attemptTimeout = (timeoutMs - elapsed) / (configuredCount - attempted + 1);
      attempted++;
      if (tryWifiProfile(profile.ssid, profile.password, attemptTimeout)) {
        networkTick();
        return true;
      }
    }
  }

  logCaptureLn("Trying compiled WiFi fallback");
  uint32_t elapsed = millis() - started;
  bool connected = elapsed < timeoutMs &&
                   tryWifiProfile(WIFI_SSID, WIFI_PASS, timeoutMs - elapsed);
  if (connected) networkTick();
  return connected;
}

bool startProvisioningAp() {
  uint32_t suffix = static_cast<uint32_t>(ESP.getEfuseMac()) & 0xFFFFFFU;
  char suffixText[7];
  snprintf(suffixText, sizeof(suffixText), "%06lx", static_cast<unsigned long>(suffix));
  apSsid = "sms-forwarder-" + String(suffixText);
  WiFi.mode(WIFI_AP_STA);
  apActive = WiFi.softAP(apSsid.c_str(), "sms-forwarder-setup");
  if (apActive) {
    Serial.printf("Provisioning AP: %s\nPassword: sms-forwarder-setup\nIP: %s\n",
                  apSsid.c_str(), WiFi.softAPIP().toString().c_str());
  }
  return apActive;
}

void networkTick() {
  if (apActive && WiFi.status() == WL_CONNECTED) {
    WiFi.softAPdisconnect(true);
    apActive = false;
    WiFi.mode(WIFI_STA);
    logCaptureLn("WiFi connected in the background; provisioning AP stopped");
  }
}

bool provisioningApActive() {
  return apActive;
}

bool networkAccessReady() {
  return WiFi.status() == WL_CONNECTED || apActive;
}

String activeNetworkIp() {
  return (WiFi.status() == WL_CONNECTED ? WiFi.localIP() : WiFi.softAPIP()).toString();
}

String activeNetworkSsid() {
  return WiFi.status() == WL_CONNECTED ? WiFi.SSID() : apSsid;
}
