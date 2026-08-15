#include "web_handlers.h"
#include <ArduinoJson.h>
#include <LittleFS.h>
#include "config.h"
#include "modem.h"
#include "push.h"
#include "utf8_validation.h"
#include "wifi_config.h"

// ---- Log ring buffer ----
String logBuffer[LOG_BUF_SIZE];
int logBufIdx = 0;
int logBufCount = 0;
static String _logLine;  // logCapture writes here; logCaptureLn commits the complete line.

static void _serialWrite(const char* msg, size_t length, bool newline = false) {
  size_t required = length + (newline ? 2 : 0);
  if ((size_t)Serial.availableForWrite() < required) return;
  Serial.write((const uint8_t*)msg, length);
  if (newline) Serial.write((const uint8_t*)"\r\n", 2);
}

static void _logAppend(const String& line) {
  logBuffer[logBufIdx] = line;
  logBufIdx = (logBufIdx + 1) % LOG_BUF_SIZE;
  if (logBufCount < LOG_BUF_SIZE) logBufCount++;
}

static void _logCommit() {
  if (_logLine.length() > 0) {
    _logAppend(_logLine);
    _logLine = "";
  }
}

static void _logAppendFragment(const String& msg) {
  if (_logLine.length() >= LOG_LINE_MAX_LENGTH) return;
  _logLine += msg.substring(0, LOG_LINE_MAX_LENGTH - _logLine.length());
}

static void _logAppendFragment(const char* msg) {
  if (_logLine.length() >= LOG_LINE_MAX_LENGTH) return;
  _logLine.concat(msg, LOG_LINE_MAX_LENGTH - _logLine.length());
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
    _logLine.trim();  // Remove trailing whitespace and any extra \n.
    _logCommit();
  }
}

void logCaptureLn(const String& msg) {
  _serialWrite(msg.c_str(), msg.length(), true);
  _logAppendFragment(msg);
  _logCommit();
}

void logCaptureLn(const char* msg) {
  _serialWrite(msg, strlen(msg), true);
  _logAppendFragment(msg);
  _logCommit();
}

// Check HTTP Basic authentication.
bool checkAuth() {
  for (int i = 0; i < MAX_WEB_ACCOUNTS; i++) {
    const WebAccount& account = config.webAccounts[i];
    if (account.username.length() > 0 && account.password.length() > 0 &&
        server.authenticate(account.username.c_str(), account.password.c_str())) return true;
  }
  server.requestAuthentication(BASIC_AUTH, "SMS Forwarding", "Enter the administrator username and password");
  return false;
}

static const size_t JSON_RESPONSE_MAX_LENGTH = 128 * 1024;

static void sendJsonFailure() {
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
  server.sendHeader("Cache-Control", "no-store");
  server.send(status, "application/json", json);
}

static void sendActionResult(int status, bool success, const char* code,
                             const String& detail = "") {
  JsonDocument response;
  response["success"] = success;
  response["code"] = code;
  response["data"].to<JsonObject>();
  response["detail"] = detail;
  sendJson(status, response);
}

static void sendActionResult(int status, bool success, const char* code,
                             JsonDocument& data, const String& detail = "") {
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
  return server.hasArg(field) && rejectInvalidOrTooLong(server.arg(field), maxBytes, field);
}

static bool rejectModemBusy() {
  if (!modemIsBusy()) return false;
  sendActionResult(429, false, "ACTION_MODEM_BUSY");
  return true;
}

// Serve the frontend build from LittleFS.
void handleRoot() {
  if (!checkAuth()) return;
  server.sendHeader("Content-Security-Policy", "frame-ancestors 'none'");
  server.sendHeader("X-Frame-Options", "DENY");
  server.sendHeader("Cache-Control", "no-store");
  File file = LittleFS.open("/index.html.gz", "r");
  if (!file) {
    server.send(503, "text/plain; charset=utf-8", "Web bundle missing. Build and upload LittleFS.");
    return;
  }
  server.sendHeader("Vary", "Accept-Encoding");
  server.streamFile(file, "text/html; charset=utf-8");
  file.close();
}

// Return the status and configuration needed to initialize the frontend. Passwords are omitted.
void handleConfig() {
  if (!checkAuth()) return;

  bool emailOk = config.smtpServer.length() > 0 && config.smtpUser.length() > 0 &&
                 config.smtpPass.length() > 0 && config.smtpSendTo.length() > 0;
  int pushCount = 0;
  for (int i = 0; i < MAX_PUSH_CHANNELS; i++) {
    if (config.pushChannels[i].enabled) pushCount++;
  }

  JsonDocument json;
  JsonObject status = json["status"].to<JsonObject>();
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
    channelJson["customBody"] = channel.customBody;
  }
  sendJson(200, json);
}

// Handle flight mode control requests.
void handleFlightMode() {
  if (!checkAuth()) return;
  
  String action = server.arg("action");
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
  
  String cmd = server.arg("cmd");
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
  
  String type = server.arg("type");
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
  
  String phone = server.arg("phone");
  String content = server.arg("content");
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

  Config next = config;
  String previousSmtpServer = next.smtpServer;
  int previousSmtpPort = next.smtpPort;
  String previousSmtpUser = next.smtpUser;

  if (rejectArgInvalidOrTooLong("smtpServer", 253) ||
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
        rejectArgInvalidOrTooLong(prefix + "body", 2048)) return;
  }

  for (int i = 0; i < MAX_WEB_ACCOUNTS; i++) {
    String prefix = "account" + String(i);
    String userKey = prefix + "user";
    String passKey = prefix + "pass";
    if (rejectArgInvalidOrTooLong(userKey, 64) ||
        rejectArgInvalidOrTooLong(passKey, 96)) return;
    String username = server.hasArg(userKey) ? server.arg(userKey) : next.webAccounts[i].username;
    String password = server.hasArg(passKey) && server.arg(passKey).length() > 0
                        ? server.arg(passKey) : next.webAccounts[i].password;
    username.trim();
    if (username.length() == 0) password = "";
    if ((server.hasArg(userKey) || server.hasArg(passKey)) &&
        username.length() + password.length() + 1 > 180) {
      sendActionResult(400, false, "ACTION_INPUT_TOO_LONG",
                       server.hasArg(passKey) ? passKey : userKey);
      return;
    }
  }

  // Account form: a blank username disables the account; a blank password preserves it.
  for (int i = 0; i < MAX_WEB_ACCOUNTS; i++) {
    String prefix = "account" + String(i);
    String userKey = prefix + "user";
    String passKey = prefix + "pass";
    if (server.hasArg(userKey)) {
      next.webAccounts[i].username = server.arg(userKey);
      next.webAccounts[i].username.trim();
      if (next.webAccounts[i].username.length() == 0) next.webAccounts[i].password = "";
    }
    if (server.hasArg(passKey) && server.arg(passKey).length() > 0) {
      next.webAccounts[i].password = server.arg(passKey);
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
  if (server.hasArg("smtpServer")) {
    next.smtpServer = server.arg("smtpServer");
  }
  if (server.hasArg("smtpPort")) {
    long smtpPort = server.arg("smtpPort").toInt();
    next.smtpPort = smtpPort > 0 && smtpPort <= 65535 ? smtpPort : 465;
  }
  if (server.hasArg("smtpUser")) {
    next.smtpUser = server.arg("smtpUser");
  }
  if (server.hasArg("smtpPass")) {
    next.smtpPass = server.arg("smtpPass");
  }
  if (server.hasArg("smtpSendTo")) {
    next.smtpSendTo = server.arg("smtpSendTo");
  }
  if (!server.hasArg("smtpPass") &&
      (next.smtpServer != previousSmtpServer || next.smtpPort != previousSmtpPort ||
       next.smtpUser != previousSmtpUser)) {
    next.smtpPass = "";
  }
  // Administrator and blacklist form: update only fields present in the request.
  if (server.hasArg("adminPhone")) {
    next.adminPhone = server.arg("adminPhone");
  }
  if (server.hasArg("numberBlackList")) {
    next.numberBlackList = server.arg("numberBlackList");
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
    String bodyKey = "push" + idx + "body";
    // Update the entire channel when any of its fields are present.
    if (server.hasArg(enKey) || server.hasArg(typeKey) || server.hasArg(urlKey) ||
        server.hasArg(nameKey) || server.hasArg(k1Key) || server.hasArg(k2Key) ||
        server.hasArg(bodyKey)) {
      next.pushChannels[i].enabled = server.arg(enKey) == "on";
      next.pushChannels[i].type = (PushType)server.arg(typeKey).toInt();
      next.pushChannels[i].url = server.arg(urlKey);
      next.pushChannels[i].name = server.arg(nameKey);
      next.pushChannels[i].key1 = server.arg(k1Key);
      next.pushChannels[i].key2 = server.arg(k2Key);
      next.pushChannels[i].customBody = server.arg(bodyKey);
      if (next.pushChannels[i].name.length() == 0) {
        next.pushChannels[i].name = "Channel " + String(i + 1);
      }
    }
  }
  
  if (!saveConfig(next)) {
    sendActionResult(500, false, "ACTION_CONFIG_SAVE_FAILED");
    return;
  }
  config = next;
  configValid = isConfigValid();
  
  sendActionResult(200, true, "ACTION_CONFIG_SAVED");
  
  // Send a startup notification when the configuration is valid.
  if (configValid) {
    logCaptureLn(String("Configuration valid; sending startup notification..."));
    String subject = "SMS Forwarder Configuration Updated";
    String body = "Device configuration updated\nDevice URL: " + getDeviceUrl();
    sendEmailNotification(subject.c_str(), body.c_str());
  }
}

// Handle log queries by returning the lines in the ring buffer.
void handleLog() {
  if (!checkAuth()) return;

  JsonDocument json;
  JsonArray lines = json.to<JsonArray>();
  int total = logBufCount;
  int start = total < LOG_BUF_SIZE ? 0 : logBufIdx;
  for (int i = 0; i < total; i++) {
    int pos = (start + i) % LOG_BUF_SIZE;
    lines.add(JsonString(logBuffer[pos].c_str(), logBuffer[pos].length(), true));
  }
  sendJson(200, json);
}

// Modem control commands.
void handleModem() {
  if (!checkAuth()) return;

  if (rejectInvalidOrTooLong(server.arg("action"), 32, "action")) return;
  if (rejectModemBusy()) return;

  String action = server.arg("action");
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

  if (rejectInvalidOrTooLong(server.arg("action"), 32, "action")) return;

  String action = server.arg("action");
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
