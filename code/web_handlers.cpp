#include "web_handlers.h"
#include <LittleFS.h>
#include "config.h"
#include "modem.h"
#include "push.h"
#include "wifi_config.h"

// ---- 日志环形缓冲区 ----
String logBuffer[LOG_BUF_SIZE];
int logBufIdx = 0;
int logBufCount = 0;
static String _logLine;  // 行缓冲：logCapture 写入这里，logCaptureLn 提交整行

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
  Serial.print(msg);
  _logAppendFragment(msg);
}

void logCapture(const char* msg) {
  Serial.print(msg);
  _logAppendFragment(msg);
}

void logCaptureF(const char* fmt, ...) {
  char buf[256];
  va_list args;
  va_start(args, fmt);
  vsnprintf(buf, sizeof(buf), fmt, args);
  va_end(args);
  Serial.print(buf);
  _logAppendFragment(buf);
  // 如果格式化字符串以 \n 结尾，则提交此行
  size_t len = strlen(buf);
  if (len > 0 && buf[len - 1] == '\n') {
    _logLine.trim();  // 去掉尾部空格和可能多余的 \n
    _logCommit();
  }
}

void logCaptureLn(const String& msg) {
  Serial.println(msg);
  _logAppendFragment(msg);
  _logCommit();
}

void logCaptureLn(const char* msg) {
  Serial.println(msg);
  _logAppendFragment(msg);
  _logCommit();
}

// 检查HTTP Basic认证
bool checkAuth() {
  for (int i = 0; i < MAX_WEB_ACCOUNTS; i++) {
    const WebAccount& account = config.webAccounts[i];
    if (account.username.length() > 0 && account.password.length() > 0 &&
        server.authenticate(account.username.c_str(), account.password.c_str())) return true;
  }
  server.requestAuthentication(BASIC_AUTH, "SMS Forwarding", "请输入管理员账号密码");
  return false;
}

static String jsonStringOrNull(const String& value) {
  return value == "N/A" ? "null" : "\"" + jsonEscape(value) + "\"";
}

static void sendActionResult(int status, bool success, const char* code,
                             const String& data = "{}", const String& detail = "") {
  String json = "{\"success\":" + String(success ? "true" : "false") +
                ",\"code\":\"" + code + "\",\"data\":" + data +
                ",\"detail\":\"" + jsonEscape(detail) + "\"}";
  server.sendHeader("Cache-Control", "no-store");
  server.send(status, "application/json", json);
}

// 从 LittleFS 提供前端构建产物
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
  server.sendHeader("Content-Encoding", "gzip");
  server.sendHeader("Vary", "Accept-Encoding");
  server.streamFile(file, "text/html; charset=utf-8");
  file.close();
}

// 前端初始化所需的状态与配置。密码内容不返回。
void handleConfig() {
  if (!checkAuth()) return;

  bool emailOk = config.smtpServer.length() > 0 && config.smtpUser.length() > 0 &&
                 config.smtpPass.length() > 0 && config.smtpSendTo.length() > 0;
  int pushCount = 0;
  for (int i = 0; i < MAX_PUSH_CHANNELS; i++) {
    if (config.pushChannels[i].enabled) pushCount++;
  }

  String json;
  json.reserve(3072);
  json += "{\"status\":{";
  json += "\"ip\":\"" + jsonEscape(WiFi.localIP().toString()) + "\",";
  json += "\"wifiSsid\":\"" + jsonEscape(WiFi.SSID()) + "\",";
  json += "\"freeHeapKb\":" + String(ESP.getFreeHeap() / 1024) + ",";
  json += "\"uptimeSeconds\":" + String(millis() / 1000) + ",";
  json += "\"modemReady\":" + String(modemReady ? "true" : "false") + ",";
  json += "\"emailConfigured\":" + String(emailOk ? "true" : "false") + ",";
  json += "\"enabledPushChannels\":" + String(pushCount) + "},";
  json += "\"config\":{";
  json += "\"webAccounts\":[";
  for (int i = 0; i < MAX_WEB_ACCOUNTS; i++) {
    if (i > 0) json += ",";
    json += "{\"username\":\"" + jsonEscape(config.webAccounts[i].username) + "\",\"password\":\"\"}";
  }
  json += "],";
  json += "\"smtpServer\":\"" + jsonEscape(config.smtpServer) + "\",";
  json += "\"smtpPort\":" + String(config.smtpPort) + ",";
  json += "\"smtpUser\":\"" + jsonEscape(config.smtpUser) + "\",";
  json += "\"smtpPass\":\"\",";
  json += "\"smtpSendTo\":\"" + jsonEscape(config.smtpSendTo) + "\",";
  json += "\"adminPhone\":\"" + jsonEscape(config.adminPhone) + "\",";
  json += "\"numberBlackList\":\"" + jsonEscape(config.numberBlackList) + "\",";
  json += "\"pushChannels\":[";
  for (int i = 0; i < MAX_PUSH_CHANNELS; i++) {
    if (i > 0) json += ",";
    const PushChannel& channel = config.pushChannels[i];
    json += "{\"enabled\":" + String(channel.enabled ? "true" : "false") + ",";
    json += "\"type\":" + String((int)channel.type) + ",";
    json += "\"name\":\"" + jsonEscape(channel.name) + "\",";
    json += "\"url\":\"" + jsonEscape(channel.url) + "\",";
    json += "\"key1\":\"" + jsonEscape(channel.key1) + "\",";
    json += "\"key2\":\"" + jsonEscape(channel.key2) + "\",";
    json += "\"customBody\":\"" + jsonEscape(channel.customBody) + "\"}";
  }
  json += "]}}";
  server.sendHeader("Cache-Control", "no-store");
  server.send(200, "application/json", json);
}

// 处理飞行模式控制请求
void handleFlightMode() {
  if (!checkAuth()) return;
  
  String action = server.arg("action");
  bool success = false;
  String data = "{}";
  String detail = "";
  const char* code = "ACTION_UNKNOWN";
  
  if (action == "query") {
    // 查询当前功能模式
    logCaptureLn(String("网页端查询飞行模式: AT+CFUN?"));
    String resp = sendATCommand("AT+CFUN?", 2000);
    logCaptureLn(String("CFUN查询响应: " + resp));
    
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
      data = "{\"mode\":" + String(mode) + "}";
    } else {
      code = "ACTION_FLIGHT_FAILED";
      detail = resp;
    }
  }
  else if (action == "toggle") {
    // 先查询当前状态
    String resp = sendATCommand("AT+CFUN?", 2000);
    logCaptureLn(String("CFUN查询响应: " + resp));
    
    if (resp.indexOf("+CFUN:") >= 0) {
      int idx = resp.indexOf("+CFUN:");
      int currentMode = resp.substring(idx + 6).toInt();
      
      // 切换模式：1(正常) <-> 4(飞行模式)
      int newMode = (currentMode == 1) ? 4 : 1;
      String cmd = "AT+CFUN=" + String(newMode);
      
      logCaptureLn(String("切换飞行模式: " + cmd));
      String setResp = sendATCommand(cmd.c_str(), 5000);
      logCaptureLn(String("CFUN设置响应: " + setResp));
      
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
    // 强制开启飞行模式
    logCaptureLn(String("网页端强制开启飞行模式: AT+CFUN=4"));
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
    // 强制关闭飞行模式
    logCaptureLn(String("网页端关闭飞行模式: AT+CFUN=1"));
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

// 处理AT指令测试请求
void handleATCommand() {
  if (!checkAuth()) return;
  
  String cmd = server.arg("cmd");
  bool success = false;
  String data = "{}";
  const char* code = "ACTION_AT_REQUIRED";
  
  if (cmd.length() == 0) {
  } else {
    logCaptureLn(String("网页端发送AT指令: " + cmd));
    String resp = sendATCommand(cmd.c_str(), 5000);
    logCaptureLn(String("模组响应: " + resp));
    
    if (resp.length() > 0) {
      success = true;
      code = "ACTION_AT_OK";
      data = "{\"raw\":\"" + jsonEscape(resp) + "\"}";
    } else {
      code = "ACTION_AT_TIMEOUT";
    }
  }

  sendActionResult(200, success, code, data);
}

// 处理模组信息查询请求
void handleQuery() {
  if (!checkAuth()) return;
  
  String type = server.arg("type");
  bool success = false;
  String data = "{}";
  String detail = "";
  const char* code = "ACTION_QUERY_UNKNOWN";
  
  if (type == "ati") {
    // 固件信息查询
    String resp = sendATCommand("ATI", 2000);
    logCaptureLn(String("ATI响应: " + resp));
    
    if (resp.indexOf("OK") >= 0) {
      success = true;
      code = "ACTION_QUERY_OK";
      // 解析ATI响应
      String manufacturer = "N/A";
      String model = "N/A";
      String version = "N/A";
      
      // 按行解析
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
      
      data = "{\"manufacturer\":" + jsonStringOrNull(manufacturer) +
             ",\"model\":" + jsonStringOrNull(model) +
             ",\"revision\":" + jsonStringOrNull(version) + "}";
    } else {
      code = "ACTION_QUERY_FAILED";
      detail = resp;
    }
  }
  else if (type == "signal") {
    // 信号质量查询
    String resp = sendATCommand("AT+CESQ", 2000);
    logCaptureLn(String("CESQ响应: " + resp));
    
    if (resp.indexOf("+CESQ:") >= 0) {
      success = true;
      code = "ACTION_QUERY_OK";
      // 解析 +CESQ: <rxlev>,<ber>,<rscp>,<ecno>,<rsrq>,<rsrp>
      int idx = resp.indexOf("+CESQ:");
      String params = resp.substring(idx + 6);
      int endIdx = params.indexOf('\r');
      if (endIdx < 0) endIdx = params.indexOf('\n');
      if (endIdx > 0) params = params.substring(0, endIdx);
      params.trim();
      
      // 分割参数
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
      
      // RSRP转换为dBm (0-97映射到-140到-44 dBm, 99表示未知)
      int rsrp = values[5].toInt();
      String rsrpValue;
      if (rsrp == 99 || rsrp == 255) {
        rsrpValue = "null";
      } else {
        rsrpValue = String(-140 + rsrp);
      }
      
      // RSRQ转换 (0-34映射到-19.5到-3 dB)
      int rsrq = values[4].toInt();
      String rsrqValue;
      if (rsrq == 99 || rsrq == 255) {
        rsrqValue = "null";
      } else {
        rsrqValue = String(-19.5 + rsrq * 0.5, 1);
      }
      
      data = "{\"rsrpDbm\":" + rsrpValue + ",\"rsrqDb\":" + rsrqValue +
             ",\"cesq\":\"" + jsonEscape(params) + "\"}";
    } else {
      code = "ACTION_QUERY_FAILED";
      detail = resp;
    }
  }
  else if (type == "siminfo") {
    // SIM卡信息查询
    success = true;
    code = "ACTION_QUERY_OK";
    
    // 查询IMSI
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
    // 查询ICCID
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
    // 查询本机号码 (如果SIM卡支持)
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
    data = "{\"imsi\":" + jsonStringOrNull(imsi) +
           ",\"iccid\":" + jsonStringOrNull(iccid) +
           ",\"msisdn\":" + jsonStringOrNull(phoneNum) + "}";
  }
  else if (type == "network") {
    // 网络状态查询
    success = true;
    code = "ACTION_QUERY_OK";
    
    // 查询网络注册状态
    String resp = sendATCommand("AT+CEREG?", 2000);
    String regStatus = "N/A";
    if (resp.indexOf("+CEREG:") >= 0) {
      int idx = resp.indexOf("+CEREG:");
      String tmp = resp.substring(idx + 7);
      int commaIdx = tmp.indexOf(',');
      if (commaIdx >= 0) {
        String stat = tmp.substring(commaIdx + 1, commaIdx + 2);
        regStatus = stat;
      }
    }
    // 查询运营商
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
    // 查询PDP上下文激活状态
    resp = sendATCommand("AT+CGACT?", 2000);
    String pdpStatus = "0";
    if (resp.indexOf("+CGACT: 1,1") >= 0) {
      pdpStatus = "1";
    }
    // 查询APN
    resp = sendATCommand("AT+CGDCONT?", 2000);
    String apn = "N/A";
    if (resp.indexOf("+CGDCONT:") >= 0) {
      int idx = resp.indexOf(",\"");
      if (idx >= 0) {
        idx = resp.indexOf(",\"", idx + 2);  // 跳过PDP类型
        if (idx >= 0) {
          int endIdx = resp.indexOf("\"", idx + 2);
          if (endIdx > idx) {
            apn = resp.substring(idx + 2, endIdx);
            if (apn.length() == 0) apn = "N/A";
          }
        }
      }
    }
    data = "{\"registration\":" + (regStatus == "N/A" ? String("null") : String(regStatus.toInt())) +
           ",\"operator\":" + jsonStringOrNull(oper) +
           ",\"pdpActive\":" + String(pdpStatus == "1" ? "true" : "false") +
           ",\"apn\":" + jsonStringOrNull(apn) + "}";
  }
  else if (type == "wifi") {
    // WiFi状态查询
    success = true;
    code = "ACTION_QUERY_OK";
    
    // SSID
    String ssid = WiFi.SSID();
    if (ssid.length() == 0) ssid = "N/A";
    // 信号强度 RSSI
    int rssi = WiFi.RSSI();

    data = "{\"wifiStatus\":" + String((int)WiFi.status()) +
           ",\"ssid\":" + jsonStringOrNull(ssid) +
           ",\"rssiDbm\":" + String(rssi) +
           ",\"ip\":\"" + jsonEscape(WiFi.localIP().toString()) +
           "\",\"gateway\":\"" + jsonEscape(WiFi.gatewayIP().toString()) +
           "\",\"netmask\":\"" + jsonEscape(WiFi.subnetMask().toString()) +
           "\",\"dns\":\"" + jsonEscape(WiFi.dnsIP().toString()) +
           "\",\"mac\":\"" + jsonEscape(WiFi.macAddress()) +
           "\",\"bssid\":\"" + jsonEscape(WiFi.BSSIDstr()) +
           "\",\"channel\":" + String(WiFi.channel()) + "}";
  }

  sendActionResult(200, success, code, data, detail);
}

// 处理发送短信请求
void handleSendSms() {
  if (!checkAuth()) return;
  
  String phone = server.arg("phone");
  String content = server.arg("content");
  
  phone.trim();
  content.trim();
  
  bool success = false;
  const char* code = "ACTION_SMS_FAILED";
  
  if (phone.length() == 0) {
    code = "ACTION_SMS_PHONE_REQUIRED";
  } else if (content.length() == 0) {
    code = "ACTION_SMS_CONTENT_REQUIRED";
  } else {
    logCaptureLn(String("网页端发送短信请求"));
    
    success = sendSMS(phone.c_str(), content.c_str());
    code = success ? "ACTION_SMS_SENT" : "ACTION_SMS_FAILED";
  }

  sendActionResult(200, success, code);
}

// 处理Ping请求
void handlePing() {
  if (!checkAuth()) return;
  
  logCaptureLn(String("网页端发起Ping请求"));
  
  // 清空串口缓冲区
  while (Serial1.available()) Serial1.read();
  
  // 激活PDP上下文（数据连接）
  logCaptureLn(String("激活数据连接(CGACT)..."));
  String activateResp = sendATCommand("AT+CGACT=1,1", 10000);
  logCaptureLn(String("CGACT响应: " + activateResp));
  
  // 检查激活是否成功（OK或已激活的情况）
  bool networkActivated = (activateResp.indexOf("OK") >= 0);
  if (!networkActivated) {
    logCaptureLn(String("数据连接激活失败，尝试继续执行..."));
  }
  
  // 清空串口缓冲区
  while (Serial1.available()) Serial1.read();
  delay(500);  // 等待网络稳定
  
  // 发送MPING命令，ping 8.8.8.8，超时30秒，ping 1次
  Serial1.println("AT+MPING=\"8.8.8.8\",30,1");
  
  // 等待响应
  unsigned long start = millis();
  String resp = "";
  bool gotOK = false;
  bool gotError = false;
  bool gotPingResult = false;
  bool pingSucceeded = false;
  String pingResultMsg = "";
  String pingData = "{}";
  
  // 等待最多35秒（30秒超时 + 5秒余量）
  while (millis() - start < 35000) {
    while (Serial1.available()) {
      char c = Serial1.read();
      if (resp.length() < MODEM_RESPONSE_MAX_LENGTH) resp += c;
      logCapture(String(c));  // 调试输出
      
      // 检查是否收到OK
      if (resp.indexOf("OK") >= 0 && !gotOK) {
        gotOK = true;
      }
      
      // 检查是否收到ERROR
      if (resp.indexOf("+CME ERROR") >= 0 || resp.indexOf("ERROR") >= 0) {
        gotError = true;
        pingResultMsg = resp;
        break;
      }
      
      // 检查是否收到Ping结果URC
      // 成功格式: +MPING: 1,8.8.8.8,32,xxx,xxx
      // 失败格式: +MPING: 2 或其他
      int mpingIdx = resp.indexOf("+MPING:");
      if (mpingIdx >= 0) {
        // 找到换行符确定完整的一行
        int lineEnd = resp.indexOf('\n', mpingIdx);
        if (lineEnd >= 0) {
          String mpingLine = resp.substring(mpingIdx, lineEnd);
          mpingLine.trim();
          logCaptureLn(String("收到MPING结果: " + mpingLine));
          
          // 解析结果
          // +MPING: <result>[,<ip>,<packet_len>,<time>,<ttl>]
          int colonIdx = mpingLine.indexOf(':');
          if (colonIdx >= 0) {
            String params = mpingLine.substring(colonIdx + 1);
            params.trim();
            
            // 获取第一个参数（result）
            int commaIdx = params.indexOf(',');
            String resultStr;
            if (commaIdx >= 0) {
              resultStr = params.substring(0, commaIdx);
            } else {
              resultStr = params;
            }
            resultStr.trim();
            int result = resultStr.toInt();
            
            gotPingResult = true;
            
            // result=0或1都表示成功（不同模组可能返回不同值）
            // 如果有完整的响应参数（IP、时间等），也视为成功
            bool pingSuccess = (result == 0 || result == 1) || (params.indexOf(',') >= 0 && params.length() > 5);
            
            if (pingSuccess) {
              pingSucceeded = true;
              // 成功，解析详细信息
              // 格式: 0/1,"8.8.8.8",16,时间,TTL
              int idx1 = params.indexOf(',');
              if (idx1 >= 0) {
                String rest = params.substring(idx1 + 1);
                // 处理IP地址（可能带引号）
                String ip;
                int idx2;
                if (rest.startsWith("\"")) {
                  // 带引号的IP
                  int quoteEnd = rest.indexOf('\"', 1);
                  if (quoteEnd >= 0) {
                    ip = rest.substring(1, quoteEnd);
                    idx2 = rest.indexOf(',', quoteEnd);
                  } else {
                    idx2 = rest.indexOf(',');
                    ip = rest.substring(0, idx2);
                  }
                } else {
                  idx2 = rest.indexOf(',');
                  ip = rest.substring(0, idx2);
                }
                
                if (idx2 >= 0) {
                  rest = rest.substring(idx2 + 1);
                  int idx3 = rest.indexOf(',');  // packet_len后
                  if (idx3 >= 0) {
                    rest = rest.substring(idx3 + 1);
                    int idx4 = rest.indexOf(',');  // time后
                    String timeStr, ttlStr;
                    if (idx4 >= 0) {
                      timeStr = rest.substring(0, idx4);
                      ttlStr = rest.substring(idx4 + 1);
                    } else {
                      timeStr = rest;
                      ttlStr = "N/A";
                    }
                    timeStr.trim();
                    ttlStr.trim();
                    pingData = "{\"ip\":\"" + jsonEscape(ip) +
                               "\",\"latencyMs\":" + String(timeStr.toInt()) +
                               ",\"ttl\":" + (ttlStr == "N/A" ? String("null") : String(ttlStr.toInt())) + "}";
                  }
                }
              }
              if (pingData == "{}") {
                pingData = "{\"ip\":\"8.8.8.8\"}";
              }
            } else {
              // 失败
              pingResultMsg = "MPING: " + String(result);
            }
            break;
          }
        }
      }
    }
    
    if (gotError || gotPingResult) break;
    server.handleClient();
  }
  
  logCaptureLn(String("\nPing操作完成"));
  
  // 关闭数据连接以节省流量
  logCaptureLn(String("关闭PDP上下文(CGACT=0)..."));
  String deactivateResp = sendATCommand("AT+CGACT=0,1", 5000);
  logCaptureLn(String("CGACT关闭响应: " + deactivateResp));
  
  if (pingSucceeded) {
    sendActionResult(200, true, "ACTION_PING_OK", pingData);
  } else if (gotError) {
    sendActionResult(200, false, "ACTION_PING_MODEM_ERROR", "{}", pingResultMsg);
  } else if (gotPingResult) {
    sendActionResult(200, false, "ACTION_PING_UNREACHABLE", "{}", pingResultMsg);
  } else {
    sendActionResult(200, false, "ACTION_PING_TIMEOUT");
  }
}

// 处理保存配置请求
void handleSave() {
  if (!checkAuth()) return;

  String previousSmtpServer = config.smtpServer;
  int previousSmtpPort = config.smtpPort;
  String previousSmtpUser = config.smtpUser;

  // 账号管理表单：空账号会停用该组，空密码会保留现有密码
  for (int i = 0; i < MAX_WEB_ACCOUNTS; i++) {
    String prefix = "account" + String(i);
    String userKey = prefix + "user";
    String passKey = prefix + "pass";
    if (server.hasArg(userKey)) {
      config.webAccounts[i].username = server.arg(userKey);
      config.webAccounts[i].username.trim();
      if (config.webAccounts[i].username.length() == 0) config.webAccounts[i].password = "";
    }
    if (server.hasArg(passKey) && server.arg(passKey).length() > 0) {
      config.webAccounts[i].password = server.arg(passKey);
    }
    if (config.webAccounts[i].password.length() == 0) config.webAccounts[i].username = "";
  }
  bool hasWebAccount = false;
  for (int i = 0; i < MAX_WEB_ACCOUNTS; i++) {
    if (config.webAccounts[i].username.length() > 0 && config.webAccounts[i].password.length() > 0) {
      hasWebAccount = true;
      break;
    }
  }
  if (!hasWebAccount) {
    config.webAccounts[0].username = DEFAULT_WEB_USER;
    config.webAccounts[0].password = DEFAULT_WEB_PASS;
  }

  // 邮件通知表单：只在字段存在时更新
  if (server.hasArg("smtpServer")) {
    config.smtpServer = server.arg("smtpServer");
  }
  if (server.hasArg("smtpPort")) {
    long smtpPort = server.arg("smtpPort").toInt();
    config.smtpPort = smtpPort > 0 && smtpPort <= 65535 ? smtpPort : 465;
  }
  if (server.hasArg("smtpUser")) {
    config.smtpUser = server.arg("smtpUser");
  }
  if (server.hasArg("smtpPass")) {
    config.smtpPass = server.arg("smtpPass");
  }
  if (server.hasArg("smtpSendTo")) {
    config.smtpSendTo = server.arg("smtpSendTo");
  }
  if (!server.hasArg("smtpPass") &&
      (config.smtpServer != previousSmtpServer || config.smtpPort != previousSmtpPort ||
       config.smtpUser != previousSmtpUser)) {
    config.smtpPass = "";
  }
  // 管理员 & 黑名单表单：只在字段存在时更新
  if (server.hasArg("adminPhone")) {
    config.adminPhone = server.arg("adminPhone");
  }
  if (server.hasArg("numberBlackList")) {
    config.numberBlackList = server.arg("numberBlackList");
  }

  // 推送通道配置：只在对应通道的字段存在时更新
  for (int i = 0; i < MAX_PUSH_CHANNELS; i++) {
    String idx = String(i);
    String enKey = "push" + idx + "en";
    String typeKey = "push" + idx + "type";
    String urlKey = "push" + idx + "url";
    String nameKey = "push" + idx + "name";
    String k1Key = "push" + idx + "key1";
    String k2Key = "push" + idx + "key2";
    String bodyKey = "push" + idx + "body";
    // 只要该通道的任一字段存在，就更新整个通道
    if (server.hasArg(enKey) || server.hasArg(typeKey) || server.hasArg(urlKey) ||
        server.hasArg(nameKey) || server.hasArg(k1Key) || server.hasArg(k2Key) ||
        server.hasArg(bodyKey)) {
      config.pushChannels[i].enabled = server.arg(enKey) == "on";
      config.pushChannels[i].type = (PushType)server.arg(typeKey).toInt();
      config.pushChannels[i].url = server.arg(urlKey);
      config.pushChannels[i].name = server.arg(nameKey);
      config.pushChannels[i].key1 = server.arg(k1Key);
      config.pushChannels[i].key2 = server.arg(k2Key);
      config.pushChannels[i].customBody = server.arg(bodyKey);
      if (config.pushChannels[i].name.length() == 0) {
        config.pushChannels[i].name = "通道" + String(i + 1);
      }
    }
  }
  
  if (!saveConfig()) {
    sendActionResult(500, false, "ACTION_CONFIG_SAVE_FAILED");
    return;
  }
  configValid = isConfigValid();
  
  sendActionResult(200, true, "ACTION_CONFIG_SAVED");
  
  // 如果配置有效，发送启动通知
  if (configValid) {
    logCaptureLn(String("配置有效，发送启动通知..."));
    String subject = "短信转发器配置已更新";
    String body = "设备配置已更新\n设备地址: " + getDeviceUrl();
    sendEmailNotification(subject.c_str(), body.c_str());
  }
}

// 处理日志查询请求 — 返回环形缓冲区中的日志行
void handleLog() {
  if (!checkAuth()) return;

  String json = "[";
  int total = logBufCount;
  int start = total < LOG_BUF_SIZE ? 0 : logBufIdx;
  for (int i = 0; i < total; i++) {
    int pos = (start + i) % LOG_BUF_SIZE;
    if (i > 0) json += ",";
    json += "\"" + jsonEscape(logBuffer[pos]) + "\"";
  }
  json += "]";
  server.sendHeader("Cache-Control", "no-store");
  server.send(200, "application/json", json);
}

// 模组控制命令
void handleModem() {
  if (!checkAuth()) return;

  // 防止重入：modemInit() 内部会调 server.handleClient()，
  // 若浏览器超时重试会导致嵌套调用，最终拖垮 WiFi
  static bool busy = false;
  if (busy) {
    sendActionResult(429, false, "ACTION_MODEM_BUSY");
    return;
  }
  busy = true;

  String action = server.arg("action");
  bool success = false;
  String data = "{}";
  String detail = "";
  const char* code = "ACTION_UNKNOWN";

  if (action == "restart") {
    // AT 软重启 — 先响应浏览器再初始化，防止浏览器超时重试
    logCaptureLn(String("网页端请求软重启模组..."));
    sendActionResult(200, true, "ACTION_MODEM_RESTARTING");
    String resp = sendATCommand("AT+CFUN=1,1", 15000);
    success = (resp.indexOf("OK") >= 0);
    logCaptureLn(String(success ? "模组软重启成功: " : "软重启失败: ") + resp);
    if (success) modemInit();
    busy = false;
    return;
  }
  else if (action == "hardreset") {
    // EN 引脚断电重启（内部已调用 modemInit()）
    logCaptureLn(String("网页端请求硬重启模组..."));
    sendActionResult(200, true, "ACTION_MODEM_HARD_RESTARTING");
    resetModule();
    busy = false;
    return;
  }
  else if (action == "signal") {
    logCaptureLn(String("网页端查询信号: AT+CSQ"));
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
        String dbm = rssi == 99 ? "null" : String(-113 + rssi * 2);
        data = "{\"signalDbm\":" + dbm + ",\"rssi\":" + String(rssi) +
               ",\"ber\":" + String(ber) + "}";
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
    logCaptureLn(String("网页端查询运营商: AT+COPS?"));
    String resp = sendATCommand("AT+COPS?", 5000);
    int copsIdx = resp.indexOf("+COPS:");
    if (copsIdx >= 0) {
      String copsLine = resp.substring(copsIdx);
      copsLine = copsLine.substring(0, copsLine.indexOf('\n'));
      copsLine.trim();
      int q1 = copsLine.indexOf('"');
      int q2 = copsLine.indexOf('"', q1 + 1);
      if (q1 >= 0 && q2 >= 0) {
        data = "{\"operator\":\"" + jsonEscape(copsLine.substring(q1 + 1, q2)) + "\"}";
        success = true;
        code = "ACTION_MODEM_OK";
      } else {
        data = "{\"operator\":\"" + jsonEscape(copsLine) + "\"}";
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
    logCaptureLn(String("网页端查询IMEI: AT+GSN"));
    String resp = sendATCommand("AT+GSN", 3000);
    resp.trim();
    int okIdx = resp.lastIndexOf("OK");
    if (okIdx > 0) resp = resp.substring(0, okIdx);
    int gsnIdx = resp.indexOf("AT+GSN");
    if (gsnIdx >= 0) resp = resp.substring(gsnIdx + 6);
    resp.trim();
    if (resp.length() > 0) {
      data = "{\"imei\":\"" + jsonEscape(resp) + "\"}";
      success = true;
      code = "ACTION_MODEM_OK";
    } else {
      code = "ACTION_MODEM_FAILED";
    }
  }
  else {
    detail = action;
  }

  busy = false;
  sendActionResult(200, success, code, data, detail);
}

// WiFi 重启
void handleWifi() {
  if (!checkAuth()) return;

  static bool busy = false;
  if (busy) {
    sendActionResult(429, false, "ACTION_WIFI_BUSY");
    return;
  }
  busy = true;

  String action = server.arg("action");
  if (action == "restart") {
    logCaptureLn(String("网页端请求重启WiFi..."));
    sendActionResult(200, true, "ACTION_WIFI_RESTARTING");
    WiFi.disconnect(true);
    delay(500);
    WiFi.setSleep(false);
    WiFi.setAutoReconnect(true);
    WiFi.setScanMethod(WIFI_FAST_SCAN);
    WiFi.begin(WIFI_SSID, WIFI_PASS);
    logCaptureLn(String("正在重新连接WiFi: " + String(WIFI_SSID)));
    unsigned long start = millis();
    while (WiFi.status() != WL_CONNECTED && millis() - start < 15000) {
      delay(50);
      server.handleClient();
    }
    if (WiFi.status() == WL_CONNECTED) {
      logCaptureLn(String("WiFi 重连成功, IP: " + WiFi.localIP().toString()));
    } else {
      logCaptureLn(String("WiFi 重连失败，将在后台持续尝试"));
    }
  } else {
    sendActionResult(200, false, "ACTION_UNKNOWN");
  }
  busy = false;
}
