#include "modem.h"
#include "web_handlers.h"
#include "utf8_validation.h"

// 发送AT命令并获取响应
String sendATCommand(const char* cmd, unsigned long timeout) {
  while (Serial1.available()) Serial1.read();
  Serial1.println(cmd);
  
  unsigned long start = millis();
  String resp = "";
  while (millis() - start < timeout) {
    if (Serial1.available()) {
      char c = Serial1.read();
      resp += c;
      if (resp.indexOf("OK") >= 0 || resp.indexOf("ERROR") >= 0) {
        // 读取剩余数据（最多 50ms）
        unsigned long t = millis();
        while (millis() - t < 50) {
          if (Serial1.available()) resp += (char)Serial1.read();
          server.handleClient();
        }
        return resp;
      }
    }
    server.handleClient();
  }
  return resp;
}

// 新增"模组断电重启"函数
void modemPowerCycle() {
  pinMode(MODEM_EN_PIN, OUTPUT);

  logCaptureLn(String("EN 拉低：关闭模组"));
  digitalWrite(MODEM_EN_PIN, LOW);
  delay(1200);  // 关机时间给够

  logCaptureLn(String("EN 拉高：开启模组"));
  digitalWrite(MODEM_EN_PIN, HIGH);
  delay(6000);  // 等模组完全启动再发AT（关键）
}

// 重启模组（EN引脚断电重启 + 重新初始化）
void resetModule() {
  logCaptureLn(String("正在硬重启模组（EN 断电重启）..."));
  modemPowerCycle();
  modemInit();
}

// 模组 AT 初始化流程（setup 中调用，resetModule 后也调用）
void modemInit() {
  // 清掉上电噪声/残留
  while (Serial1.available()) Serial1.read();

  while (!sendATandWaitOK("AT", 1000)) {
    logCaptureLn(String("AT未响应，重试..."));
    blink_short();
  }
  logCaptureLn(String("模组AT响应正常"));

  //判断型号，做一些特定操作
  bool need_set_CGACT = true;
  String resp = sendATCommand("ATI", 2000);
  logCaptureLn(String("ATI响应: " + resp));
  if (resp.indexOf("OK") >= 0) {
    // 解析ATI响应
    String manufacturer = "未知";
    String model = "未知";
    String version = "未知";
    
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
    //这个模组这条命令有bug
    if(model == "ML307Y") need_set_CGACT = false;
  }

  if(need_set_CGACT) {
    while (!sendATandWaitOK("AT+CGACT=0,1", 5000)) {
      logCaptureLn(String("设置CGACT失败，重试..."));
      blink_short();
    }
    logCaptureLn(String("已禁用数据连接(AT+CGACT=0,1)，防止流量消耗"));
  } else {
    logCaptureLn(String("该型号无法配置(AT+CGACT=0,1)，跳过该命令，会不会消耗流量？自求多福"));
  }
  while (!sendATandWaitOK("AT+CNMI=2,2,0,0,0", 1000)) {
    logCaptureLn(String("设置CNMI失败，重试..."));
    blink_short();
  }
  logCaptureLn(String("CNMI参数设置完成"));
  while (!sendATandWaitOK("AT+CMGF=0", 1000)) {
    logCaptureLn(String("设置PDU模式失败，重试..."));
    blink_short();
  }
  logCaptureLn(String("PDU模式设置完成"));
  int ceregRetry = 0;
  while (!waitCEREG() && ceregRetry < 30) {
    logCaptureLn(String("等待网络注册..."));
    ceregRetry++;
    blink_short();
  }
  if (ceregRetry < 30) {
    logCaptureLn(String("网络已注册"));
    modemReady = true;
  } else {
    logCaptureLn(String("⚠️ 网络注册超时（无SIM卡或信号差），模组功能不可用"));
    modemReady = false;
  }
}

void blink_short(unsigned long gap_time) {
  digitalWrite(LED_BUILTIN, LOW);
  delay(50);
  digitalWrite(LED_BUILTIN, HIGH);
  delay(gap_time);
}

bool sendATandWaitOK(const char* cmd, unsigned long timeout) {
  while (Serial1.available()) Serial1.read();
  Serial1.println(cmd);
  unsigned long start = millis();
  String resp = "";
  while (millis() - start < timeout) {
    if (Serial1.available()) {
      char c = Serial1.read();
      resp += c;
      if (resp.indexOf("OK") >= 0) return true;
      if (resp.indexOf("ERROR") >= 0) return false;
    }
    server.handleClient();
  }
  return false;
}

// 检测网络注册状态（LTE/4G）
// CEREG状态: 1=已注册本地, 5=已注册漫游
bool waitCEREG() {
  Serial1.println("AT+CEREG?");
  unsigned long start = millis();
  String resp = "";
  while (millis() - start < 2000) {
    if (Serial1.available()) {
      char c = Serial1.read();
      resp += c;
      if (resp.indexOf("+CEREG:") >= 0) {
        if (resp.indexOf(",1") >= 0 || resp.indexOf(",5") >= 0) return true;
        if (resp.indexOf(",0") >= 0 || resp.indexOf(",2") >= 0 || 
            resp.indexOf(",3") >= 0 || resp.indexOf(",4") >= 0) return false;
      }
    }
    server.handleClient();
  }
  return false;
}

static bool isGsm7Extension(unsigned short value) {
  return value == 0x000C || value == '^' || value == '{' || value == '}' ||
         value == '\\' || value == '[' || value == '~' || value == ']' ||
         value == '|' || value == 0x20AC;
}

static bool smsInfo(const char* message, bool& gsm7, int& units) {
  gsm7 = true;
  int gsmUnits = 0;
  int ucsUnits = 0;
  while (*message) {
    int bytes = validUtf8CharLength(message);
    if (bytes < 1) return false;
    unsigned short ucs2[2] = {0, 0};
    int ucsBytes = pdu.utf8_to_ucs2_single(message, ucs2);
    unsigned short value = (ucs2[0] << 8) | (ucs2[0] >> 8);
    if (!pdu.isGSM7(&value)) gsm7 = false;
    gsmUnits += isGsm7Extension(value) ? 2 : 1;
    ucsUnits += ucsBytes / 2;
    message += bytes;
  }
  units = gsm7 ? gsmUnits : ucsUnits;
  return true;
}

static int smsCharUnits(const char* text, bool gsm7, int& bytes) {
  bytes = validUtf8CharLength(text);
  if (bytes < 1) return -1;
  unsigned short ucs2[2] = {0, 0};
  int ucsBytes = pdu.utf8_to_ucs2_single(text, ucs2);
  if (!gsm7) return ucsBytes / 2;
  unsigned short value = (ucs2[0] << 8) | (ucs2[0] >> 8);
  return isGsm7Extension(value) ? 2 : 1;
}

static int smsPartCount(const char* message, bool gsm7, int limit) {
  int parts = 1;
  int used = 0;
  while (*message) {
    int bytes = 0;
    int units = smsCharUnits(message, gsm7, bytes);
    if (bytes < 1 || units < 1 || units > limit) return -1;
    if (used + units > limit) {
      parts++;
      used = 0;
    }
    used += units;
    message += bytes;
  }
  return parts;
}

static bool sendEncodedPdu(int pduLen) {
  while (Serial1.available()) Serial1.read();
  Serial1.println("AT+CMGS=" + String(pduLen));
  
  unsigned long start = millis();
  bool gotPrompt = false;
  while (millis() - start < 5000) {
    if (Serial1.available()) {
      char c = Serial1.read();
      logCapture(String(c));
      if (c == '>') {
        gotPrompt = true;
        break;
      }
    }
    server.handleClient();
  }
  
  if (!gotPrompt) {
    logCaptureLn(String("未收到>提示符"));
    return false;
  }
  
  Serial1.print(pdu.getSMS());
  start = millis();
  String resp = "";
  while (millis() - start < 30000) {
    while (Serial1.available()) {
      char c = Serial1.read();
      resp += c;
      logCapture(String(c));
      if (resp.indexOf("OK") >= 0) {
        logCaptureLn(String("\n短信发送成功"));
        return true;
      }
      if (resp.indexOf("ERROR") >= 0) {
        logCaptureLn(String("\n短信发送失败"));
        return false;
      }
    }
    server.handleClient();
  }
  logCaptureLn(String("短信发送超时"));
  return false;
}

// 发送短信（PDU模式，长内容自动拆成 concatenated SMS）
bool sendSMS(const char* phoneNumber, const char* message) {
  bool gsm7 = true;
  int units = 0;
  if (!smsInfo(message, gsm7, units)) return false;

  int singleLimit = gsm7 ? 160 : 70;
  int partLimit = gsm7 ? 152 : 66;
  int totalParts = units <= singleLimit ? 1 : smsPartCount(message, gsm7, partLimit);
  if (totalParts < 1 || totalParts > 255) return false;

  pdu.setSCAnumber();
  unsigned short reference = (unsigned short)(millis() & 0xFFFF);
  if (reference == 0) reference = 1;
  const char* cursor = message;

  for (int partNumber = 1; partNumber <= totalParts; partNumber++) {
    String part;
    int used = 0;
    int limit = totalParts == 1 ? singleLimit : partLimit;
    while (*cursor) {
      int bytes = 0;
      int charUnits = smsCharUnits(cursor, gsm7, bytes);
      if (used + charUnits > limit) break;
      part.concat(cursor, bytes);
      cursor += bytes;
      used += charUnits;
    }

    int pduLen = totalParts == 1
      ? pdu.encodePDU(phoneNumber, part.c_str())
      : pdu.encodePDU(phoneNumber, part.c_str(), reference, totalParts, partNumber);
    if (pduLen < 0 || !sendEncodedPdu(pduLen)) return false;
  }
  return true;
}
