#include "modem.h"
#include "web_handlers.h"
#include "sms_process.h"
#include "utf8_validation.h"

static bool transactionBusy = false;
static bool transactionDone = false;
static bool transactionPrompt = false;
static bool expectPrompt = false;
static String transactionResponse;
static String transactionTerminal;
static char modemLine[SERIAL_BUFFER_SIZE];
static size_t modemLineLength = 0;
static bool modemLineOverflow = false;
static String detectedModel;
static ModemDataState dataState = MODEM_DATA_UNKNOWN;

static void appendTransactionLine(const String& line) {
  if (transactionResponse.length() < MODEM_RESPONSE_MAX_LENGTH) {
    transactionResponse.concat(line.c_str(),
      min((size_t)line.length(),
          (size_t)MODEM_RESPONSE_MAX_LENGTH - transactionResponse.length()));
    if (transactionResponse.length() < MODEM_RESPONSE_MAX_LENGTH)
      transactionResponse += '\n';
  }

  String trimmed = line;
  trimmed.trim();
  bool error = trimmed == "ERROR" || trimmed.startsWith("+CME ERROR") ||
               trimmed.startsWith("+CMS ERROR");
  bool terminal = transactionTerminal.length() > 0 &&
                  line.indexOf(transactionTerminal) >= 0;
  if (error || terminal ||
      (transactionTerminal.length() == 0 && trimmed == "OK"))
    transactionDone = true;
}

void modemPoll() {
  while (Serial1.available()) {
    char c = Serial1.read();
    if (transactionBusy && expectPrompt && c == '>' && modemLineLength == 0) {
      transactionPrompt = transactionDone = true;
      continue;
    }
    if (c == '\n') {
      if (!modemLineOverflow) {
        modemLine[modemLineLength] = 0;
        String line(modemLine);
        if (line.endsWith("\r")) line.remove(line.length() - 1);
        if (!processModemLine(line) && transactionBusy)
          appendTransactionLine(line);
      }
      modemLineLength = 0;
      modemLineOverflow = false;
    } else if (!modemLineOverflow) {
      if (modemLineLength < sizeof(modemLine) - 1)
        modemLine[modemLineLength++] = c;
      else
        modemLineOverflow = true;
    }
  }
}

void modemDrainInput() {
  modemPoll();
}

bool modemIsBusy() {
  return transactionBusy;
}

bool modemCommandAllowed(const String& input) {
  if (input.length() == 0 || input.length() > MAX_AT_COMMAND_LENGTH ||
      input.indexOf('\r') >= 0 || input.indexOf('\n') >= 0) return false;
  String cmd = input;
  cmd.trim();
  cmd.toUpperCase();
  if (!cmd.startsWith("AT")) return false;
  return !cmd.startsWith("ATD") && cmd != "ATO" &&
         !cmd.startsWith("AT+CMGS") && !cmd.startsWith("AT+CMGW") &&
         !cmd.startsWith("AT+CGDATA") && !cmd.startsWith("AT+CMUX") &&
         cmd.indexOf("CIPSEND") < 0 && cmd.indexOf("QISEND") < 0 &&
         cmd.indexOf("CASEND") < 0;
}

static ModemCommandResult runTransaction(const char* cmd, unsigned long timeout,
                                         String& response, const char* terminal,
                                         bool prompt, bool validate = true) {
  if (transactionBusy) return MODEM_COMMAND_BUSY;
  if (validate && cmd && !modemCommandAllowed(String(cmd)))
    return MODEM_COMMAND_REJECTED;

  modemPoll();
  transactionBusy = true;
  transactionDone = false;
  transactionPrompt = false;
  expectPrompt = prompt;
  transactionResponse = "";
  transactionTerminal = terminal ? terminal : "";
  if (cmd) Serial1.println(cmd);

  unsigned long start = millis();
  while (!transactionDone && millis() - start < timeout) {
    modemPoll();
    delay(1);
  }
  modemPoll();
  response = transactionResponse;
  bool completed = transactionDone;
  transactionBusy = false;
  expectPrompt = false;
  transactionTerminal = "";
  return completed ? MODEM_COMMAND_COMPLETED : MODEM_COMMAND_TIMEOUT;
}

ModemCommandResult modemTryCommand(const char* cmd, unsigned long timeout,
                                   String& response, const char* terminal) {
  return runTransaction(cmd, timeout, response, terminal, false);
}

String sendATCommand(const char* cmd, unsigned long timeout) {
  String response;
  modemTryCommand(cmd, timeout, response);
  return response;
}

String sendATCommandUntil(const char* cmd, const char* terminal,
                          unsigned long timeout) {
  String response;
  modemTryCommand(cmd, timeout, response, terminal);
  return response;
}

ModemDataState modemGetDataState() {
  return dataState;
}

bool modemSetDataActive(bool active, String& response) {
  if (!active && detectedModel == "ML307Y") {
    dataState = MODEM_DATA_UNKNOWN;
    response = "";
    return true;
  }
  ModemCommandResult result = modemTryCommand(
    active ? "AT+CGACT=1,1" : "AT+CGACT=0,1", 10000, response);
  bool ok = result == MODEM_COMMAND_COMPLETED && response.indexOf("OK") >= 0;
  dataState = ok ? (active ? MODEM_DATA_ACTIVE : MODEM_DATA_INACTIVE)
                 : MODEM_DATA_UNKNOWN;
  return ok;
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
  const int INIT_RETRIES = 5;
  modemReady = false;
  modemDrainInput();

  bool initialized = false;
  for (int retry = 0; retry < INIT_RETRIES; retry++) {
    if (sendATandWaitOK("AT", 1000)) {
      initialized = true;
      break;
    }
    logCaptureLn(String("AT未响应，重试..."));
    blink_short();
  }
  if (!initialized) {
    logCaptureLn(String("⚠️ AT握手失败，模组进入降级状态"));
    return;
  }
  logCaptureLn(String("模组AT响应正常"));

  detectedModel = "";
  String resp = sendATCommand("ATI", 2000);
  if (resp.indexOf("ML307Y") >= 0) detectedModel = "ML307Y";

  String dataResponse;
  if (modemSetDataActive(false, dataResponse) && detectedModel != "ML307Y") {
    logCaptureLn(String("已禁用数据连接(AT+CGACT=0,1)，防止流量消耗"));
  } else if (detectedModel == "ML307Y") {
    logCaptureLn(String("ML307Y不支援安全停用PDP，数据状态未知"));
  } else {
    logCaptureLn(String("⚠️ 停用PDP失败，数据状态未知"));
  }

  initialized = false;
  for (int retry = 0; retry < INIT_RETRIES; retry++) {
    if (sendATandWaitOK("AT+CNMI=2,2,0,0,0", 1000)) {
      initialized = true;
      break;
    }
    logCaptureLn(String("设置CNMI失败，重试..."));
    blink_short();
  }
  if (!initialized) {
    logCaptureLn(String("⚠️ CNMI设置失败，模组进入降级状态"));
    return;
  }
  logCaptureLn(String("CNMI参数设置完成"));

  initialized = false;
  for (int retry = 0; retry < INIT_RETRIES; retry++) {
    if (sendATandWaitOK("AT+CMGF=0", 1000)) {
      initialized = true;
      break;
    }
    logCaptureLn(String("设置PDU模式失败，重试..."));
    blink_short();
  }
  if (!initialized) {
    logCaptureLn(String("⚠️ PDU模式设置失败，模组进入降级状态"));
    return;
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
  String resp;
  ModemCommandResult result = modemTryCommand(cmd, timeout, resp);
  return result == MODEM_COMMAND_COMPLETED && resp.indexOf("OK") >= 0;
}

// 检测网络注册状态（LTE/4G）
// CEREG状态: 1=已注册本地, 5=已注册漫游
bool waitCEREG() {
  String resp = sendATCommand("AT+CEREG?", 2000);
  if (resp.indexOf("+CEREG:") < 0) return false;
  return resp.indexOf(",1") >= 0 || resp.indexOf(",5") >= 0;
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
  String command = "AT+CMGS=" + String(pduLen);
  String response;
  ModemCommandResult result = runTransaction(command.c_str(), 5000, response,
                                              nullptr, true, false);
  if (result != MODEM_COMMAND_COMPLETED || !transactionPrompt) {
    logCaptureLn(String("未收到>提示符"));
    return false;
  }

  Serial1.print(pdu.getSMS());
  result = runTransaction(nullptr, 30000, response, nullptr, false, false);
  if (result == MODEM_COMMAND_COMPLETED && response.indexOf("OK") >= 0) {
    logCaptureLn(String("短信发送成功"));
    return true;
  }
  logCaptureLn(String(result == MODEM_COMMAND_TIMEOUT ? "短信发送超时" : "短信发送失败"));
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
