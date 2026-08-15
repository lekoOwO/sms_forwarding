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
static String localNumber;
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

bool modemRefreshLocalNumber() {
  String response = sendATCommand("AT+CNUM", 2000);
  localNumber = "";
  int start = response.indexOf(",\"");
  if (start < 0) return false;
  int end = response.indexOf('"', start + 2);
  if (end <= start + 2) return false;
  String candidate = response.substring(start + 2, end);
  candidate.trim();
  if (candidate.length() > 32) return false;
  for (size_t i = 0; i < candidate.length(); ++i) {
    char c = candidate[i];
    if (!isdigit(static_cast<unsigned char>(c)) && c != '+' && c != '*' && c != '#') return false;
  }
  localNumber = candidate;
  return localNumber.length() > 0;
}

const String& modemGetLocalNumber() {
  return localNumber;
}

// Power-cycle the modem
void modemPowerCycle() {
  pinMode(MODEM_EN_PIN, OUTPUT);

  logCaptureLn(String("EN low: powering off modem"));
  digitalWrite(MODEM_EN_PIN, LOW);
  delay(1200);  // Allow enough time for the modem to power off.

  logCaptureLn(String("EN high: powering on modem"));
  digitalWrite(MODEM_EN_PIN, HIGH);
  delay(6000);  // Wait for the modem to finish booting before sending AT commands.
}

// Power-cycle and reinitialize the modem
void resetModule() {
  logCaptureLn(String("Hard-resetting modem with an EN power cycle..."));
  modemPowerCycle();
  modemInit();
}

// Initialize the modem AT interface during setup and after resetModule()
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
    logCaptureLn(String("No AT response; retrying..."));
    blink_short();
  }
  if (!initialized) {
    logCaptureLn(String("⚠️ AT handshake failed; modem is degraded"));
    return;
  }
  logCaptureLn(String("Modem AT interface is responding"));

  detectedModel = "";
  String resp = sendATCommand("ATI", 2000);
  if (resp.indexOf("ML307Y") >= 0) detectedModel = "ML307Y";

  String dataResponse;
  if (modemSetDataActive(false, dataResponse) && detectedModel != "ML307Y") {
    logCaptureLn(String("Data connection disabled with AT+CGACT=0,1 to prevent data usage"));
  } else if (detectedModel == "ML307Y") {
    logCaptureLn(String("ML307Y cannot safely deactivate PDP; data state is unknown"));
  } else {
    logCaptureLn(String("⚠️ Failed to deactivate PDP; data state is unknown"));
  }

  initialized = false;
  for (int retry = 0; retry < INIT_RETRIES; retry++) {
    if (sendATandWaitOK("AT+CNMI=2,2,0,0,0", 1000)) {
      initialized = true;
      break;
    }
    logCaptureLn(String("Failed to configure CNMI; retrying..."));
    blink_short();
  }
  if (!initialized) {
    logCaptureLn(String("⚠️ Failed to configure CNMI; modem is degraded"));
    return;
  }
  logCaptureLn(String("CNMI configured"));

  initialized = false;
  for (int retry = 0; retry < INIT_RETRIES; retry++) {
    if (sendATandWaitOK("AT+CMGF=0", 1000)) {
      initialized = true;
      break;
    }
    logCaptureLn(String("Failed to set PDU mode; retrying..."));
    blink_short();
  }
  if (!initialized) {
    logCaptureLn(String("⚠️ Failed to set PDU mode; modem is degraded"));
    return;
  }
  logCaptureLn(String("PDU mode configured"));
  int ceregRetry = 0;
  while (!waitCEREG() && ceregRetry < 30) {
    logCaptureLn(String("Waiting for network registration..."));
    ceregRetry++;
    blink_short();
  }
  modemRefreshLocalNumber();
  if (ceregRetry < 30) {
    logCaptureLn(String("Network registered"));
    modemReady = true;
  } else {
    logCaptureLn(String("⚠️ Network registration timed out (missing SIM or weak signal); modem is unavailable"));
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

// Check LTE/4G network registration status
// CEREG status: 1 = registered locally, 5 = registered while roaming
int modemParseCeregQueryStatus(const String& response) {
  int prefix = response.indexOf("+CEREG:");
  if (prefix < 0) return -1;
  int lineEnd = response.indexOf('\n', prefix);
  int comma = response.indexOf(',', prefix + 7);
  if (comma < 0 || (lineEnd >= 0 && comma > lineEnd)) return -1;

  int cursor = comma + 1;
  while (cursor < (int)response.length() && response[cursor] == ' ') cursor++;
  if (cursor >= (int)response.length() || response[cursor] < '0' ||
      response[cursor] > '9') return -1;

  int status = 0;
  while (cursor < (int)response.length() && response[cursor] >= '0' &&
         response[cursor] <= '9') {
    status = status * 10 + response[cursor++] - '0';
    if (status > 255) return -1;
  }
  return status;
}

bool waitCEREG() {
  String resp = sendATCommand("AT+CEREG?", 2000);
  int status = modemParseCeregQueryStatus(resp);
  return status == 1 || status == 5;
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
    logCaptureLn(String("Did not receive the > prompt"));
    return false;
  }

  Serial1.print(pdu.getSMS());
  result = runTransaction(nullptr, 30000, response, nullptr, false, false);
  if (result == MODEM_COMMAND_COMPLETED && response.indexOf("OK") >= 0) {
    logCaptureLn(String("SMS sent successfully"));
    return true;
  }
  logCaptureLn(String(result == MODEM_COMMAND_TIMEOUT ? "SMS send timed out" : "Failed to send SMS"));
  return false;
}

// Send an SMS in PDU mode, splitting long content into concatenated parts
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
