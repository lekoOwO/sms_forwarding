#ifndef MODEM_H
#define MODEM_H

#include "globals.h"

enum ModemCommandResult {
  MODEM_COMMAND_COMPLETED,
  MODEM_COMMAND_TIMEOUT,
  MODEM_COMMAND_BUSY,
  MODEM_COMMAND_REJECTED
};

enum ModemDataState {
  MODEM_DATA_UNKNOWN,
  MODEM_DATA_INACTIVE,
  MODEM_DATA_ACTIVE
};

void modemPoll();
void modemDrainInput();
bool modemIsBusy();
bool modemCommandAllowed(const String& cmd);
ModemCommandResult modemTryCommand(const char* cmd, unsigned long timeout,
                                   String& response,
                                   const char* terminal = nullptr);
String sendATCommand(const char* cmd, unsigned long timeout);
String sendATCommandUntil(const char* cmd, const char* terminal,
                          unsigned long timeout);
ModemDataState modemGetDataState();
bool modemSetDataActive(bool active, String& response);
bool modemRefreshLocalNumber();
const String& modemGetLocalNumber();
void modemPowerCycle();
void resetModule();
void modemInit();
bool sendATandWaitOK(const char* cmd, unsigned long timeout);
int modemParseCeregQueryStatus(const String& response);
bool waitCEREG();
void blink_short(unsigned long gap_time = 500);
bool sendSMS(const char* phoneNumber, const char* message);

#endif
