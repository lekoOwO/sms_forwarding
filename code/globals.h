#ifndef GLOBALS_H
#define GLOBALS_H

#include <Arduino.h>
#include <WiFi.h>
#include <WiFiClientSecure.h>
#include <WebServer.h>
#include <Preferences.h>
#include "src/pdulib/pdulib.h"
#define ENABLE_SMTP
#define ENABLE_DEBUG
#include <ReadyMail.h>
#include "config_types.h"

// UART pin mapping
#define TXD 3
#define RXD 4
#define MODEM_EN_PIN 5

// Fallback LED pin used for CI compilation
#ifndef LED_BUILTIN
#define LED_BUILTIN 8
#endif

#define SERIAL_BUFFER_SIZE 500
// Standard SMSC + SMS-DELIVER needs at most 350 hex characters; keep vendor headroom.
#define MAX_PDU_LENGTH 400
#define PDU_WAIT_TIMEOUT_MS 5000
#define MODEM_RESPONSE_MAX_LENGTH 1024
#define MAX_AT_COMMAND_LENGTH 256
#define LOG_LINE_MAX_LENGTH 512

#ifndef ENABLE_MODEM_USB_RAW_BRIDGE
#define ENABLE_MODEM_USB_RAW_BRIDGE 0
#endif

// Global declarations
extern Config config;
extern Preferences preferences;
extern PDU pdu;
extern WiFiClientSecure ssl_client;
extern SMTPClient smtp;
extern WebServer server;
extern bool configValid;
extern bool timeSynced;
extern bool modemReady;
extern unsigned long lastPrintTime;
extern ConcatSms concatBuffer[MAX_CONCAT_MESSAGES];

bool connectWifi(uint32_t timeoutMs = 20000);
bool startProvisioningAp();
void networkTick();
bool provisioningApActive();
bool networkAccessReady();
String activeNetworkIp();
String activeNetworkSsid();

#endif
