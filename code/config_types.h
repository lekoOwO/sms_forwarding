#ifndef CONFIG_TYPES_H
#define CONFIG_TYPES_H

#include <Arduino.h>
#include "config_schema_generated.h"

// Push channel configuration shared by all providers
struct PushChannel {
  bool enabled;           // Whether the channel is enabled
  PushType type;          // Push provider type
  String name;            // Display name
  String url;             // Push or webhook URL
  String key1;            // Provider-specific value, such as a secret or token
  String key2;            // Secondary provider-specific value
  String titleTemplate;   // Optional title template for typed providers
  String bodyTemplate;    // Optional body template for typed providers
  String customBody;      // Custom request body using the notification template placeholders
};

struct WebAccount {
  String username;
  String password;
};

// Configuration values
struct Config {
  String deviceName;
  String hostname;
  String notificationLocale;
  String smtpServer;
  int smtpPort;
  String smtpUser;
  String smtpPass;
  String smtpSendTo;
  String adminPhone;
  PushChannel pushChannels[MAX_PUSH_CHANNELS];  // Push channels
  WebAccount webAccounts[MAX_WEB_ACCOUNTS];
  String numberBlackList;  // Phone number blacklist, one number per line
};

// Default web management credentials
#define DEFAULT_WEB_USER "admin"
#define DEFAULT_WEB_PASS "admin123"

// Concatenated SMS limits
#define MAX_CONCAT_PARTS 10       // Maximum number of parts per concatenated SMS
#define CONCAT_TIMEOUT_MS 30000   // Time to wait for missing parts, in milliseconds
#define MAX_CONCAT_MESSAGES 5     // Maximum number of concatenated SMS messages buffered at once

// One part of a concatenated SMS
struct SmsPart {
  bool valid;           // Whether this part has been received
  String text;          // Part contents
};

// Buffered concatenated SMS
struct ConcatSms {
  bool inUse;                           // Whether this slot is in use
  int refNumber;                        // Concatenation reference number
  String sender;                        // Sender
  String timestamp;                     // Timestamp from the first received part
  int totalParts;                       // Expected number of parts
  int receivedParts;                    // Number of received parts
  unsigned long firstPartTime;          // Time when the first part was received
  SmsPart parts[MAX_CONCAT_PARTS];      // Part contents
};

#endif
