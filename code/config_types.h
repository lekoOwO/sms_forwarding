#ifndef CONFIG_TYPES_H
#define CONFIG_TYPES_H

#include <Arduino.h>

// Push channel types
enum PushType {
  PUSH_TYPE_NONE = 0,      // Disabled
  PUSH_TYPE_POST_JSON = 1, // POST JSON format: {"sender":"xxx","message":"xxx","timestamp":"xxx"}
  PUSH_TYPE_BARK = 2,      // Bark format: POST {"title":"xxx","body":"xxx"}
  PUSH_TYPE_GET = 3,       // GET request with parameters in the URL
  PUSH_TYPE_DINGTALK = 4,  // DingTalk bot
  PUSH_TYPE_PUSHPLUS = 5,  // PushPlus
  PUSH_TYPE_SERVERCHAN = 6,// ServerChan
  PUSH_TYPE_CUSTOM = 7,    // Custom template
  PUSH_TYPE_FEISHU = 8,    // Feishu bot
  PUSH_TYPE_GOTIFY = 9,    // Gotify
  PUSH_TYPE_TELEGRAM = 10  // Telegram Bot
};

// Maximum number of push channels
#define MAX_PUSH_CHANNELS 5
#define MAX_WEB_ACCOUNTS 10

// Push channel configuration shared by all providers
struct PushChannel {
  bool enabled;           // Whether the channel is enabled
  PushType type;          // Push provider type
  String name;            // Display name
  String url;             // Push or webhook URL
  String key1;            // Provider-specific value, such as a secret or token
  String key2;            // Secondary provider-specific value
  String customBody;      // Custom request body with {sender}, {message}, and {timestamp} placeholders
};

struct WebAccount {
  String username;
  String password;
};

// Configuration values
struct Config {
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
