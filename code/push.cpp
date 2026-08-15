#include "push.h"
#include "web_handlers.h"
#include "config.h"
#include "utf8_validation.h"
#include <HTTPClient.h>
#include <mbedtls/md.h>
#include <base64.h>
#include <sys/time.h>

static bool hmacSha256(const String& key, const String& data, uint8_t output[32]) {
  const mbedtls_md_info_t* info = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
  return info != nullptr &&
         mbedtls_md_hmac(info,
                         reinterpret_cast<const unsigned char*>(key.c_str()), key.length(),
                         reinterpret_cast<const unsigned char*>(data.c_str()), data.length(),
                         output) == 0;
}

static bool hasValidEpoch() {
  return time(nullptr) >= 1700000000;
}

static String htmlEscape(const String& value) {
  String escaped;
  escaped.reserve(value.length());
  for (size_t i = 0; i < value.length(); ++i) {
    switch (value[i]) {
      case '&': escaped += "&amp;"; break;
      case '<': escaped += "&lt;"; break;
      case '>': escaped += "&gt;"; break;
      case '"': escaped += "&quot;"; break;
      case '\'': escaped += "&#39;"; break;
      default: escaped += value[i];
    }
  }
  return escaped;
}

// Send an email notification
void sendEmailNotification(const char* subject, const char* body) {
  if (config.smtpServer.length() == 0 || config.smtpUser.length() == 0 || 
      config.smtpPass.length() == 0 || config.smtpSendTo.length() == 0) {
    logCaptureLn(String("Email configuration is incomplete; skipping delivery"));
    return;
  }
  
  auto statusCallback = [](SMTPStatus status) {
    if (status.errorCode != 0) logCaptureF("SMTP status error: %d\n", status.errorCode);
  };
  if (smtp.connect(config.smtpServer.c_str(), config.smtpPort, statusCallback) && smtp.isConnected()) {
    if (!smtp.authenticate(config.smtpUser.c_str(), config.smtpPass.c_str(), readymail_auth_password)) {
      logCaptureLn("Email server authentication failed");
      return;
    }

    SMTPMessage msg;
    String from = "sms notify <"; from += config.smtpUser; from += ">";
    msg.headers.add(rfc822_from, from.c_str());
    String to = "your_email <"; to += config.smtpSendTo; to += ">";
    msg.headers.add(rfc822_to, to.c_str());
    String safeSubject = String(subject);
    safeSubject.replace('\r', ' ');
    safeSubject.replace('\n', ' ');
    msg.headers.add(rfc822_subject, safeSubject.c_str());
    msg.text.body(body);
    msg.timestamp = time(nullptr);
    if (smtp.send(msg)) {
      logCaptureLn("Email server accepted the message");
    } else {
      logCaptureLn("Failed to send email");
    }
  } else {
    logCaptureLn(String("Failed to connect to the email server"));
  }
}

// URL-encode a string
String urlEncode(const String& str) {
  String encoded = "";
  unsigned char c;
  char code0;
  char code1;
  for (unsigned int i = 0; i < str.length(); i++) {
    c = static_cast<unsigned char>(str.charAt(i));
    if (c == ' ') {
      encoded += '+';
    } else if (isalnum(c)) {
      encoded += c;
    } else {
      code1 = (c & 0xf) + '0';
      if ((c & 0xf) > 9) code1 = (c & 0xf) - 10 + 'A';
      c = (c >> 4) & 0xf;
      code0 = c + '0';
      if (c > 9) code0 = c - 10 + 'A';
      encoded += '%';
      encoded += code0;
      encoded += code1;
    }
  }
  return encoded;
}

// Create a DingTalk signature using a UTC timestamp in milliseconds
String dingtalkSign(const String& secret, int64_t timestamp) {
  String stringToSign = String(timestamp) + "\n" + secret;
  
  uint8_t hmacResult[32] = {0};
  if (!hmacSha256(secret, stringToSign, hmacResult)) return "";
  
  String base64Encoded = base64::encode(hmacResult, 32);
  return urlEncode(base64Encoded);
}

// Get the current UTC timestamp in milliseconds for DingTalk signatures
int64_t getUtcMillis() {
  struct timeval tv;
  if (gettimeofday(&tv, NULL) == 0) {
    return (int64_t)tv.tv_sec * 1000LL + tv.tv_usec / 1000;
  }
  // Fall back to time() if gettimeofday() fails.
  return (int64_t)time(nullptr) * 1000LL;
}

// Escape a string for JSON
String jsonEscape(const String& str) {
  String result = "";
  result.reserve(str.length());
  for (unsigned int i = 0; i < str.length(); i++) {
    unsigned char c = static_cast<unsigned char>(str.charAt(i));
    if (c == '"') result += "\\\"";
    else if (c == '\\') result += "\\\\";
    else if (c == '\n') result += "\\n";
    else if (c == '\r') result += "\\r";
    else if (c == '\t') result += "\\t";
    else if (c < 0x20) {
      char escaped[7];
      snprintf(escaped, sizeof(escaped), "\\u%04X", c);
      result += escaped;
    } else if (c >= 0x80) {
      int utf8Length = validUtf8CharLength(str.c_str() + i);
      if (utf8Length > 0) {
        result.concat(str.c_str() + i, utf8Length);
        i += utf8Length - 1;
      } else {
        char escaped[7];
        snprintf(escaped, sizeof(escaped), "\\u%04X", c);
        result += escaped;
      }
    } else {
      result += static_cast<char>(c);
    }
  }
  return result;
}

// Send to one push channel
void sendToChannel(const PushChannel& channel, const char* sender, const char* message, const char* timestamp) {
  if (!channel.enabled) return;
  
  // Some providers can use a default URL.
  bool needUrl = (channel.type == PUSH_TYPE_POST_JSON || channel.type == PUSH_TYPE_BARK || 
                  channel.type == PUSH_TYPE_GET || channel.type == PUSH_TYPE_DINGTALK || 
                  channel.type == PUSH_TYPE_CUSTOM);
  if (needUrl && channel.url.length() == 0) return;
  
  HTTPClient http;
  http.setConnectTimeout(3000);
  http.setTimeout(3000);
  String channelName = channel.name.length() > 0 ? channel.name : ("Channel " + String(channel.type));
  logCaptureLn(String("Sending to push channel: " + channelName));

  if ((channel.type == PUSH_TYPE_DINGTALK || channel.type == PUSH_TYPE_FEISHU) &&
      channel.key1.length() > 0 && !hasValidEpoch()) {
    logCaptureLn(String("Time is not synchronized; skipping push that requires a timestamp signature"));
    return;
  }
  
  int httpCode = 0;
  String senderEscaped = jsonEscape(String(sender));
  String messageEscaped = jsonEscape(String(message));
  String timestampEscaped = jsonEscape(String(timestamp));
  
  switch (channel.type) {
    case PUSH_TYPE_POST_JSON: {
      // Standard POST JSON format
      http.begin(channel.url);
      http.addHeader("Content-Type", "application/json");
      String jsonData = "{";
      jsonData += "\"sender\":\"" + senderEscaped + "\",";
      jsonData += "\"message\":\"" + messageEscaped + "\",";
      jsonData += "\"timestamp\":\"" + timestampEscaped + "\"";
      jsonData += "}";
      httpCode = http.POST(jsonData);
      break;
    }
    
    case PUSH_TYPE_BARK: {
      // Bark push format
      http.begin(channel.url);
      http.addHeader("Content-Type", "application/json");
      String jsonData = "{";
      jsonData += "\"title\":\"" + senderEscaped + "\",";
      jsonData += "\"body\":\"" + messageEscaped + "\"";
      jsonData += "}";
      httpCode = http.POST(jsonData);
      break;
    }
    
    case PUSH_TYPE_GET: {
      // GET request with parameters in the URL
      String getUrl = channel.url;
      if (getUrl.indexOf('?') == -1) {
        getUrl += "?";
      } else {
        getUrl += "&";
      }
      getUrl += "sender=" + urlEncode(String(sender));
      getUrl += "&message=" + urlEncode(String(message));
      getUrl += "&timestamp=" + urlEncode(String(timestamp));
      http.begin(getUrl);
      httpCode = http.GET();
      break;
    }
    
    case PUSH_TYPE_DINGTALK: {
      // DingTalk bot
      String webhookUrl = channel.url;
      
      // Add a signature when a secret is configured.
      if (channel.key1.length() > 0) {
        // DingTalk requires a UTC timestamp in milliseconds.
        int64_t ts = getUtcMillis();
        String sign = dingtalkSign(channel.key1, ts);
        if (sign.length() == 0) {
          logCaptureLn(String("Failed to create DingTalk signature; skipping delivery"));
          return;
        }
        if (webhookUrl.indexOf('?') == -1) {
          webhookUrl += "?";
        } else {
          webhookUrl += "&";
        }
        // Format the int64_t explicitly before appending it.
        char tsBuf[21];
        snprintf(tsBuf, sizeof(tsBuf), "%lld", ts);
        webhookUrl += "timestamp=" + String(tsBuf) + "&sign=" + sign;
      }
      
      http.begin(webhookUrl);
      http.addHeader("Content-Type", "application/json");
      String jsonData = "{\"msgtype\":\"text\",\"text\":{\"content\":\"";
      jsonData += "📱 SMS notification\\nSender: " + senderEscaped + "\\nMessage: " + messageEscaped + "\\nTime: " + timestampEscaped;
      jsonData += "\"}}";
      httpCode = http.POST(jsonData);
      break;
    }

    case PUSH_TYPE_PUSHPLUS: {
      // PushPlus
      String pushUrl = channel.url.length() > 0 ? channel.url : "https://www.pushplus.plus/send";
      http.begin(pushUrl);
      http.addHeader("Content-Type", "application/json");
      // Delivery channel
      String channelValue = "wechat";
      if (channel.key2.length() > 0) {
          // Supported channels: WeChat, browser extension, and PushPlus App.
          if (channel.key2 == "wechat" || channel.key2 == "extension" || channel.key2 == "app") {
              channelValue = channel.key2;
          } else {
              logCaptureLn(String("Invalid PushPlus channel '" + channel.key2 + "'. Using default 'wechat'."));
          }
      }
      String jsonData = "{";
      String senderHtml = jsonEscape(htmlEscape(String(sender)));
      String messageHtml = jsonEscape(htmlEscape(String(message)));
      String timestampHtml = jsonEscape(htmlEscape(String(timestamp)));
      jsonData += "\"token\":\"" + jsonEscape(channel.key1) + "\",";
      jsonData += "\"title\":\"SMS from: " + senderHtml + "\",";
      jsonData += "\"content\":\"<b>Sender:</b> " + senderHtml + "<br><b>Time:</b> " + timestampHtml + "<br><b>Message:</b><br>" + messageHtml + "\",";
      jsonData += "\"channel\":\"" + channelValue + "\"";
      jsonData += "}";
      httpCode = http.POST(jsonData);
      break;
    }

    case PUSH_TYPE_SERVERCHAN: {
      // ServerChan
      String scUrl = channel.url.length() > 0 ? channel.url : ("https://sctapi.ftqq.com/" + channel.key1 + ".send");
      http.begin(scUrl);
      http.addHeader("Content-Type", "application/x-www-form-urlencoded");
      String postData = "title=" + urlEncode("SMS from: " + String(sender));
      postData += "&desp=" + urlEncode("**Sender:** " + String(sender) + "\n\n**Time:** " + String(timestamp) + "\n\n**Message:**\n\n" + String(message));
      httpCode = http.POST(postData);
      break;
    }
    
    case PUSH_TYPE_CUSTOM: {
      // Custom template
      if (channel.customBody.length() == 0) {
        logCaptureLn(String("Custom template is empty; skipping delivery"));
        return;
      }
      http.begin(channel.url);
      http.addHeader("Content-Type", "application/json");
      String body = channel.customBody;
      body.replace("{sender}", senderEscaped);
      body.replace("{message}", messageEscaped);
      body.replace("{timestamp}", timestampEscaped);
      httpCode = http.POST(body);
      break;
    }
    
    case PUSH_TYPE_FEISHU: {
      // Feishu bot
      String webhookUrl = channel.url;
      String jsonData = "{";
      
      // Add a signature when a secret is configured.
      if (channel.key1.length() > 0) {
        // Feishu uses a timestamp in seconds.
        int64_t ts = time(nullptr);
        // Feishu signature: base64(HMAC-SHA256(key=timestamp + "\n" + secret, msg=""))
        String stringToSign = String(ts) + "\n" + channel.key1;
        uint8_t hmacResult[32] = {0};
        if (!hmacSha256(stringToSign, "", hmacResult)) {
          logCaptureLn(String("Failed to create Feishu signature; skipping delivery"));
          return;
        }
        String sign = base64::encode(hmacResult, 32);
        
        jsonData += "\"timestamp\":\"" + String(ts) + "\",";
        jsonData += "\"sign\":\"" + sign + "\",";
      }
      
      // Feishu message body
      jsonData += "\"msg_type\":\"text\",";
      jsonData += "\"content\":{\"text\":\"";
      jsonData += "📱 SMS notification\\nSender: " + senderEscaped + "\\nMessage: " + messageEscaped + "\\nTime: " + timestampEscaped;
      jsonData += "\"}}";
      
      http.begin(webhookUrl);
      http.addHeader("Content-Type", "application/json");
      httpCode = http.POST(jsonData);
      break;
    }
    
    case PUSH_TYPE_GOTIFY: {
      // Gotify push
      String gotifyUrl = channel.url;
      // Ensure the URL ends with a slash.
      if (!gotifyUrl.endsWith("/")) gotifyUrl += "/";
      gotifyUrl += "message?token=" + channel.key1;
      
      http.begin(gotifyUrl);
      http.addHeader("Content-Type", "application/json");
      String jsonData = "{";
      jsonData += "\"title\":\"SMS from: " + senderEscaped + "\",";
      jsonData += "\"message\":\"" + messageEscaped + "\\n\\nTime: " + timestampEscaped + "\",";
      jsonData += "\"priority\":5";
      jsonData += "}";
      httpCode = http.POST(jsonData);
      break;
    }
    
    case PUSH_TYPE_TELEGRAM: {
      // Telegram bot push
      // channel.key1 is the chat ID; channel.key2 is the bot token.
      String tgBaseUrl = channel.url.length() > 0 ? channel.url : "https://api.telegram.org";
      if (tgBaseUrl.endsWith("/")) tgBaseUrl.remove(tgBaseUrl.length() - 1);
      
      String tgUrl = tgBaseUrl + "/bot" + channel.key2 + "/sendMessage";
      http.begin(tgUrl);
      http.addHeader("Content-Type", "application/json");
      
      String jsonData = "{";
      jsonData += "\"chat_id\":\"" + jsonEscape(channel.key1) + "\",";
      String text = "📱 SMS notification\nSender: " + String(sender) +
                    "\nMessage: " + String(message) + "\nTime: " + String(timestamp);
      jsonData += "\"text\":\"" + jsonEscape(text) + "\"";
      jsonData += "}";
      
      httpCode = http.POST(jsonData);
      break;
    }
    
    default:
      logCaptureLn(String("Unknown push type"));
      return;
  }
  
  if (httpCode >= 200 && httpCode < 300) {
    logCaptureF("[%s] Provider accepted request: %d\n", channelName.c_str(), httpCode);
  } else {
    logCaptureF("[%s] HTTP request failed: %d\n", channelName.c_str(), httpCode);
  }
  http.end();
}

// Send an SMS notification to all enabled push channels
void sendSMSToServer(const char* sender, const char* message, const char* timestamp) {
  if (WiFi.status() != WL_CONNECTED) {
    logCaptureLn(String("WiFi is disconnected; skipping push notifications"));
    return;
  }
  
  bool hasEnabledChannel = false;
  for (int i = 0; i < MAX_PUSH_CHANNELS; i++) {
    if (isPushChannelValid(config.pushChannels[i])) {
      hasEnabledChannel = true;
      break;
    }
  }
  
  if (!hasEnabledChannel) {
    logCaptureLn(String("No push channels are enabled"));
    return;
  }
  
  logCaptureLn(String("\n=== Starting multi-channel push ==="));
  for (int i = 0; i < MAX_PUSH_CHANNELS; i++) {
    if (isPushChannelValid(config.pushChannels[i])) {
      sendToChannel(config.pushChannels[i], sender, message, timestamp);
      delay(100); // Brief pause to avoid sending requests too quickly
    }
  }
  logCaptureLn(String("=== Multi-channel push complete ===\n"));
}
