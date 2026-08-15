#include "push.h"
#include "web_handlers.h"
#include "config.h"
#include "notification_locale.h"
#include "utf8_validation.h"
#include <ArduinoJson.h>
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

static bool serializeJsonChecked(const JsonDocument& json, String& output) {
  const size_t expectedSize = json.overflowed() ? 0 : measureJson(json);
  output = "";
  if (expectedSize == 0 || !output.reserve(expectedSize) ||
      serializeJson(json, output) != expectedSize || output.length() != expectedSize ||
      !hasValidJsonEncoding(output.c_str())) {
    logCaptureLn(String("Failed to build push JSON payload; skipping delivery"));
    return false;
  }
  return true;
}

static bool postJson(HTTPClient& http, const String& url, const JsonDocument& json, int& httpCode) {
  String payload;
  if (!serializeJsonChecked(json, payload)) return false;
  http.begin(url);
  http.addHeader("Content-Type", "application/json");
  httpCode = http.POST(payload);
  return true;
}

static bool serializeJsonStringContent(const String& value, String& output) {
  JsonDocument json;
  json.set(value);
  if (!serializeJsonChecked(json, output)) return false;
  if (output.length() < 2 || output[0] != '"' || output[output.length() - 1] != '"') {
    logCaptureLn(String("Failed to build custom push placeholders; skipping delivery"));
    return false;
  }
  output.remove(output.length() - 1);
  output.remove(0, 1);
  return true;
}

static bool renderTemplate(const String& source, const String& sender, const String& message,
                           const String& timestamp, const String& device, size_t maxBytes,
                           bool title, String& output) {
  output = "";
  size_t estimate = source.length() + sender.length() + message.length() +
                    timestamp.length() + device.length();
  if (!output.reserve(static_cast<unsigned int>(min(maxBytes, estimate)))) return false;
  for (size_t i = 0; i < source.length();) {
    const String* replacement = nullptr;
    size_t placeholderLength = 0;
    if (source.startsWith("{sender}", i)) {
      replacement = &sender;
      placeholderLength = 8;
    } else if (source.startsWith("{message}", i)) {
      replacement = &message;
      placeholderLength = 9;
    } else if (source.startsWith("{timestamp}", i)) {
      replacement = &timestamp;
      placeholderLength = 11;
    } else if (source.startsWith("{device}", i)) {
      replacement = &device;
      placeholderLength = 8;
    }
    if (replacement) {
      if (replacement->length() > maxBytes - output.length()) return false;
      if (!output.concat(*replacement)) return false;
      i += placeholderLength;
    } else {
      if (output.length() == maxBytes) return false;
      if (!output.concat(source[i++])) return false;
    }
  }
  return isValidUtf8(output.c_str()) &&
         (!title || (output.indexOf('\r') < 0 && output.indexOf('\n') < 0));
}

static bool renderTypedNotification(const PushChannel& channel, const String& sender,
                                    const String& message, const String& timestamp,
                                    String& title, String& body) {
  String defaultTitle;
  String defaultBody;
  getDefaultSmsTemplates(config.notificationLocale, defaultTitle, defaultBody);
  const String& titleSource = channel.titleTemplate.length() > 0 ? channel.titleTemplate : defaultTitle;
  const String& bodySource = channel.bodyTemplate.length() > 0 ? channel.bodyTemplate : defaultBody;
  if (!renderTemplate(titleSource, sender, message, timestamp, config.deviceName,
                      MAX_RENDERED_TITLE_BYTES, true, title) ||
      !renderTemplate(bodySource, sender, message, timestamp, config.deviceName,
                      MAX_RENDERED_BODY_BYTES, false, body)) {
    logCaptureLn("Rendered push template is invalid or too long; skipping delivery");
    return false;
  }
  return true;
}

bool buildDefaultSmsNotification(const char* sender, const char* message, const char* timestamp,
                                 String& title, String& body) {
  String titleTemplate;
  String bodyTemplate;
  getDefaultSmsTemplates(config.notificationLocale, titleTemplate, bodyTemplate);
  return renderTemplate(titleTemplate, String(sender), String(message), String(timestamp),
                        config.deviceName, MAX_RENDERED_TITLE_BYTES, true, title) &&
         renderTemplate(bodyTemplate, String(sender), String(message), String(timestamp),
                        config.deviceName, MAX_RENDERED_BODY_BYTES, false, body);
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
  const String senderValue(sender);
  const String messageValue(message);
  const String timestampValue(timestamp);
  String notificationTitle;
  String notificationBody;
  if (channel.type != PUSH_TYPE_CUSTOM &&
      !renderTypedNotification(channel, senderValue, messageValue, timestampValue,
                               notificationTitle, notificationBody)) return;
  
  switch (channel.type) {
    case PUSH_TYPE_POST_JSON: {
      // Standard POST JSON format
      JsonDocument json;
      json["sender"] = senderValue;
      json["message"] = messageValue;
      json["timestamp"] = timestampValue;
      json["title"] = notificationTitle;
      json["body"] = notificationBody;
      if (!postJson(http, channel.url, json, httpCode)) return;
      break;
    }
    
    case PUSH_TYPE_BARK: {
      // Bark push format
      JsonDocument json;
      json["title"] = notificationTitle;
      json["body"] = notificationBody;
      if (!postJson(http, channel.url, json, httpCode)) return;
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
      getUrl += "&title=" + urlEncode(notificationTitle);
      getUrl += "&body=" + urlEncode(notificationBody);
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
      
      JsonDocument json;
      json["msgtype"] = "text";
      JsonObject text = json["text"].to<JsonObject>();
      text["content"] = notificationTitle + "\n" + notificationBody;
      if (!postJson(http, webhookUrl, json, httpCode)) return;
      break;
    }

    case PUSH_TYPE_PUSHPLUS: {
      // PushPlus
      String pushUrl = channel.url.length() > 0 ? channel.url : "https://www.pushplus.plus/send";
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
      String titleHtml = htmlEscape(notificationTitle);
      String bodyHtml = htmlEscape(notificationBody);
      bodyHtml.replace("\n", "<br>");
      JsonDocument json;
      json["token"] = channel.key1;
      json["title"] = titleHtml;
      json["content"] = bodyHtml;
      json["channel"] = channelValue;
      if (!postJson(http, pushUrl, json, httpCode)) return;
      break;
    }

    case PUSH_TYPE_SERVERCHAN: {
      // ServerChan
      String scUrl = channel.url.length() > 0 ? channel.url : ("https://sctapi.ftqq.com/" + channel.key1 + ".send");
      http.begin(scUrl);
      http.addHeader("Content-Type", "application/x-www-form-urlencoded");
      String postData = "title=" + urlEncode(notificationTitle);
      postData += "&desp=" + urlEncode(notificationBody);
      httpCode = http.POST(postData);
      break;
    }
    
    case PUSH_TYPE_CUSTOM: {
      // Custom template
      if (channel.customBody.length() == 0) {
        logCaptureLn(String("Custom template is empty; skipping delivery"));
        return;
      }
      String senderContent;
      String messageContent;
      String timestampContent;
      String deviceContent;
      if (!serializeJsonStringContent(senderValue, senderContent) ||
          !serializeJsonStringContent(messageValue, messageContent) ||
          !serializeJsonStringContent(timestampValue, timestampContent) ||
          !serializeJsonStringContent(config.deviceName, deviceContent)) return;
      http.begin(channel.url);
      http.addHeader("Content-Type", "application/json");
      String body;
      if (!renderTemplate(channel.customBody, senderContent, messageContent, timestampContent,
                          deviceContent, MAX_RENDERED_CUSTOM_BODY_BYTES, false, body)) {
        logCaptureLn("Rendered custom push body is invalid or too long; skipping delivery");
        return;
      }
      httpCode = http.POST(body);
      break;
    }
    
    case PUSH_TYPE_FEISHU: {
      // Feishu bot
      String webhookUrl = channel.url;
      JsonDocument json;
      
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
        
        json["timestamp"] = String(ts);
        json["sign"] = sign;
      }
      
      // Feishu message body
      json["msg_type"] = "text";
      JsonObject content = json["content"].to<JsonObject>();
      content["text"] = notificationTitle + "\n" + notificationBody;
      if (!postJson(http, webhookUrl, json, httpCode)) return;
      break;
    }
    
    case PUSH_TYPE_GOTIFY: {
      // Gotify push
      String gotifyUrl = channel.url;
      // Ensure the URL ends with a slash.
      if (!gotifyUrl.endsWith("/")) gotifyUrl += "/";
      gotifyUrl += "message?token=" + channel.key1;
      
      JsonDocument json;
      json["title"] = notificationTitle;
      json["message"] = notificationBody;
      json["priority"] = 5;
      if (!postJson(http, gotifyUrl, json, httpCode)) return;
      break;
    }
    
    case PUSH_TYPE_TELEGRAM: {
      // Telegram bot push
      // channel.key1 is the chat ID; channel.key2 is the bot token.
      String tgBaseUrl = channel.url.length() > 0 ? channel.url : "https://api.telegram.org";
      if (tgBaseUrl.endsWith("/")) tgBaseUrl.remove(tgBaseUrl.length() - 1);
      
      String tgUrl = tgBaseUrl + "/bot" + channel.key2 + "/sendMessage";
      String text = notificationTitle + "\n" + notificationBody;
      JsonDocument json;
      json["chat_id"] = channel.key1;
      json["text"] = text;
      if (!postJson(http, tgUrl, json, httpCode)) return;
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
