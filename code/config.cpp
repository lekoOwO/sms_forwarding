#include "config.h"
#include "web_handlers.h"

static bool putStringChecked(const char* key, const String& value) {
  size_t written = preferences.putString(key, value);
  if (value.length() > 0) return written == value.length();
  return preferences.getType(key) == PT_STR && preferences.getString(key) == value;
}

// 保存配置到NVS
bool saveConfig() {
  if (!preferences.begin("sms_config", false)) {
    logCaptureLn(String("配置保存失败：无法打开NVS"));
    return false;
  }

  bool ok = true;
  ok &= putStringChecked("smtpServer", config.smtpServer);
  ok &= preferences.putInt("smtpPort", config.smtpPort) == sizeof(int32_t);
  ok &= putStringChecked("smtpUser", config.smtpUser);
  ok &= putStringChecked("smtpPass", config.smtpPass);
  ok &= putStringChecked("smtpSendTo", config.smtpSendTo);
  ok &= putStringChecked("adminPhone", config.adminPhone);
  for (int i = 0; i < MAX_WEB_ACCOUNTS; i++) {
    String prefix = "account" + String(i);
    ok &= putStringChecked((prefix + "user").c_str(), config.webAccounts[i].username);
    ok &= putStringChecked((prefix + "pass").c_str(), config.webAccounts[i].password);
  }
  ok &= putStringChecked("webUser", config.webAccounts[0].username);
  ok &= putStringChecked("webPass", config.webAccounts[0].password);
  ok &= putStringChecked("numBlkList", config.numberBlackList);
  
  // 保存推送通道配置
  for (int i = 0; i < MAX_PUSH_CHANNELS; i++) {
    String prefix = "push" + String(i);
    ok &= preferences.putBool((prefix + "en").c_str(), config.pushChannels[i].enabled) == 1;
    ok &= preferences.putUChar((prefix + "type").c_str(), (uint8_t)config.pushChannels[i].type) == 1;
    ok &= putStringChecked((prefix + "url").c_str(), config.pushChannels[i].url);
    ok &= putStringChecked((prefix + "name").c_str(), config.pushChannels[i].name);
    ok &= putStringChecked((prefix + "k1").c_str(), config.pushChannels[i].key1);
    ok &= putStringChecked((prefix + "k2").c_str(), config.pushChannels[i].key2);
    ok &= putStringChecked((prefix + "body").c_str(), config.pushChannels[i].customBody);
  }
  
  preferences.end();
  logCaptureLn(String(ok ? "配置已保存" : "配置保存失败：部分字段未持久化"));
  return ok;
}

// 从NVS加载配置
void loadConfig() {
  preferences.begin("sms_config", true);
  config.smtpServer = preferences.getString("smtpServer", "");
  config.smtpPort = preferences.getInt("smtpPort", 465);
  config.smtpUser = preferences.getString("smtpUser", "");
  config.smtpPass = preferences.getString("smtpPass", "");
  config.smtpSendTo = preferences.getString("smtpSendTo", "");
  config.adminPhone = preferences.getString("adminPhone", "");
  bool hasAccountList = preferences.isKey("account0user");
  for (int i = 0; i < MAX_WEB_ACCOUNTS; i++) {
    String prefix = "account" + String(i);
    if (i == 0 && !hasAccountList) {
      config.webAccounts[i].username = preferences.getString("webUser", DEFAULT_WEB_USER);
      config.webAccounts[i].password = preferences.getString("webPass", DEFAULT_WEB_PASS);
    } else {
      config.webAccounts[i].username = preferences.getString((prefix + "user").c_str(), "");
      config.webAccounts[i].password = preferences.getString((prefix + "pass").c_str(), "");
    }
  }
  config.numberBlackList = preferences.getString("numBlkList", "");
  
  // 加载推送通道配置
  for (int i = 0; i < MAX_PUSH_CHANNELS; i++) {
    String prefix = "push" + String(i);
    config.pushChannels[i].enabled = preferences.getBool((prefix + "en").c_str(), false);
    config.pushChannels[i].type = (PushType)preferences.getUChar((prefix + "type").c_str(), PUSH_TYPE_POST_JSON);
    config.pushChannels[i].url = preferences.getString((prefix + "url").c_str(), "");
    config.pushChannels[i].name = preferences.getString((prefix + "name").c_str(), "通道" + String(i + 1));
    config.pushChannels[i].key1 = preferences.getString((prefix + "k1").c_str(), "");
    config.pushChannels[i].key2 = preferences.getString((prefix + "k2").c_str(), "");
    config.pushChannels[i].customBody = preferences.getString((prefix + "body").c_str(), "");
  }
  
  // 兼容旧配置：如果有旧的httpUrl配置，迁移到第一个通道
  String oldHttpUrl = preferences.getString("httpUrl", "");
  if (oldHttpUrl.length() > 0 && !config.pushChannels[0].enabled) {
    config.pushChannels[0].enabled = true;
    config.pushChannels[0].url = oldHttpUrl;
    config.pushChannels[0].type = preferences.getUChar("barkMode", 0) != 0 ? PUSH_TYPE_BARK : PUSH_TYPE_POST_JSON;
    config.pushChannels[0].name = "迁移通道";
    logCaptureLn(String("已迁移旧HTTP配置到推送通道1"));
  }
  
  preferences.end();
  logCaptureLn(String("配置已加载"));
}

// 检查推送通道是否有效配置
bool isPushChannelValid(const PushChannel& ch) {
  if (!ch.enabled) return false;
  if (ch.url.indexOf('\r') >= 0 || ch.url.indexOf('\n') >= 0 ||
      ch.key1.indexOf('\r') >= 0 || ch.key1.indexOf('\n') >= 0 ||
      ch.key2.indexOf('\r') >= 0 || ch.key2.indexOf('\n') >= 0) return false;
  
  switch (ch.type) {
    case PUSH_TYPE_POST_JSON:
    case PUSH_TYPE_BARK:
    case PUSH_TYPE_GET:
    case PUSH_TYPE_DINGTALK:
    case PUSH_TYPE_FEISHU:
    case PUSH_TYPE_CUSTOM:
      return ch.url.length() > 0;
    case PUSH_TYPE_PUSHPLUS:
    case PUSH_TYPE_SERVERCHAN:
      return ch.key1.length() > 0;  // 这两个主要靠key1（token/sendkey）
    case PUSH_TYPE_GOTIFY:
      return ch.url.length() > 0 && ch.key1.length() > 0;  // 需要URL和Token
    case PUSH_TYPE_TELEGRAM:
      return ch.key1.length() > 0 && ch.key2.length() > 0; // 需要Chat ID和Token
    default:
      return false;
  }
}

// 检查配置是否有效（至少配置了邮件或任一推送通道）
bool isConfigValid() {
  bool emailValid = config.smtpServer.length() > 0 && 
                    config.smtpUser.length() > 0 && 
                    config.smtpPass.length() > 0 && 
                    config.smtpSendTo.length() > 0;
  
  bool pushValid = false;
  for (int i = 0; i < MAX_PUSH_CHANNELS; i++) {
    if (isPushChannelValid(config.pushChannels[i])) {
      pushValid = true;
      break;
    }
  }
  
  return emailValid || pushValid;
}

// 获取当前设备URL
String getDeviceUrl() {
  return "http://" + WiFi.localIP().toString() + "/";
}
