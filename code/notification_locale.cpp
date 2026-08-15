#include "notification_locale.h"

#include "config_schema_generated.h"

void getDefaultSmsTemplates(const String& locale, String& title, String& body) {
  if (locale == NOTIFICATION_LOCALE_EN) {
    title = "SMS from {sender}";
    body = "Device: {device}\nSender: {sender}\nTime: {timestamp}\nMessage: {message}";
  } else if (locale == NOTIFICATION_LOCALE_ZH_CN) {
    title = "来自 {sender} 的短信";
    body = "设备：{device}\n发件人：{sender}\n时间：{timestamp}\n内容：{message}";
  } else {
    title = "來自 {sender} 的簡訊";
    body = "裝置：{device}\n寄件者：{sender}\n時間：{timestamp}\n內容：{message}";
  }
}

void buildSystemNotificationText(const String& locale, SystemNotificationKind kind,
                                 const String& deviceName, const String& deviceUrl,
                                 String& title, String& body) {
  if (locale == NOTIFICATION_LOCALE_EN) {
    title = kind == SYSTEM_NOTIFICATION_STARTED ? "SMS Forwarder started" :
                                                  "SMS Forwarder configuration updated";
    body = "Device: " + deviceName + "\nStatus: " +
           (kind == SYSTEM_NOTIFICATION_STARTED ? "Started" : "Configuration updated") +
           "\nDevice URL: " + deviceUrl;
  } else if (locale == NOTIFICATION_LOCALE_ZH_CN) {
    title = kind == SYSTEM_NOTIFICATION_STARTED ? "短信转发器已启动" : "短信转发器配置已更新";
    body = "设备：" + deviceName + "\n状态：" +
           (kind == SYSTEM_NOTIFICATION_STARTED ? "已启动" : "配置已更新") +
           "\n设备网址：" + deviceUrl;
  } else {
    title = kind == SYSTEM_NOTIFICATION_STARTED ? "簡訊轉發器已啟動" : "簡訊轉發器設定已更新";
    body = "裝置：" + deviceName + "\n狀態：" +
           (kind == SYSTEM_NOTIFICATION_STARTED ? "已啟動" : "設定已更新") +
           "\n裝置網址：" + deviceUrl;
  }
}
