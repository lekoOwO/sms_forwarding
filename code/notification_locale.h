#ifndef NOTIFICATION_LOCALE_H
#define NOTIFICATION_LOCALE_H

#include <Arduino.h>

enum SystemNotificationKind {
  SYSTEM_NOTIFICATION_STARTED,
  SYSTEM_NOTIFICATION_CONFIG_UPDATED,
};

void getDefaultSmsTemplates(const String& locale, String& title, String& body);
void buildSystemNotificationText(const String& locale, SystemNotificationKind kind,
                                 const String& deviceName, const String& deviceUrl,
                                 String& title, String& body);
void buildHeartbeatNotificationText(const String& locale, const String& deviceName,
                                    const String& hostname, const String& localNumber,
                                    const String& networkAddress, const String& deviceUrl,
                                    const String& eventTime, String& title, String& body);

#endif
