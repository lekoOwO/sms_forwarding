#ifndef PUSH_H
#define PUSH_H

#include "globals.h"

void sendEmailNotification(const char* subject, const char* body);
void sendSMSToServer(const char* sender, const char* message, const char* timestamp);
void sendSystemPushNotification(const String& title, const String& body,
                                const String& timestamp);
void sendToChannel(const PushChannel& channel, const char* sender, const char* message, const char* timestamp);
bool buildDefaultSmsNotification(const char* sender, const char* message, const char* timestamp,
                                 String& title, String& body);
String urlEncode(const String& str);
String dingtalkSign(const String& secret, int64_t timestamp);
int64_t getUtcMillis();

#endif
