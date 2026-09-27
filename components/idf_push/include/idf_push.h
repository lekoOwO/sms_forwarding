#pragma once

#include <stdint.h>

#include <string>

#include "esp_err.h"

esp_err_t idf_push_start(void);

bool idf_push_enqueue_forward(const char* sender, const char* text, const char* timestamp, uint32_t inbox_id,
                              bool supplement = false);
int idf_push_enqueue_notify(const char* title, const char* body, const char* timestamp);
bool idf_push_enqueue_email(const char* subject, const char* body);
bool idf_push_enqueue_startup_notification(void);
bool idf_push_heartbeat_tick(void);
int idf_push_forward_queue_depth(void);
int idf_push_retry_queue_depth(void);
int idf_push_email_queue_depth(void);
bool idf_push_busy(void);
bool idf_push_test_active(void);
bool idf_push_test_channel_active(uint8_t channel);

bool idf_push_enqueue_test(uint8_t channel, std::string& message);
std::string idf_push_test_status_json(uint8_t channel, bool include_cleanup = false);
