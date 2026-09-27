#pragma once

/* IDF's bundle implementation only needs logging macros in this native test.
 * Keep them silent so no target-specific ROM logging symbols enter the fixture.
 */
#define ESP_LOGE(...) do { } while (0)
#define ESP_LOGW(...) do { } while (0)
#define ESP_LOGI(...) do { } while (0)
#define ESP_LOGD(...) do { } while (0)
#define ESP_LOGV(...) do { } while (0)
