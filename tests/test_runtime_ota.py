import csv
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


class RuntimeOtaTest(unittest.TestCase):
    def test_runtime_uses_dedicated_http_task_and_bounded_jobs(self):
        sketch = (ROOT / "code/code.ino").read_text()
        handlers = (ROOT / "code/web_handlers.cpp").read_text()
        header = (ROOT / "code/web_handlers.h").read_text()
        self.assertIn("startManagementHttpTask", sketch)
        self.assertIn("processWebJobs", sketch)
        self.assertIn("xTaskCreate", handlers)
        self.assertIn("MAX_ACTIVE_WEB_JOBS 3", header)
        self.assertIn("ACTION_JOB_ACCEPTED", handlers)
        self.assertIn('server.on("/api/jobs"', sketch)
        self.assertIn("xTaskGetCurrentTaskHandle() == jobTaskHandle", handlers)
        self.assertEqual(1, handlers.count("server.handleClient()"))
        self.assertIn("static void httpTask", handlers)
        self.assertIn("emptySlot", handlers)
        self.assertIn("oldestDoneSlot", handlers)
        self.assertIn("emptySlot >= 0 ? emptySlot : oldestDoneSlot", handlers)
        self.assertIn("uint32_t age = now - webJobs[i].completedAt", handlers)
        self.assertIn("age > oldestAge", handlers)

    def test_logs_are_byte_bounded_and_cursor_paginated(self):
        handlers = (ROOT / "code/web_handlers.cpp").read_text()
        header = (ROOT / "code/web_handlers.h").read_text()
        self.assertIn("LOG_BYTE_BUDGET (24 * 1024)", header)
        self.assertIn("nextCursor", handlers)
        self.assertIn("hasMore", handlers)
        self.assertIn('requestArg("cursor")', handlers)

    def test_state_changes_require_boot_random_csrf(self):
        handlers = (ROOT / "code/web_handlers.cpp").read_text()
        sketch = (ROOT / "code/code.ino").read_text()
        self.assertIn("esp_fill_random", handlers)
        self.assertIn("constantTimeEqual", handlers)
        self.assertIn('server.header("X-CSRF-Token")', handlers)
        self.assertIn("csrfToken", handlers)
        self.assertIn("collectHeaders", sketch)
        self.assertIn("AUTH_FAILURE_LIMIT", handlers)
        self.assertIn("Retry-After", handlers)

    def test_partition_layout_has_two_equal_ota_slots_and_no_filesystem(self):
        with (ROOT / "code/partitions.csv").open() as stream:
            rows = [
                [cell.strip() for cell in row]
                for row in csv.reader(line for line in stream if not line.startswith("#"))
            ]
        by_name = {row[0]: row for row in rows}
        self.assertEqual(["app", "ota_0", "0x10000", "0x1E0000"], by_name["ota_0"][1:5])
        self.assertEqual(["app", "ota_1", "0x1F0000", "0x1E0000"], by_name["ota_1"][1:5])
        self.assertEqual(["data", "nvs", "0x3D0000", "0x20000"], by_name["appcfg"][1:5])
        self.assertNotIn("spiffs", by_name)

    def test_ota_is_chunked_signed_and_health_confirmed(self):
        ota = (ROOT / "code/ota_update.cpp").read_text()
        ota_header = (ROOT / "code/ota_update.h").read_text()
        sketch = (ROOT / "code/code.ino").read_text()
        self.assertIn("OTA_CHUNK_SIZE 8192", ota_header)
        self.assertIn("mbedtls_pk_verify", ota)
        self.assertIn("SHA256Builder", ota)
        self.assertIn("releaseCounter", ota)
        self.assertIn("Update.end()", ota)
        self.assertIn("verifyRollbackLater", sketch)
        self.assertIn("esp_ota_mark_app_valid_cancel_rollback", ota)
        self.assertIn('metadata.getUInt("pendingAddr", 0)', ota)
        self.assertIn("pending > accepted ? pending : accepted", ota)
        self.assertIn('metadata.getUInt("accepted", 0) != counter', ota)
        self.assertIn("running->address == pendingAddress", ota)
        self.assertIn("deviceRestartPending()", ota)
        self.assertIn("restartPending = true", ota)
        self.assertIn("decodeBase64RequestChunk", ota)
        self.assertNotIn('String chunk = server.arg("plain")', ota)

    def test_frontend_bundle_is_embedded_and_release_is_signed(self):
        sketch = (ROOT / "code/code.ino").read_text()
        handlers = (ROOT / "code/web_handlers.cpp").read_text()
        package = (ROOT / "web/scripts/package.mjs").read_text()
        workflow = (ROOT / ".github/workflows/build.yml").read_text()
        self.assertNotIn("LittleFS", sketch)
        self.assertNotIn("LittleFS", handlers)
        self.assertIn('web_bundle.h', handlers)
        self.assertIn('Content-Encoding", "gzip', handlers)
        self.assertIn("web_bundle.h", package)
        self.assertIn("OTA_SIGNING_PRIVATE_KEY", workflow)
        self.assertIn("scripts/sign-ota-release.py", workflow)
        self.assertIn("trap 'rm -f", workflow)

    def test_release_signing_is_isolated_from_the_build_workspace(self):
        workflow = (ROOT / ".github/workflows/build.yml").read_text()
        self.assertIn("permissions:\n  contents: read", workflow)
        self.assertIn("persist-credentials: false", workflow)
        self.assertIn("release:\n    if: startsWith(github.ref, 'refs/tags/v')", workflow)
        self.assertIn("environment: release", workflow)
        self.assertIn("contents: write", workflow[workflow.index("  release:"):])
        build = workflow[workflow.index("  build:"):workflow.index("  release:")]
        self.assertNotIn("OTA_SIGNING_PRIVATE_KEY", build)
        self.assertNotIn("contents: write", build)

    def test_config_backup_crypto_is_bounded_and_fail_closed(self):
        backup = (ROOT / "code/config_backup.cpp").read_text()
        handlers = (ROOT / "code/web_handlers.cpp").read_text()
        self.assertIn("mbedtls_pkcs5_pbkdf2_hmac_ext", backup)
        self.assertIn("mbedtls_gcm_crypt_and_tag", backup)
        self.assertIn("mbedtls_gcm_auth_decrypt", backup)
        self.assertIn("read32(header + 12) != BACKUP_KDF_ITERATIONS", backup)
        self.assertIn("MAX_ENCRYPTED_CONFIG_BYTES", backup)
        self.assertIn("mbedtls_platform_zeroize", backup)
        self.assertIn("xTaskCreate(cryptoTask", backup)
        self.assertIn('xTaskCreate(cryptoTask, "config-crypto", 8192, raw, 1, nullptr)', backup)
        self.assertGreaterEqual(backup.count("clearCryptoBusy();"), 6)
        self.assertGreaterEqual(backup.count("allowRestoreRetry();"), 2)
        self.assertIn('strcmp(type, "config-export") != 0', handlers)
        self.assertIn("deviceRestartPending()", handlers)
        self.assertIn("if (!jobMutex || executingJob >= 0) return;", handlers)
        self.assertIn("cancelQueuedJobsForRestart();", handlers)
        self.assertNotIn('deviceRestartPending() && strcmp(type, "query")', handlers)
        self.assertIn("static void cancelQueuedJobsForRestart()", handlers)
        self.assertIn('job.resultJson = actionResultJson(false, "ACTION_BUSY")', handlers)
        self.assertIn("deviceRestartPending()", backup)
        self.assertIn("if (otaUploadActive())", backup)
        self.assertIn("decodeBase64RequestChunk", backup)
        self.assertNotIn('String chunk = server.arg("plain")', backup)
        self.assertIn("static uint8_t decoded[MAX_REQUEST_CHUNK_BYTES]", handlers)
        self.assertNotIn("uint8_t chunk[BACKUP_CHUNK_SIZE]", backup)


if __name__ == "__main__":
    unittest.main()
