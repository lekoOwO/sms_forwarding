#!/usr/bin/env python3
import json
import re
from pathlib import Path


ROOT = Path(__file__).resolve().parents[3]
SOURCE = (ROOT / "components/idf_web/idf_web.cpp").read_text()
SPEC = json.loads((ROOT / "dev_doc/openapi.json").read_text())


def main() -> None:
    limits = SPEC["x-requestLimits"]
    assert limits == {
        "requestLineBytes": 2048,
        "totalHeaderBytes": 8192,
        "bodyBytes": 16384,
        "description": limits["description"],
    }
    deferred = set(SPEC["x-espIdfMigration"]["deferredRoutes"])
    assert deferred == set()
    assert set(SPEC["x-espIdfMigration"]["blockedContracts"]) == set()
    provisioning = SPEC["x-apProvisioning"]
    assert provisioning["localAddress"] == "192.168.1.1"
    assert set(provisioning["unauthenticatedRoutes"]) == {
        "GET /", "GET /wifiscan", "GET /apstatus", "POST /wificonfig"
    }
    assert SPEC["x-configSchema"]["currentVersion"] == 6
    assert set(SPEC["paths"]["/api/ota/start"]["post"]["responses"]) == {
        "201", "400", "401", "403", "409", "413", "500"
    }
    assert set(SPEC["paths"]["/api/ota/chunk"]["post"]["responses"]) == {
        "200", "400", "401", "403", "409", "413", "500"
    }
    assert set(SPEC["paths"]["/api/ota/finish"]["post"]["responses"]) == {
        "202", "401", "403", "409", "413", "429"
    }

    documented = {
        f"{method.upper()} {path}"
        for path, item in SPEC["paths"].items()
        for method in item
        if method.lower() in {"get", "post", "put", "delete", "patch"}
    }
    registered = set()
    for path, method in re.findall(
        r'register_handler\(s_server, "([^"]+)", (HTTP_[A-Z]+),', SOURCE
    ):
        verbs = ("GET", "POST") if method == "HTTP_ANY" else (method[5:],)
        registered.update(f"{verb} {path}" for verb in verbs)
    assert documented - deferred <= registered
    assert deferred.isdisjoint(registered)
    assert {
        "GET /api/config/export", "POST /api/config/export",
        "POST /api/config/restore/start", "POST /api/config/restore/chunk",
        "POST /api/config/restore/finish",
    } <= registered
    assert {"GET /tools", "GET /sms"} <= registered
    csrf_methods = {
        f"{method.upper()} {path}"
        for path, item in SPEC["paths"].items()
        for method, operation in item.items()
        if method.lower() in {"get", "post"}
        and any(parameter.get("$ref", "").endswith("/CsrfToken")
                for parameter in operation.get("parameters", []))
    }
    assert csrf_methods == {
        "POST /save", "POST /sendsms", "POST /ping", "GET /flight", "GET /at",
        "GET /modem", "GET /wifi", "GET /api/config/export", "POST /api/config/export",
        "POST /api/config/restore/start", "POST /api/config/restore/chunk",
        "POST /api/config/restore/finish", "POST /api/ota/start", "POST /api/ota/chunk",
        "POST /api/ota/finish",
    }

    # Provisioning endpoints are firmware-private AP routes. Legacy plaintext
    # Import and raw OTA entry points remain absent; signed OTA uses /api/ota/*.
    assert not any(path in SOURCE for path in ('"/import"', '"/update"', '"/config.json"'))
    assert "handle_import_config" not in SOURCE
    assert "handle_ota_update" not in SOURCE

    action_codes = set(SPEC["components"]["schemas"]["ActionResult"]["properties"]["code"]["enum"])
    required_codes = {
        "ACTION_JOB_ACCEPTED", "ACTION_JOB_NOT_FOUND", "ACTION_JOB_QUEUE_FULL",
        "ACTION_INPUT_INVALID", "ACTION_INPUT_TOO_LONG", "ACTION_TOO_MANY_FIELDS",
        "ACTION_CONFIG_SAVED", "ACTION_CONFIG_SAVE_FAILED", "ACTION_CONFIG_ACCOUNT_REQUIRED",
        "ACTION_SMS_PHONE_REQUIRED", "ACTION_SMS_CONTENT_REQUIRED", "ACTION_SMS_SENT", "ACTION_SMS_FAILED",
        "ACTION_PING_OK", "ACTION_PING_MODEM_ERROR", "ACTION_PING_UNREACHABLE", "ACTION_PING_TIMEOUT",
        "ACTION_WIFI_RESTARTING", "ACTION_AT_REJECTED", "ACTION_FLIGHT_FAILED",
    }
    assert required_codes <= action_codes

    config_update = SPEC["components"]["schemas"]["ConfigUpdate"]
    assert config_update["maxProperties"] == 51
    log_limit = SPEC["paths"]["/log"]["get"]["parameters"][1]["schema"]
    assert log_limit["maximum"] == 50


if __name__ == "__main__":
    main()
