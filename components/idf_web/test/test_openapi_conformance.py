#!/usr/bin/env python3
import json
import re
from pathlib import Path


ROOT = Path(__file__).resolve().parents[3]
SOURCE = (ROOT / "components/idf_web/idf_web.cpp").read_text()
SPEC = json.loads((ROOT / "dev_doc/openapi.json").read_text())
CONFIG_SCHEMA = json.loads((ROOT / "dev_doc/config-schema/v7.json").read_text())


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
    assert SPEC["x-configSchema"]["currentVersion"] == 7
    assert set(SPEC["paths"]["/api/ota/start"]["post"]["responses"]) == {
        "201", "400", "401", "403", "409", "413", "500"
    }
    assert set(SPEC["paths"]["/api/ota/chunk"]["post"]["responses"]) == {
        "200", "400", "401", "403", "409", "413", "500"
    }
    assert set(SPEC["paths"]["/api/ota/finish"]["post"]["responses"]) == {
        "202", "401", "403", "409", "413", "429"
    }
    restart = SPEC["paths"]["/api/device/restart"]
    assert set(restart) == {"post"}
    assert restart["post"]["parameters"] == [{"$ref": "#/components/parameters/CsrfToken"}]
    assert "requestBody" not in restart["post"]
    assert "body must be empty" in restart["post"]["description"]
    assert set(restart["post"]["responses"]) == {"200", "400", "401", "403", "405", "409", "413"}
    assert restart["post"]["responses"]["200"]["content"]["application/json"]["schema"] == {
        "$ref": "#/components/schemas/ActionResult"
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
        "POST /api/config/restore/finish", "GET /api/push/test", "POST /api/push/test",
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
        "POST /api/ota/finish", "POST /api/push/test", "POST /api/device/restart",
        "POST /api/esim", "POST /api/push/ca/probe", "POST /api/push/ca/install",
    }

    assert set(SPEC["paths"]["/api/push/ca/probe"]) == {"post"}
    assert set(SPEC["paths"]["/api/push/ca/install"]) == {"post"}
    assert set(SPEC["paths"]["/api/push/ca/status"]) == {"get"}
    assert SPEC["paths"]["/api/push/ca/install"]["post"]["requestBody"]["content"]["application/pkix-cert"]["schema"]["maxLength"] == 8192
    for path, verb, allow in (
        ("/api/push/ca/probe", "post", "POST"),
        ("/api/push/ca/install", "post", "POST"),
        ("/api/push/ca/status", "get", "GET"),
    ):
        operation = SPEC["paths"][path][verb]
        method_error = operation["responses"]["405"]
        assert method_error["headers"]["Allow"]["schema"] == {
            "type": "string", "const": allow,
        }
        assert method_error["content"]["application/json"]["schema"] == {
            "$ref": "#/components/schemas/ActionResult",
        }
    assert "only query key" in SPEC["paths"]["/api/push/ca/probe"]["post"]["description"]
    assert "only query key" in SPEC["paths"]["/api/push/ca/status"]["get"]["description"]
    install_description = SPEC["paths"]["/api/push/ca/install"]["post"]["description"]
    for phrase in ("only query keys", "Content-Length", "Transfer-Encoding"):
        assert phrase in install_description
    action_data = SPEC["components"]["schemas"]["ActionData"]
    assert action_data["additionalProperties"] is False
    ca_data = action_data["properties"]
    assert ca_data["nonce"] == {
        "type": "string", "minLength": 32, "maxLength": 32,
        "pattern": "^[0-9a-f]{32}$",
    }
    assert ca_data["expiresInMs"] == {
        "type": "integer", "minimum": 1, "maximum": 120000,
    }
    assert ca_data["configured"] == {"type": "boolean"}
    assert ca_data["sha256"] == {
        "type": "string", "pattern": "^(?:|[0-9a-f]{64})$",
    }
    chain = ca_data["chain"]
    assert {key: chain[key] for key in ("type", "minItems", "maxItems")} == {
        "type": "array", "minItems": 1, "maxItems": 4,
    }
    entry = chain["items"]
    assert entry["additionalProperties"] is False
    assert set(entry["required"]) == {"certSha256", "issuerDer", "aki"}
    assert entry["properties"] == {
        "certSha256": {"type": "string", "pattern": "^[0-9a-f]{64}$"},
        "issuerDer": {
            "type": "string", "contentEncoding": "base64", "maxLength": 216,
        },
        "aki": {"type": "string", "pattern": "^(?:[0-9a-f]{2}){0,32}$"},
    }

    push_test = SPEC["paths"]["/api/push/test"]
    assert set(push_test) == {"get", "post"}
    assert push_test["get"]["parameters"][0]["schema"] == {
        "type": "integer", "minimum": 0, "maximum": 4
    }
    for operation in (push_test["get"], push_test["post"]):
        detail = next(parameter for parameter in operation["parameters"]
                      if parameter.get("name") == "detail")
        assert detail["required"] is False
        assert detail["schema"] == {"type": "string", "enum": ["1"]}
        assert "bounded terminal diagnostic detail" in detail["description"]
    assert push_test["post"]["parameters"][2]["$ref"].endswith("/CsrfToken")
    assert "requestBody" not in push_test["post"]
    assert "body must be empty" in push_test["post"]["description"]
    assert "five-key" in push_test["get"]["description"]
    push_status = SPEC["components"]["schemas"]["PushTestStatus"]
    assert set(push_status["required"]) == {"queued", "running", "done", "success", "message"}
    assert push_status["additionalProperties"] is False
    assert {name: schema["type"] for name, schema in push_status["properties"].items()} == {
        "queued": "boolean", "running": "boolean", "done": "boolean",
        "success": "boolean", "message": "string", "cleanupMessage": "string",
        "failureReason": "string", "cleanupReason": "string", "resetNeeded": "boolean",
    }
    cleanup_message = push_status["properties"]["cleanupMessage"]
    assert "cleanupMessage" not in push_status["required"]
    assert cleanup_message["maxLength"] == 95
    assert cleanup_message["enum"] == [
        "HTTPS cleanup socket close failed",
        "HTTPS cleanup SSL config restore failed",
        "HTTPS cleanup autofree config restore failed",
        "HTTPS cleanup encoding config restore failed",
        "HTTPS cleanup PDP deactivate failed",
        "HTTPS cleanup PDP profile restore failed",
    ]
    assert push_status["properties"]["failureReason"]["enum"] == [
        "command_failure", "timeout", "response_invalid", "terminal_failure",
        "poll_timeout", "result_nonzero", "unknown",
    ]
    assert push_status["properties"]["cleanupReason"]["enum"] == [
        "command_failure", "timeout", "response_invalid", "result_nonzero", "unknown",
    ]
    assert {"failureReason", "cleanupReason", "resetNeeded"}.isdisjoint(
        push_status["required"]
    )
    assert len(push_status["oneOf"]) == 5

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
        "ACTION_PING_UNSUPPORTED",
        "ACTION_WIFI_RESTARTING", "ACTION_DEVICE_RESTARTING", "ACTION_AT_REJECTED", "ACTION_FLIGHT_FAILED",
        "ACTION_ESIM_IDLE", "ACTION_ESIM_RUNNING", "ACTION_ESIM_COMPLETE", "ACTION_ESIM_FAILED",
        "ACTION_ESIM_BUSY", "ACTION_ESIM_HANDLE_STALE",
    }
    assert required_codes <= action_codes
    ping = SPEC["paths"]["/ping"]["post"]
    assert "unsupported" in ping["summary"].lower()
    assert "unsupported" in ping["description"].lower()
    assert "enables the PDP context" not in ping["description"]

    config_update = SPEC["components"]["schemas"]["ConfigUpdate"]
    assert config_update["maxProperties"] == 66
    snapshot_config = SPEC["components"]["schemas"]["DeviceSnapshot"]["properties"]["config"]
    for field in ("emailEnabled", "pushEnabled"):
        assert field in snapshot_config["required"]
        assert snapshot_config["properties"][field]["type"] == "boolean"
        assert config_update["properties"][field]["enum"] == ["0", "1"]
    push_channel = SPEC["components"]["schemas"]["PushChannel"]
    assert {"cellularEnabled", "cellularUrlSet"} <= set(push_channel["required"])
    assert "cellularUrl" not in push_channel["properties"]
    for pattern in (
        "^push[0-4]cellularEnabled$", "^push[0-4]cellularUrl$",
        "^push[0-4]cellularUrlClear$",
    ):
        assert pattern in config_update["patternProperties"]
    config_properties = CONFIG_SCHEMA["properties"]["config"]["properties"]
    update_properties = config_update["properties"]
    assert "forwardRules" in snapshot_config["required"]
    assert snapshot_config["properties"]["forwardRules"]["x-maxUtf8Bytes"] == 2048
    assert update_properties["forwardRules"]["x-maxUtf8Bytes"] == 2048
    for field in ("smtpSendTo", "adminPhone"):
        assert update_properties[field]["x-maxUtf8Bytes"] == config_properties[field]["x-maxUtf8Bytes"]
    assert update_properties["smtpPort"]["minimum"] == config_properties["smtpPort"]["minimum"]
    assert update_properties["smtpPort"]["maximum"] == config_properties["smtpPort"]["maximum"]

    field_limits = SOURCE[
        SOURCE.index("static size_t modern_field_limit"):
        SOURCE.index("static bool validate_modern_fields")
    ]
    assert re.search(r'key == "smtpSendTo"\)\s+return MAX_SMTP_RECIPIENT_BYTES;', field_limits)
    assert re.search(r'key == "adminPhone"\)\s+return MAX_ADMIN_PHONE_BYTES;', field_limits)
    log_limit = SPEC["paths"]["/log"]["get"]["parameters"][1]["schema"]
    assert log_limit["maximum"] == 50


if __name__ == "__main__":
    main()
