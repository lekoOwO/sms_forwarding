#!/usr/bin/env python3
import base64
import hashlib
import re
import subprocess
import tempfile
from pathlib import Path


ROOT = Path(__file__).resolve().parents[3]
WEB = ROOT / "components/idf_web"


def function_definition(source: str, name: str) -> str:
    match = re.search(rf"\b(?:bool|esp_err_t)\s+{re.escape(name)}\s*\(", source)
    assert match is not None
    brace = source.index("{", match.end())
    depth = 1
    for index in range(brace + 1, len(source)):
        if source[index] == "{":
            depth += 1
        elif source[index] == "}":
            depth -= 1
            if depth == 0:
                return source[match.start():index + 1]
    raise AssertionError(f"unterminated function: {name}")


def check_public_key_hash_function(source: str) -> None:
    decode = function_definition(source, "decode_embedded_public_key")
    fingerprint = function_definition(source, "idf_web_ota_get_public_key_sha256")
    fixtures = (
        (
            b"test-public-key-der",
            "d7699fd512f82cfa86924a2ed90f3f165b1b21795455641f4327b24dc04fbe0b",
        ),
        (
            b"test-public-key-der-mutated",
            hashlib.sha256(b"test-public-key-der-mutated").hexdigest(),
        ),
    )
    assert fixtures[0][1] != fixtures[1][1]
    for der, expected in fixtures:
        encoded = base64.b64encode(der)
        def byte_list(value):
            return ",".join(str(byte) for byte in value)
        harness = f'''
#include <cassert>
#include <cstddef>
#include <cstdint>
#include <cstring>

using esp_err_t = int;
static constexpr esp_err_t ESP_OK = 0;
static constexpr esp_err_t ESP_FAIL = -1;
static constexpr esp_err_t ESP_ERR_INVALID_ARG = -2;
static const uint8_t kEncoded[] = {{{byte_list(encoded)}}};
static const uint8_t kDer[] = {{{byte_list(der)}}};
static const uint8_t kDigest[] = {{{byte_list(bytes.fromhex(expected))}}};
static const uint8_t kWrongDigest[] = {{{byte_list(bytes.fromhex("a3b8325cb8bbff1acaa402b7f1a39124b1297462da44f4c57b60929c996c4735"))}}};
static bool decode_fails = false;
static bool hash_fails = false;

extern const uint8_t ota_public_key_b64_start[] asm("ota_public_key_b64_start");
extern const uint8_t ota_public_key_b64_end[] asm("ota_public_key_b64_end");
asm(".pushsection .rodata\\n"
    ".global ota_public_key_b64_start\\n"
    "ota_public_key_b64_start:\\n"
    ".byte {byte_list(encoded)}\\n"
    ".global ota_public_key_b64_end\\n"
    "ota_public_key_b64_end:\\n"
    ".popsection\\n");

int mbedtls_base64_decode(uint8_t* output, size_t capacity, size_t* output_size,
                          const uint8_t* input, size_t input_size) {{
    if (decode_fails) {{
        std::memset(output, 0xA5, capacity);
        *output_size = capacity;
        return -1;
    }}
    if (input_size != sizeof(kEncoded) || capacity < sizeof(kDer) ||
        std::memcmp(input, kEncoded, sizeof(kEncoded)) != 0) return -1;
    std::memcpy(output, kDer, sizeof(kDer));
    *output_size = sizeof(kDer);
    return 0;
}}

int mbedtls_sha256(const uint8_t* input, size_t input_size,
                   uint8_t output[32], int is224) {{
    if (hash_fails) {{
        std::memset(output, 0xA5, 32);
        return -1;
    }}
    if (is224 != 0 || input_size != sizeof(kDer) ||
        std::memcmp(input, kDer, sizeof(kDer)) != 0) return -1;
    std::memcpy(output, kDigest, sizeof(kDigest));
    return 0;
}}

{decode}
{fingerprint}

int main() {{
    uint8_t actual[32] = {{}};
    assert(idf_web_ota_get_public_key_sha256(actual) == ESP_OK);
    assert(std::memcmp(actual, kDigest, sizeof(actual)) == 0);
    std::memset(actual, 0x5A, sizeof(actual));
    decode_fails = true;
    assert(idf_web_ota_get_public_key_sha256(actual) == ESP_FAIL);
    for (uint8_t byte : actual) assert(byte == 0);
    decode_fails = false;
    std::memset(actual, 0x5A, sizeof(actual));
    hash_fails = true;
    assert(idf_web_ota_get_public_key_sha256(actual) == ESP_FAIL);
    for (uint8_t byte : actual) assert(byte == 0);
}}
'''
        with tempfile.TemporaryDirectory() as directory:
            test_source = Path(directory) / "public_key_hash_test.cpp"
            binary = Path(directory) / "public_key_hash_test"
            test_source.write_text(harness, encoding="utf-8")
            subprocess.run([
                "g++", "-std=c++17", "-Wall", "-Wextra", "-Werror",
                str(test_source), "-o", str(binary),
            ], check=True)
            subprocess.run([str(binary)], check=True)
            if der == fixtures[0][0]:
                mutation = harness.replace(
                    "const int hash_error = mbedtls_sha256(key_der, key_size, output, 0);",
                    "std::memcpy(output, kWrongDigest, 32); const int hash_error = 0;",
                    1,
                )
                assert mutation != harness
                test_source.write_text(mutation, encoding="utf-8")
                subprocess.run([
                    "g++", "-std=c++17", "-Wall", "-Wextra", "-Werror",
                    str(test_source), "-o", str(binary),
                ], check=True)
                rejected = subprocess.run([str(binary)], capture_output=True, check=False)
                assert rejected.returncode != 0
                for old, new in (
                    ("std::memset(output, 0, 32);", ""),
                    ("return ESP_FAIL;", "return ESP_OK;"),
                ):
                    mutation = harness.replace(old, new, 1)
                    assert mutation != harness
                    test_source.write_text(mutation, encoding="utf-8")
                    subprocess.run([
                        "g++", "-std=c++17", "-Wall", "-Wextra", "-Werror",
                        str(test_source), "-o", str(binary),
                    ], check=True)
                    rejected = subprocess.run(
                        [str(binary)], capture_output=True, check=False,
                    )
                    assert rejected.returncode != 0


def main() -> None:
    key_bytes = base64.b64decode((WEB / "ota_public_key.der.b64").read_text().strip(), validate=True)
    key_fingerprint = hashlib.sha256(key_bytes).hexdigest()
    assert key_fingerprint == (
        "a3b8325cb8bbff1acaa402b7f1a39124b1297462da44f4c57b60929c996c4735"
    )
    workflow = (ROOT / ".github/workflows/build.yml").read_text(encoding="utf-8")
    workflow_pin = re.search(r"--expected-public-sha256 ([0-9a-f]{64})", workflow)
    assert workflow_pin is not None and workflow_pin.group(1) == key_fingerprint
    mutated = workflow.replace(workflow_pin.group(1), "0" * 64, 1)
    mutated_pin = re.search(r"--expected-public-sha256 ([0-9a-f]{64})", mutated)
    assert mutated_pin is not None and mutated_pin.group(1) != key_fingerprint
    sdkconfig = (ROOT / "sdkconfig.defaults").read_text(encoding="utf-8")
    assert "CONFIG_BOOTLOADER_APP_ROLLBACK_ENABLE=y" in sdkconfig
    assert "CONFIG_APP_REPRODUCIBLE_BUILD=y" in sdkconfig
    assert "CONFIG_BOOTLOADER_APP_ANTI_ROLLBACK" not in sdkconfig
    app_main = (ROOT / "main/app_main.cpp").read_text(encoding="utf-8")
    config_failure = app_main.index("if (cfg_err != ESP_OK)")
    config_failure_return = app_main.index("return;", config_failure)
    assert app_main.index("idf_web_ota_health_check(false, false, true)", config_failure) < config_failure_return
    assert "idf_web_ota_init();" in app_main
    ota_init = app_main.index("idf_web_ota_init();")
    usb_start = app_main.index("idf_usb_recovery_start())")
    assert ota_init < usb_start
    ota_runtime = (WEB / "idf_web_ota.cpp").read_text(encoding="utf-8")
    assert "decode_embedded_public_key" in ota_runtime
    assert "idf_web_ota_get_public_key_sha256" in ota_runtime
    verify_signature = function_definition(ota_runtime, "verify_signature")
    assert "decode_embedded_public_key(key_der, sizeof(key_der), &key_size)" in verify_signature
    check_public_key_hash_function(ota_runtime)
    health = ota_runtime[ota_runtime.index("esp_err_t idf_web_ota_health_check") :]
    assert "if (!lock()) return ESP_ERR_TIMEOUT;" in health
    assert "if (!other || other == running)" in ota_runtime
    assert "if (other_error != ESP_OK)" in ota_runtime
    assert "ESP_OTA_IMG_INVALID" in ota_runtime

    harness = r'''
#include <cassert>
#include <cstdint>
#include <string>
#include <vector>

#include "idf_web_ota_core.h"

struct Fake {
    uint32_t accepted = 0;
    uint32_t pending = 0;
    uint32_t target = 0x1f0000;
    bool signature_ok = true;
    bool begin_ok = true;
    bool write_ok = true;
    bool hash_begin_ok = true;
    bool hash_update_ok = true;
    bool metadata_ok = true;
    bool end_ok = true;
    bool boot_ok = true;
    int begin_calls = 0;
    int abort_calls = 0;
    std::vector<uint8_t> image;
    std::vector<uint8_t> hashed;
    std::vector<std::string> calls;
};

static bool counters(void* raw, uint32_t* accepted, uint32_t* pending) {
    auto& f = *static_cast<Fake*>(raw); *accepted = f.accepted; *pending = f.pending;
    f.calls.push_back("counters"); return true;
}
static bool signature(void* raw, const uint8_t*, size_t, const uint8_t*, size_t) {
    auto& f = *static_cast<Fake*>(raw); f.calls.push_back("signature"); return f.signature_ok;
}
static bool hash_begin(void* raw) {
    auto& f = *static_cast<Fake*>(raw); f.hashed.clear(); f.calls.push_back("hash-begin"); return f.hash_begin_ok;
}
static bool hash_update(void* raw, const uint8_t* data, size_t size) {
    auto& f = *static_cast<Fake*>(raw); f.hashed.insert(f.hashed.end(), data, data + size);
    f.calls.push_back("hash-update"); return f.hash_update_ok;
}
static bool hash_matches(void* raw, const char* expected) {
    auto& f = *static_cast<Fake*>(raw); f.calls.push_back("hash-final");
    return f.hashed == std::vector<uint8_t>({'a', 'b', 'c'}) &&
        std::string(expected) == "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";
}
static bool begin(void* raw, size_t, uint32_t* address) {
    auto& f = *static_cast<Fake*>(raw); ++f.begin_calls; f.calls.push_back("begin");
    *address = f.target; return f.begin_ok;
}
static bool write(void* raw, const uint8_t* data, size_t size) {
    auto& f = *static_cast<Fake*>(raw); f.calls.push_back("write");
    f.image.insert(f.image.end(), data, data + size); return f.write_ok;
}
static bool finish(void* raw) {
    auto& f = *static_cast<Fake*>(raw); f.calls.push_back("end"); return f.end_ok;
}
static void abort_ota(void* raw) {
    auto& f = *static_cast<Fake*>(raw); ++f.abort_calls; f.calls.push_back("abort");
}
static bool store(void* raw, uint32_t counter, uint32_t address) {
    auto& f = *static_cast<Fake*>(raw); f.calls.push_back("metadata");
    if (!f.metadata_ok) return false;
    f.pending = counter;
    return address == f.target;
}
static void clear(void* raw) {
    auto& f = *static_cast<Fake*>(raw); f.calls.push_back("clear"); f.pending = 0;
}
static bool boot(void* raw, uint32_t address) {
    auto& f = *static_cast<Fake*>(raw); f.calls.push_back("boot");
    return f.boot_ok && address == f.target;
}
static IdfWebOtaPlatform platform(Fake& f) {
    return {&f, counters, signature, hash_begin, hash_update, hash_matches,
            begin, write, finish, abort_ota, store, clear, boot};
}

struct HealthFake {
    bool bind_ok = true, mark_ok = true, persist_ok = true, clear_ok = true;
    bool bound = false, marked = false, persisted = false, cleared = false, rolled_back = false;
};
static bool health_bind(void* raw, uint32_t address) {
    auto& f = *static_cast<HealthFake*>(raw); f.bound = true;
    return f.bind_ok && address == 0x1f0000;
}
static bool health_mark(void* raw) {
    auto& f = *static_cast<HealthFake*>(raw); f.marked = true; return f.mark_ok;
}
static bool health_persist(void* raw, uint32_t counter) {
    auto& f = *static_cast<HealthFake*>(raw); f.persisted = true;
    return f.persist_ok && counter == 31;
}
static bool health_clear(void* raw) {
    auto& f = *static_cast<HealthFake*>(raw); f.cleared = true; return f.clear_ok;
}
static void health_rollback(void* raw) { static_cast<HealthFake*>(raw)->rolled_back = true; }
static IdfWebOtaHealthPlatform health_platform(HealthFake& f) {
    return {&f, health_bind, health_mark, health_persist, health_clear, health_rollback};
}

static const std::string manifest =
    R"({"format":1,"releaseCounter":31,"sha256":"ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad","size":3,"target":"esp32c3","version":"1.1.4"})";
static const uint8_t sig[] = {0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01};
static const uint8_t abc[] = {'a', 'b', 'c'};

int main() {
    IdfWebOtaManifest parsed;
    assert(idf_web_ota_parse_manifest(manifest, parsed) == IdfWebOtaCode::Ok);
    assert(parsed.release_counter == 31 && parsed.size == 3 && parsed.version == "1.1.4");
    for (const std::string& rejected : {
        std::string(R"({ "format":1,"releaseCounter":31,"sha256":"ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad","size":3,"target":"esp32c3","version":"1.1.4"})"),
        std::string(R"({"format":1,"format":1,"releaseCounter":31,"sha256":"ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad","size":3,"target":"esp32c3","version":"1.1.4"})"),
        std::string(R"({"format":1,"releaseCounter":31,"sha256":"ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad","size":3,"target":"esp32c3","version":"1.1.4","extra":1})"),
        std::string(R"({"format":"1","releaseCounter":31,"sha256":"ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad","size":3,"target":"esp32c3","version":"1.1.4"})"),
        std::string(R"({"format":1,"releaseCounter":031,"sha256":"ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad","size":3,"target":"esp32c3","version":"1.1.4"})")}) {
        assert(idf_web_ota_parse_manifest(rejected, parsed) == IdfWebOtaCode::ManifestInvalid);
    }

    Fake bad_signature; bad_signature.signature_ok = false;
    IdfWebOtaSession bad_sig_session(platform(bad_signature));
    assert(bad_sig_session.start(manifest, sig, sizeof(sig), 7, 10) == IdfWebOtaCode::SignatureInvalid);
    assert(bad_signature.begin_calls == 0);

    Fake replay; replay.accepted = 31;
    IdfWebOtaSession replay_session(platform(replay));
    assert(replay_session.start(manifest, sig, sizeof(sig), 8, 10) == IdfWebOtaCode::Replay);
    assert(replay.begin_calls == 0);
    replay.accepted = 0; replay.pending = 31;
    IdfWebOtaSession pending_replay(platform(replay));
    assert(pending_replay.start(manifest, sig, sizeof(sig), 8, 10) == IdfWebOtaCode::Replay);

    Fake too_long_signature;
    IdfWebOtaSession signature_bound(platform(too_long_signature));
    const uint8_t oversized_signature[73] = {};
    assert(signature_bound.start(manifest, oversized_signature, sizeof(oversized_signature), 8, 10) ==
           IdfWebOtaCode::SignatureInvalid);
    assert(too_long_signature.begin_calls == 0);

    Fake wrong_order;
    IdfWebOtaSession ordered(platform(wrong_order));
    assert(ordered.start(manifest, sig, sizeof(sig), 9, 10) == IdfWebOtaCode::Ok);
    assert(ordered.append(99, 0, abc, sizeof(abc), 11) == IdfWebOtaCode::SessionInvalid);
    assert(ordered.active() && wrong_order.abort_calls == 0);
    assert(!ordered.cancel_upload(99) && ordered.active());
    assert(ordered.cancel_upload(9) && !ordered.active() && wrong_order.abort_calls == 1);
    assert(ordered.start(manifest, sig, sizeof(sig), 9, 11) == IdfWebOtaCode::Ok);
    assert(ordered.append(9, 1, abc, sizeof(abc), 12) == IdfWebOtaCode::ChunkInvalid);
    assert(!ordered.active() && wrong_order.abort_calls == 2);

    Fake happy;
    IdfWebOtaSession session(platform(happy));
    assert(session.start(manifest, sig, sizeof(sig), 10, 100) == IdfWebOtaCode::Ok);
    size_t next = 0;
    assert(session.append(10, 0, abc, sizeof(abc), 101, &next) == IdfWebOtaCode::Ok && next == 3);
    assert(session.prepare_finish(10) == IdfWebOtaCode::Ok);
    assert(session.finish(10) == IdfWebOtaCode::Ok);
    assert(happy.pending == 31 && !session.active());
    assert(happy.calls[happy.calls.size() - 2] == "metadata");
    assert(happy.calls.back() == "boot");

    Fake queue_failure;
    IdfWebOtaSession queued(platform(queue_failure));
    assert(queued.start(manifest, sig, sizeof(sig), 14, 100) == IdfWebOtaCode::Ok);
    assert(queued.append(14, 0, abc, sizeof(abc), 101) == IdfWebOtaCode::Ok);
    assert(queued.prepare_finish(14) == IdfWebOtaCode::Ok && queued.finishing());
    assert(queued.cancel_finish(14) && !queued.finishing() && queued.active());
    assert(queued.prepare_finish(14) == IdfWebOtaCode::Ok);

    Fake bad_hash;
    IdfWebOtaSession hash_session(platform(bad_hash));
    assert(hash_session.start(manifest, sig, sizeof(sig), 11, 1) == IdfWebOtaCode::Ok);
    const uint8_t abd[] = {'a', 'b', 'd'};
    assert(hash_session.append(11, 0, abd, sizeof(abd), 2) == IdfWebOtaCode::Ok);
    assert(hash_session.prepare_finish(11) == IdfWebOtaCode::Ok);
    assert(hash_session.finish(11) == IdfWebOtaCode::HashInvalid);
    assert(bad_hash.abort_calls == 1 && bad_hash.pending == 0);

    Fake metadata_fail; metadata_fail.metadata_ok = false;
    IdfWebOtaSession metadata_session(platform(metadata_fail));
    assert(metadata_session.start(manifest, sig, sizeof(sig), 12, 1) == IdfWebOtaCode::Ok);
    assert(metadata_session.append(12, 0, abc, sizeof(abc), 2) == IdfWebOtaCode::Ok);
    assert(metadata_session.prepare_finish(12) == IdfWebOtaCode::Ok);
    assert(metadata_session.finish(12) == IdfWebOtaCode::MetadataFailed);
    assert(metadata_fail.abort_calls == 0);
    for (const auto& call : metadata_fail.calls) assert(call != "boot");

    Fake end_fail; end_fail.end_ok = false;
    IdfWebOtaSession ending(platform(end_fail));
    assert(ending.start(manifest, sig, sizeof(sig), 15, 1) == IdfWebOtaCode::Ok);
    assert(ending.append(15, 0, abc, sizeof(abc), 2) == IdfWebOtaCode::Ok);
    assert(ending.prepare_finish(15) == IdfWebOtaCode::Ok);
    assert(ending.finish(15) == IdfWebOtaCode::FinalizeFailed && end_fail.abort_calls == 1);

    Fake boot_fail; boot_fail.boot_ok = false;
    IdfWebOtaSession booting(platform(boot_fail));
    assert(booting.start(manifest, sig, sizeof(sig), 16, 1) == IdfWebOtaCode::Ok);
    assert(booting.append(16, 0, abc, sizeof(abc), 2) == IdfWebOtaCode::Ok);
    assert(booting.prepare_finish(16) == IdfWebOtaCode::Ok);
    assert(booting.finish(16) == IdfWebOtaCode::BootFailed);
    assert(boot_fail.abort_calls == 0 && boot_fail.pending == 0);

    Fake incomplete;
    IdfWebOtaSession partial(platform(incomplete));
    assert(partial.start(manifest, sig, sizeof(sig), 17, 1) == IdfWebOtaCode::Ok);
    assert(partial.append(17, 0, abc, 1, 20) == IdfWebOtaCode::Ok);
    assert(!partial.expire(35, 20));
    assert(partial.prepare_finish(17) == IdfWebOtaCode::SessionInvalid);
    assert(incomplete.abort_calls == 1);

    Fake expired;
    IdfWebOtaSession expiring(platform(expired));
    assert(expiring.start(manifest, sig, sizeof(sig), 13, 0xfffffff0U) == IdfWebOtaCode::Ok);
    assert(expiring.expire(0x20U, 0x20U));
    assert(!expiring.active() && expired.abort_calls == 1);

    using S = IdfWebOtaImageState;
    using D = IdfWebOtaHealthDecision;
    assert(idf_web_ota_health_decide(S::PendingVerify, true, true, false, 30, 31, 0x1f0000, 0x1f0000) == D::Confirm);
    assert(idf_web_ota_health_decide(S::PendingVerify, false, true, false, 30, 31, 0x1f0000, 0x1f0000) == D::Wait);
    assert(idf_web_ota_health_decide(S::PendingVerify, true, true, true, 30, 31, 0x1f0000, 0x1f0000) == D::Rollback);
    assert(idf_web_ota_health_decide(S::PendingVerify, true, true, false, 31, 30, 0x1f0000, 0x1f0000) == D::Rollback);
    assert(idf_web_ota_health_decide(S::Valid, true, true, false, 30, 31, 0x1f0000, 0x1f0000) == D::CommitAccepted);
    assert(idf_web_ota_health_decide(S::Valid, true, true, false, 31, 0, 0x1f0000, 0) == D::None);
    assert(idf_web_ota_migration_recovery_allowed(S::PendingVerify, 0, 0, 0));
    assert(!idf_web_ota_migration_recovery_allowed(S::Valid, 0, 0, 0));
    assert(!idf_web_ota_migration_recovery_allowed(S::PendingVerify, 1, 0, 0));
    assert(!idf_web_ota_migration_recovery_allowed(S::PendingVerify, 0, 1, 0));
    assert(!idf_web_ota_migration_recovery_allowed(S::PendingVerify, 0, 0, 0x1f0000));

    HealthFake legacy;
    assert(idf_web_ota_apply_health(S::PendingVerify, true, true, false, 30, 31,
        0x1f0000, 0, health_platform(legacy)) == IdfWebOtaHealthResult::Done);
    assert(legacy.bound && legacy.marked && legacy.persisted && legacy.cleared && !legacy.rolled_back);

    HealthFake commit_failure; commit_failure.persist_ok = false;
    assert(idf_web_ota_apply_health(S::Valid, true, true, false, 30, 31,
        0x1f0000, 0x1f0000, health_platform(commit_failure)) == IdfWebOtaHealthResult::Retry);
    assert(commit_failure.persisted && !commit_failure.cleared && !commit_failure.rolled_back);

    HealthFake unknown_bootloader;
    assert(idf_web_ota_apply_health(S::Other, true, true, false, 0, 31,
        0x1f0000, 0x1f0000, health_platform(unknown_bootloader)) ==
        IdfWebOtaHealthResult::Waiting);
    assert(!unknown_bootloader.cleared && !unknown_bootloader.rolled_back);

    HealthFake deadline;
    assert(idf_web_ota_apply_health(S::PendingVerify, false, false, true, 30, 31,
        0x1f0000, 0x1f0000, health_platform(deadline)) == IdfWebOtaHealthResult::RolledBack);
    assert(deadline.rolled_back && !deadline.marked);
}
'''
    with tempfile.TemporaryDirectory() as directory:
        source = Path(directory) / "ota_test.cpp"
        binary = Path(directory) / "ota_test"
        source.write_text(harness, encoding="utf-8")
        subprocess.run([
            "g++", "-std=c++17", "-fno-exceptions", "-Wall", "-Wextra", "-Werror",
            f"-I{WEB / 'include'}", str(WEB / "idf_web_ota_core.cpp"), str(source),
            "-o", str(binary),
        ], check=True)
        subprocess.run([str(binary)], check=True)


if __name__ == "__main__":
    main()
