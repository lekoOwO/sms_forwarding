#include "idf_modem_https_wire.h"

#include <algorithm>
#include <cassert>
#include <cstdint>
#include <string>
#include <string_view>
#include <type_traits>
#include <utility>
#include <vector>

int fixture_tls_setup_result = 0;
int fixture_tls_handshake_result = 0;

namespace {

using idf_modem_https_wire::HttpResponse;
using idf_modem_https_wire::MipOpenLatch;
using idf_modem_https_wire::MipStateDisposition;
using idf_modem_https_wire::parse_cgact;
using idf_modem_https_wire::parse_cgdccont;
using idf_modem_https_wire::parse_cfg_response;
using idf_modem_https_wire::classify_mip_state;
using idf_modem_https_wire::parse_mip_state;
using idf_modem_https_wire::parse_mip_open;
using idf_modem_https_wire::parse_mip_urc;
using idf_modem_https_wire::parse_read;
using idf_modem_https_wire::parse_result;
using idf_modem_https_wire::scan_frame;
using idf_modem_https_wire::build_cgdccont_command;

std::string frame(std::string_view command, std::string_view body)
{
    std::string response = "\r\n";
    response.append(command.data(), command.size());
    response += "\r\n";
    response.append(body.data(), body.size());
    response += "\r\nOK\r\n";
    return response;
}

bool is_upper_hex(std::string_view value)
{
    return std::all_of(value.begin(), value.end(), [](unsigned char ch) {
        return (ch >= '0' && ch <= '9') || (ch >= 'A' && ch <= 'F');
    });
}

void assert_failure_message(std::string_view actual, std::string_view expected)
{
    assert(actual == expected);
    assert(actual.size() < 96);
    assert(actual != "Test push failed; see the log");
    for (const std::string_view forbidden : {"AT+", "fixture.example", "internet", "DER", "{}",
                                             "INITIAL", "CONNECTED", "CLOSED", "TCP", "\r", "\n"}) {
        assert(actual.find(forbidden) == std::string_view::npos);
    }
}

template <typename T, typename = void>
struct CleanupMessageAccessor {
    static std::string_view get(const T&) { return {}; }
};

template <typename T>
struct CleanupMessageAccessor<T, std::void_t<decltype(std::declval<const T&>().cleanupMessage)>> {
    static std::string_view get(const T& result) { return result.cleanupMessage; }
};

void assert_cleanup_message(const IdfModemHttpsPostResult& result,
                            std::string_view expected)
{
    const std::string_view actual = CleanupMessageAccessor<IdfModemHttpsPostResult>::get(result);
    assert(actual == expected);
    assert(!actual.empty() && actual.size() < 96);
    for (const std::string_view forbidden : {"AT+", "fixture", "request-apn", "CONNECTED",
                                             "TCP", "\r", "\n"}) {
        assert(actual.find(forbidden) == std::string_view::npos);
    }
}

constexpr std::string_view kInitialQueryCommandFailure =
    "HTTPS modem initial query command failed";
constexpr std::string_view kInitialQueryResponseInvalid =
    "HTTPS modem initial query response invalid";
constexpr std::string_view kStaleCloseCommandFailure =
    "HTTPS modem stale socket close command failed";
constexpr std::string_view kStaleCloseResponseInvalid =
    "HTTPS modem stale socket close response invalid";
constexpr std::string_view kPostCloseQueryCommandFailure =
    "HTTPS modem post-close query command failed";
constexpr std::string_view kPostCloseQueryResponseInvalid =
    "HTTPS modem post-close query response invalid";

enum class InitialStateMode {
    initial,
    connected_then_initial,
    closed_then_initial,
    state_failed,
    state_timeout,
    malformed_state,
    ambiguous_state,
    unknown_state,
    wrong_cid,
    close_failed,
    close_ambiguous,
    connected_after_close,
    post_close_state_failed,
};

struct InitialStateTranscript {
    explicit InitialStateTranscript(InitialStateMode selected) : mode(selected) {}

    InitialStateMode mode;
    size_t state_queries = 0;
    std::vector<std::string> commands;
    std::vector<bool> cleanup;
    std::string result_message;

    static IdfModemHttpsCommandResult send(void* context, std::string_view command,
                                           std::string& response, bool cleanup)
    {
        auto& transcript = *static_cast<InitialStateTranscript*>(context);
        transcript.commands.emplace_back(command);
        transcript.cleanup.push_back(cleanup);
        if (command == "AT+MIPSTATE=0") {
            ++transcript.state_queries;
            const bool initial = transcript.mode == InitialStateMode::initial ||
                                 ((transcript.mode == InitialStateMode::connected_then_initial ||
                                   transcript.mode == InitialStateMode::closed_then_initial) &&
                                  transcript.state_queries == 2);
            if (transcript.mode == InitialStateMode::state_failed) {
                return IdfModemHttpsCommandResult::failed;
            }
            if (transcript.mode == InitialStateMode::post_close_state_failed &&
                transcript.state_queries == 2) {
                return IdfModemHttpsCommandResult::failed;
            }
            if (transcript.mode == InitialStateMode::state_timeout) {
                return IdfModemHttpsCommandResult::timeout;
            }
            if (transcript.mode == InitialStateMode::malformed_state) {
                response = frame(command, "+MIPSTATE: 0,\"TCP\",\"fixture.example\",\"CONNECTED\"");
            } else if (transcript.mode == InitialStateMode::ambiguous_state) {
                response = frame(command, "+MIPSTATE: 0,,,,\"INITIAL\"\r\n"
                                          "+MIPSTATE: 0,\"TCP\",\"fixture.example\",443,\"CONNECTED\"");
            } else if (transcript.mode == InitialStateMode::unknown_state) {
                response = frame(command, "+MIPSTATE: 0,,,,\"OTHER\"");
            } else if (transcript.mode == InitialStateMode::wrong_cid) {
                response = frame(command,
                                 "+MIPSTATE: 1,\"TCP\",\"fixture.example\",443,\"CONNECTED\"");
            } else {
                const std::string_view state =
                    initial ? "+MIPSTATE: 0,,,,\"INITIAL\""
                    : transcript.mode == InitialStateMode::closed_then_initial
                        ? "+MIPSTATE: 0,\"TCP\",\"fixture.example\",443,\"CLOSED\""
                        : "+MIPSTATE: 0,\"TCP\",\"fixture.example\",443,\"CONNECTED\"";
                response = frame(command, state);
            }
            return IdfModemHttpsCommandResult::ok;
        }
        if (command == "AT+MIPCLOSE=0") {
            if (transcript.mode == InitialStateMode::close_failed) {
                return IdfModemHttpsCommandResult::failed;
            }
            response = frame(command, transcript.mode == InitialStateMode::close_ambiguous
                                          ? "+MIPCLOSE: 0,1"
                                          : "+MIPCLOSE: 0,0");
            return IdfModemHttpsCommandResult::ok;
        }
        return IdfModemHttpsCommandResult::failed;
    }

    static IdfModemHttpsCommandResult confirm(void*)
    {
        return IdfModemHttpsCommandResult::ok;
    }
};

IdfModemHttpsRunResult run_initial_state_transcript(InitialStateTranscript& transcript)
{
    IdfModemHttpsPostRequest request;
    request.url = "https://fixture.example/notify";
    request.body = "{}";
    request.rootCertificateDer = {'D', 'E', 'R'};
    request.rootCertificateSha256.fill(0xab);
    IdfModemHttpsCallbacks callbacks{
        &transcript, &InitialStateTranscript::send, &InitialStateTranscript::confirm};
    IdfModemHttpsPostResult result;
    const IdfModemHttpsRunResult outcome = idf_modem_https_run_post(request, callbacks, result);
    transcript.result_message = result.message;
    return outcome;
}

void check_initial_state_transcripts()
{
    InitialStateTranscript initial{InitialStateMode::initial};
    assert(run_initial_state_transcript(initial) == IdfModemHttpsRunResult::command_failed);
    assert((initial.commands == std::vector<std::string>{
                                    "AT+MIPSTATE=0", "AT+MIPCFG=\"cid\",0"}));
    assert(std::count(initial.commands.begin(), initial.commands.end(), "AT+MIPCLOSE=0") == 0);
    assert_failure_message(initial.result_message, "HTTPS modem runtime snapshot failed");

    InitialStateTranscript recovered{InitialStateMode::connected_then_initial};
    assert(run_initial_state_transcript(recovered) == IdfModemHttpsRunResult::command_failed);
    assert((recovered.commands == std::vector<std::string>{
                                      "AT+MIPSTATE=0", "AT+MIPCLOSE=0",
                                      "AT+MIPSTATE=0", "AT+MIPCFG=\"cid\",0"}));
    assert((recovered.cleanup == std::vector<bool>{false, true, false, false}));
    assert_failure_message(recovered.result_message, "HTTPS modem runtime snapshot failed");

    InitialStateTranscript closed{InitialStateMode::closed_then_initial};
    assert(run_initial_state_transcript(closed) == IdfModemHttpsRunResult::command_failed);
    assert((closed.commands == std::vector<std::string>{
                                   "AT+MIPSTATE=0", "AT+MIPCLOSE=0",
                                   "AT+MIPSTATE=0", "AT+MIPCFG=\"cid\",0"}));
    assert((closed.cleanup == std::vector<bool>{false, true, false, false}));
    assert_failure_message(closed.result_message, "HTTPS modem runtime snapshot failed");

    for (const auto& [mode, expected_message] : {
             std::pair{InitialStateMode::state_failed, kInitialQueryCommandFailure},
             std::pair{InitialStateMode::state_timeout, kInitialQueryCommandFailure},
             std::pair{InitialStateMode::malformed_state, kInitialQueryResponseInvalid},
             std::pair{InitialStateMode::ambiguous_state, kInitialQueryResponseInvalid},
             std::pair{InitialStateMode::unknown_state, kInitialQueryResponseInvalid},
             std::pair{InitialStateMode::wrong_cid, kInitialQueryResponseInvalid},
         }) {
        InitialStateTranscript rejected{mode};
        const IdfModemHttpsRunResult expected = mode == InitialStateMode::state_timeout
                                                    ? IdfModemHttpsRunResult::timed_out
                                                    : IdfModemHttpsRunResult::command_failed;
        assert(run_initial_state_transcript(rejected) == expected);
        assert((rejected.commands == std::vector<std::string>{"AT+MIPSTATE=0"}));
        assert(std::count(rejected.commands.begin(), rejected.commands.end(),
                          "AT+MIPCLOSE=0") == 0);
        assert_failure_message(rejected.result_message, expected_message);
    }

    for (const auto& [mode, expected_message] : {
             std::pair{InitialStateMode::close_failed, kStaleCloseCommandFailure},
             std::pair{InitialStateMode::close_ambiguous, kStaleCloseResponseInvalid},
         }) {
        InitialStateTranscript rejected{mode};
        assert(run_initial_state_transcript(rejected) == IdfModemHttpsRunResult::command_failed);
        assert((rejected.commands == std::vector<std::string>{
                                         "AT+MIPSTATE=0", "AT+MIPCLOSE=0"}));
        assert_failure_message(rejected.result_message, expected_message);
    }

    InitialStateTranscript still_connected{InitialStateMode::connected_after_close};
    assert(run_initial_state_transcript(still_connected) == IdfModemHttpsRunResult::command_failed);
    assert((still_connected.commands == std::vector<std::string>{
                                         "AT+MIPSTATE=0", "AT+MIPCLOSE=0",
                                         "AT+MIPSTATE=0"}));
    assert_failure_message(still_connected.result_message, kPostCloseQueryResponseInvalid);

    InitialStateTranscript post_close_failed{InitialStateMode::post_close_state_failed};
    assert(run_initial_state_transcript(post_close_failed) == IdfModemHttpsRunResult::command_failed);
    assert((post_close_failed.commands == std::vector<std::string>{
                                           "AT+MIPSTATE=0", "AT+MIPCLOSE=0",
                                           "AT+MIPSTATE=0"}));
    assert((post_close_failed.cleanup == std::vector<bool>{false, true, false}));
    assert_failure_message(post_close_failed.result_message, kPostCloseQueryCommandFailure);
}

enum class RemoteCloseMode {
    data_then_disconnect,
    disconnect_only,
    unread_data,
    duplicate_disconnect,
    open_ok_connected,
    open_ok_initial_connected,
    open_result_failed,
    open_duplicate,
    open_wrong_cid,
    open_disconnect,
    open_malformed,
    open_command_timeout,
    post_open_initial_timeout,
    post_open_state_command_failure,
    post_open_state_command_timeout,
    post_open_closed,
    post_open_wrong_cid,
    post_open_invalid,
    pdp_failure,
    runtime_config_failure,
    tls_setup_failure,
    tls_handshake_failure,
    request_write_failure,
    http_non_success,
    http_invalid_zero,
    http_invalid_high,
    http_invalid_max,
};

enum class CleanupFailure {
    none,
    socket_close,
    ssl,
    autofree,
    encoding,
    pdp_deactivate,
    pdp_profile,
    socket_close_and_ssl,
};

enum class CleanupFailurePhase {
    command,
    command_timeout,
    malformed_response,
    nonzero_response,
    unexpected_response,
    query_command,
    verify_mismatch,
    profile_mismatch,
};

enum class LateOpenKind {
    none,
    success,
    result_failed,
    duplicate,
    wrong_cid,
    disconnect,
    malformed,
};

enum class LateOpenStage {
    none,
    before_first_state,
    between_initial_polls,
    in_first_state_response,
    after_connected_before_confirm,
    after_confirm_before_first_send,
};

bool parse_decimal(std::string_view value, size_t& parsed)
{
    if (value.empty()) return false;
    parsed = 0;
    for (const char ch : value) {
        if (ch < '0' || ch > '9') return false;
        parsed = parsed * 10U + static_cast<size_t>(ch - '0');
    }
    return true;
}

struct RemoteCloseTranscript {
    explicit RemoteCloseTranscript(RemoteCloseMode selected,
                                   LateOpenKind late = LateOpenKind::none,
                                   LateOpenStage stage = LateOpenStage::none,
                                   CleanupFailure cleanup = CleanupFailure::none,
                                   CleanupFailurePhase phase = CleanupFailurePhase::command)
        : mode(selected), late_open(late), late_stage(stage), cleanup_failure(cleanup),
          cleanup_failure_phase(phase)
    {
        if (cleanup == CleanupFailure::pdp_deactivate ||
            cleanup == CleanupFailure::pdp_profile) {
            pdp_active = false;
        }
    }

    RemoteCloseMode mode;
    LateOpenKind late_open;
    LateOpenStage late_stage;
    CleanupFailure cleanup_failure;
    CleanupFailurePhase cleanup_failure_phase;
    bool late_consumed = false;
    size_t late_feed_calls = 0;
    size_t state_queries = 0;
    size_t open_commands = 0;
    size_t send_commands = 0;
    size_t read_commands = 0;
    size_t close_commands = 0;
    bool close_was_cleanup = false;
    uint8_t encoding_send = 0;
    uint8_t encoding_receive = 0;
    uint8_t autofree = 0;
    bool pdp_active = true;
    std::string current_apn = "fixture";
    std::string current_profile = "1,\"IPV4V6\",\"fixture\",,0,0,,,,";
    std::vector<std::string> cleanup_commands;
    std::vector<std::string_view> cleanup_steps;
    MipOpenLatch open_latch;

    bool cleanup_fails(CleanupFailure failure) const
    {
        return cleanup_failure == failure ||
               (cleanup_failure == CleanupFailure::socket_close_and_ssl &&
                (failure == CleanupFailure::socket_close || failure == CleanupFailure::ssl));
    }

    std::string late_open_bytes() const
    {
        switch (late_open) {
            case LateOpenKind::success:
                return "+MIPOPEN: 0,0\r\n";
            case LateOpenKind::result_failed:
                return "+MIPOPEN: 0,4\r\n";
            case LateOpenKind::duplicate:
                return "+MIPOPEN: 0,0\r\n+MIPOPEN: 0,0\r\n";
            case LateOpenKind::wrong_cid:
                return "+MIPOPEN: 1,0\r\n";
            case LateOpenKind::disconnect:
                return "+MIPURC: \"disconn\",0,2\r\n";
            case LateOpenKind::malformed:
                return "+MIPOPEN: 0\r\n";
            case LateOpenKind::none:
                return {};
        }
        return {};
    }

    bool feed_late_open_split()
    {
        const std::string bytes = late_open_bytes();
        assert(bytes.size() > 5);
        ++late_feed_calls;
        if (!open_latch.feed(std::string_view(bytes).substr(0, 5))) return false;
        ++late_feed_calls;
        return open_latch.feed(std::string_view(bytes).substr(5));
    }

    static IdfModemHttpsCommandResult send(void* context, std::string_view command,
                                           std::string& response, bool cleanup)
    {
        auto& transcript = *static_cast<RemoteCloseTranscript*>(context);
        if (cleanup) {
            transcript.open_latch.reset();
            transcript.cleanup_commands.emplace_back(command);
            if (command == "AT+MIPCLOSE=0") transcript.cleanup_steps.emplace_back("socket_close");
            else if (command == "AT+MIPCFG=\"ssl\",0,0,0") {
                transcript.cleanup_steps.emplace_back("ssl");
            } else if (command == "AT+MIPCFG=\"autofree\",0,0") {
                transcript.cleanup_steps.emplace_back("autofree");
            } else if (command == "AT+MIPCFG=\"encoding\",0,0,0") {
                transcript.cleanup_steps.emplace_back("encoding");
            } else if (command == "AT+CGACT=0,1") {
                transcript.cleanup_steps.emplace_back("pdp_deactivate");
            } else if (command == "AT+CGDCONT=1,\"IPV4V6\",\"fixture\",,0,0,,,,") {
                transcript.cleanup_steps.emplace_back("pdp_profile");
            }
        }
        if (!transcript.open_latch.nonfatal()) return IdfModemHttpsCommandResult::open_failed;
        if (command.rfind("AT+MIPSEND=0,", 0) == 0 &&
            transcript.late_open != LateOpenKind::none && !transcript.late_consumed &&
            transcript.late_stage == LateOpenStage::after_confirm_before_first_send) {
            assert(transcript.open_latch.connected());
            transcript.late_consumed = true;
            if (!transcript.feed_late_open_split()) {
                return IdfModemHttpsCommandResult::open_failed;
            }
        }
        if (command == "AT+MIPSTATE=0") {
            if (transcript.late_open != LateOpenKind::none && !transcript.late_consumed &&
                ((transcript.late_stage == LateOpenStage::before_first_state &&
                  transcript.state_queries == 1) ||
                 (transcript.late_stage == LateOpenStage::between_initial_polls &&
                  transcript.state_queries == 2))) {
                transcript.late_consumed = true;
                if (!transcript.open_latch.feed(transcript.late_open_bytes())) {
                    return IdfModemHttpsCommandResult::open_failed;
                }
            }
            if (transcript.mode == RemoteCloseMode::post_open_state_command_failure &&
                transcript.state_queries == 1) {
                ++transcript.state_queries;
                return IdfModemHttpsCommandResult::failed;
            }
            if (transcript.mode == RemoteCloseMode::post_open_state_command_timeout &&
                transcript.state_queries == 1) {
                ++transcript.state_queries;
                return IdfModemHttpsCommandResult::timeout;
            }
            ++transcript.state_queries;
            std::string_view state = "+MIPSTATE: 0,\"TCP\",\"fixture.example\",443,\"CONNECTED\"";
            if (transcript.state_queries == 1 ||
                transcript.mode == RemoteCloseMode::post_open_initial_timeout ||
                (transcript.mode == RemoteCloseMode::open_ok_initial_connected &&
                 transcript.state_queries == 2)) {
                state = "+MIPSTATE: 0,,,,\"INITIAL\"";
            } else if (transcript.mode == RemoteCloseMode::post_open_closed) {
                state = "+MIPSTATE: 0,,,,\"CLOSED\"";
            } else if (transcript.mode == RemoteCloseMode::post_open_wrong_cid) {
                state = "+MIPSTATE: 1,\"TCP\",\"fixture.example\",443,\"CONNECTED\"";
            } else if (transcript.mode == RemoteCloseMode::post_open_invalid) {
                state = "+MIPSTATE: 0,,,,\"OTHER\"";
            }
            std::string state_body(state);
            if (transcript.late_open != LateOpenKind::none && !transcript.late_consumed &&
                transcript.late_stage == LateOpenStage::in_first_state_response &&
                transcript.state_queries == 2) {
                transcript.late_consumed = true;
                state_body = transcript.late_open_bytes() + state_body;
            }
            response = frame(command, state_body);
            if (!transcript.open_latch.feed(response)) {
                return IdfModemHttpsCommandResult::open_failed;
            }
            return IdfModemHttpsCommandResult::ok;
        }
        if (command == "AT+MIPCFG=\"cid\",0") {
            response = frame(command, "+MIPCFG: \"cid\",0,1");
            return IdfModemHttpsCommandResult::ok;
        }
        if (command == "AT+MIPCFG=\"encoding\",0") {
            if (cleanup && transcript.cleanup_fails(CleanupFailure::encoding) &&
                transcript.cleanup_failure_phase == CleanupFailurePhase::query_command) {
                return IdfModemHttpsCommandResult::failed;
            }
            if (cleanup && transcript.cleanup_fails(CleanupFailure::encoding) &&
                transcript.cleanup_failure_phase == CleanupFailurePhase::verify_mismatch) {
                response = frame(command, "+MIPCFG: \"encoding\",0,1,1");
                return IdfModemHttpsCommandResult::ok;
            }
            response = frame(command, "+MIPCFG: \"encoding\",0," +
                                          std::to_string(transcript.encoding_send) + "," +
                                          std::to_string(transcript.encoding_receive));
            return IdfModemHttpsCommandResult::ok;
        }
        if (command == "AT+MIPCFG=\"autofree\",0") {
            if (cleanup && transcript.cleanup_fails(CleanupFailure::autofree) &&
                transcript.cleanup_failure_phase == CleanupFailurePhase::query_command) {
                return IdfModemHttpsCommandResult::failed;
            }
            if (cleanup && transcript.cleanup_fails(CleanupFailure::autofree) &&
                transcript.cleanup_failure_phase == CleanupFailurePhase::verify_mismatch) {
                response = frame(command, "+MIPCFG: \"autofree\",0,1");
                return IdfModemHttpsCommandResult::ok;
            }
            response = frame(command, "+MIPCFG: \"autofree\",0," +
                                          std::to_string(transcript.autofree));
            return IdfModemHttpsCommandResult::ok;
        }
        if (command == "AT+MIPCFG=\"ssl\",0") {
            if (cleanup && transcript.cleanup_fails(CleanupFailure::ssl) &&
                transcript.cleanup_failure_phase == CleanupFailurePhase::query_command) {
                return IdfModemHttpsCommandResult::failed;
            }
            if (cleanup && transcript.cleanup_fails(CleanupFailure::ssl) &&
                transcript.cleanup_failure_phase == CleanupFailurePhase::verify_mismatch) {
                response = frame(command, "+MIPCFG: \"ssl\",0,1,0");
                return IdfModemHttpsCommandResult::ok;
            }
            response = frame(command, "+MIPCFG: \"ssl\",0,0,0");
            return IdfModemHttpsCommandResult::ok;
        }
        if (command == "AT+MIPCFG=\"encoding\",0,1,1" ||
            command == "AT+MIPCFG=\"encoding\",0,0,0") {
            if (transcript.mode == RemoteCloseMode::runtime_config_failure &&
                command == "AT+MIPCFG=\"encoding\",0,1,1") {
                return IdfModemHttpsCommandResult::failed;
            }
            if (cleanup && transcript.cleanup_fails(CleanupFailure::encoding) &&
                transcript.cleanup_failure_phase == CleanupFailurePhase::command) {
                return IdfModemHttpsCommandResult::failed;
            }
            transcript.encoding_send = command == "AT+MIPCFG=\"encoding\",0,1,1" ? 1 : 0;
            transcript.encoding_receive = transcript.encoding_send;
            response = frame(command, "");
            return IdfModemHttpsCommandResult::ok;
        }
        if (command == "AT+MIPCFG=\"autofree\",0,1" ||
            command == "AT+MIPCFG=\"autofree\",0,0") {
            if (cleanup && transcript.cleanup_fails(CleanupFailure::autofree) &&
                transcript.cleanup_failure_phase == CleanupFailurePhase::command) {
                return IdfModemHttpsCommandResult::failed;
            }
            transcript.autofree = command == "AT+MIPCFG=\"autofree\",0,1" ? 1 : 0;
            response = frame(command, "");
            return IdfModemHttpsCommandResult::ok;
        }
        if (command == "AT+MIPCFG=\"ssl\",0,0,0") {
            if (cleanup && transcript.cleanup_fails(CleanupFailure::ssl) &&
                transcript.cleanup_failure_phase == CleanupFailurePhase::command) {
                return IdfModemHttpsCommandResult::failed;
            }
            response = frame(command, "");
            return IdfModemHttpsCommandResult::ok;
        }
        if (command == "AT+CGDCONT?") {
            if (transcript.mode == RemoteCloseMode::pdp_failure) {
                return IdfModemHttpsCommandResult::failed;
            }
            if (cleanup && transcript.cleanup_fails(CleanupFailure::pdp_profile)) {
                if (transcript.cleanup_failure_phase == CleanupFailurePhase::query_command) {
                    return IdfModemHttpsCommandResult::failed;
                }
                if (transcript.cleanup_failure_phase == CleanupFailurePhase::verify_mismatch) {
                    response = frame(command, "+CGDCONT: malformed");
                    return IdfModemHttpsCommandResult::ok;
                }
                if (transcript.cleanup_failure_phase == CleanupFailurePhase::profile_mismatch) {
                    response = frame(command,
                                     "+CGDCONT: 1,\"IPV4V6\",\"other\",,0,0,,,,");
                    return IdfModemHttpsCommandResult::ok;
                }
            }
            response = frame(command, "+CGDCONT: " + transcript.current_profile);
            return IdfModemHttpsCommandResult::ok;
        }
        if (command == "AT+CGACT?") {
            response = frame(command, transcript.pdp_active ? "+CGACT: 1,1" : "+CGACT: 1,0");
            return IdfModemHttpsCommandResult::ok;
        }
        if (command == "AT+CGDCONT=1,\"IPV4V6\",\"request-apn\"") {
            transcript.current_apn = "request-apn";
            transcript.current_profile = "1,\"IPV4V6\",\"request-apn\",,0,0,,,,";
            response = frame(command, "");
            return IdfModemHttpsCommandResult::ok;
        }
        if (command == "AT+CGDCONT=1,\"IPV4V6\",\"fixture\",,0,0,,,,") {
            if (cleanup && transcript.cleanup_fails(CleanupFailure::pdp_profile) &&
                transcript.cleanup_failure_phase == CleanupFailurePhase::command) {
                return IdfModemHttpsCommandResult::failed;
            }
            transcript.current_apn = "fixture";
            transcript.current_profile = "1,\"IPV4V6\",\"fixture\",,0,0,,,,";
            response = frame(command, "");
            return IdfModemHttpsCommandResult::ok;
        }
        if (command == "AT+CGACT=1,1") {
            transcript.pdp_active = true;
            response = frame(command, "");
            return IdfModemHttpsCommandResult::ok;
        }
        if (command == "AT+CGACT=0,1") {
            if (cleanup && transcript.cleanup_fails(CleanupFailure::pdp_deactivate)) {
                if (transcript.cleanup_failure_phase == CleanupFailurePhase::command) {
                    return IdfModemHttpsCommandResult::failed;
                }
                transcript.pdp_active = false;
                if (transcript.cleanup_failure_phase == CleanupFailurePhase::malformed_response) {
                    response = "\r\nAT+CGACT=0,1\r\n";
                    return IdfModemHttpsCommandResult::ok;
                }
                if (transcript.cleanup_failure_phase == CleanupFailurePhase::unexpected_response) {
                    response = frame(command, "+CGACT: 1,0");
                    return IdfModemHttpsCommandResult::ok;
                }
            }
            transcript.pdp_active = false;
            response = frame(command, "");
            return IdfModemHttpsCommandResult::ok;
        }
        constexpr std::string_view open_prefix = "AT+MIPOPEN=0,\"TCP\",\"fixture.example\",443,";
        if (command.compare(0, open_prefix.size(), open_prefix) == 0) {
            ++transcript.open_commands;
            transcript.open_latch.begin();
            if (transcript.mode == RemoteCloseMode::open_command_timeout) {
                return IdfModemHttpsCommandResult::timeout;
            }
            std::string_view body = "+MIPOPEN: 0,0";
            if (transcript.mode == RemoteCloseMode::open_ok_connected ||
                transcript.mode == RemoteCloseMode::open_ok_initial_connected) {
                body = "";
            } else if (transcript.mode == RemoteCloseMode::open_result_failed) {
                body = "+MIPOPEN: 0,4";
            } else if (transcript.mode == RemoteCloseMode::open_duplicate) {
                body = "+MIPOPEN: 0,0\r\n+MIPOPEN: 0,0";
            } else if (transcript.mode == RemoteCloseMode::open_wrong_cid) {
                body = "+MIPOPEN: 1,0";
            } else if (transcript.mode == RemoteCloseMode::open_disconnect) {
                body = "+MIPURC: \"disconn\",0,2";
            } else if (transcript.mode == RemoteCloseMode::open_malformed) {
                body = "+MIPOPEN: 0";
            }
            response = frame(command, body);
            if (!transcript.open_latch.feed(response)) {
                return IdfModemHttpsCommandResult::open_failed;
            }
            return IdfModemHttpsCommandResult::ok;
        }
        constexpr std::string_view send_prefix = "AT+MIPSEND=0,";
        if (command.compare(0, send_prefix.size(), send_prefix) == 0) {
            if (transcript.mode == RemoteCloseMode::request_write_failure) {
                return IdfModemHttpsCommandResult::failed;
            }
            ++transcript.send_commands;
            const size_t comma = command.find(',', send_prefix.size());
            size_t sent = 0;
            if (comma == std::string_view::npos ||
                !parse_decimal(command.substr(send_prefix.size(), comma - send_prefix.size()), sent)) {
                return IdfModemHttpsCommandResult::failed;
            }
            response = frame(command, "+MIPSEND: 0," + std::to_string(sent));
            return IdfModemHttpsCommandResult::ok;
        }
        if (command == "AT+MIPRD=0,4096") {
            ++transcript.read_commands;
            if (transcript.mode == RemoteCloseMode::disconnect_only) {
                response = frame(command, "+MIPURC: \"disconn\",0,2");
            } else if (transcript.mode == RemoteCloseMode::unread_data) {
                response = frame(command,
                                 "+MIPRD: 0,1,1,41\r\n+MIPURC: \"disconn\",0,2");
            } else if (transcript.mode == RemoteCloseMode::duplicate_disconnect) {
                response = frame(command,
                                 "+MIPRD: 0,0,1,41\r\n+MIPURC: \"disconn\",0,2\r\n"
                                 "+MIPURC: \"disconn\",0,2");
            } else {
                const std::string_view http =
                    transcript.mode == RemoteCloseMode::http_non_success
                        ? "HTTP/1.1 503 Service Unavailable\r\nX-Test: remote-close\r\n\r\nbody"
                        : transcript.mode == RemoteCloseMode::http_invalid_zero
                            ? "HTTP/1.1 000 Invalid\r\nX-Test: remote-close\r\n\r\nbody"
                            : transcript.mode == RemoteCloseMode::http_invalid_high
                                ? "HTTP/1.1 600 Invalid\r\nX-Test: remote-close\r\n\r\nbody"
                                : transcript.mode == RemoteCloseMode::http_invalid_max
                                    ? "HTTP/1.1 999 Invalid\r\nX-Test: remote-close\r\n\r\nbody"
                                    : "HTTP/1.1 200 OK\r\nX-Test: remote-close\r\n\r\nbody";
                const std::string hex = idf_modem_https_wire::hex_encode(
                    reinterpret_cast<const uint8_t*>(http.data()), http.size());
                response = frame(command, "+MIPRD: 0,0," + std::to_string(http.size()) + "," +
                                              hex + "\r\n+MIPURC: \"disconn\",0,2");
            }
            return IdfModemHttpsCommandResult::ok;
        }
        if (command == "AT+MIPCLOSE=0") {
            ++transcript.close_commands;
            transcript.close_was_cleanup = cleanup;
            if (cleanup && transcript.cleanup_fails(CleanupFailure::socket_close)) {
                if (transcript.cleanup_failure_phase == CleanupFailurePhase::command) {
                    return IdfModemHttpsCommandResult::failed;
                }
                if (transcript.cleanup_failure_phase == CleanupFailurePhase::command_timeout) {
                    return IdfModemHttpsCommandResult::timeout;
                }
                if (transcript.cleanup_failure_phase == CleanupFailurePhase::malformed_response) {
                    response = "\r\nAT+MIPCLOSE=0\r\n";
                    return IdfModemHttpsCommandResult::ok;
                }
                if (transcript.cleanup_failure_phase == CleanupFailurePhase::nonzero_response) {
                    response = frame(command, "+MIPCLOSE: 0,1");
                    return IdfModemHttpsCommandResult::ok;
                }
            }
            response = frame(command, "+MIPCLOSE: 0,0");
            return IdfModemHttpsCommandResult::ok;
        }
        return IdfModemHttpsCommandResult::failed;
    }

    static IdfModemHttpsCommandResult confirm(void* context)
    {
        auto& transcript = *static_cast<RemoteCloseTranscript*>(context);
        if (transcript.late_open != LateOpenKind::none && !transcript.late_consumed &&
            transcript.late_stage == LateOpenStage::after_connected_before_confirm) {
            assert(!transcript.open_latch.connected());
            transcript.late_consumed = true;
            if (!transcript.feed_late_open_split()) {
                return IdfModemHttpsCommandResult::open_failed;
            }
        }
        if (!transcript.open_latch.finish()) return IdfModemHttpsCommandResult::open_failed;
        return IdfModemHttpsCommandResult::ok;
    }
};

IdfModemHttpsRunResult run_remote_close_transcript(RemoteCloseTranscript& transcript,
                                                   IdfModemHttpsPostResult& result)
{
    IdfModemHttpsPostRequest request;
    request.url = "https://fixture.example/notify";
    request.body = "{}";
    if (transcript.cleanup_failure == CleanupFailure::pdp_profile) {
        request.apn = "request-apn";
    }
    request.rootCertificateDer = {'D', 'E', 'R'};
    request.rootCertificateSha256.fill(0xab);
    IdfModemHttpsCallbacks callbacks{
        &transcript, &RemoteCloseTranscript::send, &RemoteCloseTranscript::confirm};
    fixture_tls_setup_result =
        transcript.mode == RemoteCloseMode::tls_setup_failure ? -1 : 0;
    fixture_tls_handshake_result =
        transcript.mode == RemoteCloseMode::tls_handshake_failure ? -1 : 0;
    const IdfModemHttpsRunResult outcome = idf_modem_https_run_post(request, callbacks, result);
    fixture_tls_setup_result = 0;
    fixture_tls_handshake_result = 0;
    return outcome;
}

int cleanup_command_rank(const std::string& command)
{
    if (command == "AT+MIPCLOSE=0") return 0;
    if (command.find("MIPCFG=\"ssl\"") != std::string::npos) return 1;
    if (command.find("MIPCFG=\"autofree\"") != std::string::npos) return 2;
    if (command.find("MIPCFG=\"encoding\"") != std::string::npos) return 3;
    if (command == "AT+CGACT=0,1") return 4;
    if (command.rfind("AT+CGDCONT", 0) == 0) return 5;
    return -1;
}

void assert_cleanup_action_order(const RemoteCloseTranscript& transcript)
{
    int previous_rank = -1;
    for (const std::string& command : transcript.cleanup_commands) {
        const int rank = cleanup_command_rank(command);
        assert(rank >= previous_rank);
        previous_rank = rank;
        assert(std::count(transcript.cleanup_commands.begin(),
                          transcript.cleanup_commands.end(), command) == 1);
    }
    for (const auto& [setter, query] : {
             std::pair<std::string_view, std::string_view>{
                 "AT+MIPCFG=\"ssl\",0,0,0", "AT+MIPCFG=\"ssl\",0"},
             {"AT+MIPCFG=\"autofree\",0,0", "AT+MIPCFG=\"autofree\",0"},
             {"AT+MIPCFG=\"encoding\",0,0,0", "AT+MIPCFG=\"encoding\",0"},
             {"AT+CGDCONT=1,\"IPV4V6\",\"fixture\",,0,0,,,,", "AT+CGDCONT?"},
         }) {
        const auto setter_at = std::find(transcript.cleanup_commands.begin(),
                                         transcript.cleanup_commands.end(), setter);
        const auto query_at = std::find(transcript.cleanup_commands.begin(),
                                        transcript.cleanup_commands.end(), query);
        if (setter_at != transcript.cleanup_commands.end() &&
            query_at != transcript.cleanup_commands.end()) {
            assert(setter_at < query_at);
        }
    }
}

void check_remote_close_transcripts()
{
    static constexpr std::string_view http =
        "HTTP/1.1 200 OK\r\nX-Test: remote-close\r\n\r\nbody";
    assert(http.size() > 7);
    RemoteCloseTranscript delivered{RemoteCloseMode::data_then_disconnect};
    IdfModemHttpsPostResult result;
    assert(run_remote_close_transcript(delivered, result) == IdfModemHttpsRunResult::ok);
    assert(result.ok && result.httpStatus == 200 && result.responseBytes == http.size());
    assert(result.failureStage == IdfHttpsFailureStage::none);
    assert(result.expectedResponseBytes == 0);
    assert(CleanupMessageAccessor<IdfModemHttpsPostResult>::get(result).empty());
    assert(delivered.read_commands == 1 && delivered.close_commands == 1 &&
           delivered.close_was_cleanup);
    assert(delivered.encoding_send == 0 && delivered.encoding_receive == 0 &&
           delivered.autofree == 0);

    for (const RemoteCloseMode mode : {RemoteCloseMode::disconnect_only,
                                       RemoteCloseMode::unread_data,
                                       RemoteCloseMode::duplicate_disconnect}) {
        RemoteCloseTranscript rejected{mode};
        result = {};
        assert(run_remote_close_transcript(rejected, result) ==
               IdfModemHttpsRunResult::response_failed);
        assert(!result.ok && result.responseBytes == 0 && rejected.read_commands == 1 &&
               rejected.close_commands == 1 && rejected.close_was_cleanup);
        assert(result.failureStage == IdfHttpsFailureStage::response);
        assert_failure_message(result.message, "HTTPS response failed");
    }

    for (const RemoteCloseMode mode : {RemoteCloseMode::open_ok_connected,
                                       RemoteCloseMode::open_ok_initial_connected}) {
        RemoteCloseTranscript accepted{mode};
        result = {};
        assert(run_remote_close_transcript(accepted, result) == IdfModemHttpsRunResult::ok);
        const size_t expected_state_queries =
            mode == RemoteCloseMode::open_ok_connected ? 2 : 3;
        assert(result.ok && accepted.state_queries == expected_state_queries &&
               accepted.open_commands == 1 && accepted.send_commands == 1 &&
               accepted.read_commands == 1 && accepted.close_commands == 1 &&
               accepted.close_was_cleanup);
    }

    for (const RemoteCloseMode mode : {RemoteCloseMode::open_result_failed,
                                       RemoteCloseMode::open_duplicate,
                                       RemoteCloseMode::open_wrong_cid,
                                       RemoteCloseMode::open_disconnect,
                                       RemoteCloseMode::open_malformed}) {
        RemoteCloseTranscript rejected{mode};
        result = {};
        assert(run_remote_close_transcript(rejected, result) ==
               IdfModemHttpsRunResult::command_failed);
        assert(!result.ok && rejected.state_queries == 1 && rejected.open_commands == 1 &&
               rejected.send_commands == 0 && rejected.read_commands == 0 &&
               rejected.close_commands == 1 && rejected.close_was_cleanup);
        assert(result.failureStage == IdfHttpsFailureStage::socket);
        assert(!rejected.open_latch.active());
        assert_failure_message(result.message, "HTTPS modem socket open failed");
    }

    RemoteCloseTranscript open_timeout{RemoteCloseMode::open_command_timeout};
    result = {};
    assert(run_remote_close_transcript(open_timeout, result) ==
           IdfModemHttpsRunResult::timed_out);
    assert(!result.ok && open_timeout.state_queries == 1 && open_timeout.open_commands == 1 &&
           open_timeout.send_commands == 0 && open_timeout.read_commands == 0 &&
           open_timeout.close_commands == 1 && open_timeout.close_was_cleanup);
    assert_failure_message(result.message, "HTTPS modem socket open failed");

    for (const RemoteCloseMode mode : {RemoteCloseMode::post_open_closed,
                                       RemoteCloseMode::post_open_wrong_cid,
                                       RemoteCloseMode::post_open_invalid}) {
        RemoteCloseTranscript rejected{mode};
        result = {};
        assert(run_remote_close_transcript(rejected, result) ==
               IdfModemHttpsRunResult::command_failed);
        assert(!result.ok && rejected.state_queries == 2 && rejected.open_commands == 1 &&
               rejected.send_commands == 0 && rejected.read_commands == 0 &&
               rejected.close_commands == 1 && rejected.close_was_cleanup);
        assert(result.failureStage == IdfHttpsFailureStage::registration);
        assert(rejected.encoding_send == 0 && rejected.encoding_receive == 0 &&
               rejected.autofree == 0);
        assert_failure_message(result.message, "HTTPS modem connected-state poll failed");
    }

    for (const auto& [mode, expected_reason] : {
             std::pair{RemoteCloseMode::post_open_state_command_failure,
                       IdfModemHttpsDiagnosticReason::command_failure},
             std::pair{RemoteCloseMode::post_open_state_command_timeout,
                       IdfModemHttpsDiagnosticReason::timeout},
             std::pair{RemoteCloseMode::post_open_invalid,
                       IdfModemHttpsDiagnosticReason::response_invalid},
             std::pair{RemoteCloseMode::post_open_closed,
                       IdfModemHttpsDiagnosticReason::terminal_failure},
             std::pair{RemoteCloseMode::post_open_initial_timeout,
                       IdfModemHttpsDiagnosticReason::poll_timeout},
         }) {
        RemoteCloseTranscript rejected{mode};
        result = {};
        const IdfModemHttpsRunResult expected_outcome =
            expected_reason == IdfModemHttpsDiagnosticReason::timeout ||
                    expected_reason == IdfModemHttpsDiagnosticReason::poll_timeout
                ? IdfModemHttpsRunResult::timed_out
                : IdfModemHttpsRunResult::command_failed;
        assert(run_remote_close_transcript(rejected, result) == expected_outcome);
        assert(result.failureReason == expected_reason);
        assert(rejected.send_commands == 0 && rejected.read_commands == 0 &&
               rejected.close_commands == 1 && rejected.close_was_cleanup);
    }

    RemoteCloseTranscript state_timeout{RemoteCloseMode::post_open_initial_timeout};
    result = {};
    assert(run_remote_close_transcript(state_timeout, result) ==
           IdfModemHttpsRunResult::timed_out);
    assert(!result.ok && state_timeout.state_queries == 22 && state_timeout.open_commands == 1 &&
           state_timeout.send_commands == 0 && state_timeout.read_commands == 0 &&
           state_timeout.close_commands == 1 && state_timeout.close_was_cleanup);
    assert_failure_message(result.message, "HTTPS modem connected-state poll failed");

    for (const LateOpenStage stage : {LateOpenStage::before_first_state,
                                      LateOpenStage::between_initial_polls,
                                      LateOpenStage::in_first_state_response}) {
        for (const LateOpenKind late : {LateOpenKind::result_failed,
                                        LateOpenKind::duplicate,
                                        LateOpenKind::wrong_cid,
                                        LateOpenKind::disconnect,
                                        LateOpenKind::malformed}) {
            const RemoteCloseMode mode = stage == LateOpenStage::before_first_state
                                             ? RemoteCloseMode::open_ok_connected
                                             : RemoteCloseMode::open_ok_initial_connected;
            RemoteCloseTranscript rejected{mode, late, stage};
            result = {};
            assert(run_remote_close_transcript(rejected, result) ==
                   IdfModemHttpsRunResult::command_failed);
            assert(rejected.late_consumed && rejected.send_commands == 0 &&
                   rejected.read_commands == 0 && rejected.close_commands == 1 &&
                   rejected.close_was_cleanup);
            assert(!rejected.open_latch.active());
            assert_failure_message(result.message, "HTTPS modem socket open failed");
        }
    }

    for (const LateOpenStage stage : {LateOpenStage::after_connected_before_confirm,
                                      LateOpenStage::after_confirm_before_first_send}) {
        for (const LateOpenKind late : {LateOpenKind::result_failed,
                                        LateOpenKind::duplicate,
                                        LateOpenKind::wrong_cid,
                                        LateOpenKind::disconnect,
                                        LateOpenKind::malformed}) {
            RemoteCloseTranscript rejected{RemoteCloseMode::open_ok_connected, late, stage};
            result = {};
            assert(run_remote_close_transcript(rejected, result) ==
                   IdfModemHttpsRunResult::command_failed);
            assert(rejected.late_consumed && rejected.late_feed_calls == 2 &&
                   rejected.send_commands == 0 && rejected.read_commands == 0 &&
                   rejected.close_commands == 1 && rejected.close_was_cleanup);
            assert(!rejected.open_latch.active());
            assert_failure_message(result.message, "HTTPS modem socket open failed");
        }
    }

    struct FailureCase {
        RemoteCloseMode mode;
        IdfModemHttpsRunResult outcome;
        std::string_view message;
    };
    for (const FailureCase failure : {
             FailureCase{RemoteCloseMode::pdp_failure,
                         IdfModemHttpsRunResult::command_failed,
                         "HTTPS modem PDP/APN setup failed"},
             FailureCase{RemoteCloseMode::runtime_config_failure,
                         IdfModemHttpsRunResult::command_failed,
                         "HTTPS modem runtime configuration failed"},
             FailureCase{RemoteCloseMode::tls_setup_failure,
                         IdfModemHttpsRunResult::command_failed,
                         "HTTPS TLS setup failed"},
             FailureCase{RemoteCloseMode::tls_handshake_failure,
                         IdfModemHttpsRunResult::command_failed,
                         "HTTPS TLS handshake failed"},
             FailureCase{RemoteCloseMode::request_write_failure,
                         IdfModemHttpsRunResult::command_failed,
                         "HTTPS request write failed"},
             FailureCase{RemoteCloseMode::http_non_success,
                         IdfModemHttpsRunResult::response_failed,
                         "HTTPS POST returned a non-2xx status"},
             FailureCase{RemoteCloseMode::http_invalid_zero,
                         IdfModemHttpsRunResult::response_failed,
                         "HTTPS response status is invalid"},
             FailureCase{RemoteCloseMode::http_invalid_high,
                         IdfModemHttpsRunResult::response_failed,
                         "HTTPS response status is invalid"},
             FailureCase{RemoteCloseMode::http_invalid_max,
                         IdfModemHttpsRunResult::response_failed,
                         "HTTPS response status is invalid"},
         }) {
        RemoteCloseTranscript rejected{failure.mode};
        result = {};
        assert(run_remote_close_transcript(rejected, result) == failure.outcome);
        assert(!result.ok && rejected.close_commands ==
                                 (failure.mode == RemoteCloseMode::pdp_failure ||
                                          failure.mode == RemoteCloseMode::runtime_config_failure
                                      ? 0U
                                      : 1U));
        const IdfHttpsFailureStage expected_stage =
            failure.mode == RemoteCloseMode::pdp_failure
                ? IdfHttpsFailureStage::pdp
                : failure.mode == RemoteCloseMode::runtime_config_failure
                    ? IdfHttpsFailureStage::modem
                    : failure.mode == RemoteCloseMode::tls_setup_failure ||
                            failure.mode == RemoteCloseMode::tls_handshake_failure
                        ? IdfHttpsFailureStage::tls
                        : failure.mode == RemoteCloseMode::request_write_failure
                            ? IdfHttpsFailureStage::request
                            : failure.mode == RemoteCloseMode::http_invalid_zero ||
                                    failure.mode == RemoteCloseMode::http_invalid_high ||
                                    failure.mode == RemoteCloseMode::http_invalid_max
                                ? IdfHttpsFailureStage::response
                                : IdfHttpsFailureStage::http;
        assert(result.failureStage == expected_stage);
        assert_failure_message(result.message, failure.message);
    }

    struct CleanupFailureCase {
        CleanupFailure failure;
        CleanupFailurePhase phase;
        std::string_view cleanup_message;
        std::string_view failed_command;
    };
    for (const CleanupFailureCase failure : {
             CleanupFailureCase{CleanupFailure::socket_close,
                                CleanupFailurePhase::command,
                                "HTTPS cleanup socket close failed", "AT+MIPCLOSE=0"},
             CleanupFailureCase{CleanupFailure::socket_close,
                                CleanupFailurePhase::command_timeout,
                                "HTTPS cleanup socket close failed", "AT+MIPCLOSE=0"},
             CleanupFailureCase{CleanupFailure::socket_close,
                                CleanupFailurePhase::malformed_response,
                                "HTTPS cleanup socket close failed", "AT+MIPCLOSE=0"},
             CleanupFailureCase{CleanupFailure::socket_close,
                                CleanupFailurePhase::nonzero_response,
                                "HTTPS cleanup socket close failed", "AT+MIPCLOSE=0"},
             CleanupFailureCase{CleanupFailure::ssl,
                                CleanupFailurePhase::command,
                                "HTTPS cleanup SSL config restore failed",
                                "AT+MIPCFG=\"ssl\",0,0,0"},
             CleanupFailureCase{CleanupFailure::ssl,
                                CleanupFailurePhase::query_command,
                                "HTTPS cleanup SSL config restore failed",
                                "AT+MIPCFG=\"ssl\",0"},
             CleanupFailureCase{CleanupFailure::ssl,
                                CleanupFailurePhase::verify_mismatch,
                                "HTTPS cleanup SSL config restore failed",
                                "AT+MIPCFG=\"ssl\",0"},
             CleanupFailureCase{CleanupFailure::autofree,
                                CleanupFailurePhase::command,
                                "HTTPS cleanup autofree config restore failed",
                                "AT+MIPCFG=\"autofree\",0,0"},
             CleanupFailureCase{CleanupFailure::encoding,
                                CleanupFailurePhase::command,
                                "HTTPS cleanup encoding config restore failed",
                                "AT+MIPCFG=\"encoding\",0,0,0"},
             CleanupFailureCase{CleanupFailure::pdp_deactivate,
                                CleanupFailurePhase::command,
                                "HTTPS cleanup PDP deactivate failed", "AT+CGACT=0,1"},
             CleanupFailureCase{CleanupFailure::pdp_deactivate,
                                CleanupFailurePhase::malformed_response,
                                "HTTPS cleanup PDP deactivate failed", "AT+CGACT=0,1"},
             CleanupFailureCase{CleanupFailure::pdp_deactivate,
                                CleanupFailurePhase::unexpected_response,
                                "HTTPS cleanup PDP deactivate failed", "AT+CGACT=0,1"},
             CleanupFailureCase{CleanupFailure::pdp_profile,
                                CleanupFailurePhase::command,
                                "HTTPS cleanup PDP profile restore failed",
                                "AT+CGDCONT=1,\"IPV4V6\",\"fixture\",,0,0,,,,"},
             CleanupFailureCase{CleanupFailure::pdp_profile,
                                CleanupFailurePhase::query_command,
                                "HTTPS cleanup PDP profile restore failed", "AT+CGDCONT?"},
             CleanupFailureCase{CleanupFailure::pdp_profile,
                                CleanupFailurePhase::verify_mismatch,
                                "HTTPS cleanup PDP profile restore failed", "AT+CGDCONT?"},
             CleanupFailureCase{CleanupFailure::pdp_profile,
                                CleanupFailurePhase::profile_mismatch,
                                "HTTPS cleanup PDP profile restore failed", "AT+CGDCONT?"},
         }) {
        RemoteCloseTranscript cleanup_failed{RemoteCloseMode::data_then_disconnect,
                                              LateOpenKind::none, LateOpenStage::none,
                                              failure.failure, failure.phase};
        result = {};
        assert(run_remote_close_transcript(cleanup_failed, result) ==
               IdfModemHttpsRunResult::cleanup_failed);
        assert(!result.ok && result.httpStatus == 200 && result.responseBytes == http.size() &&
               result.expectedResponseBytes == 0);
        assert_failure_message(result.message, "HTTPS cleanup failed");
        assert_cleanup_message(result, failure.cleanup_message);
        if (failure.failure == CleanupFailure::socket_close) {
            const IdfModemHttpsDiagnosticReason expected_cleanup_reason =
                failure.phase == CleanupFailurePhase::command
                    ? IdfModemHttpsDiagnosticReason::command_failure
                    : failure.phase == CleanupFailurePhase::command_timeout
                        ? IdfModemHttpsDiagnosticReason::timeout
                        : failure.phase == CleanupFailurePhase::nonzero_response
                            ? IdfModemHttpsDiagnosticReason::result_nonzero
                            : IdfModemHttpsDiagnosticReason::response_invalid;
            assert(result.cleanupReason == expected_cleanup_reason);
        } else {
            assert(result.cleanupReason == IdfModemHttpsDiagnosticReason::none);
        }
        assert(result.cleanupRequiresReset == (failure.failure == CleanupFailure::socket_close));
        assert(result.failureStage == IdfHttpsFailureStage::cleanup);
        assert(cleanup_failed.close_commands == 1 && cleanup_failed.close_was_cleanup);
        assert(std::count(cleanup_failed.cleanup_commands.begin(),
                          cleanup_failed.cleanup_commands.end(), "AT+MIPCLOSE=0") == 1);
        assert(std::count(cleanup_failed.cleanup_commands.begin(),
                          cleanup_failed.cleanup_commands.end(), failure.failed_command) == 1);
        std::vector<std::string_view> expected_steps{
            "socket_close", "ssl", "autofree", "encoding"};
        if (failure.failure == CleanupFailure::pdp_deactivate ||
            failure.failure == CleanupFailure::pdp_profile) {
            expected_steps.emplace_back("pdp_deactivate");
        }
        if (failure.failure == CleanupFailure::pdp_profile) {
            expected_steps.emplace_back("pdp_profile");
        }
        assert(cleanup_failed.cleanup_steps == expected_steps);
        assert_cleanup_action_order(cleanup_failed);
        assert(cleanup_failed.encoding_send ==
               (failure.failure == CleanupFailure::encoding &&
                        failure.phase == CleanupFailurePhase::command
                    ? 1
                    : 0));
        assert(cleanup_failed.encoding_receive == cleanup_failed.encoding_send);
        assert(cleanup_failed.autofree ==
               (failure.failure == CleanupFailure::autofree &&
                        failure.phase == CleanupFailurePhase::command
                    ? 1
                    : 0));
        if (failure.failure == CleanupFailure::pdp_deactivate &&
            failure.phase == CleanupFailurePhase::command) {
            assert(cleanup_failed.pdp_active);
        }
        if (failure.failure == CleanupFailure::pdp_profile) {
            assert(!cleanup_failed.pdp_active);
            assert(cleanup_failed.current_apn ==
                   (failure.phase == CleanupFailurePhase::command ? "request-apn" : "fixture"));
        }
    }

    RemoteCloseTranscript primary_and_cleanup_failed{
        RemoteCloseMode::request_write_failure, LateOpenKind::none, LateOpenStage::none,
        CleanupFailure::socket_close};
    result = {};
    assert(run_remote_close_transcript(primary_and_cleanup_failed, result) ==
           IdfModemHttpsRunResult::cleanup_failed);
    assert(!result.ok && result.httpStatus == -1 && result.responseBytes == 0 &&
           result.expectedResponseBytes == 0);
    assert_failure_message(result.message, "HTTPS request write failed");
    assert(result.failureStage == IdfHttpsFailureStage::request);
    assert_cleanup_message(result, "HTTPS cleanup socket close failed");
    assert(result.cleanupReason == IdfModemHttpsDiagnosticReason::command_failure);
    assert(result.cleanupRequiresReset);

    RemoteCloseTranscript first_cleanup_failure_wins{
        RemoteCloseMode::data_then_disconnect, LateOpenKind::none, LateOpenStage::none,
        CleanupFailure::socket_close_and_ssl};
    result = {};
    assert(run_remote_close_transcript(first_cleanup_failure_wins, result) ==
           IdfModemHttpsRunResult::cleanup_failed);
    assert_failure_message(result.message, "HTTPS cleanup failed");
    assert_cleanup_message(result, "HTTPS cleanup socket close failed");
    assert(first_cleanup_failure_wins.cleanup_failure == CleanupFailure::socket_close_and_ssl);
    assert(result.cleanupReason == IdfModemHttpsDiagnosticReason::command_failure);
    assert(result.cleanupRequiresReset);
    assert(std::count(first_cleanup_failure_wins.cleanup_commands.begin(),
                      first_cleanup_failure_wins.cleanup_commands.end(), "AT+MIPCLOSE=0") == 1);
    assert((first_cleanup_failure_wins.cleanup_steps ==
            std::vector<std::string_view>{"socket_close", "ssl", "autofree", "encoding"}));

    RemoteCloseTranscript late_success{RemoteCloseMode::open_ok_connected,
                                       LateOpenKind::success,
                                       LateOpenStage::before_first_state};
    result = {};
    assert(run_remote_close_transcript(late_success, result) == IdfModemHttpsRunResult::ok);
    assert(result.ok && late_success.late_consumed && late_success.send_commands == 1 &&
           late_success.read_commands == 1 && late_success.close_commands == 1 &&
           late_success.close_was_cleanup);

    RemoteCloseTranscript response_success{RemoteCloseMode::open_ok_connected,
                                           LateOpenKind::success,
                                           LateOpenStage::in_first_state_response};
    result = {};
    assert(run_remote_close_transcript(response_success, result) == IdfModemHttpsRunResult::ok);
    assert(result.ok && response_success.late_consumed && response_success.send_commands == 1 &&
           response_success.read_commands == 1 && response_success.close_commands == 1 &&
           response_success.close_was_cleanup);
    assert(!response_success.open_latch.active());
}

void check_invalid_request_stages()
{
    IdfModemHttpsPostRequest request;
    request.url = "https://fixture.example/notify";
    request.body = "{}";
    request.rootCertificateDer = {'D', 'E', 'R'};
    request.rootCertificateSha256.fill(0xab);
    IdfModemHttpsCallbacks callbacks;
    IdfModemHttpsPostResult result;

    request.url = "http://fixture.example/notify";
    assert(idf_modem_https_run_post(request, callbacks, result) ==
           IdfModemHttpsRunResult::invalid_request);
    assert(result.failureStage == IdfHttpsFailureStage::target);

    request.url = "https://fixture.example/notify";
    request.body.clear();
    assert(idf_modem_https_run_post(request, callbacks, result) ==
           IdfModemHttpsRunResult::invalid_request);
    assert(result.failureStage == IdfHttpsFailureStage::request);

    request.body = "{}";
    request.rootCertificateDer.clear();
    assert(idf_modem_https_run_post(request, callbacks, result) ==
           IdfModemHttpsRunResult::invalid_request);
    assert(result.failureStage == IdfHttpsFailureStage::ca);

    request.rootCertificateDer = {'D', 'E', 'R'};
    request.rootCertificateSha256.fill(0xab);
    assert(idf_modem_https_run_post(request, callbacks, result) ==
           IdfModemHttpsRunResult::invalid_request);
    assert(result.failureStage == IdfHttpsFailureStage::modem);
}

}  // namespace

int main()
{
    check_initial_state_transcripts();
    check_remote_close_transcripts();
    check_invalid_request_stages();
    const uint8_t pdp_cid = 1;
    const std::string open_command = "AT+MIPOPEN=0,\"TCP\",\"fixture.example\",80,30,2";
    const std::string state_command = "AT+MIPSTATE=0";
    const std::string send_command = "AT+MIPSEND=0,57,\"";
    const std::string read_command = "AT+MIPRD=0,4096";
    const std::string close_command = "AT+MIPCLOSE=0";

    uint8_t first = 0;
    uint8_t second = 0;
    bool has_second = false;
    assert(parse_cfg_response(frame("AT+MIPCFG=\"encoding\",0",
                                    "+MIPCFG: \"encoding\",0,1,1"),
                              "AT+MIPCFG=\"encoding\",0", "encoding", first, second,
                              has_second));
    assert(first == 1 && second == 1 && has_second);

    std::string apn;
    std::string original_profile;
    assert(parse_cgdccont(
        frame("AT+CGDCONT?", "+CGDCONT: 1,\"IPV4V6\",\"fixture\",,0,0,,,,"),
        "AT+CGDCONT?", pdp_cid, &apn, &original_profile));
    assert(apn == "fixture");
    assert(original_profile == "1,\"IPV4V6\",\"fixture\",,0,0,,,,");
    bool active = false;
    assert(parse_cgact(frame("AT+CGACT?", "+CGACT: 1,1"), "AT+CGACT?", pdp_cid, active));
    assert(active);
    assert(!parse_cgact(frame("AT+CGACT?", "+CGACT: 1,1\r\n+CGACT: 1,0"),
                        "AT+CGACT?", pdp_cid, active));
    assert(!parse_cgact(frame("AT+CGACT?", "+CGACT: 2,0"), "AT+CGACT?", pdp_cid,
                        active));

    const std::string duplicate_cgdcont = frame(
        "AT+CGDCONT?", "+CGDCONT: 1,\"IPV4V6\",\"fixture\",,0,0,,,,\r\n"
                       "+CGDCONT: 1,\"IPV4V6\",\"fixture\",,0,0,,,,");
    assert(!parse_cgdccont(duplicate_cgdcont, "AT+CGDCONT?", pdp_cid));
    const std::string out_of_range_cgdcont = frame(
        "AT+CGDCONT?", "+CGDCONT: 17,\"IPV4V6\",\"fixture\",,0,0,,,,");
    assert(!parse_cgdccont(out_of_range_cgdcont, "AT+CGDCONT?", pdp_cid));

    uint32_t urc_received = 0;
    uint32_t urc_total = 0;
    uint8_t urc_state = 0;
    bool urc_disconnected = false;
    assert(parse_mip_urc("+MIPURC: \"rtcp\",0,1,3", urc_received, urc_total,
                         urc_state, urc_disconnected));
    assert(!urc_disconnected && urc_received == 1 && urc_total == 3);
    assert(parse_mip_urc("+MIPURC: \"disconn\",0,2", urc_received, urc_total,
                         urc_state, urc_disconnected));
    assert(urc_disconnected && urc_state == 2);
    assert(!parse_mip_urc("+MIPURC: \"rtcp\",0,4,3", urc_received, urc_total,
                          urc_state, urc_disconnected));
    assert(!parse_mip_urc("+MIPURC: \"disconn\",0,0", urc_received, urc_total,
                          urc_state, urc_disconnected));
    assert(!parse_mip_urc("+MIPURC: \"other\",0,1", urc_received, urc_total,
                          urc_state, urc_disconnected));

    std::string configure_apn;
    assert(build_cgdccont_command(pdp_cid, "request-apn", configure_apn));
    assert(configure_apn == "AT+CGDCONT=1,\"IPV4V6\",\"request-apn\"");
    assert(!build_cgdccont_command(pdp_cid, "bad\"apn", configure_apn));
    assert(!build_cgdccont_command(pdp_cid, "bad\napn", configure_apn));
    assert(!build_cgdccont_command(pdp_cid, std::string(97, 'a'), configure_apn));

    const std::vector<std::string> apn_commands = {
        "AT+CGDCONT?", configure_apn, "AT+CGDCONT?", "AT+CGACT=1,1"};
    assert(apn_commands[0] == "AT+CGDCONT?");
    assert(apn_commands[1] == configure_apn);
    assert(apn_commands[2] == "AT+CGDCONT?");
    assert(apn_commands[3] == "AT+CGACT=1,1");
    assert(std::find(apn_commands.begin(), apn_commands.end(), "AT+MIPOPEN=0") ==
           apn_commands.end());

    const std::string wrong_apn_response = frame(
        "AT+CGDCONT?", "+CGDCONT: 1,\"IPV4V6\",\"other-apn\",,0,0,,,,");
    std::string verified_apn;
    assert(parse_cgdccont(wrong_apn_response, "AT+CGDCONT?", pdp_cid, &verified_apn));
    assert(verified_apn != "request-apn");
    const std::vector<std::string> failed_apn_commands = {
        "AT+CGDCONT?", configure_apn, "AT+CGDCONT?",
        "AT+CGDCONT=" + original_profile};
    assert(std::find(failed_apn_commands.begin(), failed_apn_commands.end(),
                     "AT+MIPOPEN=0") == failed_apn_commands.end());
    assert(std::find(failed_apn_commands.begin(), failed_apn_commands.end(),
                     "AT+MIPCLOSE=0") == failed_apn_commands.end());
    assert(std::find(failed_apn_commands.begin(), failed_apn_commands.end(),
                     "AT+CGACT=1,1") == failed_apn_commands.end());

    std::vector<std::string> phases;
    std::vector<std::string_view> body;

    const std::string open_response =
        frame(open_command, "+CMTI: \"SM\",1\r\n+CEREG: 1,1\r\n"
                           "+MIPURC: \"rtcp\",0,1,3\r\n+MIPOPEN: 0,0");
    const std::string open_after_ok_response =
        "\r\n" + open_command + "\r\nOK\r\n+CEREG: 1,1\r\n"
        "+MIPURC: \"rtcp\",0,1,3\r\n+MIPOPEN: 0,0\r\n";
    uint32_t value = 0;
    assert(scan_frame(open_response, open_command, body));
    assert(body.size() == 2 && body[0] == "+MIPURC: \"rtcp\",0,1,3" &&
           body[1] == "+MIPOPEN: 0,0");
    assert(parse_result(open_response, open_command, "+MIPOPEN:", 0, value));
    assert(value == 0);
    phases.emplace_back("OPEN");

    bool open_present = false;
    assert(parse_mip_open(open_response, open_command, 0, open_present));
    assert(open_present);
    assert(parse_mip_open(open_after_ok_response, open_command, 0, open_present));
    assert(open_present);
    bool no_open_present = true;
    assert(parse_mip_open(frame(open_command, "+CEREG: 1,1"), open_command, 0,
                          no_open_present));
    assert(!no_open_present);
    assert(!parse_mip_open(frame(open_command, "+MIPOPEN: 0,4"), open_command, 0,
                           open_present));
    assert(!parse_mip_open(frame(open_command, "+MIPOPEN: 1,0"), open_command, 0,
                           open_present));
    const std::string duplicate_open = frame(
        open_command, "+MIPOPEN: 0,0\r\n+MIPOPEN: 0,0");
    assert(!parse_mip_open(duplicate_open, open_command, 0, open_present));
    assert(!parse_mip_open(frame(open_command, "+UNKNOWN: 1"), open_command, 0,
                           open_present));
    assert(!parse_mip_open(frame(open_command, "+MIPURC: \"disconn\",0,2"),
                           open_command, 0, open_present));

    const std::string initial_state_response =
        frame(state_command, "+MIPSTATE: 0,,,,\"INITIAL\"");
    assert(classify_mip_state(initial_state_response, state_command, 0) ==
           MipStateDisposition::initial);
    uint8_t initial_cid = 0;
    assert(parse_mip_state(initial_state_response, state_command, "INITIAL", initial_cid));
    assert(initial_cid == 0);
    const std::string state_response =
        frame(state_command, "+CSQ: 99,99\r\n+MIPSTATE: 0,\"TCP\",\"fixture.example\",80,\"CONNECTED\"");
    assert(classify_mip_state(state_response, state_command, 0) ==
           MipStateDisposition::connected);
    assert(classify_mip_state(state_response, state_command, 1) ==
           MipStateDisposition::invalid);
    assert(classify_mip_state(frame(state_command, "+MIPSTATE: 0,,,,\"OTHER\""),
                              state_command, 0) == MipStateDisposition::invalid);
    assert(classify_mip_state(frame(state_command, "+MIPSTATE: 0,,,,\"CLOSED\""),
                              state_command, 0) == MipStateDisposition::closed);
    const std::string closed_state_response =
        frame(state_command, "+MIPSTATE: 0,,,,\"CLOSED\"");
    uint8_t closed_cid = 0;
    assert(!parse_mip_state(closed_state_response, state_command, "CONNECTED", closed_cid));
    assert(!parse_mip_state(closed_state_response, state_command, "INITIAL", closed_cid));
    const std::string populated_closed_state =
        frame(state_command, "+MIPSTATE: 0,\"TCP\",\"fixture.example\",443,\"CLOSED\"");
    assert(classify_mip_state(populated_closed_state, state_command, 0) ==
           MipStateDisposition::closed);
    assert(classify_mip_state(
               frame(state_command, "+MIPSTATE: 0,\"TCP\",\"fixture.example\",1,\"CLOSED\""),
               state_command, 0) == MipStateDisposition::closed);
    assert(classify_mip_state(
               frame(state_command, "+MIPSTATE: 0,\"TCP\",\"fixture.example\",65535,\"CLOSED\""),
               state_command, 0) == MipStateDisposition::closed);
    const std::string maximum_address(255, 'a');
    assert(classify_mip_state(
               frame(state_command, "+MIPSTATE: 0,\"TCP\",\"" + maximum_address +
                                      "\",443,\"CLOSED\""),
               state_command, 0) == MipStateDisposition::closed);
    std::vector<std::string> invalid_closed_states = {
        frame(state_command, "+MIPSTATE: 0,\"TCP\",\"fixture.example\",,\"CLOSED\""),
        frame(state_command, "+MIPSTATE: 0,\"TCP\",,443,\"CLOSED\""),
        frame(state_command, "+MIPSTATE: 0,,\"fixture.example\",443,\"CLOSED\""),
        frame(state_command, "+MIPSTATE: 0,\"UDP\",\"fixture.example\",443,\"CLOSED\""),
        frame(state_command, "+MIPSTATE: 0,\"TCP\",\"\",443,\"CLOSED\""),
        frame(state_command, "+MIPSTATE: 0,\"TCP\",\"fixture.example\",0,\"CLOSED\""),
        frame(state_command, "+MIPSTATE: 0,\"TCP\",\"fixture.example\",65536,\"CLOSED\""),
        frame(state_command, "+MIPSTATE: 0,\"TCP\",\"fixture.example\",\"443\",\"CLOSED\""),
        frame(state_command, "+MIPSTATE: 0,\"TCP\",\"fixture.example\",+443,\"CLOSED\""),
        frame(state_command, "+MIPSTATE: 0,\"TCP\",\"fixture.example\",443,\"CLOSED\",extra"),
        frame(state_command, "+MIPSTATE: 0,\"TCP\",\"fixture\"evil\",443,\"CLOSED\""),
        frame(state_command, "+MIPSTATE: 0,\"TCP\",\"fixture\r\n+CEREG: 1,1\",443,\"CLOSED\""),
    };
    for (const std::string& invalid : invalid_closed_states) {
        assert(classify_mip_state(invalid, state_command, 0) == MipStateDisposition::invalid);
    }
    const std::string oversized_address(256, 'a');
    assert(classify_mip_state(
               frame(state_command, "+MIPSTATE: 0,\"TCP\",\"" + oversized_address +
                                      "\",443,\"CLOSED\""),
               state_command, 0) == MipStateDisposition::invalid);
    std::string control_address = "+MIPSTATE: 0,\"TCP\",\"fixture";
    control_address.push_back('\x01');
    control_address += ".example\",443,\"CLOSED\"";
    assert(classify_mip_state(frame(state_command, control_address), state_command, 0) ==
           MipStateDisposition::invalid);
    uint8_t state_cid = 0;
    assert(parse_mip_state(state_response, state_command, "CONNECTED", state_cid));
    assert(state_cid == 0);
    phases.emplace_back("STATE");

    std::vector<uint8_t> request(57);
    for (size_t index = 0; index < request.size(); ++index) {
        request[index] = static_cast<uint8_t>(index);
    }
    const std::string request_hex = idf_modem_https_wire::hex_encode(request.data(), request.size());
    assert(request_hex.size() == request.size() * 2U);
    assert(is_upper_hex(request_hex));
    const std::string send_wire_command = send_command + request_hex + "\"";
    const std::string send_response =
        frame(send_wire_command, "+MIPURC: \"rtcp\",0,57,57\r\n+MIPSEND: 0,57");
    assert(parse_result(send_response, send_wire_command, "+MIPSEND:", 0, value));
    assert(value == request.size());
    phases.emplace_back("SEND");

    const std::string http_body(1536U, 'b');
    const std::string http_headers =
        "HTTP/1.1 200 OK\r\nContent-Length: " + std::to_string(http_body.size()) +
        "\r\nX-Transcript: fragmented\r\n\r\n";
    const std::string http_wire = http_headers + http_body;
    assert(http_wire.size() > 1024U);
    const std::vector<size_t> read_ends = {
        http_headers.size() - 1U,
        http_headers.size() - 1U + 1024U,
        http_wire.size(),
    };
    uint32_t unread = 0;
    std::vector<uint8_t> read_data;
    bool remote_closed = false;
    HttpResponse http;
    IdfModemHttpsPostResult result;
    size_t offset = 0;
    for (const size_t end : read_ends) {
        const size_t chunk = end - offset;
        assert(chunk <= 1024U);
        const std::string http_hex = idf_modem_https_wire::hex_encode(
            reinterpret_cast<const uint8_t*>(http_wire.data() + offset), chunk);
        const std::string read_response = frame(
            read_command, "+CEREG: 1,1\r\n+MIPRD: 0," +
                              std::to_string(http_wire.size() - end) + "," +
                              std::to_string(chunk) + "," + http_hex);
        assert(parse_read(read_response, read_command, 0, unread, read_data, remote_closed));
        assert(!remote_closed);
        assert(unread == http_wire.size() - end && read_data.size() == chunk);
        assert(http.feed(read_data.data(), read_data.size(), result));
        offset = end;
    }

    const std::string remote_close_response = frame(
        read_command, "+MIPRD: 0,0,3,414243\r\n+MIPURC: \"disconn\",0,2");
    assert(parse_read(remote_close_response, read_command, 0, unread, read_data, remote_closed));
    assert(remote_closed);
    assert(read_data == std::vector<uint8_t>({'A', 'B', 'C'}));
    assert(parse_read(frame(read_command, "+MIPURC: \"disconn\",0,2"),
                      read_command, 0, unread, read_data, remote_closed));
    assert(remote_closed && unread == 0 && read_data.empty());
    assert(!parse_read(frame(read_command,
                             "+MIPRD: 0,1,1,41\r\n+MIPURC: \"disconn\",0,2"),
                       read_command, 0, unread, read_data, remote_closed));
    assert(!parse_read(frame(read_command, "+MIPURC: \"other\",0,2"),
                       read_command, 0, unread, read_data, remote_closed));
    assert(!parse_read(frame(read_command, "+MIPURC: \"disconn\",0,0"),
                       read_command, 0, unread, read_data, remote_closed));
    phases.emplace_back("READ");
    assert(http.complete());
    assert(result.httpStatus == 200);
    assert(result.expectedResponseBytes == http_body.size());
    assert(result.responseBytes == http_wire.size());
    assert(http.header_bytes() == http_headers.size());
    phases.emplace_back("HTTP200");

    const std::string close_response = frame(close_command, "+MIPCLOSE: 0,0");
    assert(parse_result(close_response, close_command, "+MIPCLOSE:", 0, value));
    assert(value == 0);
    const std::string close_error = frame(close_command, "+MIPCLOSE: 0,1");
    assert(parse_result(close_error, close_command, "+MIPCLOSE:", 0, value));
    assert(value == 1);
    phases.emplace_back("CLOSE");

    const std::vector<std::string> expected_phases = {"OPEN", "STATE", "SEND", "READ",
                                                       "HTTP200", "CLOSE"};
    assert(phases == expected_phases);
    assert(std::count(phases.begin(), phases.end(), "CLOSE") == 1);

    std::vector<uint8_t> rejected;
    const std::string odd_hex = frame(read_command, "+MIPRD: 0,0,0,A");
    assert(!parse_read(odd_hex, read_command, 0, unread, rejected, remote_closed));
    const std::string declared_mismatch = frame(read_command, "+MIPRD: 0,0,2,AB");
    assert(!parse_read(declared_mismatch, read_command, 0, unread, rejected, remote_closed));
    const std::string invalid_hex = frame(read_command, "+MIPRD: 0,0,1,0G");
    assert(!parse_read(invalid_hex, read_command, 0, unread, rejected, remote_closed));

    HttpResponse malformed_status;
    IdfModemHttpsPostResult malformed_result;
    const std::string bad_status = "HTTP/1.1 20 OK\r\n\r\n";
    assert(!malformed_status.feed(reinterpret_cast<const uint8_t*>(bad_status.data()),
                                  bad_status.size(), malformed_result));

    HttpResponse body_mismatch;
    IdfModemHttpsPostResult body_result;
    const std::string body_prefix = "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\n";
    assert(body_mismatch.feed(reinterpret_cast<const uint8_t*>(body_prefix.data()),
                              body_prefix.size(), body_result));
    assert(!body_mismatch.complete());
    const std::string body_partial = "a";
    assert(body_mismatch.feed(reinterpret_cast<const uint8_t*>(body_partial.data()),
                              body_partial.size(), body_result));
    assert(!body_mismatch.complete());
    const std::string body_overrun = "bc";
    assert(!body_mismatch.feed(reinterpret_cast<const uint8_t*>(body_overrun.data()),
                               body_overrun.size(), body_result));

    HttpResponse exact_body;
    IdfModemHttpsPostResult exact_result;
    const std::string exact_wire = "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nab";
    assert(exact_body.feed(reinterpret_cast<const uint8_t*>(exact_wire.data()),
                           exact_wire.size(), exact_result));
    assert(exact_body.complete() && exact_result.responseBytes == exact_wire.size());
    const std::string extra_body = "x";
    assert(!exact_body.feed(reinterpret_cast<const uint8_t*>(extra_body.data()),
                            extra_body.size(), exact_result));

    HttpResponse case_insensitive_length;
    IdfModemHttpsPostResult case_result;
    const std::string case_wire = "HTTP/1.1 200 OK\r\ncontent-length: 2\r\n\r\nab";
    assert(case_insensitive_length.feed(reinterpret_cast<const uint8_t*>(case_wire.data()),
                                        case_wire.size(), case_result));
    assert(case_insensitive_length.complete() && case_result.expectedResponseBytes == 2);

    HttpResponse no_length;
    IdfModemHttpsPostResult no_length_result;
    const std::string no_length_wire = "HTTP/1.1 200 OK\r\nX-Mode: close\r\n\r\nbody";
    assert(no_length.feed(reinterpret_cast<const uint8_t*>(no_length_wire.data()),
                          no_length_wire.size(), no_length_result));
    assert(!no_length.complete());
    assert(no_length.finish_eof(no_length_result));
    assert(no_length.complete() && no_length_result.expectedResponseBytes == 0);

    HttpResponse chunked;
    IdfModemHttpsPostResult chunked_result;
    const std::string chunked_wire =
        "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n";
    assert(!chunked.feed(reinterpret_cast<const uint8_t*>(chunked_wire.data()),
                         chunked_wire.size(), chunked_result));

    HttpResponse conflicting_length;
    IdfModemHttpsPostResult conflicting_result;
    const std::string conflicting_wire =
        "HTTP/1.1 200 OK\r\nContent-Length: 2\r\ncontent-length: 2\r\n\r\nab";
    assert(!conflicting_length.feed(reinterpret_cast<const uint8_t*>(conflicting_wire.data()),
                                    conflicting_wire.size(), conflicting_result));

    HttpResponse timeout;
    IdfModemHttpsPostResult timeout_result;
    assert(timeout.feed(nullptr, 0, timeout_result));
    assert(!timeout.complete());
    const std::string partial_status = "HTTP/1.1 200 OK\r\n";
    assert(timeout.feed(reinterpret_cast<const uint8_t*>(partial_status.data()),
                        partial_status.size(), timeout_result));
    assert(!timeout.complete());
    // A no-progress poll remains incomplete; the owner deadline classifies it as timeout.

    return 0;
}
