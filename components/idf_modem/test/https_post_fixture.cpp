#include "idf_modem_https_wire.h"

#include <algorithm>
#include <cassert>
#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

namespace {

using idf_modem_https_wire::HttpResponse;
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
};

struct InitialStateTranscript {
    explicit InitialStateTranscript(InitialStateMode selected) : mode(selected) {}

    InitialStateMode mode;
    size_t state_queries = 0;
    std::vector<std::string> commands;
    std::vector<bool> cleanup;

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
                        ? "+MIPSTATE: 0,,,,\"CLOSED\""
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
};

IdfModemHttpsRunResult run_initial_state_transcript(InitialStateTranscript& transcript)
{
    IdfModemHttpsPostRequest request;
    request.url = "https://fixture.example/notify";
    request.body = "{}";
    request.rootCertificateDer = {'D', 'E', 'R'};
    request.rootCertificateSha256.fill(0xab);
    IdfModemHttpsCallbacks callbacks{&transcript, &InitialStateTranscript::send};
    IdfModemHttpsPostResult result;
    return idf_modem_https_run_post(request, callbacks, result);
}

void check_initial_state_transcripts()
{
    InitialStateTranscript initial{InitialStateMode::initial};
    assert(run_initial_state_transcript(initial) == IdfModemHttpsRunResult::command_failed);
    assert((initial.commands == std::vector<std::string>{
                                    "AT+MIPSTATE=0", "AT+MIPCFG=\"cid\",0"}));
    assert(std::count(initial.commands.begin(), initial.commands.end(), "AT+MIPCLOSE=0") == 0);

    InitialStateTranscript recovered{InitialStateMode::connected_then_initial};
    assert(run_initial_state_transcript(recovered) == IdfModemHttpsRunResult::command_failed);
    assert((recovered.commands == std::vector<std::string>{
                                      "AT+MIPSTATE=0", "AT+MIPCLOSE=0",
                                      "AT+MIPSTATE=0", "AT+MIPCFG=\"cid\",0"}));
    assert((recovered.cleanup == std::vector<bool>{false, true, false, false}));

    InitialStateTranscript closed{InitialStateMode::closed_then_initial};
    assert(run_initial_state_transcript(closed) == IdfModemHttpsRunResult::command_failed);
    assert((closed.commands == std::vector<std::string>{
                                   "AT+MIPSTATE=0", "AT+MIPCLOSE=0",
                                   "AT+MIPSTATE=0", "AT+MIPCFG=\"cid\",0"}));
    assert((closed.cleanup == std::vector<bool>{false, true, false, false}));

    for (const InitialStateMode mode : {InitialStateMode::state_failed,
                                        InitialStateMode::state_timeout,
                                        InitialStateMode::malformed_state,
                                        InitialStateMode::ambiguous_state,
                                        InitialStateMode::unknown_state,
                                        InitialStateMode::wrong_cid}) {
        InitialStateTranscript rejected{mode};
        const IdfModemHttpsRunResult expected = mode == InitialStateMode::state_timeout
                                                    ? IdfModemHttpsRunResult::timed_out
                                                    : IdfModemHttpsRunResult::command_failed;
        assert(run_initial_state_transcript(rejected) == expected);
        assert((rejected.commands == std::vector<std::string>{"AT+MIPSTATE=0"}));
        assert(std::count(rejected.commands.begin(), rejected.commands.end(),
                          "AT+MIPCLOSE=0") == 0);
    }

    for (const InitialStateMode mode : {InitialStateMode::close_failed,
                                        InitialStateMode::close_ambiguous}) {
        InitialStateTranscript rejected{mode};
        assert(run_initial_state_transcript(rejected) == IdfModemHttpsRunResult::command_failed);
        assert((rejected.commands == std::vector<std::string>{
                                         "AT+MIPSTATE=0", "AT+MIPCLOSE=0"}));
    }

    InitialStateTranscript still_connected{InitialStateMode::connected_after_close};
    assert(run_initial_state_transcript(still_connected) == IdfModemHttpsRunResult::command_failed);
    assert((still_connected.commands == std::vector<std::string>{
                                         "AT+MIPSTATE=0", "AT+MIPCLOSE=0",
                                         "AT+MIPSTATE=0"}));
}

enum class RemoteCloseMode {
    data_then_disconnect,
    disconnect_only,
    unread_data,
    duplicate_disconnect,
    post_open_closed,
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
    explicit RemoteCloseTranscript(RemoteCloseMode selected) : mode(selected) {}

    RemoteCloseMode mode;
    size_t state_queries = 0;
    size_t send_commands = 0;
    size_t read_commands = 0;
    size_t close_commands = 0;
    bool close_was_cleanup = false;
    uint8_t encoding_send = 0;
    uint8_t encoding_receive = 0;
    uint8_t autofree = 0;

    static IdfModemHttpsCommandResult send(void* context, std::string_view command,
                                           std::string& response, bool cleanup)
    {
        auto& transcript = *static_cast<RemoteCloseTranscript*>(context);
        if (command == "AT+MIPSTATE=0") {
            ++transcript.state_queries;
            const std::string_view state =
                transcript.state_queries == 1
                    ? "+MIPSTATE: 0,,,,\"INITIAL\""
                : transcript.mode == RemoteCloseMode::post_open_closed
                    ? "+MIPSTATE: 0,,,,\"CLOSED\""
                    : "+MIPSTATE: 0,\"TCP\",\"fixture.example\",443,\"CONNECTED\"";
            response = frame(command, state);
            return IdfModemHttpsCommandResult::ok;
        }
        if (command == "AT+MIPCFG=\"cid\",0") {
            response = frame(command, "+MIPCFG: \"cid\",0,1");
            return IdfModemHttpsCommandResult::ok;
        }
        if (command == "AT+MIPCFG=\"encoding\",0") {
            response = frame(command, "+MIPCFG: \"encoding\",0," +
                                          std::to_string(transcript.encoding_send) + "," +
                                          std::to_string(transcript.encoding_receive));
            return IdfModemHttpsCommandResult::ok;
        }
        if (command == "AT+MIPCFG=\"autofree\",0") {
            response = frame(command, "+MIPCFG: \"autofree\",0," +
                                          std::to_string(transcript.autofree));
            return IdfModemHttpsCommandResult::ok;
        }
        if (command == "AT+MIPCFG=\"ssl\",0") {
            response = frame(command, "+MIPCFG: \"ssl\",0,0,0");
            return IdfModemHttpsCommandResult::ok;
        }
        if (command == "AT+MIPCFG=\"encoding\",0,1,1" ||
            command == "AT+MIPCFG=\"encoding\",0,0,0") {
            transcript.encoding_send = command == "AT+MIPCFG=\"encoding\",0,1,1" ? 1 : 0;
            transcript.encoding_receive = transcript.encoding_send;
            response = frame(command, "");
            return IdfModemHttpsCommandResult::ok;
        }
        if (command == "AT+MIPCFG=\"autofree\",0,1" ||
            command == "AT+MIPCFG=\"autofree\",0,0") {
            transcript.autofree = command == "AT+MIPCFG=\"autofree\",0,1" ? 1 : 0;
            response = frame(command, "");
            return IdfModemHttpsCommandResult::ok;
        }
        if (command == "AT+MIPCFG=\"ssl\",0,0,0") {
            response = frame(command, "");
            return IdfModemHttpsCommandResult::ok;
        }
        if (command == "AT+CGDCONT?") {
            response = frame(command, "+CGDCONT: 1,\"IPV4V6\",\"fixture\",,0,0,,,,");
            return IdfModemHttpsCommandResult::ok;
        }
        if (command == "AT+CGACT?") {
            response = frame(command, "+CGACT: 1,1");
            return IdfModemHttpsCommandResult::ok;
        }
        constexpr std::string_view open_prefix = "AT+MIPOPEN=0,\"TCP\",\"fixture.example\",443,";
        if (command.compare(0, open_prefix.size(), open_prefix) == 0) {
            response = frame(command, "+MIPOPEN: 0,0");
            return IdfModemHttpsCommandResult::ok;
        }
        constexpr std::string_view send_prefix = "AT+MIPSEND=0,";
        if (command.compare(0, send_prefix.size(), send_prefix) == 0) {
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
                static constexpr std::string_view http =
                    "HTTP/1.1 200 OK\r\nX-Test: remote-close\r\n\r\nbody";
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
            response = frame(command, "+MIPCLOSE: 0,0");
            return IdfModemHttpsCommandResult::ok;
        }
        return IdfModemHttpsCommandResult::failed;
    }
};

IdfModemHttpsRunResult run_remote_close_transcript(RemoteCloseTranscript& transcript,
                                                   IdfModemHttpsPostResult& result)
{
    IdfModemHttpsPostRequest request;
    request.url = "https://fixture.example/notify";
    request.body = "{}";
    request.rootCertificateDer = {'D', 'E', 'R'};
    request.rootCertificateSha256.fill(0xab);
    IdfModemHttpsCallbacks callbacks{&transcript, &RemoteCloseTranscript::send};
    return idf_modem_https_run_post(request, callbacks, result);
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
    assert(result.expectedResponseBytes == 0);
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
    }

    RemoteCloseTranscript closed_after_open{RemoteCloseMode::post_open_closed};
    result = {};
    assert(run_remote_close_transcript(closed_after_open, result) ==
           IdfModemHttpsRunResult::command_failed);
    assert(!result.ok && closed_after_open.send_commands == 0 &&
           closed_after_open.read_commands == 0 && closed_after_open.close_commands == 1 &&
           closed_after_open.close_was_cleanup);
    assert(closed_after_open.encoding_send == 0 && closed_after_open.encoding_receive == 0 &&
           closed_after_open.autofree == 0);
}

}  // namespace

int main()
{
    check_initial_state_transcripts();
    check_remote_close_transcripts();
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
