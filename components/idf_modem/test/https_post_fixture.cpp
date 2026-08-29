#include "idf_modem_https_wire.h"

#include <algorithm>
#include <cassert>
#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

namespace {

using idf_modem_https_wire::HttpResponse;
using idf_modem_https_wire::parse_cgact;
using idf_modem_https_wire::parse_cgdccont;
using idf_modem_https_wire::parse_cfg_response;
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

}  // namespace

int main()
{
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
    uint8_t initial_cid = 0;
    assert(parse_mip_state(initial_state_response, state_command, "INITIAL", initial_cid));
    assert(initial_cid == 0);
    const std::string state_response =
        frame(state_command, "+CSQ: 99,99\r\n+MIPSTATE: 0,\"TCP\",\"fixture.example\",80,\"CONNECTED\"");
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

    std::string http_wire = "HTTP/1.1 200 OK\r\nContent-Length: 0\r\nX-Transcript: ";
    assert(http_wire.size() + 4U < 269U);
    http_wire.append(269U - http_wire.size() - 4U, 'a');
    http_wire += "\r\n\r\n";
    assert(http_wire.size() == 269U);
    const std::string http_hex = idf_modem_https_wire::hex_encode(
        reinterpret_cast<const uint8_t*>(http_wire.data()), http_wire.size());
    const std::string read_response = frame(
        read_command, "+CEREG: 1,1\r\n+MIPRD: 0,0,269," + http_hex);
    uint32_t unread = 0;
    std::vector<uint8_t> read_data;
    assert(parse_read(read_response, read_command, 0, unread, read_data));
    assert(unread == 0 && read_data.size() == http_wire.size());
    phases.emplace_back("READ");

    HttpResponse http;
    IdfModemHttpsPostResult result;
    for (size_t offset = 0; offset < read_data.size();) {
        const size_t chunk = std::min(read_data.size() - offset, (offset % 11U) + 1U);
        assert(http.feed(read_data.data() + offset, chunk, result));
        offset += chunk;
    }
    assert(http.complete());
    assert(result.httpStatus == 200);
    assert(result.expectedResponseBytes == 0);
    assert(result.responseBytes == 269);
    assert(http.header_bytes() == 269);
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
    assert(!parse_read(odd_hex, read_command, 0, unread, rejected));
    const std::string declared_mismatch = frame(read_command, "+MIPRD: 0,0,2,AB");
    assert(!parse_read(declared_mismatch, read_command, 0, unread, rejected));
    const std::string invalid_hex = frame(read_command, "+MIPRD: 0,0,1,0G");
    assert(!parse_read(invalid_hex, read_command, 0, unread, rejected));

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
