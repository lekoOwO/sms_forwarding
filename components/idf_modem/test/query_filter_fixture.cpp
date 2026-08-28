#include "idf_modem_query_filter.h"
#include "idf_modem_cpol_summary.h"
#include "idf_modem_registration.h"

#include <cassert>
#include <condition_variable>
#include <cstdint>
#include <iostream>
#include <mutex>
#include <string>
#include <thread>

struct HealthResetRetryFixture {
    uint8_t attempts = 0;
    uint32_t delays[3] = {};
    size_t accepted = 0;

    bool request(void)
    {
        if (!idf_modem_health_reset_retry_allowed(attempts)) return false;
        delays[accepted++] = idf_modem_health_reset_backoff_ms(attempts++);
        return true;
    }
};

struct SimPresenceFixture {
    int baseline = -1;
    int last_confirmed = -1;
    int removal_events = 0;
    int insertion_events = 0;

    void reset(void)
    {
        baseline = -1;
    }

    void observe(std::string_view state)
    {
        int observed = idf_modem_sim_presence(state);
        if (observed < 0) {
            baseline = -1;
            return;
        }
        IdfModemSimPresenceEvent event =
            idf_modem_sim_presence_event(last_confirmed, observed);
        last_confirmed = observed;
        baseline = observed;
        if (event == IdfModemSimPresenceEvent::removed) ++removal_events;
        if (event == IdfModemSimPresenceEvent::inserted) ++insertion_events;
    }
};

struct RawOwnerUrcFixture {
    std::string urcs;

    void observe(std::string_view line)
    {
        if (idf_modem_is_standalone_urc_line(line)) {
            urcs += std::string(line) + "\r\n";
        }
    }
};

struct SmsHealthCompletionFixture {
    bool backoff_cleared = false;

    void finish(bool registered, bool phase2, bool pdu, bool cnmi, bool storage)
    {
        if (idf_modem_sms_health_complete(registered, phase2, pdu, cnmi, storage)) {
            backoff_cleared = true;
        }
    }
};

struct ResetBarrierFixture {
    std::mutex command_mutex;
    std::mutex barrier_mutex;
    std::condition_variable barrier;
    bool owner_started = false;
    bool owner_running = false;
    bool owner_release = false;
    bool reset_started = false;
    bool reset_applied = false;
    bool queue_ready = true;
    bool reset_requested = false;
    bool completed = false;
    int completion_count = 0;
    int uart_writes = 0;
    int result = 0;

    void signal(bool& flag)
    {
        {
            std::lock_guard<std::mutex> lock(barrier_mutex);
            flag = true;
        }
        barrier.notify_all();
    }

    void wait_for(bool& flag)
    {
        std::unique_lock<std::mutex> lock(barrier_mutex);
        barrier.wait(lock, [&flag] { return flag; });
    }

    void dispatch_normal(bool priority, bool hold_running)
    {
        signal(owner_started);
        std::unique_lock<std::mutex> lock(command_mutex);
        if (!idf_modem_owner_command_allowed(priority, reset_requested, queue_ready)) {
            result = 1;
            completed = true;
            ++completion_count;
            return;
        }
        signal(owner_running);
        if (hold_running) {
            wait_for(owner_release);
        }
        lock.unlock();
        ++uart_writes;
        completed = true;
        ++completion_count;
    }

    void request_reset()
    {
        signal(reset_started);
        std::lock_guard<std::mutex> lock(command_mutex);
        queue_ready = false;
        reset_requested = true;
        reset_applied = true;
    }
};

enum class QueryOutcome {
    not_ready,
    busy_runtime_gate,
    submitted,
    busy_command_mutex,
    busy_slots,
    busy_queue,
    timeout_owner,
};

static const char* query_outcome_name(QueryOutcome outcome)
{
    switch (outcome) {
        case QueryOutcome::not_ready: return "not-ready";
        case QueryOutcome::busy_runtime_gate: return "busy-runtime-gate";
        case QueryOutcome::submitted: return "submitted";
        case QueryOutcome::busy_command_mutex: return "busy-command-mutex";
        case QueryOutcome::busy_slots: return "busy-slots";
        case QueryOutcome::busy_queue: return "busy-queue";
        case QueryOutcome::timeout_owner: return "timeout-owner";
    }
    return "unknown";
}

struct QuerySubmitFixture {
    bool owner_queue_ready = true;
    bool at_ready = true;
    bool reset_requested = false;
    bool command_mutex_available = true;
    int free_slots = 4;
    bool queue_accepts = true;
    bool owner_completes = true;
    int submit_calls = 0;
    uint8_t reason = 0;

    QueryOutcome run()
    {
        const IdfModemUsbQueryAdmission admission = idf_modem_usb_query_admission(
            owner_queue_ready, at_ready, reset_requested);
        if (admission == IdfModemUsbQueryAdmission::busy) {
            reason = 1;
            return QueryOutcome::busy_runtime_gate;
        }
        if (admission == IdfModemUsbQueryAdmission::not_ready) {
            return QueryOutcome::not_ready;
        }

        // Submit through the existing owner queue after admission; do not reject an idle race.
        ++submit_calls;
        if (!command_mutex_available) {
            reason = 2;
            return QueryOutcome::busy_command_mutex;
        }
        if (free_slots == 0) {
            reason = 3;
            return QueryOutcome::busy_slots;
        }
        if (!queue_accepts) {
            reason = 4;
            return QueryOutcome::busy_queue;
        }
        return owner_completes ? QueryOutcome::submitted : QueryOutcome::timeout_owner;
    }
};

static void print_query_case(const char* name, QuerySubmitFixture fixture)
{
    const QueryOutcome outcome = fixture.run();
    const char* reason = fixture.reason == 1 ? "gate_closed" :
                         fixture.reason == 2 ? "mutex_timeout" :
                         fixture.reason == 3 ? "slots_full" :
                         fixture.reason == 4 ? "queue_full" : "unknown";
    std::cout << "query=" << name << " outcome=" << query_outcome_name(outcome)
              << " reason=" << reason
              << " submit-calls=" << fixture.submit_calls << '\n';
}

struct QueryTimeoutFixture {
    static constexpr uint32_t normal_timeout_ms = 1500;
    static constexpr uint32_t cpol_timeout_ms = 5000;

    static bool completes(uint32_t command_duration_ms, uint32_t timeout_ms)
    {
        return command_duration_ms <= timeout_ms;
    }
};

struct AbsoluteDeadlineFixture {
    static uint32_t remaining(uint32_t start, uint32_t now, uint32_t span)
    {
        const uint32_t elapsed = now - start;
        return elapsed >= span ? 0 : span - elapsed;
    }
};

int main()
{
    const std::string ipv4 = std::to_string(192) + "." + std::to_string(0) + "." +
                             std::to_string(2) + "." + std::to_string(44);
    const std::string second_ipv4 = std::to_string(198) + "." + std::to_string(51) + "." +
                                    std::to_string(100) + "." + std::to_string(7);
    const std::string ipv6 = std::string("2001") + ":" + "db8" + "::" + "44";
    const std::string full_ipv6 = std::string("2001") + ":" + "db8" + ":0:0:0:0:0:" + "44";
    const std::string mixed_ipv6 = std::string("::") + "ffff" + ":" + second_ipv4;
    const auto cgpaddr_response = [](const std::string& fields) {
        return std::string("\r\n+CGPADDR: ") + fields + "\r\nOK\r\n";
    };
    std::string parsed_ip;
    const auto accept_cgpaddr = [&parsed_ip, &cgpaddr_response](
                                    const std::string& fields, const std::string& expected) {
        parsed_ip.clear();
        assert(idf_modem_parse_cgpaddr_ipv4(cgpaddr_response(fields), parsed_ip));
        assert(parsed_ip == expected);
    };
    const auto reject_cgpaddr = [&parsed_ip](const std::string& response) {
        parsed_ip = "unchanged";
        assert(!idf_modem_parse_cgpaddr_ipv4(response, parsed_ip));
        assert(parsed_ip == "unchanged");
    };
    accept_cgpaddr("1," + ipv4, ipv4);
    accept_cgpaddr("255,\"" + ipv4 + "\"", ipv4);
    for (bool quoted : {false, true}) {
        const std::string quote = quoted ? "\"" : "";
        accept_cgpaddr("1," + quote + ipv4 + quote + "," + quote + ipv6 + quote, ipv4);
    }
    accept_cgpaddr("1," + ipv4 + "," + full_ipv6, ipv4);
    accept_cgpaddr("1," + ipv4 + "," + mixed_ipv6, ipv4);
    accept_cgpaddr("1,\"" + ipv6 + "\",\"" + second_ipv4 + "\"", second_ipv4);

    reject_cgpaddr(cgpaddr_response("1," + ipv4 + "," + ipv6 + "g"));
    for (const std::string& malformed_ipv6 : {
             ipv6 + "::" + "1",
             std::string("2001") + ":" + "db8" + ":" + "1",
             std::string("1:2:3:4:5:6:7:8:9"),
             std::string("12345") + "::" + "1",
         }) {
        reject_cgpaddr(cgpaddr_response("1," + ipv4 + "," + malformed_ipv6));
    }
    reject_cgpaddr(cgpaddr_response("1"));
    reject_cgpaddr(cgpaddr_response("1," + ipv6));
    for (const std::string& cid : {std::string("0"), std::string("256"), std::string("bad")}) {
        reject_cgpaddr(cgpaddr_response(cid + "," + ipv4));
    }
    reject_cgpaddr(cgpaddr_response("1," + ipv4 + "x," + ipv6));
    reject_cgpaddr(cgpaddr_response("1,\"" + ipv4));
    reject_cgpaddr(cgpaddr_response("1,\""));
    reject_cgpaddr(cgpaddr_response("1," + ipv4 + "," + ipv6 + "," + second_ipv4));
    reject_cgpaddr(cgpaddr_response("1," + ipv4 + "," + ipv6 + "\x1b"));
    reject_cgpaddr("+CGPADDR: 1," + ipv4 + "\r\n+CGPADDR: 1," + second_ipv4 +
                   "\r\nOK\r\n");
    reject_cgpaddr(cgpaddr_response("1," + ipv4) + "NO CARRIER\r\n");

    int cereg_stat = -1;
    assert(idf_modem_parse_cereg_status("\r\n+CEREG: 0,11\r\nOK\r\n", cereg_stat));
    assert(cereg_stat == 11); // 3GPP RLOS-only must remain observable.
    for (int expected : {0, 1, 2, 3, 4, 5, 11}) {
        const std::string query = "\r\n+CEREG: 0," + std::to_string(expected) + "\r\nOK\r\n";
        assert(idf_modem_parse_cereg_status(query, cereg_stat));
        assert(cereg_stat == expected);
    }
    for (int unsupported : {6, 7, 8, 9, 10}) {
        const std::string query = "\r\n+CEREG: 0," + std::to_string(unsupported) + "\r\nOK\r\n";
        assert(!idf_modem_parse_cereg_status(query, cereg_stat));
    }
    assert(idf_modem_parse_cereg_status(
        "\r\n+CEREG: 2,5,\"ABCD\",\"12345678\",7\r\nOK\r\n", cereg_stat));
    assert(cereg_stat == 5);
    assert(!idf_modem_parse_cereg_status("+CEREG: 0,12\r\nOK\r\n", cereg_stat));
    assert(!idf_modem_parse_cereg_status("+CEREG: 0,1\r\n", cereg_stat));
    assert(!idf_modem_parse_cereg_status("+CEREG: 0,1\r\n\r\nOK\r\n", cereg_stat));
    assert(!idf_modem_parse_cereg_status(
        "+CEREG: 2,1,\"ABCD\",\"12345678\",7\r\nOK\r\n+CEREG: 2\r\n", cereg_stat));
    assert(!idf_modem_parse_cereg_status(
        "+CEREG: 2,1,\"ABCD\",\"12345678\",7\r\n+CEREG: 2\r\nOK\r\n", cereg_stat));
    assert(!idf_modem_parse_cereg_status(
        "+CEREG: 2,1,\"ABCD\",\"1234\",7\r\nOK\r\n", cereg_stat));
    assert(!idf_modem_parse_cereg_status(
        "+CEREG: 2,1,\"ABCD\",\"12345678\",8\r\nOK\r\n", cereg_stat));
    assert(!idf_modem_parse_cereg_status(
        "+CEREG: 2,01,\"ABCD\",\"12345678\",7\r\nOK\r\n", cereg_stat));
    assert(!idf_modem_parse_cereg_status(
        "+CEREG: 2,1,\"ABCD\",\"12345678\",07\r\nOK\r\n", cereg_stat));
    assert(!idf_modem_parse_cereg_status(
        "+CEREG: 2,1,\"ABCD\",\"12345678\",7\vOK\r\n", cereg_stat));
    assert(!idf_modem_parse_cereg_status("+CEREG:\t0,1\r\nOK\r\n", cereg_stat));
    assert(!idf_modem_parse_cereg_status("+CEREG: 0,\t1\r\nOK\r\n", cereg_stat));
    assert(!idf_modem_parse_cereg_status("+CEREG: 0,1\v\r\nOK\r\n", cereg_stat));
    assert(!idf_modem_parse_cereg_status("+CEREG: 0,1\f\r\nOK\r\n", cereg_stat));
    assert(idf_modem_data_activation_allowed(1));
    assert(!idf_modem_data_activation_allowed(5));
    assert(!idf_modem_data_activation_allowed(11));
    assert(!idf_modem_data_activation_allowed(0));
    assert(!idf_modem_data_activation_allowed(-1));
    assert(!idf_modem_sms_health_reset_required(true, true, true, true, true));
    assert(!idf_modem_sms_health_reset_required(true, true, true, true, true));
    assert(idf_modem_sms_health_reset_required(false, true, true, true, true));
    assert(idf_modem_sms_health_reset_required(true, false, true, true, true));
    assert(idf_modem_sms_health_reset_required(true, true, false, true, true));
    assert(idf_modem_sms_health_reset_required(true, true, true, false, true));
    assert(idf_modem_sms_health_reset_required(true, true, true, true, false));
    assert(!idf_modem_health_reset_required(true, false, true, false, -1, false, false));
    assert(!idf_modem_health_reset_required(true, true, true, true, 11, false, false));
    assert(idf_modem_health_reset_required(true, true, true, false, -1, true, true));
    assert(idf_modem_health_reset_required(true, true, true, true, 0, false, true));
    assert(idf_modem_unregistered_reset_allowed(false, 0) == false);
    assert(idf_modem_unregistered_reset_allowed(true, 11) == false);
    assert(idf_modem_unregistered_reset_allowed(true, 0));
    assert(!idf_modem_unregistered_reset_allowed(true, 1));
    assert(idf_modem_sim_presence("absent") == 0);
    assert(idf_modem_sim_presence("unknown") == -1);
    assert(idf_modem_sim_presence("ready") == 1);
    assert(idf_modem_sim_presence("pin") == 1);
    assert(idf_modem_health_reset_backoff_ms(0) == 60000UL);
    assert(idf_modem_health_reset_backoff_ms(1) == 120000UL);
    assert(idf_modem_health_reset_backoff_ms(2) == 240000UL);
    assert(idf_modem_health_reset_backoff_ms(3) == 300000UL);
    assert(idf_modem_health_reset_backoff_ms(10) == 300000UL);
    assert(idf_modem_health_reset_retry_allowed(0));
    assert(idf_modem_health_reset_retry_allowed(2));
    assert(!idf_modem_health_reset_retry_allowed(3));
    assert(!idf_modem_health_reset_retry_allowed(255));
    SmsHealthCompletionFixture health_fixture;
    health_fixture.finish(true, false, true, true, true);
    assert(!health_fixture.backoff_cleared);
    health_fixture.finish(true, true, true, true, true);
    assert(health_fixture.backoff_cleared);
    HealthResetRetryFixture retry_fixture;
    for (int i = 0; i < 10; ++i) retry_fixture.request();
    assert(retry_fixture.accepted == 3);
    assert(retry_fixture.delays[0] == 60000UL);
    assert(retry_fixture.delays[1] == 120000UL);
    assert(retry_fixture.delays[2] == 240000UL);
    SimPresenceFixture sim_fixture;
    sim_fixture.observe("ready");
    assert(sim_fixture.baseline == 1);
    sim_fixture.observe("unknown");
    assert(sim_fixture.baseline == -1);
    sim_fixture.observe("absent");
    assert(sim_fixture.baseline == 0);
    assert(sim_fixture.removal_events == 1);
    assert(sim_fixture.insertion_events == 0);
    SimPresenceFixture reset_fixture;
    reset_fixture.observe("ready");
    reset_fixture.reset();
    reset_fixture.observe("unknown");
    assert(reset_fixture.removal_events == 0);
    reset_fixture.observe("absent");
    assert(reset_fixture.removal_events == 1);

    RawOwnerUrcFixture raw_owner;
    raw_owner.observe("+CEREG: 2");
    raw_owner.observe("+CSQ: 31,99");
    assert(raw_owner.urcs.find("+CEREG: 2") != std::string::npos);
    assert(raw_owner.urcs.find("+CSQ: 31,99") == std::string::npos);
    assert(idf_modem_identity_sampling_allowed(1));
    assert(!idf_modem_identity_sampling_allowed(5));
    assert(!idf_modem_identity_sampling_allowed(11));
    assert(!idf_modem_identity_sampling_allowed(0));
    int stale_stat = 1;
    idf_modem_invalidate_registration_stat(stale_stat);
    assert(stale_stat == -1);
    assert(!idf_modem_data_activation_allowed(stale_stat));
    assert(!idf_modem_identity_sampling_allowed(stale_stat));

    assert(!idf_modem_query_transport_ready(false, true, false));  // startup queue is closed
    assert(idf_modem_query_transport_ready(true, true, false));   // SIM locked/unregistered
    assert(!idf_modem_query_transport_ready(true, true, true));   // reset is in progress
    assert(!idf_modem_query_transport_ready(true, false, false)); // AT transport is down

    assert(idf_modem_usb_query_admission(false, true, false) ==
           IdfModemUsbQueryAdmission::busy);       // runtime queue is not ready
    assert(idf_modem_usb_query_admission(true, false, false) ==
           IdfModemUsbQueryAdmission::not_ready);  // AT transport is down
    assert(idf_modem_usb_query_admission(true, true, true) ==
           IdfModemUsbQueryAdmission::not_ready);  // reset is in progress
    // A briefly busy owner still uses the existing queue; the USB caller does not recheck idle.
    assert(idf_modem_usb_query_admission(true, true, false) ==
           IdfModemUsbQueryAdmission::submit);

    struct OwnerDispatchFixture {
        enum class State { queued, done };

        State state = State::queued;
        bool completed = false;
        bool cancelled = false;
        int uart_writes = 0;
        int result = 0;

        bool dispatch(bool priority, bool reset_requested, bool queue_ready)
        {
            assert(state == State::queued);
            if (!idf_modem_owner_command_allowed(priority, reset_requested, queue_ready)) {
                result = 1; // ESP_ERR_INVALID_STATE / NOT_READY in the firmware.
                cancelled = true;
                state = State::done;
                completed = true;
                return false;
            }
            ++uart_writes;
            state = State::done;
            completed = true;
            return true;
        }
    };

    OwnerDispatchFixture reset_race;
    const bool reset_race_dispatched = reset_race.dispatch(false, true, false);
    assert(!reset_race_dispatched);
    assert(reset_race.completed);
    assert(reset_race.state == OwnerDispatchFixture::State::done);
    assert(reset_race.cancelled);
    assert(reset_race.result != 0);
    assert(reset_race.uart_writes == 0); // queued query is cancelled before UART

    OwnerDispatchFixture reset_flag;
    const bool reset_flag_dispatched = reset_flag.dispatch(false, true, true);
    assert(!reset_flag_dispatched);
    assert(reset_flag.completed);
    assert(reset_flag.cancelled);
    assert(reset_flag.uart_writes == 0); // reset request wins over a stale ready flag

    OwnerDispatchFixture recovered_query;
    const bool recovered_query_dispatched = recovered_query.dispatch(false, false, true);
    assert(recovered_query_dispatched); // reset recovery resumes queries
    assert(recovered_query.completed);
    assert(recovered_query.state == OwnerDispatchFixture::State::done);
    assert(!recovered_query.cancelled);
    assert(recovered_query.uart_writes == 1);

    OwnerDispatchFixture priority_cnma;
    const bool priority_cnma_dispatched = priority_cnma.dispatch(true, true, false);
    assert(priority_cnma_dispatched);
    assert(priority_cnma.completed);
    assert(priority_cnma.uart_writes == 1); // Priority CNMA work bypasses the normal reset gate.

    ResetBarrierFixture reset_first;
    reset_first.command_mutex.lock();
    std::thread reset_first_owner([&reset_first] { reset_first.dispatch_normal(false, false); });
    reset_first.wait_for(reset_first.owner_started);
    assert(reset_first.owner_started);
    reset_first.queue_ready = false;
    reset_first.reset_requested = true;
    reset_first.command_mutex.unlock();
    reset_first_owner.join();
    assert(reset_first.completed);
    assert(reset_first.completion_count == 1);
    assert(reset_first.result == 1);
    assert(reset_first.uart_writes == 0);

    ResetBarrierFixture owner_first;
    std::thread owner_first_owner([&owner_first] { owner_first.dispatch_normal(false, true); });
    owner_first.wait_for(owner_first.owner_running);
    assert(owner_first.owner_running);
    std::thread owner_first_reset([&owner_first] { owner_first.request_reset(); });
    owner_first.wait_for(owner_first.reset_started);
    assert(!owner_first.reset_applied);
    {
        std::lock_guard<std::mutex> lock(owner_first.barrier_mutex);
        owner_first.owner_release = true;
    }
    owner_first.barrier.notify_all();
    owner_first_owner.join();
    owner_first_reset.join();
    assert(owner_first.completed);
    assert(owner_first.completion_count == 1);
    assert(owner_first.uart_writes == 1);
    assert(owner_first.reset_applied);
    assert(!owner_first.queue_ready);
    assert(owner_first.reset_requested);

    QuerySubmitFixture runtime_gate;
    runtime_gate.owner_queue_ready = false;
    print_query_case("runtime-gate", runtime_gate);
    QuerySubmitFixture not_ready;
    not_ready.at_ready = false;
    print_query_case("not-ready", not_ready);
    QuerySubmitFixture idle_collision;
    print_query_case("idle-collision", idle_collision);
    QuerySubmitFixture mutex_busy;
    mutex_busy.command_mutex_available = false;
    print_query_case("mutex", mutex_busy);
    QuerySubmitFixture slots_busy;
    slots_busy.free_slots = 0;
    print_query_case("slots", slots_busy);
    QuerySubmitFixture queue_busy;
    queue_busy.queue_accepts = false;
    print_query_case("queue", queue_busy);
    QuerySubmitFixture owner_timeout;
    owner_timeout.owner_completes = false;
    print_query_case("owner", owner_timeout);

    // CPOL needs the bounded 5s command window; normal fixed queries keep 1.5s.
    assert(QueryTimeoutFixture::completes(2000, QueryTimeoutFixture::cpol_timeout_ms));
    assert(!QueryTimeoutFixture::completes(5001, QueryTimeoutFixture::cpol_timeout_ms));
    assert(QueryTimeoutFixture::completes(1499, QueryTimeoutFixture::normal_timeout_ms));
    assert(!QueryTimeoutFixture::completes(1501, QueryTimeoutFixture::normal_timeout_ms));

    // Every wait consumes the same budget; no second full wait is allowed.
    assert(AbsoluteDeadlineFixture::remaining(0, 5500, 6000) == 500);
    assert(AbsoluteDeadlineFixture::remaining(0, 6000, 6000) == 0);
    assert(AbsoluteDeadlineFixture::remaining(0xFFFFFFFCU, 2, 10) == 4);
    assert(AbsoluteDeadlineFixture::remaining(0xFFFFFFFCU, 6, 10) == 0);
    assert(AbsoluteDeadlineFixture::remaining(0xFFFFFFFCU, 7, 10) == 0);

    IdfModemQueryResponseFilter filter("AT+CPIN?", "+CPIN:", "", false);
    const std::string interleaved =
        "\r\n+CMT: \"+886900000\",145\r\n"
        "00112233445566778899AABBCCDDEEFF\r\n"
        "+CEREG: 2\r\n"
        "+CPIN: READY\r\nOK\r\n";
    filter.feed(interleaved.data(), interleaved.size());

    assert(filter.response().find("+CPIN: READY") != std::string::npos);
    assert(filter.response().find("OK") != std::string::npos);
    assert(filter.response().find("+CMT:") == std::string::npos);
    assert(filter.response().find("0011223344556677") == std::string::npos);
    assert(filter.response().find("+CEREG:") == std::string::npos);
    assert(filter.urcs().find("+CMT: \"+886900000\",145") != std::string::npos);
    assert(filter.urcs().find("00112233445566778899AABBCCDDEEFF") != std::string::npos);
    assert(filter.urcs().find("+CEREG: 2") != std::string::npos);

    struct FixedQueryCase {
        const char* command;
        const char* prefix;
        const char* expected;
        const char* duplicate;
    };
    const FixedQueryCase fixed_queries[] = {
        {"AT+CPIN?", "+CPIN:", "+CPIN: READY", "+CPIN: TEST"},
        {"AT+COPS?", "+COPS:", "+COPS: 0", "+COPS: 2"},
        {"AT+CGATT?", "+CGATT:", "+CGATT: 1", "+CGATT: 0"},
        {"AT+CGACT?", "+CGACT:", "+CGACT: 1,1", "+CGACT: 1,0"},
        {"AT+CGPADDR", "+CGPADDR:", "+CGPADDR: 1,10.0.0.2", "+CGPADDR: 1,10.0.0.3"},
        {"AT+ICCID", "+ICCID:", "+ICCID: 1234567890123456789", "+ICCID: 9876543210987654321"},
        {"AT+CSQ", "+CSQ:", "+CSQ: 31,99", "+CSQ: 0,99"},
        {"AT+CESQ", "+CESQ:", "+CESQ: 99,99,255,255,17,71", "+CESQ: 99,99,255,255,0,0"},
        {"AT+CFUN?", "+CFUN:", "+CFUN: 1", "+CFUN: 0"},
        {"AT+CREG?", "+CREG:", "+CREG: 0,1", "+CREG: 0,0"},
        {"AT+CGREG?", "+CGREG:", "+CGREG: 0,1", "+CGREG: 0,0"},
        {"AT+CEER", "+CEER:", "+CEER: 0", "+CEER: 1"},
    };
    for (const FixedQueryCase& query : fixed_queries) {
        IdfModemQueryResponseFilter shaped(query.command, query.prefix, "", false);
        const std::string input = std::string(query.command) + "\r\n"
                                  "+CMT: \"sender\",145\r\n"
                                  "00112233445566778899AABBCCDDEEFF\r\n"
                                  "+OTHER: unsolicited\r\n" + query.expected + "\r\n"
                                  + query.duplicate + "\r\nRING\r\nOK\r\n";
        shaped.feed(input.data(), input.size());
        assert(shaped.response().find(query.command) == std::string::npos);
        assert(shaped.response().find(query.expected) != std::string::npos);
        assert(shaped.response().find(query.duplicate) == std::string::npos);
        assert(shaped.urcs().find(query.duplicate) != std::string::npos);
        assert(shaped.response().find("+CMT:") == std::string::npos);
        assert(shaped.response().find("00112233445566778899AABBCCDDEEFF") == std::string::npos);
        assert(shaped.response().find("+OTHER:") == std::string::npos);
        assert(shaped.response().find("RING") == std::string::npos);
        assert(shaped.urcs().find("+CMT:") != std::string::npos);
        assert(shaped.urcs().find("00112233445566778899AABBCCDDEEFF") != std::string::npos);
    }

    IdfModemQueryResponseFilter msslcipher(
        "AT+MSSLCIPHER=?", "+MSSLCIPHER:", "", false);
    const std::string msslcipher_input =
        "AT+MSSLCIPHER=?\r\n"
        "+MSSLCIPHER: (C02B,C02C,C02F,C030,1301)\r\n"
        "+OTHER: unsolicited\r\n"
        "+MSSLCIPHER: duplicate\r\n"
        "OK\r\n";
    msslcipher.feed(msslcipher_input.data(), msslcipher_input.size());
    assert(msslcipher.response().find("+MSSLCIPHER: (C02B,C02C,C02F,C030,1301)") !=
           std::string::npos);
    assert(msslcipher.response().find("OK") != std::string::npos);
    assert(msslcipher.response().find("+OTHER:") == std::string::npos);
    assert(msslcipher.response().find("duplicate") == std::string::npos);
    assert(msslcipher.urcs().find("+OTHER: unsolicited") != std::string::npos);
    assert(msslcipher.urcs().find("+MSSLCIPHER: duplicate") != std::string::npos);
    assert(msslcipher.other_line_present());

    IdfModemQueryResponseFilter msslcipher_bare(
        "AT+MSSLCIPHER=?", "+MSSLCIPHER:", "", false);
    const std::string msslcipher_bare_input = "AT+MSSLCIPHER=?\r\nOK\r\n";
    msslcipher_bare.feed(msslcipher_bare_input.data(), msslcipher_bare_input.size());
    assert(!msslcipher_bare.other_line_present());

    IdfModemQueryResponseFilter msslcipher_other(
        "AT+MSSLCIPHER=?", "+MSSLCIPHER:", "", false);
    const std::string msslcipher_other_input =
        "AT+MSSLCIPHER=?\r\n+UNEXPECTED: value\r\nOK\r\n";
    msslcipher_other.feed(msslcipher_other_input.data(), msslcipher_other_input.size());
    assert(msslcipher_other.other_line_present());

    IdfModemQueryResponseFilter cereg_filter("AT+CEREG?", "+CEREG:", "", false);
    const std::string cereg_interleaved =
        "AT+CEREG?\r\n+CEREG: 5\r\n"
        "+CMT: \"sender\",145\r\n"
        "00112233445566778899AABBCCDDEEFF\r\n"
        "+OTHER: unsolicited\r\n"
        "+CEREG: 2,1,\"ABCD\",\"12345678\",7\r\n"
        "+CEREG: 1\r\nOK\r\n";
    cereg_filter.feed(cereg_interleaved.data(), cereg_interleaved.size());
    cereg_filter.flush_pending();
    assert(cereg_filter.response().find("+CEREG: 2,1") != std::string::npos);
    assert(cereg_filter.response().find("+CEREG: 5") == std::string::npos);
    assert(cereg_filter.response().find("+CEREG: 1") == std::string::npos);
    assert(cereg_filter.response().find("+OTHER:") == std::string::npos);
    assert(cereg_filter.response().find("+CMT:") == std::string::npos);
    assert(cereg_filter.response().find("00112233445566778899AABBCCDDEEFF") == std::string::npos);
    assert(cereg_filter.urcs().find("+CEREG: 5") != std::string::npos);
    assert(cereg_filter.urcs().find("+CEREG: 1") != std::string::npos);
    assert(cereg_filter.urcs().find("+OTHER: unsolicited") != std::string::npos);
    assert(cereg_filter.urcs().find("+CMT:") != std::string::npos);
    assert(cereg_filter.urcs().find("00112233445566778899AABBCCDDEEFF") != std::string::npos);
    assert(idf_modem_parse_cereg_status(cereg_filter.response(), cereg_stat));
    assert(cereg_stat == 1);

    for (const std::string malformed : {
             "AT+CEREG?\r\n\t+CEREG: 0,1\r\nOK\r\n",
             "AT+CEREG?\r\n+CEREG: 0,1\t\r\nOK\r\n",
             "AT+CEREG?\r\n\v+CEREG: 0,1\r\nOK\r\n",
             "AT+CEREG?\r\n+CEREG: 0,1\f\r\nOK\r\n",
         }) {
        IdfModemQueryResponseFilter malformed_filter("AT+CEREG?", "+CEREG:", "", false);
        malformed_filter.feed(malformed.data(), malformed.size());
        malformed_filter.flush_pending();
        assert(!idf_modem_parse_cereg_status(malformed_filter.response(), cereg_stat));
    }

    IdfModemQueryResponseFilter cimi("AT+CIMI", "", "", false);
    const std::string cimi_response = "AT+CIMI\r\n460011234567890\r\nOK\r\n";
    cimi.feed(cimi_response.data(), cimi_response.size());
    assert(cimi.response().find("AT+CIMI") == std::string::npos);
    assert(cimi.response().find("460011234567890") != std::string::npos);
    assert(cimi.response().find("OK") != std::string::npos);

    const FixedQueryCase multi_line_queries[] = {
        {"AT+CPOL?", "+CPOL:", "+CPOL: 0,2,\"46000\"", "+CPOL: 1,2,\"46001\",1,0,0,1"},
        {"AT+CGDCONT?", "+CGDCONT:", "+CGDCONT: 1,\"IP\",\"apn\",\"10.0.0.1\"",
         "+CGDCONT: 2,\"IPV6\",\"\",\"::\""},
    };
    for (const FixedQueryCase& query : multi_line_queries) {
        IdfModemQueryResponseFilter shaped(query.command, query.prefix, "", false);
        const std::string input = std::string(query.command) + "\r\n" + query.expected + "\r\n" +
                                  query.duplicate + "\r\nOK\r\n";
        shaped.feed(input.data(), input.size());
        assert(shaped.response().find(query.command) == std::string::npos);
        assert(shaped.response().find(query.expected) != std::string::npos);
        assert(shaped.response().find(query.duplicate) != std::string::npos);
        assert(shaped.urcs().empty());
    }

    IdfModemQueryResponseFilter unsupported_ceer("AT+CEER", "+CEER:", "", false);
    const std::string ceer_error = "AT+CEER\r\nERROR\r\n";
    unsupported_ceer.feed(ceer_error.data(), ceer_error.size());
    assert(unsupported_ceer.response().find("ERROR") != std::string::npos);

    IdfModemQueryResponseFilter no_trailing_newline("AT+CPIN?", "+CPIN:", "", false);
    const std::string short_final = "+CPIN: READY\r\nOK";
    no_trailing_newline.feed(short_final.data(), short_final.size());
    no_trailing_newline.flush_pending();
    assert(no_trailing_newline.response().find("OK") != std::string::npos);

    IdfModemQueryResponseFilter ati("ATI", "", "", false);
    const std::string boot_urc = "\r\nATI\r\nRDY\r\nML307Y\r\nRevision: FW-1.2\r\nOK\r\n";
    ati.feed(boot_urc.data(), boot_urc.size());
    assert(ati.response().find("ATI") == std::string::npos);
    assert(ati.response().find("RDY") == std::string::npos);
    assert(ati.response().find("ML307Y") != std::string::npos);
    assert(ati.response().find("Revision: FW-1.2") != std::string::npos);
    assert(ati.urcs().find("RDY") != std::string::npos);

    const std::string cpol_complete_input =
        "+CPOL: 0,0,\"name\",1,0,1,0\r\n"
        "+CPOL: 1,1,\"short\",0,1,1,0\r\n"
        "+CPOL: 2,2,\"46000\",1,0,0,1\r\nOK\r\n";
    const std::string cpol_complete = idf_modem_cpol_compact_summary(cpol_complete_input);
    assert(cpol_complete.size() <= 96);
    assert(cpol_complete.find("rec=3") != std::string::npos);
    assert(cpol_complete.find("fmt=7,1,1,1") != std::string::npos);
    assert(cpol_complete.find("rat=complete,2,1,2,1") != std::string::npos);
    assert(cpol_complete.find("name") == std::string::npos);
    assert(cpol_complete.find("46000") == std::string::npos);
    assert(cpol_complete.find("OK\r\n") != std::string::npos);

    const std::string cpol_no_rat = idf_modem_cpol_compact_summary(
        "+CPOL: 0,2,\"46000\"\r\nOK\r\n");
    assert(cpol_no_rat.find("rat=missing,0,0,0,0") != std::string::npos);
    const std::string cpol_mixed_rat = idf_modem_cpol_compact_summary(
        "+CPOL: 0,0,\"x\",1,0,0,0\r\n"
        "+CPOL: 1,1,\"y\"\r\nOK\r\n");
    assert(cpol_mixed_rat.find("rat=missing,1,0,0,0") != std::string::npos);
    const std::string cpol_bad_count = idf_modem_cpol_compact_summary(
        "+CPOL: 0,2,\"x\",0\r\n"
        "+CPOL: 1,2,\"x\",0,1,0\r\n"
        "+CPOL: 2,2,\"x\",0,1,0,1,0\r\n"
        "+CPOL: 4,2,\"x\",0,1\r\n"
        "+CPOL: 3,2,\"\x01\"\r\nOK\r\n");
    assert(cpol_bad_count.find("rec=0") != std::string::npos);
    assert(cpol_bad_count.find("bad=5;fail=1") != std::string::npos);
    const std::string cpol_non_boolean = idf_modem_cpol_compact_summary(
        "+CPOL: 0,0,\"x\",1,2,0,0\r\nOK\r\n");
    assert(cpol_non_boolean.find("rec=0") != std::string::npos);
    assert(cpol_non_boolean.find("bad=1;fail=1") != std::string::npos);
    const std::string cpol_duplicate = idf_modem_cpol_compact_summary(
        "+CPOL: 0,0,\"x\"\r\n"
        "+CPOL: 0,1,\"y\"\r\nOK\r\n");
    assert(cpol_duplicate.find("rec=1") != std::string::npos);
    assert(cpol_duplicate.find("bad=1;fail=1") != std::string::npos);
    const std::string cpol_control = idf_modem_cpol_compact_summary(
        "+CPOL: 0,0,\"\x01\"\r\nOK\r\n");
    assert(cpol_control.find("rec=0") != std::string::npos);
    assert(cpol_control.find("bad=1;fail=1") != std::string::npos);

    std::string cpol_sample(514, 'x');
    cpol_sample += "\r\nOK\r\n";
    const std::string cpol_sample_summary = idf_modem_cpol_compact_summary(cpol_sample);
    assert(cpol_sample.size() == 520);
    assert(cpol_sample_summary.size() <= 96);
    assert(cpol_sample_summary.find("len=520") != std::string::npos);
    assert(cpol_sample_summary.find('x') == std::string::npos);
    return 0;
}
