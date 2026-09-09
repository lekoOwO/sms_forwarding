import subprocess
import tempfile
import unittest
from pathlib import Path

from components.idf_web.test.test_web_security import function_body


class KeepaliveCaQueryTest(unittest.TestCase):
    def test_keepalive_handler_rejects_ambiguous_query_and_transfer_encoding(self):
        root = Path(__file__).resolve().parents[1]
        source = (root / "idf_web.cpp").read_text()
        fixture = r'''
#include "idf_web_core.h"
#include <cassert>
#include <cstring>
constexpr int ESP_OK=0;
struct httpd_req_t { std::string query; size_t content_len=0; bool transfer=false; };
bool reject_oversized_body(httpd_req_t*){return false;}
bool check_auth(httpd_req_t*){return true;}
bool ensure_get_or_post(httpd_req_t*){return true;}
void set_json_no_cache(httpd_req_t*){}
bool ca_has_transfer_encoding(httpd_req_t* req){return req->transfer;}
int send_ca_error(httpd_req_t*,const char*,const char*){return 400;}
size_t httpd_req_get_url_query_len(httpd_req_t* req){return req->query.size();}
int httpd_req_get_url_query_str(httpd_req_t* req,char* out,size_t size){
    if(req->query.size()>=size)return -1;
    std::memcpy(out,req->query.c_str(),req->query.size()+1);return ESP_OK;
}
bool get_query_param(httpd_req_t* req,const char* key,std::string& value){
    for(const auto& field:idf_web_decode_form(req->query,8).fields)if(field.first==key){value=field.second;return true;}
    return false;
}
'''
        prefix = function_body(source, "handle_keepalive").split('    if (action == "cancel")', 1)[0]
        fixture += "int validate_keepalive(httpd_req_t* req) {" + prefix + "return 200;}\n"
        fixture += r'''
int main(){
    httpd_req_t req;
    for(const auto& query:{"","action=run","action=cancel","action=reset"}){
        req.query=query;assert(validate_keepalive(&req)==200);
    }
    for(const auto& query:{"unknown=run","action=run&action=cancel","action=run&other=x","action=other","action=%ZZ"}){
        req.query=query;assert(validate_keepalive(&req)==400);
    }
    req.query=std::string(128,'a');assert(validate_keepalive(&req)==400);
    req.query="action=run";req.transfer=true;assert(validate_keepalive(&req)==400);
    req.transfer=false;req.content_len=1;assert(validate_keepalive(&req)==400);
}
'''
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "fixture.cpp"
            path.write_text(fixture)
            binary = Path(directory) / "fixture"
            subprocess.run(["g++", "-std=c++17", "-Wall", "-Wextra", "-Werror", "-I", str(root / "include"), str(path), str(root / "idf_web_core.cpp"), "-o", str(binary)], check=True)
            subprocess.run([str(binary)], check=True)

    def test_keepalive_admission_rejects_other_jobs_and_releases_every_terminal_path(self):
        root = Path(__file__).resolve().parents[1]
        source = (root / "idf_web.cpp").read_text()
        fixture = r'''
#include <atomic>
#include <cassert>
#include <memory>
#include <new>
#include <string>
#include <type_traits>
constexpr int portMAX_DELAY=-1, pdPASS=1;
struct IdfKeepaliveRunView { int kaAction=1,kaTrafficKB=1,kaIntervalDays=175; bool kaEnabled=true; uint32_t kaLastTime=1700000000; std::string kaUrl="https://old.test/body"; };
IdfKeepaliveRunView saved_config;
struct WebAsyncJob { bool queued=false,running=false,done=false,success=false; std::string message; };
WebAsyncJob s_keepalive_job;
std::atomic<bool> s_keepalive_cancel{false},s_keepalive_cancellable{false};
std::atomic<unsigned> s_keepalive_bytes{0},s_keepalive_requests{0};
bool admission=false,locked=false,lock_ok=true,preflight=true,cell_busy=false,allocation=true;
bool due=true;
bool snapshot_failure=false;
IdfKeepaliveRunView observed_config;
std::unique_ptr<IdfKeepaliveRunView> idf_config_get_keepalive_snapshot(){assert(admission&&!locked);return snapshot_failure?nullptr:std::make_unique<IdfKeepaliveRunView>(saved_config);}
int64_t fixture_time(void*){return 1800000000;}
#define time fixture_time
bool keepalive_due(uint32_t,uint32_t,uint32_t){return due;}
bool epoch_valid(uint32_t value){return value>=1700000000;}
bool backup=false,ota=false,restart=false,restore=false,api=false,push=false;
int create_result=pdPASS,created=0;
struct KeepAliveTaskArg {
    IdfKeepaliveRunView config;
    explicit KeepAliveTaskArg(IdfKeepaliveRunView&& view) noexcept : config(std::move(view)) {}
    static void* operator new(size_t n,const std::nothrow_t&) noexcept { return allocation ? ::operator new(n,std::nothrow) : nullptr; }
    static void operator delete(void* p) noexcept { ::operator delete(p); }
};
void* queued_arg=nullptr;
bool try_shared_admission(bool) { assert(!locked); if(admission)return false; admission=true; return true; }
void release_shared_admission() { assert(!locked && admission); admission=false; }
bool backup_transfer_active(){assert(!locked);return backup;}
bool ota_active(){return ota;}
bool device_restart_pending(){return restart;}
bool restore_restart_pending(){return restore;}
bool api_jobs_active(){assert(!locked);return api;}
bool idf_push_test_active(){return push;}
bool keepalive_traffic_preflight(const IdfKeepaliveRunView& cfg,std::string&){observed_config=cfg;return preflight;}
bool cell_job_lock(int=0){if(!lock_ok)return false; assert(!locked);locked=true;return true;}
void cell_job_unlock(){assert(locked);locked=false;}
bool cellular_job_active_locked(){assert(locked);return cell_busy;}
std::string keepalive_profile_note(const IdfKeepaliveRunView&){return {};}
void keepalive_task(void*){}
int xTaskCreate(void(*)(void*),const char*,int,void* arg,int,void*){assert(!locked);++created;if(create_result==pdPASS)queued_arg=arg;return create_result;}
void idf_log_line(const char*){}
void vTaskDelete(void*){}
'''
        fixture += "bool start_keepalive_job(bool scheduled,const char* queued_message,std::string& message,bool& already_running) {" + function_body(source, "start_keepalive_job") + "}\n"
        worker = function_body(source, "keepalive_task")
        tail = worker[worker.rindex("    if (cell_job_lock(portMAX_DELAY))"):]
        fixture += "void finish_keepalive(bool ok,const std::string& message) {" + tail + "}\n"
        fixture += r'''
int main(){
    std::string message;bool already=false;
    admission=true;
    assert(!start_keepalive_job(false,"manual",message,already) && admission && created==0);
    admission=false;
    for(bool* blocked:{&backup,&ota,&restart,&restore,&api,&push}){
        *blocked=true;
        for(const char* caller:{"manual","scheduled"})assert(!start_keepalive_job(std::string(caller)=="scheduled",caller,message,already)&&!admission&&created==0);
        *blocked=false;
    }
    preflight=false;assert(!start_keepalive_job(false,"manual",message,already)&&!admission);preflight=true;
    snapshot_failure=true;assert(!start_keepalive_job(false,"manual",message,already)&&!admission&&created==0);snapshot_failure=false;
    static_assert(std::is_nothrow_move_constructible<IdfKeepaliveRunView>::value);
    static_assert(std::is_nothrow_constructible<KeepAliveTaskArg,IdfKeepaliveRunView&&>::value);
    lock_ok=false;assert(!start_keepalive_job(false,"manual",message,already)&&!admission);lock_ok=true;
    cell_busy=true;assert(!start_keepalive_job(false,"manual",message,already)&&!admission);cell_busy=false;
    allocation=false;assert(!start_keepalive_job(false,"manual",message,already)&&!admission);allocation=true;
    create_result=0;assert(!start_keepalive_job(false,"manual",message,already)&&!admission);create_result=pdPASS;
    for(int outcome=0;outcome<3;++outcome){
        assert(start_keepalive_job(true,"scheduled",message,already)&&admission);
        delete static_cast<KeepAliveTaskArg*>(queued_arg);queued_arg=nullptr;
        if(outcome==2)s_keepalive_cancel.store(true);
        finish_keepalive(outcome==0,outcome==2?"cancelled":"completed");
        assert(!admission&&!locked&&s_keepalive_job.done&&!s_keepalive_job.queued&&!s_keepalive_job.running);
    }
    // Settings changed after the caller captured its scheduling view, before admission.
    saved_config.kaUrl="https://new.test/body";saved_config.kaTrafficKB=2;saved_config.kaEnabled=false;
    const int previous_created=created;
    assert(!start_keepalive_job(true,"scheduled",message,already)&&!admission&&created==previous_created);
    assert(start_keepalive_job(false,"manual",message,already));
    assert(static_cast<KeepAliveTaskArg*>(queued_arg)->config.kaUrl==saved_config.kaUrl);
    assert(static_cast<KeepAliveTaskArg*>(queued_arg)->config.kaTrafficKB==2);
    assert(observed_config.kaUrl==saved_config.kaUrl&&observed_config.kaTrafficKB==2);
    delete static_cast<KeepAliveTaskArg*>(queued_arg);queued_arg=nullptr;finish_keepalive(true,"done");
    saved_config.kaEnabled=true;due=false;
    assert(!start_keepalive_job(true,"scheduled",message,already)&&!admission);
    due=true;saved_config.kaLastTime=0;
    assert(!start_keepalive_job(true,"scheduled",message,already)&&!admission);
}
'''
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "fixture.cpp"
            path.write_text(fixture)
            binary = Path(directory) / "fixture"
            subprocess.run(["g++", "-std=c++17", "-Wall", "-Wextra", "-Werror", str(path), "-o", str(binary)], check=True)
            subprocess.run([str(binary)], check=True)

    def test_real_query_parser_keeps_keepalive_separate_from_push_channels(self):
        root = Path(__file__).resolve().parents[1]
        source = (root / "idf_web.cpp").read_text()
        fixture = r'''
#include "idf_web_core.h"
#include <cassert>
#include <cctype>
#include <cstring>
constexpr int ESP_OK=0, IDF_MAX_PUSH_CHANNELS=5, IDF_PUSH_CA_KEEPALIVE_TARGET=5;
struct httpd_req_t { const char* uri; std::string query; };
size_t httpd_req_get_url_query_len(httpd_req_t* req) { return req->query.size(); }
int httpd_req_get_url_query_str(httpd_req_t* req,char* out,size_t size) {
    if (req->query.empty() || req->query.size()>=size) return -1;
    std::memcpy(out,req->query.c_str(),req->query.size()+1); return ESP_OK;
}
'''
        fixture += "bool parse_u32_strict(const char* raw,uint32_t& value,bool allow_zero) {" + function_body(source, "parse_u32_strict") + "}\n"
        fixture += "bool ca_parse_query(httpd_req_t* req,bool include_nonce,uint8_t& channel,std::string* nonce) {" + function_body(source, "ca_parse_query") + "}\n"
        ca = (root.parent / "idf_push" / "idf_push_ca.cpp").read_text()
        fixture += r'''
struct IdfPushCellularTarget { std::string url; };
struct IdfPushChannel {};
struct KeepaliveView { std::string kaUrl; };
std::string savedUrl="https://example.test/one";
std::unique_ptr<KeepaliveView> idf_config_get_keepalive_snapshot() { return std::make_unique<KeepaliveView>(KeepaliveView{savedUrl}); }
bool idf_push_prepare_keepalive_target(const std::string& url,IdfPushCellularTarget& out) { out.url=url; return true; }
bool idf_config_get_push_channel(uint8_t channel,IdfPushChannel&) { assert(channel<5); return true; }
bool idf_push_prepare_cellular_target(const IdfPushChannel&,IdfPushCellularTarget&) { return true; }
'''
        fixture += "bool current_target(uint8_t channel,IdfPushCellularTarget& target) {" + function_body(ca, "current_target") + "}\n"
        fixture += r'''
int main() {
    IdfPushCellularTarget target;
    for (unsigned i=0;i<6;++i) assert(current_target(i,target));
    assert(target.url==savedUrl);
    savedUrl="https://different.test/two";
    assert(current_target(5,target) && target.url==savedUrl);
    assert(!current_target(6,target) && !current_target(255,target));
    uint8_t channel=255; std::string nonce;
    httpd_req_t req{"/api/push/ca/status","channel=0"};
    for (unsigned i=0;i<5;++i) {
        req.query="channel="+std::to_string(i);
        assert(ca_parse_query(&req,false,channel,nullptr) && channel==i);
    }
    for (const auto& query:{"channel=5","channel=255","channel=-1","channel=0&channel=1"}) {
        req.query=query; assert(!ca_parse_query(&req,false,channel,nullptr));
    }
    req={"/api/keepalive/ca/status",""};
    assert(ca_parse_query(&req,false,channel,nullptr) && channel==5);
    req.query="channel=5"; assert(!ca_parse_query(&req,false,channel,nullptr));
    req={"/api/keepalive/ca/install","nonce=0123456789abcdef0123456789abcdef"};
    assert(ca_parse_query(&req,true,channel,&nonce) && channel==5 && nonce.size()==32);
    for (const auto& query:{"","channel=5&nonce=a","nonce=a&nonce=b","unknown=a"}) {
        req.query=query; assert(!ca_parse_query(&req,true,channel,&nonce));
    }
    req={"/api/push/ca/install","channel=5&nonce=0123456789abcdef0123456789abcdef"};
    assert(!ca_parse_query(&req,true,channel,&nonce));
}
'''
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "fixture.cpp"
            path.write_text(fixture)
            binary = Path(directory) / "fixture"
            subprocess.run(["g++", "-std=c++17", "-Wall", "-Wextra", "-Werror", "-I", str(root / "include"), str(path), str(root / "idf_web_core.cpp"), "-o", str(binary)], check=True)
            subprocess.run([str(binary)], check=True)
