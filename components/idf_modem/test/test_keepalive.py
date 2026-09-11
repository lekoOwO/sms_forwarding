import subprocess
import tempfile
import unittest
from pathlib import Path

from components.idf_web.test.test_web_security import function_body


class KeepaliveTest(unittest.TestCase):
    def test_real_keepalive_uses_bounded_https_and_stops_on_cancellation_or_failure(self):
        source = (Path(__file__).resolve().parents[1] / "idf_modem.cpp").read_text()
        fixture = r'''
#include <algorithm>
#include <array>
#include <cassert>
#include <cstdint>
#include <string>
#include <vector>
using esp_err_t = int;
constexpr int ESP_OK=0, ESP_FAIL=-1, ESP_ERR_NOT_SUPPORTED=1, ESP_ERR_INVALID_ARG=2,
              ESP_ERR_TIMEOUT=3, ESP_ERR_INVALID_STATE=4;
constexpr uint32_t IDF_MODEM_KEEPALIVE_MAX_RUNTIME_BYTES=512*1024;
enum class IdfModemHttpsMethod { Post, Get };
struct IdfModemHttpsPostRequest {
    std::string url, body, contentType="application/json", apn;
    std::vector<uint8_t> rootCertificateDer;
    std::array<uint8_t,32> rootCertificateSha256{};
    bool dataEnabled=false;
    uint32_t timeoutMs=30000;
    IdfModemHttpsMethod method=IdfModemHttpsMethod::Post;
};
struct IdfModemHttpsPostResult {
    bool ok=true, cleanupRequiresReset=false;
    int httpStatus=200;
    uint32_t bodyBytes=1024;
    std::string message, cleanupMessage;
};
struct IdfCellularHttpConfig {
    bool dataEnabled=false;
    std::string apn;
    uint32_t minPayloadBytes=1024;
    std::vector<uint8_t> rootCertificateDer{1};
    std::array<uint8_t,32> rootCertificateSha256{};
    bool (*cancelled)()=nullptr;
    void (*progress)(uint32_t,uint32_t)=nullptr;
};
struct IdfCellularHttpResult {
    bool ok=false;
    int httpStatus=-1;
    uint32_t bytesRead=0, expectedBytes=0, requests=0;
    std::string message;
};
static int64_t now=0, duration=1000;
static unsigned calls=0;
static bool cancel=false;
static IdfModemHttpsPostResult response;
static int response_error=ESP_OK;
static int64_t esp_timer_get_time() { return now; }
static bool idf_modem_https_validate_request(const IdfModemHttpsPostRequest& r,std::string&) {
    return r.url.rfind("https://",0)==0 && !r.rootCertificateDer.empty();
}
static bool idf_modem_https_status_success(int status) { return status>=200 && status<300; }
static bool idf_modem_keepalive_validate_request(const IdfModemHttpsPostRequest& r,std::string& error) {
    return r.url.rfind("http://",0)==0 ? r.rootCertificateDer.empty() : idf_modem_https_validate_request(r,error);
}
static esp_err_t idf_modem_https_post(const IdfModemHttpsPostRequest& request,IdfModemHttpsPostResult& out) {
    assert(request.method==IdfModemHttpsMethod::Get && request.body.empty() && request.contentType.empty());
    assert(request.timeoutMs>0 && request.timeoutMs<=30000);
    assert(!request.dataEnabled && request.apn=="test-apn");
    assert(request.url.rfind("http://",0)==0 ? request.rootCertificateDer.empty() : request.rootCertificateDer==std::vector<uint8_t>{1});
    ++calls; now+=duration; out=response; return response_error;
}
static esp_err_t submit_keepalive_request(const IdfModemHttpsPostRequest& request,IdfModemHttpsPostResult& out) {
    return idf_modem_https_post(request,out);
}
'''
        fixture += "static esp_err_t idf_modem_cellular_http_get(const std::string& url, const IdfCellularHttpConfig& config, IdfCellularHttpResult& result) {" + function_body(source, "idf_modem_cellular_http_get") + "}\n"
        fixture += r'''
int main() {
    IdfCellularHttpConfig cfg; cfg.apn="test-apn"; cfg.minPayloadBytes=2048;
    cfg.cancelled=[] { return cancel; };
    IdfCellularHttpResult result;
    assert(idf_modem_cellular_http_get("https://example.test/payload",cfg,result)==ESP_OK);
    assert(result.ok && calls==2 && result.bytesRead==2048 && result.requests==2);
    calls=0; cfg.minPayloadBytes=512*1024; response.bodyBytes=65536;
    assert(idf_modem_cellular_http_get("https://example.test/payload",cfg,result)==ESP_OK);
    assert(result.ok && calls==8 && result.bytesRead==512*1024);
    response.bodyBytes=1024;
    calls=0; cfg.minPayloadBytes=1; cancel=true;
    assert(idf_modem_cellular_http_get("https://example.test/payload",cfg,result)!=ESP_OK && calls==0);
    cancel=false;
    cfg.rootCertificateDer.clear();
    assert(idf_modem_cellular_http_get("http://example.test/payload",cfg,result)==ESP_OK && calls==1);
    assert(result.ok && result.bytesRead==1024);
    calls=0; cfg.rootCertificateDer={1};
    cfg.minPayloadBytes=512*1024+1;
    assert(idf_modem_cellular_http_get("https://example.test/payload",cfg,result)!=ESP_OK && calls==0);
    cfg.minPayloadBytes=16*1024; response.bodyBytes=1;
    assert(idf_modem_cellular_http_get("https://example.test/payload",cfg,result)!=ESP_OK);
    assert(calls==8 && !result.ok && result.bytesRead==8);
    calls=0; response.bodyBytes=0;
    assert(idf_modem_cellular_http_get("https://example.test/payload",cfg,result)!=ESP_OK && calls==1);
    calls=0; response.bodyBytes=1024; response.httpStatus=302;
    assert(idf_modem_cellular_http_get("https://example.test/payload",cfg,result)!=ESP_OK && calls==1);
    calls=0; response.httpStatus=200; response.ok=false; response.cleanupRequiresReset=true;
    assert(idf_modem_cellular_http_get("https://example.test/payload",cfg,result)!=ESP_OK && calls==1);
    calls=0; response={}; cfg.minPayloadBytes=512*1024; duration=30000000;
    assert(idf_modem_cellular_http_get("https://example.test/payload",cfg,result)!=ESP_OK && calls==4);
    calls=0; duration=1000; cfg.progress=[](uint32_t, uint32_t) { cancel=true; };
    assert(idf_modem_cellular_http_get("https://example.test/payload",cfg,result)!=ESP_OK && calls==1);
}
'''
        with tempfile.TemporaryDirectory() as directory:
            cpp = Path(directory, "keepalive.cpp")
            binary = Path(directory, "keepalive")
            cpp.write_text(fixture)
            subprocess.run(["g++", "-std=c++17", str(cpp), "-o", str(binary)], check=True)
            result = subprocess.run([str(binary)], capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stderr)
