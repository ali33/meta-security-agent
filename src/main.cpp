#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>
#include <netfw.h>
#include <wscapi.h>
#include <iostream>
#include <sstream>
#include <string>
#include <vector>
#include <iomanip>
#include <cstdio>
#pragma comment(lib, "ole32.lib")
#pragma comment(lib, "wscapi.lib")

struct Check { std::string name, state, source, error; };
static std::string json_escape(const std::string& s) {
    std::string out;
    for(unsigned char c : s) {
        if(c=='"') out+="\\\"";
        else if(c=='\\') out+="\\\\";
        else if(c=='\n') out+="\\n";
        else if(c=='\r') out+="\\r";
        else if(c=='\t') out+="\\t";
        else if(c<32) { char buf[7]; sprintf_s(buf,"\\u%04x",c); out+=buf; }
        else out += static_cast<char>(c);
    }
    return out;
}
static std::string utf8(const std::wstring& w) {
    if(w.empty()) return {};
    int n=WideCharToMultiByte(CP_UTF8,0,w.c_str(),static_cast<int>(w.size()),nullptr,0,nullptr,nullptr);
    if(n<=0) return {};
    std::string s(static_cast<size_t>(n),'\0');
    WideCharToMultiByte(CP_UTF8,0,w.c_str(),static_cast<int>(w.size()),s.data(),n,nullptr,nullptr);
    return s;
}
static std::string hex_error(HRESULT hr) {
    std::ostringstream s; s<<"HRESULT 0x"<<std::hex<<std::uppercase<<static_cast<unsigned long>(hr);return s.str();
}
static std::string hostname() {
    wchar_t buf[256]{}; DWORD length=256;
    return GetComputerNameW(buf,&length) ? utf8(std::wstring(buf,length)) : "UNKNOWN";
}
static std::string windows_version() {
    return "Windows (build not queried in MVP-0)";
}
static std::vector<Check> firewall() {
    std::vector<Check> res;
    INetFwPolicy2* policy=nullptr;
    HRESULT hr=CoCreateInstance(__uuidof(NetFwPolicy2),nullptr,CLSCTX_INPROC_SERVER,__uuidof(INetFwPolicy2),reinterpret_cast<void**>(&policy));
    if(FAILED(hr)||!policy) {
        for(const char* label:{"firewall.domain","firewall.private","firewall.public"})
            res.push_back({label,"UNKNOWN","INetFwPolicy2",hex_error(hr)});
        return res;
    }
    const struct {const char* name; NET_FW_PROFILE_TYPE2 type;} profiles[]={
        {"firewall.domain",NET_FW_PROFILE2_DOMAIN},
        {"firewall.private",NET_FW_PROFILE2_PRIVATE},
        {"firewall.public",NET_FW_PROFILE2_PUBLIC}};
    for(const auto& p:profiles) {
        VARIANT_BOOL enabled=VARIANT_FALSE;
        const HRESULT result=policy->get_FirewallEnabled(p.type,&enabled);
        if(SUCCEEDED(result)) res.push_back({p.name,enabled==VARIANT_TRUE?"ENABLED":"DISABLED","INetFwPolicy2",""});
        else res.push_back({p.name,"UNKNOWN","INetFwPolicy2",hex_error(result)});
    }
    policy->Release();
    return res;
}
static Check antivirus() {
    WSC_SECURITY_PROVIDER_HEALTH health=WSC_SECURITY_PROVIDER_HEALTH_NOTMONITORED;
    HRESULT hr=WscGetSecurityProviderHealth(WSC_SECURITY_PROVIDER_ANTIVIRUS,&health);
    if(FAILED(hr)) return {"antivirus.windows_security_center","NOT_SUPPORTED","WscGetSecurityProviderHealth",hex_error(hr)};
    const char* state="UNKNOWN";
    switch(health) {
        case WSC_SECURITY_PROVIDER_HEALTH_GOOD: state="GOOD";break;
        case WSC_SECURITY_PROVIDER_HEALTH_POOR: state="POOR";break;
        case WSC_SECURITY_PROVIDER_HEALTH_SNOOZE: state="SNOOZE";break;
        case WSC_SECURITY_PROVIDER_HEALTH_NOTMONITORED: state="NOT_MONITORED";break;
        default:break;
    }
    return {"antivirus.windows_security_center",state,"WscGetSecurityProviderHealth",""};
}
int main(int argc,char** argv) {
    if(argc==1 || (std::string(argv[1])!="status" && std::string(argv[1])!="--help" && std::string(argv[1])!="-h")) {
        std::cerr<<"Usage: meta-sec status [--json] | --help\n";
        return 2;
    }
    if(std::string(argv[1])=="--help" || std::string(argv[1])=="-h") {
        std::cout<<"META Security Agent v0.1.0 (Standalone, read-only)\n"
                 <<"Usage: meta-sec status [--json]\n";
        return 0;
    }
    const bool json=argc==3 && std::string(argv[2])=="--json";
    if(argc>3 || (argc==3 && !json)) {std::cerr<<"Invalid argument. Try --help.\n";return 2;}
    const HRESULT init=CoInitializeEx(nullptr,COINIT_APARTMENTTHREADED);
    if(FAILED(init)) {std::cerr<<"COM init failed: "<<hex_error(init)<<"\n";return 2;}
    std::vector<Check> checks=firewall();
    checks.push_back(antivirus());
    bool incomplete=false;
    for(const auto& c:checks) if(c.state=="UNKNOWN" || c.state=="NOT_SUPPORTED" || c.state=="NOT_MONITORED") incomplete=true;
    if(json) {
        std::cout<<"{\"schema_version\":1,\"product\":\"META Security Agent\",\"mode\":\"standalone\",\"hostname\":\""<<json_escape(hostname())<<"\",\"platform\":\""<<json_escape(windows_version())<<"\",\"checks\":[";
        for(size_t i=0;i<checks.size();++i) {
            const auto& c=checks[i];if(i) std::cout<<",";
            std::cout<<"{\"name\":\""<<json_escape(c.name)<<"\",\"state\":\""<<json_escape(c.state)<<"\",\"source\":\""<<json_escape(c.source)<<"\",\"error\":\""<<json_escape(c.error)<<"\"}";
        }
        std::cout<<"],\"overall\":\""<<(incomplete?"INCOMPLETE":"OBSERVED")<<"\"}\n";
    } else {
        std::cout<<"META Security Agent v0.1.0 | Standalone | Read-only\n"
                 <<"Host: "<<hostname()<<"\nPlatform: "<<windows_version()<<"\n";
        for(const auto& c:checks) {
            std::cout<<std::left<<std::setw(42)<<c.name<<c.state;
            if(!c.error.empty())std::cout<<" ("<<c.error<<")";
            std::cout<<"\n";
        }
        std::cout<<"Overall: "<<(incomplete?"INCOMPLETE":"OBSERVED")<<" (not an AV protection verdict)\n";
    }
    CoUninitialize();
    return incomplete?3:0;
}
