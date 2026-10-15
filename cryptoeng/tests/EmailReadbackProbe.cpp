// Read-only Binder probe. Never prints the email address or changes credentials.
#include <aidl/vendor/oplus/hardware/cryptoeng/ICryptoeng.h>
#include "../../common/BinderPlatform.h"
#include <algorithm>
#include <cstdio>
#include <unistd.h>
using aidl::vendor::oplus::hardware::cryptoeng::ICryptoeng;
using Bytes=std::vector<uint8_t>;
void word(Bytes& b,uint32_t v) {
    b.insert(b.end(),{uint8_t(v>>24),uint8_t(v>>16),uint8_t(v>>8),uint8_t(v)});
}
uint32_t read(const Bytes& b,size_t o) {
    return uint32_t(b[o])<<24|uint32_t(b[o+1])<<16|uint32_t(b[o+2])<<8|b[o+3];
}
int main() {
    alarm(10);
    const std::string name=std::string(ICryptoeng::descriptor)+"/default";
    auto svc=ICryptoeng::fromBinder(::ndk::SpAIBinder(AServiceManager_checkService(name.c_str())));
    if(!svc){puts("FAIL service unavailable");return 1;}
    Bytes request;
    for(uint32_t v:{4005u,10000u,3u,201u,4u,1u,217u,4u,1u,221u,4u,10000u})word(request,v);
    Bytes reply;
    auto status=svc->cryptoeng_invoke_command(request,&reply);
    if(!status.isOk()||reply.size()<12||read(reply,0)!=4005||read(reply,4)!=0){
        puts("FAIL GET_INFO");return 1;
    }
    size_t off=12;
    for(uint32_t i=0;i<read(reply,8);++i) {
        if(reply.size()-off<8)return 1;
        uint32_t type=read(reply,off),n=read(reply,off+4);off+=8;
        if(n>reply.size()-off)return 1;
        if(type==217) {
            const Bytes prefix={'*','*','*','*','@'};
            bool masked=n>prefix.size()&&std::equal(prefix.begin(),prefix.end(),reply.begin()+off);
            puts(masked?"PASS live GET_INFO: recovery email present; masked response valid":"FAIL email masking");
            return masked?0:1;
        }
        off+=n;
    }
    puts("GET_INFO success; recovery email field absent");
    return 2;
}
