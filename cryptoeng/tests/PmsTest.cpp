// Only synthetic credentials in mkdtemp(). Never invokes the installed service/store.
#include "../CryptoengHal.h"
#include "../PmsStore.h"
#include "../../common/Compat.h"
#include "../../common/Sha256.h"
#include <cstdio>
#include <fstream>
#include <atomic>
#include <thread>
#include <vector>
#include <unistd.h>
using oplus_compat::CryptoengHal;
using Bytes = std::vector<uint8_t>;
using Params = std::vector<std::pair<uint32_t, Bytes>>;
Bytes I(uint32_t v) { return {uint8_t(v>>24),uint8_t(v>>16),uint8_t(v>>8),uint8_t(v)}; }
void append(Bytes& a, const Bytes& b) { a.insert(a.end(),b.begin(),b.end()); }
Bytes req(uint32_t cmd, Params p) {
    Bytes b=I(cmd); append(b,I(10000)); append(b,I(p.size()));
    for (auto& [t,d]:p) { append(b,I(t)); append(b,I(d.size())); append(b,d); }
    return b;
}
uint32_t word(const Bytes& b,size_t o) {
    return uint32_t(b.at(o))<<24|uint32_t(b.at(o+1))<<16|uint32_t(b.at(o+2))<<8|b.at(o+3);
}
Bytes param(const Bytes& b,uint32_t t) {
    if (b.size()<12) return {};
    size_t o=12;
    for (uint32_t i=0;i<word(b,8);++i) {
        auto k=word(b,o),n=word(b,o+4); o+=8;
        if (n>b.size()-o) return {};
        if (k==t) return {b.begin()+o,b.begin()+o+n};
        o+=n;
    }
    return {};
}
bool success(const Bytes& b) { return b.size()>=12 && word(b,4)==0; }
// PrivacyPasswordController.checkPassword @0070..0089: status success AND challenge.
bool clientAccepts(const Bytes& b) { return success(b) && param(b,206).size()==64; }
Bytes sha(const Bytes& b) {
    oplus_compat::Sha256 s; s.update(b.data(),b.size()); auto d=s.digest(); return {d.begin(),d.end()};
}
Bytes sha(const char* s) { return sha(Bytes(s,s+strlen(s))); }
void save(const std::string& p,const Bytes& b) {
    std::ofstream f(p,std::ios::binary); f.write(reinterpret_cast<const char*>(b.data()),b.size());
}
int main() {
    android::base::InitLogging(nullptr,android::base::LogdLogger());
    char dir[]="/data/local/tmp/cryptoeng-contract.XXXXXX";
    if (!mkdtemp(dir)) return 2;
    std::string root=dir,path=root+"/pms_store";
    auto h=::ndk::SharedRefBase::make<CryptoengHal>(path);
    int passed=0,failed=0;
    auto check=[&](const char* name,bool ok) {
        printf("%s %s\n",ok?"PASS":"FAIL",name); ok?++passed:++failed;
    };
    auto info=[&](int type=1){return h->Invoke(req(4005,{{201,I(type)}}));};
    auto enroll=[&](int type=1){
        Bytes sec=I(2); append(sec,I(32)); append(sec,sha("synthetic-answer"));
        return h->Invoke(req(4001,{{201,I(type)},{210,I(4)},{202,sha("synthetic-old")},{203,sec}}));
    };
    auto verify=[&](const char* password,int mode=1,int type=1){
        auto data=sha(password);
        if(mode==1){append(data,param(info(type),209));data=sha(data);}
        return h->Invoke(req(4002,{{201,I(type)},{204,I(mode)},{205,data}}));
    };
    auto modify=[&](const Bytes& challenge,const char* password,int kind=1,int type=1){
        return h->Invoke(req(4003,{{201,I(type)},{206,challenge},{207,I(kind)},
            {208,sha(password)},{210,I(4)}}));
    };
    check("SHA256/HMAC known answers",oplus_compat::Sha256SelfTest());
    check("empty namespace reports no enrollment",word(param(info(),210),0)==0);
    check("unenrolled verify fails",!clientAccepts(verify("synthetic-old")));
    check("enroll commits",success(enroll()));
    check("handler is eight bytes",param(info(),209).size()==8);
    check("enroll cannot overwrite",!success(enroll()));
    auto good=verify("synthetic-old"),bad=verify("synthetic-wrong");
    save(root+"/verify-good.bin",good); save(root+"/verify-bad.bin",bad);
    check("correct password accepted by client contract",clientAccepts(good));
    check("wrong password fails and issues no challenge",!success(bad)&&param(bad,206).empty());
    auto challenge=param(good,206);
    check("fresh verification issues different random challenge",param(verify("synthetic-old"),206)!=challenge);
    check("unsupported auth method fails",!clientAccepts(verify("synthetic-old",5)));
    check("wrong security answer fails",!clientAccepts(verify("wrong-answer",2)));
    check("correct security answer accepted",clientAccepts(verify("synthetic-answer",2)));
    check("missing challenge cannot change credential",!success(modify({},"synthetic-new")));
    check("forged challenge cannot change credential",!success(modify(Bytes(64,1),"synthetic-new")));
    check("same password rejected",!success(modify(challenge,"synthetic-old")));
    check("second namespace enrolls",success(enroll(2)));
    check("challenge is namespace bound",!success(modify(challenge,"synthetic-new",1,2)));
    check("authenticated password change commits field 208",success(modify(challenge,"synthetic-new")));
    check("old challenge revoked after change",!success(modify(challenge,"synthetic-third")));
    check("old password no longer accepted",!clientAccepts(verify("synthetic-old")));
    auto newgood=verify("synthetic-new");
    check("new password accepted",clientAccepts(newgood));
    save(root+"/verify-new.bin",newgood);
    check("new candidate same-password check rejects other value",!clientAccepts(verify("other-candidate")));
    h=::ndk::SharedRefBase::make<CryptoengHal>(path);
    check("new password survives HAL restart",clientAccepts(verify("synthetic-new")));
    check("old challenge invalid after restart",!success(modify(param(newgood,206),"third")));
    check("unauthenticated delete fails",!success(h->Invoke(req(4004,{{201,I(1)}}))));
    check("unsupported reset fails",!success(h->Invoke(req(4007,{{201,I(1)}}))));
    check("unsupported recovery never succeeds",!success(h->Invoke(req(13005,{{201,I(1)}}))));
    check("unsupported encryption never returns a fake key",!success(h->Invoke(req(4006,{{201,I(1)}}))));
    // Exact Settings GET_INFO contract: field 217 is both the masking selector
    // and the returned UTF-8 address. These are synthetic addresses only.
    auto emailInfo=[&](int mask,int type=1) {
        return h->Invoke(req(4005,{{201,I(type)},{217,I(mask)},{221,I(10000)}}));
    };
    auto textBytes=[](const std::string& s){return Bytes(s.begin(),s.end());};
    auto setEmail=[&](const Bytes& token,const std::string& email) {
        return h->Invoke(req(4003,{{201,I(1)},{206,token},{207,I(4)},
            {208,textBytes(email)},{210,I(4)}}));
    };
    check("unset email has no zero-length TLV",success(emailInfo(0))&&param(emailInfo(0),217).empty());
    check("unauthenticated email save fails",!success(setEmail({},"test@example.org")));
    for(size_t size:{size_t(31),size_t(32),size_t(33),size_t(64)}) {
        const std::string email=std::string(size-12,'a')+"@example.org";
        auto token=param(verify("synthetic-new"),206);
        check("authenticated email save commits",success(setEmail(token,email)));
        check("saved email returned byte-exact in field 217",param(emailInfo(0),217)==textBytes(email));
        check("masked request hides local part",param(emailInfo(1),217)==textBytes("****@example.org"));
        check("GET_INFO without email selector does not disclose email",param(info(),217).empty());
        h=::ndk::SharedRefBase::make<CryptoengHal>(path);
        check("saved email survives service restart",param(emailInfo(0),217)==textBytes(email));
    }
    auto emailToken=param(verify("synthetic-new"),206);
    check("oversized email rejected",!success(setEmail(emailToken,std::string(53,'a')+"@example.org")));
    check("short replacement removes old continuation slot",success(setEmail(emailToken,"x@example.net"))&&
        param(emailInfo(0),217)==textBytes("x@example.net"));
    check("consumed challenge cannot replace email",!success(setEmail(emailToken,"y@example.net")));
    check("invalid mask selector rejected",!success(emailInfo(2)));
    check("short mask selector rejected",!success(h->Invoke(req(4005,{{201,I(1)},{217,Bytes{0}}}))));
    check("security answer update preserves recovery email",success(modify(param(verify("synthetic-new"),206),
        "synthetic-answer",2))&&param(emailInfo(0),217)==textBytes("x@example.net"));
    check("password still verifies after email edits",clientAccepts(verify("synthetic-new")));
    check("second namespace email remains unset",param(emailInfo(0,2),217).empty());
    // Emails originally saved at enrollment use the same fixed slot layout.
    std::string enrollEmail=std::string(40,'e')+"@example.org";
    Bytes emailSec=I(2);append(emailSec,I(32));append(emailSec,sha("answer"));
    append(emailSec,I(4));append(emailSec,I(32));append(emailSec,textBytes(enrollEmail.substr(0,32)));
    append(emailSec,I(10));append(emailSec,I(enrollEmail.size()-32));
    auto tail=textBytes(enrollEmail.substr(32));tail.resize(32,0);append(emailSec,tail);
    auto emailHal=::ndk::SharedRefBase::make<CryptoengHal>(root+"/email_enrollment");
    check("email enrollment succeeds",success(emailHal->Invoke(req(4001,
        {{201,I(1)},{210,I(4)},{202,sha("enrollment-pw")},{203,emailSec}}))));
    check("enrollment email reconstructs both slots",param(emailHal->Invoke(req(4005,
        {{201,I(1)},{217,I(0)}})),217)==textBytes(enrollEmail));
    // Exact Forgot password flow from Settings: checkAnswer -> challenge 206 ->
    // ChooseNumberPrivacy -> MODIFY 207=1 / 208=new digest / 210=new quality.
    // Keep this fixture separate from both the main tests and the live service.
    auto resetHal=::ndk::SharedRefBase::make<CryptoengHal>(root+"/question_reset");
    auto resetInfo=[&] { return resetHal->Invoke(req(4005,{{201,I(1)},{217,I(0)}})); };
    auto resetVerify=[&](const char* value,int mode) {
        auto digest=sha(value);
        if(mode==1) { append(digest,param(resetInfo(),209));digest=sha(digest); }
        return resetHal->Invoke(req(4002,{{201,I(1)},{204,I(mode)},{205,digest}}));
    };
    auto resetPassword=[&](const Bytes& token) {
        return resetHal->Invoke(req(4003,{{201,I(1)},{206,token},{210,I(2)},
            {207,I(1)},{208,sha("synthetic-reset-new")}}));
    };
    check("question-reset fixture enrolls answer and long email",success(resetHal->Invoke(req(4001,
        {{201,I(1)},{210,I(4)},{202,sha("synthetic-reset-old")},{203,emailSec}}))));
    auto wrongAnswer=resetVerify("incorrect-synthetic-answer",2);
    check("wrong answer cannot authorize reset",!success(wrongAnswer)&&param(wrongAnswer,206).empty()&&
        !success(resetPassword(param(wrongAnswer,206))));
    for(int i=0;i<10;++i) resetVerify("incorrect-synthetic-password",1);
    check("reset fixture password is locked",word(param(resetInfo(),212),0)>0&&
        !clientAccepts(resetVerify("synthetic-reset-old",1)));
    auto answerProof=resetVerify("answer",2);
    check("correct answer authorizes recovery during password lock",clientAccepts(answerProof));
    auto resetResult=resetPassword(param(answerProof,206));
    check("answer-authorized password reset satisfies Settings response contract",
        success(resetResult)&&param(resetResult,209).size()==8);
    check("reset updates password quality",word(param(resetInfo(),210),0)==2);
    check("reset clears password lock and retry state",word(param(resetInfo(),212),0)==0&&
        word(param(resetInfo(),211),0)==10);
    check("reset preserves recovery email",param(resetInfo(),217)==textBytes(enrollEmail));
    check("old password fails after question reset",!clientAccepts(resetVerify("synthetic-reset-old",1)));
    check("new password works after question reset",clientAccepts(resetVerify("synthetic-reset-new",1)));
    check("question reset token cannot be replayed",!success(resetPassword(param(answerProof,206))));
    check("reset preserves security answer",clientAccepts(resetVerify("answer",2)));
    resetHal=::ndk::SharedRefBase::make<CryptoengHal>(root+"/question_reset");
    check("question-reset password and recovery data survive restart",
        clientAccepts(resetVerify("synthetic-reset-new",1))&&clientAccepts(resetVerify("answer",2))&&
        param(resetInfo(),217)==textBytes(enrollEmail));
    auto malformed=req(4001,{{201,I(1)},{201,I(2)},{202,sha("bad")}});
    check("duplicate TLV rejected",!success(h->Invoke(malformed)));
    check("truncated request rejected",!success(h->Invoke(Bytes{0,0,15,161})));
    auto valid=req(4005,{{201,I(1)}});
    for(size_t i=0;i<valid.size();++i) {
        Bytes partial(valid.begin(),valid.begin()+i);
        if(success(h->Invoke(partial))) ++failed;
    }
    auto magic=valid; magic[7]=0; check("bad header magic rejected",!success(h->Invoke(magic)));
    auto trailing=valid; trailing.push_back(0);check("trailing bytes rejected",!success(h->Invoke(trailing)));
    check("unknown namespace rejected",!success(h->Invoke(req(4005,{{201,I(7)}}))));
    for(int i=0;i<10;++i) verify("wrong");
    check("retry count reaches zero",word(param(info(),211),0)==0);
    check("lock delay exposed to client",word(param(info(),212),0)>0);
    h=::ndk::SharedRefBase::make<CryptoengHal>(path);
    check("lock survives process restart",!clientAccepts(verify("synthetic-new")));
    auto recovery=verify("synthetic-answer",2);
    check("password lock does not bypass/reject genuine recovery answer",clientAccepts(recovery));
    check("answer change uses authenticated field 208",success(modify(param(recovery,206),"new-answer",2)));
    check("old answer invalidated",!clientAccepts(verify("synthetic-answer",2)));
    check("new answer accepted",clientAccepts(verify("new-answer",2)));
    auto auth=verify("synthetic-old",1,2);
    check("authenticated delete commits",success(h->Invoke(req(4004,{{201,I(2)},{206,param(auth,206)}}))));
    check("delete persists",word(param(info(2),210),0)==0);
    auto broken=::ndk::SharedRefBase::make<CryptoengHal>(root+"/missing/pms_store");
    check("disk failure cannot claim enrollment success",!success(broken->Invoke(req(4001,
        {{201,I(1)},{210,I(4)},{202,sha("p")}}))));
    save(root+"/corrupt",Bytes{1,2,3,4,5,6,7,8});
    auto corrupt=::ndk::SharedRefBase::make<CryptoengHal>(root+"/corrupt");
    check("corrupt store fails closed",!success(corrupt->Invoke(valid)));
    check("corrupt store cannot be overwritten by enrollment",!success(corrupt->Invoke(req(4001,
        {{201,I(1)},{210,I(4)},{202,sha("p")}}))));
    // Build a synthetic PMS1 file exactly as the old service did, then migrate it.
    std::string identity;
    for(const char* key:{"ro.serialno","ro.boot.serialno","ro.vendor.boot.serialno",
                         "ro.product.vendor.device","ro.boot.cpuid","ro.boot.em.did"}) {
        identity+=android::base::GetProperty(key,""); identity+='|';
    }
    if(identity.size()<8) identity+=android::base::GetProperty("ro.build.fingerprint","onyx");
    const std::string label="OxyNish-cryptoeng-seed-v1";
    auto seed=oplus_compat::HmacSha256(reinterpret_cast<const uint8_t*>(label.data()),label.size(),
        reinterpret_cast<const uint8_t*>(identity.data()),identity.size());
    std::string legacyPath=root+"/legacy";
    oplus_compat::PmsStore legacy(seed,legacyPath);
    oplus_compat::PmsRecord record; record.quality=4; record.pwd=sha("synthetic-old");
    check("synthetic legacy fixture saved",legacy.Put(1,record));
    h=::ndk::SharedRefBase::make<CryptoengHal>(legacyPath);
    if(getuid()==0) {
        check("legacy PMS1 migration preserves correct password",clientAccepts(verify("synthetic-old")));
        check("legacy PMS1 migration still rejects wrong password",!clientAccepts(verify("synthetic-wrong")));
        h=::ndk::SharedRefBase::make<CryptoengHal>(legacyPath);
        check("migrated seed survives restart",clientAccepts(verify("synthetic-old")));
    } else {
        check("non-root cannot guess or replace a legacy seed",!h->StorageReady());
    }
    save(legacyPath+".seed",Bytes{1,2,3});
    h=::ndk::SharedRefBase::make<CryptoengHal>(legacyPath);
    check("corrupt seed is preserved and fails closed",!h->StorageReady());
    // The service runs a binder thread pool, so one HAL object serves calls
    // concurrently. Every reply must be exactly what a lone call gets.
    h=::ndk::SharedRefBase::make<CryptoengHal>(root+"/concurrent");
    check("concurrency fixture enrolls",success(enroll()));
    std::atomic<int> wrongReplies{0};
    std::vector<std::thread> workers;
    for (int t=0;t<4;++t) workers.emplace_back([&]{
        for (int i=0;i<25;++i) {
            if (!clientAccepts(verify("synthetic-old"))) ++wrongReplies;
            if (word(param(info(),210),0)!=4) ++wrongReplies;
            Bytes p=h->Invoke(req(10009,{{1,Bytes(64,0x30)}}));
            if (p!=Bytes{0x3d,0x27,0,0}) ++wrongReplies;
        }
    });
    for (auto& w:workers) w.join();
    check("4 threads x 25 rounds: every concurrent reply correct",wrongReplies==0);
    check("password still verifies after concurrent load",clientAccepts(verify("synthetic-old")));
    // PKI family: the SDK's "not supported" word (little-endian, as t2.j.e
    // reads it), so callers take their software path instead of a hard reject.
    auto le=[](const Bytes& b){ return b.size()==4 ? uint32_t(b[0])|uint32_t(b[1])<<8|
                                       uint32_t(b[2])<<16|uint32_t(b[3])<<24 : 0u; };
    Bytes cert(686,0x30);
    auto pki=[&](uint32_t cmd){ return h->Invoke(req(cmd,{{1,cert}})); };
    check("PKI cert verify (10009) answers not-supported 10045",le(pki(10009))==10045);
    check("PKI HKDF (10003) answers not-supported 10045",le(pki(10003))==10045);
    check("PKI range end (10071) answers not-supported 10045",le(pki(10071))==10045);
    check("PKI classified as unsupported, not privacy",
          CryptoengHal::Classify(10009)==CryptoengHal::Tier::PkiUnsupported);
    check("attestation (10014) stays a hardware-root refusal",le(pki(10014))==0xffffffffu);
    check("first id past PKI (10072) stays a hardware-root refusal",le(pki(10072))==0xffffffffu);
    Bytes encrypt=h->Invoke(req(4006,{{201,I(1)}}));
    check("unsupported PMS (4006) keeps the PMS failure reply",
          encrypt.size()>=12 && word(encrypt,0)==4006 && word(encrypt,4)!=0);
    printf("RESULT %d passed, %d failed\nFIXTURES %s\n",passed,failed,dir);
    return failed?1:0;
}
