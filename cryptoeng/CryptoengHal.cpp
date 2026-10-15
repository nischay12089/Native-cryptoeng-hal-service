// Software PMS protocol adapter; see cryptoeng/README.md for supported commands.
#include "CryptoengHal.h"

#include "../common/Compat.h"
#include "../common/Sha256.h"
#include "PmsStore.h"

#include <unistd.h>
#include <sys/random.h>
#include <algorithm>
#include <ctime>

#include <map>
#include <string>

namespace oplus_compat {

namespace {

// MethodParamType codes (com.oplus.settings.privacy.sdk.MethodParamType) that
// the OxygenOS privacy controllers send and read back.
enum Pms : uint32_t {
    PMS_TYPE = 201,          // which namespace (privacy password vs screen-lock)
    PMS_PWD_INFO = 202,      // ENROLL: the password verifier bytes
    PMS_SECURE_INFO = 203,   // ENROLL: secure info buffer
    PMS_VERIFY_TYPE = 204,
    PMS_VERIFY_BUFFER = 205, // VERIFY: the password bytes to check
    PMS_CHALLENGE = 206,     // 64-byte authorization issued ONLY after successful verification
    PMS_INFO_TYPE = 207,
    PMS_INFO_BUFFER = 208,
    PMS_PWD_TYPE = 210,      // quality; reply 0 => no password set
    PMS_RETRY_LEFT = 211,
    PMS_LOCK_TIME_LEFT = 212,
    PMS_HIDE_EMAIL = 217,    // GET_INFO: request 0=plain, 1=masked; reply UTF-8 email
    PMS_ENC_BUFFER = 218,    // encrypt-request output
    PMS_HANDLER = 209,       // opaque handle the controllers keep
};
constexpr uint32_t kReqMagic = 10000;   // buildBuffer's middle header word
constexpr uint32_t kVerifyFail = 1;     // non-zero exeResultCode => isExeSuccess() false (wrong password)

constexpr int32_t kFail = -1;   // FF FF FF FF, the stock "not available" marker
constexpr size_t kMaxLogLine = 256;

// A command id falls in a privacy range when the OxygenOS privacy stack
// (Settings / appplatform / securitypermission: AppLock, Hide apps, Private
// Safe, the privacy password) owns it in the stock caller ACL. These get the
// PMS dispatcher. Unsupported commands fail; no placeholder keys are issued.
struct Range { uint32_t lo, hi; };
constexpr Range kPrivacy[] = {
    {26, 26},        // CE_CMD_PRESET_DATA_DEC
    {3000, 3019}, {4000, 4012}, {5000, 5012},
    {6000, 8003},
    {11000, 11005}, {12000, 12004}, {13000, 13006},
};

// The OPlus PKI family (CE_CMD_RUN_PKI_*: hash, HMAC, HKDF, AES, RSA, ECDH,
// ECIES, ECDSA, CERT_VERIFY, SIGN, ...). Every one is a TEE operation under the
// OnePlus root of trust, so none is implemented here. 10014/10015 (attestation)
// stay hardware-root refusals.
constexpr Range kPki[] = {{10000, 10013}, {10016, 10071}};

// The protocol's own "this cryptoeng does not support the function" reply: one
// little-endian word. The OPlus crypto SDK (com.oplus...crypto-android-sdk, in
// Weather and other OPlus apps) treats it as unsupported and takes its software
// path -- for CERT_VERIFY (10009) that is a Java X509TrustManager check against
// the OPlus roots the app bundles. Any well-formed failure reply instead reads
// as "the TEE checked and rejected it", which is a hard error: Weather logged
// "signature check failed" and lost network location.
constexpr int32_t kNotSupported = 10045;

bool InRanges(uint32_t c, const Range* r, size_t n) {
    for (size_t i = 0; i < n; ++i)
        if (c >= r[i].lo && c <= r[i].hi) return true;
    return false;
}

std::vector<uint8_t> Word(int32_t v) {   // native (little-endian): device-state cmds, read by C++ callers
    return {static_cast<uint8_t>(v), static_cast<uint8_t>(v >> 8),
            static_cast<uint8_t>(v >> 16), static_cast<uint8_t>(v >> 24)};
}

void PushBE(std::vector<uint8_t>& v, uint32_t x) {   // Java CryptoengManager reads big-endian
    v.push_back(static_cast<uint8_t>(x >> 24)); v.push_back(static_cast<uint8_t>(x >> 16));
    v.push_back(static_cast<uint8_t>(x >> 8));  v.push_back(static_cast<uint8_t>(x));
}


// General RPMB reply builder: header + an ordered list of (type,data) params.
std::vector<uint8_t> RpmbParams(uint32_t cmd, uint32_t exeResult,
                                const std::vector<std::pair<uint32_t, std::vector<uint8_t>>>& params) {
    std::vector<uint8_t> r;
    PushBE(r, cmd);
    PushBE(r, exeResult);
    PushBE(r, static_cast<uint32_t>(params.size()));
    for (auto& [type, data] : params) {
        PushBE(r, type);
        PushBE(r, static_cast<uint32_t>(data.size()));
        r.insert(r.end(), data.begin(), data.end());
    }
    return r;
}

// Parse a PMS request body into its params. Layout (big-endian):
//   [methodType:4][10000:4][paramNum:4] then paramNum x ([type:4][len:4][data]).
using Params = std::map<uint32_t, std::vector<uint8_t>>;
bool ParseParams(const std::vector<uint8_t>& in, Params& out) {
    if (in.size() < 12 || in.size() > 65536) return false;
    auto u32 = [&](size_t o) {
        return (uint32_t(in[o]) << 24) | (uint32_t(in[o+1]) << 16) |
               (uint32_t(in[o+2]) << 8) | in[o+3];
    };
    if (u32(4) != kReqMagic || u32(8) > 64) return false;
    size_t o = 12;
    for (uint32_t i = 0; i < u32(8); ++i) {
        if (in.size() - o < 8) return false;
        uint32_t type = u32(o), len = u32(o+4); o += 8;
        if (len > in.size() - o || out.count(type)) return false;
        out[type].assign(in.begin()+o, in.begin()+o+len); o += len;
    }
    return o == in.size();
}
bool Equal(const std::vector<uint8_t>& a, const std::vector<uint8_t>& b) {
    if (a.size() != b.size()) return false;
    volatile uint8_t difference = 0;
    for (size_t i = 0; i < a.size(); ++i) difference |= a[i] ^ b[i];
    return difference == 0;
}
bool Random(std::vector<uint8_t>& bytes) {
    size_t off = 0;
    while (off < bytes.size()) {
        ssize_t n = getrandom(bytes.data()+off, bytes.size()-off, 0);
        if (n < 0 && errno == EINTR) continue;
        if (n <= 0) return false;
        off += size_t(n);
    }
    return true;
}

std::vector<uint8_t> U32be(uint32_t v) {
    return {uint8_t(v >> 24), uint8_t(v >> 16), uint8_t(v >> 8), uint8_t(v)};
}
int32_t ParamInt(const std::map<uint32_t, std::vector<uint8_t>>& p, uint32_t type, int32_t def = 0) {
    auto it = p.find(type);
    if (it == p.end() || it->second.size() != 4) return def;
    const auto& b = it->second;
    return int32_t((uint32_t(b[0]) << 24) | (b[1] << 16) | (b[2] << 8) | b[3]);
}

uint32_t CommandId(const std::vector<uint8_t>& in) {
    const auto b = [&](int i) { return static_cast<uint32_t>(in[i]); };
    const uint32_t le = b(0) | b(1) << 8 | b(2) << 16 | b(3) << 24;
    const uint32_t be = b(3) | b(2) << 8 | b(1) << 16 | b(0) << 24;
    // the stock rule: a plausible small id wins, else the byte-swapped form.
    if (le < 1000000) return le;
    if (be < 1000000) return be;
    return le;
}

std::string LogLine(const std::vector<uint8_t>& in) {
    std::string s;
    for (size_t i = 4; i < in.size() && s.size() < kMaxLogLine; ++i) {
        const char c = static_cast<char>(in[i]);
        if (c == '\0') break;
        s.push_back((c >= 0x20 && c < 0x7f) ? c : '?');
    }
    return s;
}

}  // namespace

CryptoengHal::CryptoengHal(const std::string& storePath) : store_path_(storePath) {
    const std::string keyPath = store_path_ + ".seed";
    auto readKey = [&] {
        int fd = open(keyPath.c_str(), O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
        if (fd < 0) return false;
        struct stat st{};
        bool ok = fstat(fd, &st) == 0 && S_ISREG(st.st_mode) && st.st_size == 32 &&
                  read(fd, seed_.data(), seed_.size()) == ssize_t(seed_.size());
        close(fd); return ok;
    };
    if (readKey()) { seed_ready_ = true; return; }
    struct stat st{};
    if (lstat(keyPath.c_str(), &st) == 0 || errno != ENOENT) {
        LOG(ERROR) << "cryptoeng: seed file unreadable/corrupt; preserving enrollment";
        return;
    }
    if (lstat(store_path_.c_str(), &st) == 0) {
        // Migration only. Serial-property access is prohibited in a vendor HAL;
        // run --migrate-store once as root before enabling the normal init service.
        if (getuid() != 0) {
            LOG(ERROR) << "cryptoeng: legacy store needs root --migrate-store once";
            return;
        }
        std::string id;
        for (const char* k : {"ro.serialno", "ro.boot.serialno", "ro.vendor.boot.serialno",
                              "ro.product.vendor.device", "ro.boot.cpuid", "ro.boot.em.did"}) {
            id += android::base::GetProperty(k, ""); id += '|';
        }
        if (id.size() < 8) id += android::base::GetProperty("ro.build.fingerprint", "onyx");
        static const char label[] = "OxyNish-cryptoeng-seed-v1";
        seed_ = HmacSha256(reinterpret_cast<const uint8_t*>(label), sizeof(label)-1,
                          reinterpret_cast<const uint8_t*>(id.data()), id.size());
        PmsStore legacy(seed_, store_path_);
        if (!legacy.Ready()) {
            LOG(ERROR) << "cryptoeng: legacy seed/store mismatch; migration refused";
            return;
        }
    } else {
        if (errno != ENOENT) return;
        std::vector<uint8_t> randomSeed(32);
        if (!Random(randomSeed)) return;
        std::copy(randomSeed.begin(), randomSeed.end(), seed_.begin());
    }
    int fd = open(keyPath.c_str(), O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW, 0600);
    if (fd < 0) { if (errno == EEXIST) seed_ready_ = readKey(); return; }
    bool ok = write(fd, seed_.data(), seed_.size()) == ssize_t(seed_.size()) && fsync(fd) == 0;
    if (close(fd) != 0) ok = false;
    if (!ok) { unlink(keyPath.c_str()); return; }
    int dir = open(store_path_.substr(0, store_path_.find_last_of('/')).c_str(),
                   O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    if (dir < 0) return;
    seed_ready_ = fsync(dir) == 0; close(dir);
}

bool CryptoengHal::StorageReady() {
    std::lock_guard<std::mutex> guard(lock_);
    return seed_ready_ && Store().Ready();
}

CryptoengHal::~CryptoengHal() = default;

CryptoengHal::Tier CryptoengHal::Classify(uint32_t cmd) {
    switch (cmd) {
        case kCleanUp: case kGetSecureType: case kWidevineSupport:
        case kCryptoSupport: case kGatekeeperLog:
            return Tier::DeviceState;
    }
    if (InRanges(cmd, kPrivacy, sizeof(kPrivacy) / sizeof(kPrivacy[0]))) return Tier::PrivacyKey;
    if (InRanges(cmd, kPki, sizeof(kPki) / sizeof(kPki[0]))) return Tier::PkiUnsupported;
    return Tier::HardwareRoot;   // default: honestly refuse anything not enumerated
}

// Preserve the legacy seed derivation to read existing PMS1 enrollments.
const std::array<uint8_t, 32>& CryptoengHal::Seed() { return seed_; }

std::vector<uint8_t> CryptoengHal::Invoke(const std::vector<uint8_t>& in) {
    if (in.size() < 4) {
        LOG(WARNING) << "cryptoeng: request of " << in.size() << " bytes has no command id";
        return Word(kFail);
    }
    const uint32_t cmd = CommandId(in);
    const Tier tier = Classify(cmd);
    // GET_INFO (4005) is polled constantly, and PKI callers retry on every
    // network request; those two are logged once below, everything else is rare.
    if (cmd != 4005 && tier != Tier::PkiUnsupported) {
        const char* name = tier == Tier::DeviceState ? "device-state"
                         : tier == Tier::PrivacyKey ? "privacy-key" : "hw-root";
        LOG(INFO) << "cryptoeng: recv cmd=" << cmd << " tier=" << name << " inlen=" << in.size();
    }
    switch (tier) {
        case Tier::DeviceState:
            switch (cmd) {
                case kGetSecureType: {
                    int32_t v = 0;
                    return android::base::ParseInt(
                               android::base::GetProperty("ro.boot.secureboot", ""), &v)
                               ? Word(v) : Word(kFail);
                }
                case kWidevineSupport: {
                    // Android 16 here serves Widevine from its APEX and keeps
                    // only OEMCrypto in /vendor; later updates may move either,
                    // so any one of them counts.
                    static const char* const kWidevine[] = {
                        "/vendor/lib64/liboemcrypto.so",
                        "/apex/com.google.android.widevine/bin/hw/android.hardware.drm-service.widevine",
                        "/vendor/bin/hw/android.hardware.drm-service.widevine",
                    };
                    for (const char* path : kWidevine)
                        if (access(path, F_OK) == 0) return Word(0);
                    return Word(1);
                }
                case kCryptoSupport:
                    return Word(1);   // OnePlus OEM crypto keys: unsupported here
                case kCleanUp:
                    return Word(0);   // nothing escrowed, nothing to wipe
                case kGatekeeperLog:
                    LOG(INFO) << "gatekeeperd: " << LogLine(in);
                    return Word(0);
            }
            return Word(kFail);

        case Tier::PrivacyKey:
            return HandlePms(cmd, in);

        case Tier::PkiUnsupported: {
            std::lock_guard<std::mutex> g(lock_);
            if (refused_logged_.insert(cmd).second) {
                LOG(INFO) << "cryptoeng: PKI cmd " << cmd << " (" << in.size()
                          << " bytes) answered 'not supported' (10045); the caller"
                             " uses its software path";
            }
            return Word(kNotSupported);
        }

        case Tier::HardwareRoot:
        default: {
            std::lock_guard<std::mutex> g(lock_);
            if (refused_logged_.insert(cmd).second) {
                LOG(INFO) << "cryptoeng: cmd " << cmd
                          << " is a hardware-root command; not available without the OnePlus TEE";
            }
            return Word(kFail);
        }
    }
}

PmsStore& CryptoengHal::Store() {
    // Called under lock_ by HandlePms only.
    if (!store_) store_ = std::make_unique<PmsStore>(Seed(), store_path_);
    return *store_;
}

std::vector<uint8_t> CryptoengHal::HandlePms(uint32_t cmd, const std::vector<uint8_t>& in) {
    std::lock_guard<std::mutex> guard(lock_); // Verify, mutation and challenge checks are atomic.
    const auto fail = [&] { return RpmbParams(cmd, kVerifyFail, {}); };
    // Unsupported families previously returned invented success. Never authenticate
    // a recovery, biometric or encryption request without its actual implementation.
    if (cmd < 4001 || cmd > 4005) return cmd < 100 ? Word(kFail) : fail();
    Params params;
    if (!ParseParams(in, params)) return fail();
    const int32_t type = ParamInt(params, PMS_TYPE, -1);
    if (type != 1 && type != 2) return fail();
    if (!seed_ready_) return fail();
    auto& store = Store();
    if (!store.Ready()) {
        LOG(ERROR) << "cryptoeng: PMS store unavailable/corrupt; refusing operation";
        return fail();
    }
    auto sha = [](const std::vector<uint8_t>& b) {
        Sha256 h; h.update(b.data(), b.size()); auto d = h.digest();
        return std::vector<uint8_t>(d.begin(), d.end());
    };
    auto m = U32be(uint32_t(type));
    m.insert(m.end(), seed_.begin(), seed_.end());
    auto digest = HmacSha256(seed_.data(), seed_.size(), m.data(), m.size());
    std::vector<uint8_t> handler(digest.begin(), digest.begin()+8);
    PmsRecord r = store.Get(type);
    const auto now = std::chrono::steady_clock::now();
    challenges_.erase(std::remove_if(challenges_.begin(), challenges_.end(),
        [&](const Challenge& c) { return c.expires <= now; }), challenges_.end());
    auto authorized = [&] {
        if (params[PMS_CHALLENGE].size() != 64) return false;
        for (const auto& c : challenges_)
            if (c.type == type && Equal(c.bytes, params[PMS_CHALLENGE])) return true;
        return false;
    };
    auto revoke = [&] {
        challenges_.erase(std::remove_if(challenges_.begin(), challenges_.end(),
            [&](const Challenge& c) { return c.type == type; }), challenges_.end());
    };
    auto commit = [&](const PmsRecord& record) {
        if (store.Put(type, record)) return true;
        LOG(ERROR) << "cryptoeng: PMS persistence failed; returning failure";
        return false;
    };
    // Secure info is a list of 40-byte slots: kind(4), length(4), padded data(32).
    auto secureSlots = [](const std::vector<uint8_t>& buffer, Params& slots) {
        if (buffer.size() % 40 || buffer.size() > 120) return false;
        for (size_t i = 0; i < buffer.size(); i += 40) {
            auto word = [&](size_t j) { return (uint32_t(buffer[j]) << 24) |
                (uint32_t(buffer[j+1]) << 16) | (uint32_t(buffer[j+2]) << 8) | buffer[j+3]; };
            uint32_t kind = word(i), len = word(i+4);
            if ((kind != 2 && kind != 4 && kind != 10) || len > 32 ||
                (kind == 2 && len != 32) || slots.count(kind)) return false;
            slots[kind] = {buffer.begin()+i+8, buffer.begin()+i+8+len};
        }
        return true;
    };
    constexpr uint32_t kAttemptsBase = 0xfffffe00, kDeadlineBase = 0xfffffe10;
    constexpr uint32_t kTries = 10, kDelay = 30;
    uint32_t epoch = uint32_t(time(nullptr));
    auto delay = [&](int mode) {
        uint32_t deadline = uint32_t(ParamInt(r.extra, kDeadlineBase+mode));
        return deadline > epoch ? std::min(deadline-epoch, kDelay) : 0u;
    };
    auto left = [&](int mode) {
        if (delay(mode)) return 0u;
        if (ParamInt(r.extra, kDeadlineBase+mode)) return kTries;
        return kTries - std::min(uint32_t(ParamInt(r.extra, kAttemptsBase+mode)), kTries);
    };
    switch (cmd) {
        case 4001: { // Enrollment cannot overwrite an existing credential.
            int quality = ParamInt(params, PMS_PWD_TYPE);
            Params slots;
            if (r.quality || !r.pwd.empty() || quality < 1 || quality > 5 ||
                params[PMS_PWD_INFO].size() != 32 || !secureSlots(params[PMS_SECURE_INFO], slots))
                return fail();
            PmsRecord fresh;
            fresh.quality = quality; fresh.pwd = params[PMS_PWD_INFO]; fresh.sec = params[PMS_SECURE_INFO];
            if (!commit(fresh)) return fail();
            revoke();
            return RpmbParams(cmd, 0, {{PMS_HANDLER, handler}});
        }
        case 4002: {
            int mode = ParamInt(params, PMS_VERIFY_TYPE, -1);
            if (r.quality < 1 || r.quality > 5 || r.pwd.size() != 32 ||
                params[PMS_VERIFY_BUFFER].size() != 32 || (mode != 1 && mode != 2) || delay(mode))
                return fail();
            std::vector<uint8_t> expected;
            if (mode == 1) {
                expected = r.pwd; expected.insert(expected.end(), handler.begin(), handler.end());
                expected = sha(expected);
            } else {
                Params slots;
                if (!secureSlots(r.sec, slots) || slots[2].size() != 32) return fail();
                expected = slots[2]; // checkAnswer sends SHA256(answer), with no handler.
            }
            const bool matched = Equal(params[PMS_VERIFY_BUFFER], expected);
            LOG(INFO) << "cryptoeng: PMS verify type=" << type << " method=" << mode
                      << " result=" << (matched ? "match" : "reject");
            if (!matched) {
                uint32_t attempts = kTries - left(mode) + 1;
                r.extra[kAttemptsBase+mode] = U32be(attempts);
                r.extra[kDeadlineBase+mode] = U32be(attempts >= kTries ? epoch+kDelay : 0);
                commit(r); // Failure still returns failure even if the retry state cannot be saved.
                return fail(); // No challenge on failure, ever.
            }
            // A real random capability is required by modify/delete, not merely dummy padding.
            std::vector<uint8_t> challenge(64);
            if (!Random(challenge)) return fail();
            if (ParamInt(r.extra, kAttemptsBase+mode) || ParamInt(r.extra, kDeadlineBase+mode)) {
                r.extra.erase(kAttemptsBase+mode); r.extra.erase(kDeadlineBase+mode);
                if (!commit(r)) return fail();
            }
            if (challenges_.size() >= 16) challenges_.erase(challenges_.begin());
            challenges_.push_back({type, challenge, now + std::chrono::minutes(10)});
            return RpmbParams(cmd, 0, {{PMS_CHALLENGE, challenge}});
        }
        case 4003: {
            if (!r.quality || !authorized()) return fail();
            int kind = ParamInt(params, PMS_INFO_TYPE, -1);
            int quality = ParamInt(params, PMS_PWD_TYPE, -1);
            const auto& data = params[PMS_INFO_BUFFER];
            if (quality < 1 || quality > 5) return fail();
            if (kind == 1) {
                if (data.size() != 32 || Equal(data, r.pwd)) return fail();
                r.pwd = data; r.quality = quality;
                r.extra.erase(kAttemptsBase+1); r.extra.erase(kDeadlineBase+1);
            } else if (kind == 2 || kind == 4) {
                if ((kind == 2 && data.size() != 32) || (kind == 4 && (data.empty() || data.size() > 64)))
                    return fail();
                Params slots;
                if (!secureSlots(r.sec, slots)) return fail();
                if (kind == 2) slots[2] = data;
                else {
                    slots[4] = {data.begin(), data.begin()+std::min(data.size(), size_t(32))};
                    slots.erase(10);
                    if (data.size() > 32) slots[10] = {data.begin()+32, data.end()};
                }
                r.sec.clear();
                for (const auto& [key, bytes] : slots) {
                    PushBE(r.sec, key); PushBE(r.sec, bytes.size());
                    r.sec.insert(r.sec.end(), bytes.begin(), bytes.end());
                    r.sec.insert(r.sec.end(), 32-bytes.size(), 0);
                }
                if (kind == 2) { r.extra.erase(kAttemptsBase+2); r.extra.erase(kDeadlineBase+2); }
            } else return fail();
            if (!commit(r)) return fail();
            revoke();
            LOG(INFO) << "cryptoeng: PMS modify committed type=" << type << " field=" << kind;
            return RpmbParams(cmd, 0, {{PMS_HANDLER, handler}});
        }
        case 4004:
            if (!r.quality || !authorized() || !store.Erase(type)) return fail();
            revoke();
            return RpmbParams(cmd, 0, {});
        case 4005: {
            // PrivacySettingsFragment saves with MODIFY/INFO_TYPE=4, then reads
            // this field through PrivacyInfo.mHideEmail. Omitting it makes a
            // successfully saved address display as "Not set". Read both fixed
            // slots so addresses longer than 32 bytes survive round-trips.
            int hideEmail = 1;
            if (params.count(PMS_HIDE_EMAIL)) {
                hideEmail = ParamInt(params, PMS_HIDE_EMAIL, -1);
                if (hideEmail != 0 && hideEmail != 1) return fail();
            }
            std::vector<std::pair<uint32_t, std::vector<uint8_t>>> out = {
                {PMS_PWD_TYPE, U32be(r.quality)}, {PMS_RETRY_LEFT, U32be(left(1))},
                {PMS_LOCK_TIME_LEFT, U32be(delay(1))}, {219, U32be(left(2))}, {220, U32be(delay(2))}};
            if (r.quality) out.push_back({PMS_HANDLER, handler});
            if (r.quality && params.count(PMS_HIDE_EMAIL)) {
                Params slots;
                if (secureSlots(r.sec, slots) && slots.count(4)) {
                    auto email = slots[4];
                    if (slots.count(10)) email.insert(email.end(), slots[10].begin(), slots[10].end());
                    auto at = std::find(email.begin(), email.end(), uint8_t('@'));
                    // Empty/unusable email is represented by an absent TLV,
                    // never a zero-length buffer (the OEM parser rejects it).
                    if (at != email.begin() && at != email.end() && at + 1 != email.end() &&
                        std::find(email.begin(), email.end(), uint8_t(0)) == email.end()) {
                        if (hideEmail) {
                            std::vector<uint8_t> masked = {'*', '*', '*', '*'};
                            masked.insert(masked.end(), at, email.end());
                            email = std::move(masked);
                        }
                        out.push_back({PMS_HIDE_EMAIL, std::move(email)});
                    }
                }
            }
            return RpmbParams(cmd, 0, out);
        }
    }
    return fail();
}

::ndk::ScopedAStatus CryptoengHal::cryptoeng_invoke_command(const std::vector<uint8_t>& in,
                                                            std::vector<uint8_t>* out) {
    *out = Invoke(in);
    return ::ndk::ScopedAStatus::ok();
}

}  // namespace oplus_compat
