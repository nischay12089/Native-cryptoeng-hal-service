// Native software PMS adapter for onyx. No TEE or hardware security claim.
#pragma once

#include <aidl/vendor/oplus/hardware/cryptoeng/BnCryptoeng.h>

#include <array>
#include <chrono>
#include <cstdint>
#include <map>
#include <memory>
#include <mutex>
#include <set>
#include <string>
#include <vector>

namespace oplus_compat {

class PmsStore;

class CryptoengHal : public ::aidl::vendor::oplus::hardware::cryptoeng::BnCryptoeng {
  public:
    explicit CryptoengHal(const std::string& storePath = "/data/vendor/cryptoeng/pms_store");
    ~CryptoengHal() override;

    ::ndk::ScopedAStatus cryptoeng_invoke_command(const std::vector<uint8_t>& in,
                                                  std::vector<uint8_t>* out) override;

    // The dispatcher without binder, for the on-device self test.
    std::vector<uint8_t> Invoke(const std::vector<uint8_t>& in);
    bool StorageReady(); // Also used by the explicit root-only legacy migration command.

    // Tier 1: device-state queries (CryptoEngManager.CommandId + gatekeeperd log).
    static constexpr uint32_t kCleanUp = 53;
    static constexpr uint32_t kGetSecureType = 54;
    static constexpr uint32_t kWidevineSupport = 59;
    static constexpr uint32_t kCryptoSupport = 60;
    static constexpr uint32_t kGatekeeperLog = 1001;

    // How a command id is classified. Exposed so the self test can show it.
    // PkiUnsupported: OPlus PKI commands, answered with the protocol's own
    // "not supported" code so SDK callers fall back to software.
    enum class Tier { DeviceState, PrivacyKey, PkiUnsupported, HardwareRoot };
    static Tier Classify(uint32_t cmd);

  private:
    const std::array<uint8_t, 32>& Seed();   // legacy enrollment compatibility seed
    PmsStore& Store();                        // lazily opened, seeded

    // The privacy/password engine: parse the PMS request and answer from the store.
    std::vector<uint8_t> HandlePms(uint32_t cmd, const std::vector<uint8_t>& in);

    std::mutex lock_;
    std::array<uint8_t, 32> seed_{};
    bool seed_ready_ = false;
    std::unique_ptr<PmsStore> store_;
    std::string store_path_;
    struct Challenge {
        int32_t type;
        std::vector<uint8_t> bytes;
        std::chrono::steady_clock::time_point expires;
    };
    std::vector<Challenge> challenges_;
    std::set<uint32_t> refused_logged_;
};

}  // namespace oplus_compat
