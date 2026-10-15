#include "../common/Compat.h"
#include "../common/BinderPlatform.h"
#include "CryptoengHal.h"
#include <cstring>
#include <unistd.h>
using oplus_compat::CryptoengHal;
using aidl::vendor::oplus::hardware::cryptoeng::ICryptoeng;
int main(int argc, char** argv) {
    android::base::InitLogging(nullptr, android::base::LogdLogger());
    if (argc == 2 && std::strcmp(argv[1], "--migrate-store") == 0) {
        if (getuid() != 0) return EXIT_FAILURE;
        auto hal = ::ndk::SharedRefBase::make<CryptoengHal>();
        if (!hal->StorageReady()) return EXIT_FAILURE;
        LOG(INFO) << "cryptoeng: software store ready; enrollment preserved";
        return EXIT_SUCCESS;
    }
    if (argc > 2 || (argc == 2 && std::strcmp(argv[1], "--live") != 0)) {
        LOG(ERROR) << "usage: cryptoeng-service [--live]; diagnostics use the isolated test binary";
        return EXIT_FAILURE;
    }

    // A small pool, STARTED before addService as AOSP HALs do. Setting the size
    // alone never spawns a thread (libbinder logged "startThreadPool was not
    // called"), so every client queued on the main thread. PMS work is
    // serialized by CryptoengHal's lock; the pool only stops a slow caller
    // from blocking GET_INFO and the others.
    ABinderProcess_setThreadPoolMaxThreadCount(2);
    ABinderProcess_startThreadPool();
    auto hal = ::ndk::SharedRefBase::make<CryptoengHal>();
    const char* instance = (argc > 1) ? argv[1] : "default";
    ::oplus_compat::g_mark_vintf_stability = (std::string(instance) == "default");
    // --live: serve the real "default" name WITHOUT VINTF marking, for a live test
    // from /data/local/tmp on a system whose manifest does not declare cryptoeng yet.
    if (std::strcmp(instance, "--live") == 0) {
        instance = "default";
        ::oplus_compat::g_mark_vintf_stability = false;
    }
    const std::string name = std::string(ICryptoeng::descriptor) + "/" + instance;
    // Retry, then exit cleanly on permanent failure: LOG(FATAL) from init at
    // boot would become a tight restart loop.
    binder_status_t st = STATUS_UNKNOWN_ERROR;
    for (int attempt = 1; attempt <= 10; ++attempt) {
        st = AServiceManager_addService(hal->asBinder().get(), name.c_str());
        if (st == STATUS_OK) break;
        LOG(WARNING) << "addService(" << name << ") attempt " << attempt << " failed, status=" << st;
        sleep(1);
    }
    if (st != STATUS_OK) {
        LOG(ERROR) << "giving up registering " << name << " status=" << st
                   << "; exiting cleanly so init does not spin";
        return EXIT_SUCCESS;
    }
    LOG(INFO) << "registered " << name;
    ABinderProcess_joinThreadPool();
    return EXIT_FAILURE;
}
