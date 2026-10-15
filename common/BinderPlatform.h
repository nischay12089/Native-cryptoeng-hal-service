// BinderPlatform.h - declarations for the platform-only libbinder_ndk APIs.
//
// AServiceManager_* and ABinderProcess_* are NOT part of the public NDK: the
// NDK's libbinder_ndk.so stub exports 89 functions and none of them are these
// (verified). Their headers (android/binder_manager.h, android/binder_process.h)
// are likewise absent from the NDK sysroot.
//
// They ARE exported by the real on-device /system/lib64/libbinder_ndk.so, which
// is what a vendor HAL links against at runtime. So when building outside an
// AOSP tree we declare the handful we need here and link against a copy of the
// device library (see tools/build.sh). Inside AOSP the real headers exist and
// are used instead.

#pragma once

#if defined(__has_include)
#  if __has_include(<android/binder_manager.h>)
#    define OPLUS_COMPAT_HAVE_BINDER_MANAGER 1
#  endif
#endif

#ifdef OPLUS_COMPAT_HAVE_BINDER_MANAGER

#include <android/binder_manager.h>
#include <android/binder_process.h>

#else

#include <android/binder_ibinder.h>
#include <android/binder_status.h>

#include <stdbool.h>
#include <stdint.h>

extern "C" {

// --- android/binder_manager.h -------------------------------------------
// Register a service under `instance`. Returns STATUS_OK on success. Requires
// the caller to be permitted by servicemanager + SELinux; a shell-uid caller is
// denied, which is exactly why these run as user=system from init.
binder_status_t AServiceManager_addService(AIBinder* binder, const char* instance);

// Non-blocking lookup. Prefer this inside a binder call: waitForService blocks
// indefinitely and can wedge the caller.
AIBinder* AServiceManager_checkService(const char* instance);

// Blocking lookup; only safe at startup.
AIBinder* AServiceManager_waitForService(const char* instance);

// Whether the instance is declared in a VINTF manifest.
bool AServiceManager_isDeclared(const char* instance);

// Register as a lazy (on-demand) service.
binder_status_t AServiceManager_registerLazyService(AIBinder* binder,
                                                   const char* instance);

// --- android/binder_process.h -------------------------------------------
void ABinderProcess_startThreadPool(void);
bool ABinderProcess_setThreadPoolMaxThreadCount(uint32_t numThreads);
bool ABinderProcess_isThreadPoolStarted(void);
void ABinderProcess_joinThreadPool(void);

}  // extern "C"

#endif  // OPLUS_COMPAT_HAVE_BINDER_MANAGER

// --- android/binder_stability.h ---------------------------------------------
// @VintfStability services MUST mark their binder VINTF-stable before sending
// it anywhere. A process in /odm or /vendor links the vendor libbinder, whose
// default stability is VENDOR, and system_server then refuses every call with
// "Cannot do a user transaction on a vendor stability binder". AOSP's generated
// BnFoo::createBinder() does this; gen_ndk_stubs.py mirrors it. Exported by the
// device libbinder_ndk.so as AIBinder_markVintfStability@@LIBBINDER_NDK30.
#if defined(__has_include) && __has_include(<android/binder_stability.h>)
#include <android/binder_stability.h>
#else
#include <android/binder_ibinder.h>
extern "C" {
void AIBinder_markVintfStability(AIBinder* binder);
}
#endif

namespace oplus_compat {
// createBinder() marks every binder VINTF-stable, which is required in
// production (system_server rejects an unmarked vendor binder). But a shell-uid
// process is not allowed to register a VINTF-stable service, which blocks
// smoke-testing over adb. A service may set this false BEFORE calling asBinder()
// so a test instance can register as shell; it defaults true so production is
// always correct even if a caller forgets.
inline bool g_mark_vintf_stability = true;
}  // namespace oplus_compat
