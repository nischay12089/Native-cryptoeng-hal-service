/* Link-time stub for libbinder_ndk.so. Never shipped: the device's own
 * /system/lib64/libbinder_ndk.so resolves these at run time. The NDK's stub
 * omits the LL-NDK entry points a vendor service needs (AServiceManager_*,
 * ABinderProcess_*, AIBinder_markVintfStability), so this one lists exactly
 * the symbols the HAL and its tests import, with their AOSP version nodes. */
void ABinderProcess_joinThreadPool(void) {}
void ABinderProcess_setThreadPoolMaxThreadCount(void) {}
void ABinderProcess_startThreadPool(void) {}
void AIBinder_Class_define(void) {}
void AIBinder_Class_setOnDump(void) {}
void AIBinder_Weak_delete(void) {}
void AIBinder_Weak_new(void) {}
void AIBinder_Weak_promote(void) {}
void AIBinder_associateClass(void) {}
void AIBinder_decStrong(void) {}
void AIBinder_dump(void) {}
void AIBinder_getUserData(void) {}
void AIBinder_incStrong(void) {}
void AIBinder_isRemote(void) {}
void AIBinder_new(void) {}
void AIBinder_prepareTransaction(void) {}
void AIBinder_transact(void) {}
void AParcel_delete(void) {}
void AParcel_readByteArray(void) {}
void AParcel_readStatusHeader(void) {}
void AParcel_writeByteArray(void) {}
void AParcel_writeInt32(void) {}
void AParcel_writeStatusHeader(void) {}
void AParcel_writeString(void) {}
void AServiceManager_addService(void) {}
void AServiceManager_checkService(void) {}
void AStatus_delete(void) {}
void AStatus_fromStatus(void) {}
void AStatus_isOk(void) {}
void AStatus_newOk(void) {}
void AIBinder_markVintfStability(void) {}

/* The real library imports these C++ runtime symbols from libc++.so. Because the
 * HAL links libc++ statically, lld exports its own copies so the import resolves
 * (the shipped binary carries them in .dynsym). Referencing them here keeps that
 * linkage, and therefore the output, identical to a build against the device
 * library. Listed in the device library's own import order, which lld follows
 * when it orders the exports. */
void _Znwm(void);
void _ZdlPvm(void);
void __cxa_pure_virtual(void);
void __cxa_guard_acquire(void);
void __cxa_guard_release(void);
void _Znam(void);
void _ZdaPv(void);
void _ZnwmRKSt9nothrow_t(void);
extern char _ZSt7nothrow;
void *const stub_libcxx_imports[] = {
    _Znwm, _ZdlPvm, __cxa_pure_virtual, __cxa_guard_acquire, __cxa_guard_release, _Znam, _ZdaPv, _ZnwmRKSt9nothrow_t, &_ZSt7nothrow,
};
