# libbinder_ndk C++ helpers (vendored)

Header-only C++ wrappers over the stable libbinder_ndk C ABI, copied UNMODIFIED
from the NDK r26d sysroot (`sysroot/usr/include/android/`). Apache License 2.0,
The Android Open Source Project; the license header is kept in every file.

Why: NDK r29 ships only the C headers (binder_ibinder.h, binder_parcel.h,
binder_status.h, ...) and no longer these C++ helpers, so the generated AIDL
stubs in ../../ndkstubs stopped compiling with it. The ABI they call is
unchanged -- every import of the built HALs still resolves on API 29-35 stubs
and on the device. Keeping the helpers here makes the build independent of
which NDK release is installed.
