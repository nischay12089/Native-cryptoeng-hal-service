# Native cryptoeng HAL service

A from-scratch, TEE-free implementation of the OnePlus
`vendor.oplus.hardware.cryptoeng.ICryptoeng` AIDL HAL for an OxygenOS port on
Xiaomi onyx (Poco F7, SM8735). The stock OnePlus 13 service needs QSEECom and a
OnePlus-signed TrustZone app that cannot load on Xiaomi firmware. This service
uses the same interface identity (AIDL V1 )


What it answers:

- **Device state** commands that OxygenOS asks about at boot.
- **Privacy password (PMS 4001-4005):** AppLock, Hide apps and Private Safe
  passwords, security question and recovery email, with challenges, retry lockout
  and a crash-safe store
- **PKI family (10000-10013, 10016-10071):** "not supported" (10045), so OPlus
  apps fall back to their own software certificate checks.
- **Everything else** (attestation, hardware-root commands): an explicit refusal.

This is software security, not a TEE replacement. See
[cryptoeng/DESIGN.md](cryptoeng/DESIGN.md) for the protocol, the store format and
the test evidence.


## Layout

| Path | Contents |
| --- | --- |
| `cryptoeng/` | HAL implementation, service entry point, PMS store, design notes |
| `cryptoeng/tests/` | contract test (103 checks), read-only email probe, Settings contract notes |
| `common/` | small shared helpers (compat, binder platform, SHA-256) |
| `aidl/` | the reconstructed `ICryptoeng.aidl` |
| `ndkstubs/` | NDK-backend AIDL stubs generated from it by `gen_ndk_stubs.py` |
| `third_party/libbinder_ndk_cpp/` | AOSP C++ binder helpers, unmodified (Apache-2.0) |
| `tools/build-cryptoeng.ps1` | build script |
| `tools/stubs/` | link-only `libbinder_ndk` / `liblog` stubs (never shipped) |
| `install/odm/` | init `.rc` and VINTF manifest |
| `sepolicy/` | the cryptoeng rules from the vendor policy block |

## Build

Requires Android NDK r26d (26.3.11579264) on Windows.

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File tools/build-cryptoeng.ps1 -Tests
```

Output goes to `out/`: the service plus `cryptoeng_contract_test` and
`cryptoeng_email_probe`. Pass `-Ndk <path>` for another NDK. Flags: ARM64,
API 34, C++17, `-Wall -Wextra -Werror`, static libc++, 16 KB-aligned segments.

The build is reproducible. The service builds byte-identical to the shipped binary:

```
22da1309ff57d92a870e6e700d359c9083e3dab0cc5edc00ac177ec9e7febcaa  vendor.oplus.hardware.cryptoeng@1.0-service
```

The NDK's `libbinder_ndk.so` stub omits the LL-NDK entry points a vendor service
needs (`AServiceManager_addService`, `ABinderProcess_*`,
`AIBinder_markVintfStability`). `tools/stubs` lists exactly the imports, with the
AOSP symbol versions, so the build needs no libraries pulled from a device.

## Install

| File | Destination |
| --- | --- |
| `out/vendor.oplus.hardware.cryptoeng@1.0-service` | `/odm/bin/hw/` (0755, `hal_cryptoeng_oplus_exec`) |
| `install/odm/etc/init/*.rc` | `/odm/etc/init/` |
| `install/odm/etc/vintf/manifest/*.xml` | `/odm/etc/vintf/manifest/` |
| `sepolicy/cryptoeng.cil` | merge into `/vendor/etc/selinux/vendor_sepolicy.cil` |
| `sepolicy/file_contexts` | merge into `/vendor/etc/selinux/vendor_file_contexts` |
| `sepolicy/service_contexts` | merge into `/vendor/etc/selinux/vendor_service_contexts` |

The CIL uses the vendor API 202404 mapping suffix. An existing PMS1 store from an
older build without a seed file needs one root run of the binary with
`--migrate-store` (see DESIGN.md).

## Tests

Push `out/cryptoeng_contract_test` to the device and run it as root. It works in
its own directory under `/data/local/tmp/cryptoeng-contract.*`, never touches the
live service or the production store, and uses synthetic credentials only.

## Notes

- `ref/...` paths in DESIGN.md point to local reverse-engineering notes that are
  not part of this repository.
- `third_party/libbinder_ndk_cpp` is Apache-2.0 (The Android Open Source
  Project). Its license headers are kept.
