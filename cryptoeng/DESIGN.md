# Native cryptoeng PMS fix for onyx

## Confirmed root causes (2026-10-09)

1. `PrivacyPasswordController.checkPassword` checks status zero, then reads
   PMS_CHALLENGE (206). The old HAL returned only PMS_HANDLER (209) on a match.
   Device logs show a matching verifier immediately followed by Settings throwing
   NullPointerException in ResultParam.getBuffer(). A successful hash comparison
   alone did not mean the application unlocked.
2. `modifyPasswordByChallenge` sends INFO_TYPE (207)=1 and INFO_BUFFER (208).
   The old HAL treated MODIFY like ENROLL and only read PWD_INFO (202), so the
   submitted replacement password was ignored while success was returned.
3. The previous test incorrectly asserted that a success had NO challenge. Older
   failure replies supplied a challenge with a success status, reversing the
   controller's meaning. Current wrong-password replies always have nonzero status
   and no challenge. This also corrects the client's same-password comparison.
4. Store writes previously truncated the file and silently ignored write errors.
   The root test module also produced files the system-UID init service cannot own.
5. Recovery email was committed by MODIFY/selector 4, but GET_INFO omitted field
   217. Settings therefore displayed "Not set". GET_INFO now returns the saved
   address, respecting the masking selector and joining slots 4 and 10. The user
   confirmed that the saved address appears after reopening the page.

Primary evidence: ref/cryptoeng/settings/ppc.txt (checkPassword 121-236;
modifyPasswordByChallenge 1251-1358), MethodParamType and RpmbResultParser in the
Settings classes2.dex dump. Actual device errors were observed at 05:22:38,
05:22:47 and 05:23:02 on 2026-10-09.

## Implemented contract

The native C++ AIDL interface remains ICryptoeng V1, frozen hash
765136eb397eb5b85ee1e089d8fec72c15e266b3. PMS is big-endian:
request [command][10000][count] then [type][length][bytes]; reply replaces 10000
with result status (zero success). Duplicate, truncated and malformed TLVs fail.

- 4001 enroll: SHA256(password), quality 1-5, optional secure-info slots. Cannot
  overwrite an existing enrollment.
- 4002 verify/password: exact SHA256(stored SHA256(password) || handler8).
  Success returns a random 64-byte challenge in parameter 206; failure returns
  status 1 without a challenge. No alternate hash guessing or credential logging.
- 4002 verify/answer: compare SHA256(answer) against secure-info slot 2.
- 4003 modify: validate the issued challenge and update parameter 208 according
  to selector 207. Password/answer/email updates are handled independently.
- 4004 delete: requires an issued challenge for the same namespace.
- 4005 info: quality, stable eight-byte handler, remaining attempts and lock time.
  When requested with field 217, returns the saved email in field 217 (selector
  0: plain address; 1: masked local part). An unset email has no email TLV.
- Challenges expire after ten minutes, are namespace-bound, and are invalidated
  after changes, deletion, or process restart. Wrong candidate checks do not
  invalidate an already issued challenge needed to change a password.
- Ten failed attempts impose a 30-second software lock, persisted across restart.
- PMS1 writes use checked temporary-file writes, fsync and rename; failures do
  not claim success. Corrupt/inaccessible stores fail closed without replacement.

Unsupported encryption, reset-all, biometric/account verification and old-password
recovery commands fail. The old generic-success and invented key handlers were
removed. **This is a password-flow repair, not verified complete Private Safe
encryption support.** Device-state command handlers are otherwise unchanged.

## Preserve existing enrollment

Never remove /data/vendor/cryptoeng/pms_store to troubleshoot this issue.
The new /data/vendor/cryptoeng/pms_store.seed preserves the old seed during an
upgrade and removes dependency on serial properties during ordinary operation.
An existing PMS1 store without its seed needs ONE root invocation of the new
binary with `--migrate-store`. Migration validates the original file and leaves
its bytes intact. The previous root test module has been removed on this device.
Fresh installations generate a random seed. Back up store and seed as a pair.

The init rc creates the directory 0700 system:system, migrates the two files to
system:system 0600, and restores their labels. vendor_file_contexts and
vendor_sepolicy.cil define vendor_cryptoeng_data_file. Service domain remains
hal_cryptoeng_oplus; no allocator label, permissive rule or precompiled-policy
patch is supplied. A flashed init service should be used without the old root
test module enabled, to avoid two service processes competing for the same name.

This is software security. The PMS1 format retains its legacy XOR masking for
compatibility and has no authenticated encryption or hardware rollback protection.
It is not a replacement for Android Gatekeeper/KeyMint or OnePlus TEE security.

## Build and verification

From the project root on Windows:

    powershell -NoProfile -ExecutionPolicy Bypass -File tools/build-cryptoeng.ps1 -Tests

NDK 26.3.11579264, ARM64 API 34, C++17, -Wall -Wextra -Werror. Original service
name: vendor.oplus.hardware.cryptoeng@1.0-service. The generated AIDL stubs are
in ndkstubs/; libbinder_ndk and liblog are linked against the link-only stubs in
tools/stubs (the device's own libraries are used at run time). No future
Android-version guarantee is claimed; client protocol, symbols and SELinux
integration need checking on updates.

The separate cryptoeng_contract_test creates a unique directory under
/data/local/tmp/cryptoeng-contract.* and never contacts the live service or uses
the production store. Run as root to include legacy migration cases. On onyx:
**95 passed, 0 failed**. Covered correct/wrong passwords, actual MODIFY fields,
answer verification/change, namespace separation, forged/replayed challenges,
restart persistence, malformed inputs, retry lockout, disk failure, corrupt store,
preserved legacy enrollment, email lengths 31/32/33/64, masking, and the complete
answer-authorized reset sequence. The latter uses synthetic credentials: correct
answer -> challenge -> MODIFY password (including quality change and clearing a
password lock) -> old password rejected -> new password accepted. Email and answer
survive reset and service restart. Results: out/cryptoeng-recovery-tests.txt.

No Java test or framework patch was used. The user confirmed that password
features work and that the recovery email appears. Full question-reset UI use
with the user's actual credentials has not been observed; the complete native
wire sequence passed with isolated synthetic credentials. The production store
and seed were byte-identical before/after deploying the email fix. A read-only
Binder probe also confirmed a valid masked email response from the live service.

SELinux: init-style compilation succeeded. Strict comparison has the same 19
pre-existing neverallow failures as the stock policy, with no added violations.
These tests ran while the device was permissive. It has since moved to enforcing;
a denial check of this service under enforcing is still pending.

After installation, manually check: existing correct password unlocks; wrong
password fails; a different new password can be saved; the old password then
fails and the new one succeeds, including after reboot. No reset is required.

## Question status on the Privacy password page

The screenshot's **Question: Set** already means a question is saved. Stock
Settings does not display the selected question text on that page:

- PrivacySettingsFragment.updatePreference calls hasSetSecurityQuestion and
  assigns resource 0x7f142267 (`privacy_answer_modify_state`, English "Set").
- When absent, it assigns 0x7f1422a7 (`privacy_not_set_security_question`, "Not set").
- hasSetSecurityQuestion reads Settings.Secure `privacy_quesion_type_choose`
  (OEM spelling) or the custom-question detail. The current device's type is 0,
  which is a saved choice. The HAL logs confirm successful answer modifications.
- The actual question choice/text belongs to Settings; the native HAL stores and
  verifies the answer digest. Adding a GET_INFO field cannot change this label.

Evidence: ref/cryptoeng/recovery/privacy-settings.txt (updatePreference),
password-reset-flow.txt (hasSetSecurityQuestion/resetPasswordOnVerifySuccess),
question-flow.txt, choose-abstract.txt and settings-resources.txt. No question
display workaround or authentication change was needed for this reported state.

## Deployment history (2026-10-09)

The email-fix binary runs through the existing init service as system in
hal_cryptoeng_oplus. It is temporarily bind-mounted over the read-only /odm
executable; that runtime update is lost on reboot. The same binary is already in
/data/DNA/DNA_hos4/odm/bin/hw/ for repacking/flashing. The release ZIP also contains
it. No helper service or precompiled-policy edit was added.

Binary SHA256: f4a92176fd0a68f0aac91bf256167f7f81d48c430e0803adfcaf4d0b83364afc.
Deployment backup: /data/DNA/cryptoeng-email-backup-20261009T142139Z.

## PKI commands and later Android versions (2026-10-13)

### PKI family answers "not supported"

Live logs showed the OPlus Weather service sending cmd 10009 (686 bytes) and
then failing its network location lookup with "signature check failed". 10009
is CE_CMD_RUN_PKI_CERT_VERIFY from the OPlus crypto SDK (enum in the app:
10000-10021, CE_CMD_RUN_PKI_*). It sat inside the old "privacy" range, so it
got the PMS failure reply: a well-formed header with exeResultCode 1. The SDK
reads that as "the TEE checked the certificate and rejected it".

The SDK has its own answer for a cryptoeng without the function: one
little-endian word, 10045 ("cryptoeng does not support function"). On that it
raises an error, and its trust manager falls back to a standard Java
X509TrustManager check of the server chain against the OPlus roots bundled in
the app. That is a real verification, done in the app; this HAL still verifies
nothing and claims nothing.

Now: 10000-10013 and 10016-10071 (Tier::PkiUnsupported) reply 10045, logged
once per command. Attestation (10014, 10015) and every other unenumerated
command keep the hardware-root refusal FF FF FF FF. PMS (4001-4005) and its
unsupported siblings (4006, 4007, 13xxx) are unchanged.

### Forward compatibility

- Segments are 16 KB-aligned (-z max-page-size=16384), so the binary also
  loads on 16 KB-page kernels (Android 15+). No effect on today's 4 KB kernel.
- Dependencies: libbinder_ndk, liblog, libc, libm, libdl only (all LLNDK);
  libc++ is static. Target API 34; runs on 34 and later (live: Android 16, SDK 36).
- AIDL V1 with the frozen hash. A later V2 client must check
  getInterfaceVersion(), which reports 1.
- Widevine support (cmd 59) accepts any of /vendor/lib64/liboemcrypto.so, the
  Widevine APEX DRM service, or a vendor Widevine DRM service. Android 16 here
  already serves Widevine from the APEX.
- Store format PMS1 is versioned by its magic, written atomically
  (tmp + fsync + rename + directory fsync), and fails closed when corrupt. It
  lives in /data, so it survives ROM updates that do not wipe data.

What an update CAN break, and the code cannot prevent: an OTA or repack that
replaces /odm without these files, a new framework compatibility matrix that
requires cryptoeng V2, or an enforcing build without the hal_cryptoeng_oplus
policy. Re-apply install/ and sepolicy/ after each repack.

### Version evidence (measured 2026-10-13)

- Interface identity equals the stock OnePlus 13 service
  (MIO-KITCHEN-4.2.1-win/oneplus13/odm): descriptor
  vendor.oplus.hardware.cryptoeng.ICryptoeng, frozen hash
  765136eb397eb5b85ee1e089d8fec72c15e266b3, one method
  cryptoeng_invoke_command, AIDL V1 "default" in VINTF, init service
  hal_cryptoeng_oplus at the same path, class hal, user system. The stock binary
  needs QSEECom/keymaster/soter/GP-TEE libraries and the OnePlus-signed
  secure_ta/cryptoeng TA, which cannot load on this TrustZone.
- Imports: 180; all 180 resolve against the device's Android 16 libraries;
  176 are public NDK symbols at every API level 29-35 (Android 10-15); the other
  4 are the LLNDK vendor-HAL entry points (ABinderProcess_joinThreadPool,
  ABinderProcess_setThreadPoolMaxThreadCount, AIBinder_markVintfStability,
  AServiceManager_addService).
- Builds with NDK r26d / API 34 (shipping) and NDK r29 / API 35, both -Werror.
  NDK r29 no longer ships the header-only C++ binder helpers the AIDL stubs use;
  they are vendored unmodified in third_party/libbinder_ndk_cpp.
- Contract test on the device: 103 passed, 0 failed for both builds, including
  4 threads x 25 rounds of verify / GET_INFO / PKI on one HAL object.

Not testable here: a running Android 17+ system. The evidence above is symbol-,
toolchain- and protocol-level.

### Live verification on the device (2026-10-13)

Deployed by bind mount over the /odm binary (backup, restart, store
byte-compare). Running as u:r:hal_cryptoeng_oplus:s0, user system.
- Weather: cmd 10009 -> "not supported" (10045) -> SDK software path ->
  "request city from net success" (it failed with "signature check failed"
  and errorCode 204 before).
- Privacy password: enroll, correct password "match", wrong password "reject".
- GET_INFO probe: recovery email present, masked response valid.
- service.cpp now starts the binder thread pool before addService; the
  "startThreadPool was not called" warning is gone.

Binary SHA256 (NDK r26d build, shipped and running):
22da1309ff57d92a870e6e700d359c9083e3dab0cc5edc00ac177ec9e7febcaa.
