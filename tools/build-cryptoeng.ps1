param([switch]$Tests, [string]$Ndk = "$env:LOCALAPPDATA\Android\Sdk\ndk\26.3.11579264")
$ErrorActionPreference = 'Stop'
Push-Location (Join-Path $PSScriptRoot '..')
try {
    New-Item -ItemType Directory -Force -Path out | Out-Null
    $cc = Join-Path $Ndk 'toolchains\llvm\prebuilt\windows-x86_64\bin\clang++.exe'
    $flags = @('--target=aarch64-linux-android34', '-std=c++17', '-O2', '-Wall', '-Wextra', '-Werror',
        '-Ithird_party/libbinder_ndk_cpp/include', '-Indkstubs', '-Icommon', '-static-libstdc++', '-fstack-protector-strong', '-Wl,-z,relro,-z,now',
        # 16 KB-page kernels (Android 15+) need 16 KB-aligned segments; harmless on 4 KB.
        '-Wl,-z,max-page-size=16384')
    # Link-only libbinder_ndk/liblog carrying the LL-NDK entry points and symbol
    # versions the NDK stubs lack; the device's own libraries are used at run time.
    New-Item -ItemType Directory -Force -Path out/stubs | Out-Null
    foreach ($lib in 'libbinder_ndk', 'liblog') {
        & (Join-Path $Ndk 'toolchains\llvm\prebuilt\windows-x86_64\bin\clang.exe') --target=aarch64-linux-android34 `
            -shared -nostdlib "-Wl,-soname,$lib.so" "-Wl,--version-script=tools/stubs/$lib.map.txt" `
            "tools/stubs/$lib.c" -o "out/stubs/$lib.so"
        if ($LASTEXITCODE) { throw "$lib stub build failed: $LASTEXITCODE" }
    }
    $sources = @('cryptoeng/CryptoengHal.cpp', 'ndkstubs/aidl/vendor/oplus/hardware/cryptoeng/ICryptoeng.cpp')
    $libs = @('-Lout/stubs', '-lbinder_ndk', '-llog')
    & $cc @flags @sources cryptoeng/service.cpp @libs -o 'out/vendor.oplus.hardware.cryptoeng@1.0-service'
    if ($LASTEXITCODE) { throw "HAL build failed: $LASTEXITCODE" }
    if ($Tests) {
        & $cc @flags @sources cryptoeng/tests/PmsTest.cpp @libs -o out/cryptoeng_contract_test
        if ($LASTEXITCODE) { throw "Contract test build failed: $LASTEXITCODE" }
        & $cc @flags ndkstubs/aidl/vendor/oplus/hardware/cryptoeng/ICryptoeng.cpp cryptoeng/tests/EmailReadbackProbe.cpp @libs -o out/cryptoeng_email_probe
        if ($LASTEXITCODE) { throw "Read-only email probe build failed: $LASTEXITCODE" }
    }
    Get-Item 'out/vendor.oplus.hardware.cryptoeng@1.0-service' | Select-Object Name,Length
} finally { Pop-Location }
