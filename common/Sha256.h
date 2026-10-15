// Minimal SHA-256 + HMAC-SHA256, header-only, no external deps.
//
// cryptoeng needs a keyed derivation but the whole point of the clean build is
// that it links only libbinder_ndk/liblog/libc/libm/libdl, so it survives OS
// updates. libcrypto is not in that set, so the primitive lives here. Public
// FIPS-180-4 / RFC-2104 construction; a known-answer test runs in --selftest.
#pragma once

#include <cstdint>
#include <cstddef>
#include <cstring>
#include <array>
#include <vector>

namespace oplus_compat {

class Sha256 {
  public:
    Sha256() { reset(); }
    void reset() {
        len_ = 0; buflen_ = 0;
        static const uint32_t kInit[8] = {0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
                                          0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19};
        memcpy(h_, kInit, sizeof(h_));
    }
    void update(const uint8_t* p, size_t n) {
        len_ += n;
        while (n) {
            size_t take = 64 - buflen_;
            if (take > n) take = n;
            memcpy(buf_ + buflen_, p, take);
            buflen_ += take; p += take; n -= take;
            if (buflen_ == 64) { block(buf_); buflen_ = 0; }
        }
    }
    std::array<uint8_t, 32> digest() {
        uint64_t bits = len_ * 8;
        uint8_t pad = 0x80;
        update(&pad, 1);
        uint8_t z = 0;
        while (buflen_ != 56) update(&z, 1);
        uint8_t be[8];
        for (int i = 0; i < 8; ++i) be[i] = static_cast<uint8_t>(bits >> (56 - 8 * i));
        update(be, 8);
        std::array<uint8_t, 32> out{};
        for (int i = 0; i < 8; ++i)
            for (int j = 0; j < 4; ++j) out[4 * i + j] = static_cast<uint8_t>(h_[i] >> (24 - 8 * j));
        return out;
    }

  private:
    static uint32_t ror(uint32_t x, int n) { return (x >> n) | (x << (32 - n)); }
    void block(const uint8_t* q) {
        static const uint32_t k[64] = {
            0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
            0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
            0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
            0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
            0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
            0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
            0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
            0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2};
        uint32_t w[64];
        for (int i = 0; i < 16; ++i)
            w[i] = q[4 * i] << 24 | q[4 * i + 1] << 16 | q[4 * i + 2] << 8 | q[4 * i + 3];
        for (int i = 16; i < 64; ++i) {
            uint32_t s0 = ror(w[i - 15], 7) ^ ror(w[i - 15], 18) ^ (w[i - 15] >> 3);
            uint32_t s1 = ror(w[i - 2], 17) ^ ror(w[i - 2], 19) ^ (w[i - 2] >> 10);
            w[i] = w[i - 16] + s0 + w[i - 7] + s1;
        }
        uint32_t v[8];
        memcpy(v, h_, sizeof(v));
        for (int i = 0; i < 64; ++i) {
            uint32_t S1 = ror(v[4], 6) ^ ror(v[4], 11) ^ ror(v[4], 25);
            uint32_t ch = (v[4] & v[5]) ^ (~v[4] & v[6]);
            uint32_t t1 = v[7] + S1 + ch + k[i] + w[i];
            uint32_t S0 = ror(v[0], 2) ^ ror(v[0], 13) ^ ror(v[0], 22);
            uint32_t maj = (v[0] & v[1]) ^ (v[0] & v[2]) ^ (v[1] & v[2]);
            uint32_t t2 = S0 + maj;
            v[7] = v[6]; v[6] = v[5]; v[5] = v[4]; v[4] = v[3] + t1;
            v[3] = v[2]; v[2] = v[1]; v[1] = v[0]; v[0] = t1 + t2;
        }
        for (int i = 0; i < 8; ++i) h_[i] += v[i];
    }
    uint32_t h_[8];
    uint8_t buf_[64];
    size_t buflen_;
    uint64_t len_;
};

inline std::array<uint8_t, 32> HmacSha256(const uint8_t* key, size_t klen,
                                          const uint8_t* msg, size_t mlen) {
    uint8_t k[64] = {0};
    if (klen > 64) {
        Sha256 s; s.update(key, klen);
        auto d = s.digest(); memcpy(k, d.data(), 32);
    } else {
        memcpy(k, key, klen);
    }
    uint8_t ipad[64], opad[64];
    for (int i = 0; i < 64; ++i) { ipad[i] = k[i] ^ 0x36; opad[i] = k[i] ^ 0x5c; }
    Sha256 inner; inner.update(ipad, 64); inner.update(msg, mlen);
    auto ih = inner.digest();
    Sha256 outer; outer.update(opad, 64); outer.update(ih.data(), 32);
    return outer.digest();
}

inline bool Sha256SelfTest() {
    // FIPS-180-4 "abc"
    Sha256 s; s.update(reinterpret_cast<const uint8_t*>("abc"), 3);
    auto d = s.digest();
    static const uint8_t want[32] = {
        0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea, 0x41, 0x41, 0x40, 0xde, 0x5d, 0xae, 0x22, 0x23,
        0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c, 0xb4, 0x10, 0xff, 0x61, 0xf2, 0x00, 0x15, 0xad};
    if (memcmp(d.data(), want, 32) != 0) return false;
    // RFC-4231 test case 2: key "Jefe", data "what do ya want for nothing?"
    auto h = HmacSha256(reinterpret_cast<const uint8_t*>("Jefe"), 4,
                        reinterpret_cast<const uint8_t*>("what do ya want for nothing?"), 28);
    static const uint8_t hw[32] = {
        0x5b, 0xdc, 0xc1, 0x46, 0xbf, 0x60, 0x75, 0x4e, 0x6a, 0x04, 0x24, 0x26, 0x08, 0x95, 0x75, 0xc7,
        0x5a, 0x00, 0x3f, 0x08, 0x9d, 0x27, 0x39, 0x83, 0x9d, 0xec, 0x58, 0xb9, 0x64, 0xec, 0x38, 0x43};
    return memcmp(h.data(), hw, 32) == 0;
}

}  // namespace oplus_compat
