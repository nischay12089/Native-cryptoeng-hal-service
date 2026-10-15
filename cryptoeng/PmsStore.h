// Compatible PMS1 storage. The legacy XOR mask is obfuscation, not encryption.
// An unreadable/corrupt file must never be treated as an empty enrollment.
#pragma once
#include "../common/Sha256.h"
#include <cerrno>
#include <cstdio>
#include <fcntl.h>
#include <map>
#include <string>
#include <sys/stat.h>
#include <unistd.h>
#include <vector>

namespace oplus_compat {
struct PmsRecord {
    int32_t quality = 0;
    std::vector<uint8_t> pwd, sec;
    std::map<uint32_t, std::vector<uint8_t>> extra;
};
// Access serialized by CryptoengHal::lock_. Tests supply a private path.
class PmsStore {
 public:
    PmsStore(std::array<uint8_t, 32> seed, std::string path)
        : seed_(seed), path_(std::move(path)) { ready_ = Load(); }
    bool Ready() const { return ready_; }
    PmsRecord Get(int32_t type) const {
        auto it = recs_.find(type);
        return it == recs_.end() ? PmsRecord{} : it->second;
    }
    bool Put(int32_t type, const PmsRecord& record) {
        auto next = recs_; next[type] = record;
        bool ok = Commit(next); if (!ok) ready_ = false; return ok;
    }
    bool Erase(int32_t type) {
        auto next = recs_; next.erase(type);
        bool ok = Commit(next); if (!ok) ready_ = false; return ok;
    }
 private:
    using Records = std::map<int32_t, PmsRecord>;
    static constexpr size_t kMaxFile = 1u << 20;
    void Mask(std::vector<uint8_t>& p) const {
        for (size_t off = 0; off < p.size(); off += 32) {
            uint32_t ctr = off / 32;
            uint8_t c[4] = {uint8_t(ctr >> 24), uint8_t(ctr >> 16), uint8_t(ctr >> 8), uint8_t(ctr)};
            auto block = HmacSha256(seed_.data(), seed_.size(), c, sizeof c);
            for (size_t i = 0; i < block.size() && off + i < p.size(); ++i) p[off+i] ^= block[i];
        }
    }
    static void U32(std::vector<uint8_t>& p, uint32_t v) {
        p.insert(p.end(), {uint8_t(v >> 24), uint8_t(v >> 16), uint8_t(v >> 8), uint8_t(v)});
    }
    bool Commit(const Records& next) {
        if (!ready_) return false;
        std::vector<uint8_t> p;
        U32(p, 0x504d5331); U32(p, next.size());
        auto blob = [&](const std::vector<uint8_t>& b) {
            U32(p, b.size()); p.insert(p.end(), b.begin(), b.end());
        };
        for (const auto& [type, r] : next) {
            U32(p, type); U32(p, r.quality); blob(r.pwd); blob(r.sec); U32(p, r.extra.size());
            for (const auto& [key, data] : r.extra) { U32(p, key); blob(data); }
        }
        if (p.size() > kMaxFile) return false;
        Mask(p);
        // Parent is created and labeled by init, not by the system-UID HAL.
        const std::string parent = path_.substr(0, path_.find_last_of('/'));
        int dir = open(parent.c_str(), O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
        if (dir < 0) return false;
        const std::string tmp = path_ + ".tmp";
        int fd = open(tmp.c_str(), O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW, 0600);
        if (fd < 0 && errno == EEXIST && unlink(tmp.c_str()) == 0)
            fd = open(tmp.c_str(), O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW, 0600);
        if (fd < 0) { close(dir); return false; }
        size_t off = 0;
        while (off < p.size()) {
            ssize_t n = write(fd, p.data() + off, p.size() - off);
            if (n < 0 && errno == EINTR) continue;
            if (n <= 0) break;
            off += size_t(n);
        }
        bool ok = off == p.size() && fsync(fd) == 0;
        if (close(fd) != 0) ok = false;
        if (ok) ok = rename(tmp.c_str(), path_.c_str()) == 0;
        if (!ok) { unlink(tmp.c_str()); close(dir); return false; }
        recs_ = next; // Rename committed; memory must match even on directory fsync failure.
        ok = fsync(dir) == 0;
        close(dir);
        if (!ok) ready_ = false;
        return ok;
    }
    bool Load() {
        int fd = open(path_.c_str(), O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
        if (fd < 0) return errno == ENOENT;
        struct stat st{};
        if (fstat(fd, &st) || !S_ISREG(st.st_mode) || st.st_size < 8 || uint64_t(st.st_size) > kMaxFile) {
            close(fd); return false;
        }
        std::vector<uint8_t> p(size_t(st.st_size));
        size_t got = 0;
        while (got < p.size()) {
            ssize_t n = read(fd, p.data() + got, p.size() - got);
            if (n < 0 && errno == EINTR) continue;
            if (n <= 0) break;
            got += size_t(n);
        }
        close(fd);
        if (got != p.size()) return false;
        Mask(p);
        size_t off = 0;
        auto word = [&](uint32_t& v) {
            if (p.size() - off < 4) return false;
            v = (uint32_t(p[off]) << 24) | (uint32_t(p[off+1]) << 16) |
                (uint32_t(p[off+2]) << 8) | p[off+3];
            off += 4; return true;
        };
        auto blob = [&](std::vector<uint8_t>& b) {
            uint32_t size;
            if (!word(size) || size > p.size() - off) return false;
            b.assign(p.begin() + off, p.begin() + off + size); off += size; return true;
        };
        uint32_t magic, count;
        if (!word(magic) || magic != 0x504d5331 || !word(count) || count > 64) return false;
        Records next;
        for (uint32_t i = 0; i < count; ++i) {
            uint32_t type, quality, extras; PmsRecord r;
            if (!word(type) || !word(quality) || !blob(r.pwd) || !blob(r.sec) ||
                !word(extras) || extras > 128 || next.count(type)) return false;
            r.quality = int32_t(quality);
            for (uint32_t j = 0; j < extras; ++j) {
                uint32_t key; std::vector<uint8_t> b;
                if (!word(key) || !blob(b) || r.extra.count(key)) return false;
                r.extra[key] = std::move(b);
            }
            next[type] = std::move(r);
        }
        if (off != p.size()) return false;
        recs_ = std::move(next); return true;
    }
    std::array<uint8_t, 32> seed_;
    std::string path_;
    Records recs_;
    bool ready_ = false;
};
} // namespace oplus_compat
