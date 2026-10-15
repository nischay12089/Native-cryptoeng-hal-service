// Compat.h - dual-mode support layer.
//
// This tree must build two ways:
//
//   1. Inside an AOSP / OxygenOS tree, where libbase and the aidl-generated
//      stubs exist. That is the shipping build.
//   2. Standalone against a plain Android NDK, which is all that is available
//      on this workstation. libbase is AOSP-internal and is NOT in the NDK, so
//      every android-base/* include would fail.
//
// So we detect libbase with __has_include and, when it is absent, provide the
// same small slice of its API on top of POSIX + liblog + libc system
// properties. The HAL sources then compile unchanged in both modes.

#pragma once

#if defined(__has_include)
#  if __has_include(<android-base/logging.h>)
#    define OPLUS_COMPAT_HAVE_LIBBASE 1
#  endif
#endif

#ifdef OPLUS_COMPAT_HAVE_LIBBASE

#include <android-base/file.h>
#include <android-base/logging.h>
#include <android-base/properties.h>
#include <android-base/stringprintf.h>
#include <android-base/strings.h>

#else  // ---------------------------- NDK standalone ----------------------------

#include <android/log.h>
#include <sys/system_properties.h>
#include <unistd.h>
#include <fcntl.h>

#include <cstdarg>
#include <cstdio>
#include <atomic>
#include <cstring>
#include <sstream>
#include <string>
#include <vector>

#ifndef OPLUS_COMPAT_LOG_TAG
#define OPLUS_COMPAT_LOG_TAG "oplus_compat"
#endif

namespace oplus_compat_log {

// Minimal ostream-style logger that mimics libbase's LOG(SEVERITY) << ... form.
class LogMessage {
  public:
    LogMessage(int prio, const char* file, int line) : prio_(prio) {
        const char* base = std::strrchr(file, '/');
#ifdef _WIN32
        const char* base2 = std::strrchr(file, '\\');
        if (base2 > base) base = base2;
#endif
        os_ << (base ? base + 1 : file) << ':' << line << ": ";
    }
    ~LogMessage() {
        __android_log_print(prio_, OPLUS_COMPAT_LOG_TAG, "%s", os_.str().c_str());
        // LOG(FATAL) must terminate, exactly as libbase does. Without this a
        // fatal error (e.g. a failed service registration) would be logged and
        // then execution would carry on into a broken state -- which is how an
        // earlier build ended up logging "registered" right after a failure.
        if (prio_ == ANDROID_LOG_FATAL) {
            __android_log_print(ANDROID_LOG_FATAL, OPLUS_COMPAT_LOG_TAG,
                                "aborting due to LOG(FATAL)");
            abort();
        }
    }
    std::ostream& stream() { return os_; }

  private:
    int prio_;
    std::ostringstream os_;
};

}  // namespace oplus_compat_log

// Severity names match libbase so call sites are identical.
#define OPLUS_SEV_VERBOSE ANDROID_LOG_VERBOSE
#define OPLUS_SEV_DEBUG   ANDROID_LOG_DEBUG
#define OPLUS_SEV_INFO    ANDROID_LOG_INFO
#define OPLUS_SEV_WARNING ANDROID_LOG_WARN
#define OPLUS_SEV_ERROR   ANDROID_LOG_ERROR
#define OPLUS_SEV_FATAL   ANDROID_LOG_FATAL

#define LOG(sev) \
    ::oplus_compat_log::LogMessage(OPLUS_SEV_##sev, __FILE__, __LINE__).stream()

namespace android {
namespace base {

inline bool ReadFileToString(const std::string& path, std::string* out) {
    int fd = ::open(path.c_str(), O_RDONLY | O_CLOEXEC);
    if (fd < 0) return false;
    out->clear();
    char buf[4096];
    ssize_t n;
    while ((n = ::read(fd, buf, sizeof(buf))) > 0) out->append(buf, static_cast<size_t>(n));
    int saved = errno;
    ::close(fd);
    if (n < 0) { errno = saved; return false; }
    return true;
}

inline std::string Trim(const std::string& s) {
    size_t b = 0, e = s.size();
    while (b < e && std::isspace(static_cast<unsigned char>(s[b]))) ++b;
    while (e > b && std::isspace(static_cast<unsigned char>(s[e - 1]))) --e;
    return s.substr(b, e - b);
}

inline std::vector<std::string> Split(const std::string& s, const std::string& delims) {
    std::vector<std::string> out;
    size_t start = 0;
    while (start <= s.size()) {
        size_t pos = s.find_first_of(delims, start);
        if (pos == std::string::npos) {
            out.push_back(s.substr(start));
            break;
        }
        out.push_back(s.substr(start, pos - start));
        start = pos + 1;
    }
    return out;
}

inline std::string StringPrintf(const char* fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    char stackbuf[512];
    va_list ap2;
    va_copy(ap2, ap);
    int n = vsnprintf(stackbuf, sizeof(stackbuf), fmt, ap2);
    va_end(ap2);
    std::string out;
    if (n >= 0 && static_cast<size_t>(n) < sizeof(stackbuf)) {
        out.assign(stackbuf, static_cast<size_t>(n));
    } else if (n >= 0) {
        out.resize(static_cast<size_t>(n) + 1);
        vsnprintf(&out[0], out.size(), fmt, ap);
        out.resize(static_cast<size_t>(n));
    }
    va_end(ap);
    return out;
}

inline bool ParseInt(const std::string& s, int32_t* out) {
    errno = 0;
    char* end = nullptr;
    long v = std::strtol(s.c_str(), &end, 10);
    if (errno != 0 || end == s.c_str()) return false;
    *out = static_cast<int32_t>(v);
    return true;
}

inline std::string GetProperty(const std::string& key, const std::string& def) {
    char buf[PROP_VALUE_MAX] = {};
    int n = __system_property_get(key.c_str(), buf);
    if (n <= 0) return def;
    return std::string(buf, static_cast<size_t>(n));
}

inline bool GetBoolProperty(const std::string& key, bool def) {
    const std::string v = GetProperty(key, "");
    if (v.empty()) return def;
    if (v == "1" || v == "true" || v == "y" || v == "yes" || v == "on") return true;
    if (v == "0" || v == "false" || v == "n" || v == "no" || v == "off") return false;
    return def;
}

// libbase provides this as a logger init hook; standalone it is a no-op because
// __android_log_print already goes to logd.
struct LogdLogger {
    void operator()(int, int, const char*, const char*, unsigned int, const char*) const {}
};
inline void InitLogging(char**, LogdLogger = LogdLogger()) {}

}  // namespace base
}  // namespace android

#endif  // OPLUS_COMPAT_HAVE_LIBBASE

#include <atomic>

// Log a line at most once per call site, for the lifetime of the process.
//
// These HALs front interfaces with a lot of methods whose backing kernel ABI
// does not exist here, and the framework calls some of them continuously --
// setSchedAssistScene fires on every UI scene change. Logging "unmapped" on
// every call buries everything else in logcat. The first occurrence carries all
// the diagnostic value; the ten thousandth carries none.
//
// The static is initialised once (guaranteed thread-safe since C++11) and the
// exchange makes the body run exactly once even with concurrent binder threads.
#define LOG_ONCE(sev)                                     \
    for (static std::atomic<bool> _oplus_log_once{false}; \
         !_oplus_log_once.exchange(true);)                \
    LOG(sev)
