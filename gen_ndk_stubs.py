#!/usr/bin/env python3
"""
Emit AIDL NDK-backend C++ stubs (I<Name>.h / I<Name>.cpp) from a reconstructed
.aidl, WITHOUT AOSP's `aidl` compiler.

The aidl compiler is an AOSP host tool and is not in the NDK, but everything it
emits for the NDK backend is mechanical and the NDK ships the runtime it targets
(binder_interface_utils.h, binder_auto_utils.h, binder_parcel_utils.h). The
output mirrors what AOSP generates, so hand-written HAL classes compile
unchanged against either.

Wire compatibility is the point:
  * transaction codes = 1-based declaration order (the .aidl files are emitted
    in recovered TRANSACTION_ / proxy-opcode order);
  * `oneway` methods write no reply and are sent with FLAG_ONEWAY;
  * parcelables use the stable-AIDL framing (int32 total size, fields, then
    skip to start+size), field order taken from the .aidl file;
  * binders are marked VINTF stability, as AOSP does for @VintfStability.
    Without that, a service started from /odm or /vendor links the vendor
    libbinder, its binder gets VENDOR stability, and system_server's calls are
    rejected with "Cannot do a user transaction on a vendor stability binder".

Parcelables and enums are read from sibling .aidl files in the same package
directory. A type that cannot be resolved is emitted as an opaque class whose
(de)serialisation fails, and every method using it is refused with
STATUS_UNKNOWN_TRANSACTION: mis-parsing a parcel corrupts every later read.

Usage: python gen_ndk_stubs.py <iface.aidl> <out-dir> [version] [frozen-hash]
"""
import os
import re
import sys

PRIM = {
    'void': 'void', 'boolean': 'bool', 'byte': 'int8_t', 'char': 'char16_t',
    'int': 'int32_t', 'long': 'int64_t', 'float': 'float', 'double': 'double',
    'String': 'std::string',
}
BY_VALUE = {'boolean', 'byte', 'char', 'int', 'long', 'float', 'double'}


# ------------------------------------------------------------------ parsing ---
def strip_comments(src):
    src = re.sub(r'/\*.*?\*/', '', src, flags=re.S)
    return re.sub(r'//[^\n]*', '', src)


def parse_decl_file(path):
    """Parse one .aidl file: interface, parcelable or enum."""
    src = strip_comments(open(path, encoding='utf-8').read())
    pkg = re.search(r'\bpackage\s+([\w.]+)\s*;', src).group(1)
    m = re.search(r'\binterface\s+(\w+)\s*\{(.*)\}', src, re.S)
    if m:
        methods = []
        for mm in re.finditer(r'(oneway\s+)?([\w.<>\[\]]+)\s+(\w+)\s*\(([^)]*)\)\s*;',
                              m.group(2)):
            params = []
            for a in [x.strip() for x in mm.group(4).split(',') if x.strip()]:
                a = re.sub(r'^(in|out|inout)\s+', '', a)
                ty, nm = a.rsplit(None, 1)
                params.append((ty.strip(), nm.strip()))
            methods.append({'oneway': bool(mm.group(1)), 'ret': mm.group(2),
                            'name': mm.group(3), 'params': params})
        return {'kind': 'interface', 'pkg': pkg, 'name': m.group(1), 'methods': methods}
    m = re.search(r'\bparcelable\s+(\w+)\s*\{(.*)\}', src, re.S)
    if m:
        fields = [(fm.group(1), fm.group(2)) for fm in
                  re.finditer(r'([\w.<>\[\]]+)\s+(\w+)\s*(?:=[^;]*)?;', m.group(2))]
        return {'kind': 'parcelable', 'pkg': pkg, 'name': m.group(1), 'fields': fields}
    m = re.search(r'\benum\s+(\w+)\s*\{(.*)\}', src, re.S)
    if m:
        backing = re.search(r'@Backing\s*\(\s*type\s*=\s*"(\w+)"', src)
        values = re.findall(r'(\w+)\s*=\s*([-\w]+)', m.group(2))
        return {'kind': 'enum', 'pkg': pkg, 'name': m.group(1),
                'backing': backing.group(1) if backing else 'byte', 'values': values}
    return None


class Types:
    """Resolves type names against the .aidl files in the interface's package."""

    def __init__(self, pkg_dir):
        self.decls = {}
        for fn in sorted(os.listdir(pkg_dir)):
            if fn.endswith('.aidl'):
                d = parse_decl_file(os.path.join(pkg_dir, fn))
                if d:
                    self.decls[d['name']] = d

    def base(self, t):
        return t[:-2] if t.endswith('[]') else t

    def kind(self, t):
        b = self.base(t)
        if b in PRIM:
            return 'prim'
        d = self.decls.get(b)
        if d:
            return d['kind']
        if len(b) > 1 and b[0] == 'I' and b[1].isupper():
            return 'interface'  # not in this package: still a binder
        return 'opaque'

    def known(self, t):
        return self.kind(t) != 'opaque' and all(
            self.known(ft) for ft, _ in self.decls.get(self.base(t), {}).get('fields', []))

    def cpp(self, t):
        if t == 'byte[]':
            # AOSP's NDK backend maps byte[] to vector<uint8_t> (a lone byte stays
            # int8_t); the NDK only has parcel overloads for that element type.
            return 'std::vector<uint8_t>'
        if t.endswith('[]'):
            return 'std::vector<%s>' % self.cpp(t[:-2])
        if t in PRIM:
            return PRIM[t]
        if self.kind(t) == 'interface':
            return 'std::shared_ptr<%s>' % t
        return t

    def param(self, t, nm):
        if t in BY_VALUE or self.kind(t) == 'enum':
            return '%s %s' % (self.cpp(t), nm)
        return 'const %s& %s' % (self.cpp(t), nm)

    def referenced(self, t, seen):
        """Collect package-local parcelable/enum declarations t depends on."""
        b = self.base(t)
        d = self.decls.get(b)
        if not d or d['kind'] not in ('parcelable', 'enum') or b in seen:
            return
        for ft, _ in d.get('fields', []):
            self.referenced(ft, seen)
        seen[b] = d  # dependency-first order


# ------------------------------------------------------------------ codegen ---
def gen_enum(d):
    backing = {'byte': 'int8_t', 'int': 'int32_t', 'long': 'int64_t'}[d['backing']]
    out = ['enum class %s : %s {' % (d['name'], backing)]
    out += ['    %s = %s,' % v for v in d['values']]
    out += ['};', '']
    return out


def gen_parcelable_h(d, ty):
    out = ['class %s {' % d['name'], '  public:',
           '    typedef std::false_type fixed_size;',
           '    static inline const char* descriptor = "%s.%s";' % (d['pkg'], d['name']), '']
    for ft, fn in d['fields']:
        init = '' if (ft.endswith('[]') or ft == 'String' or ty.kind(ft) == 'parcelable') else ' = {}'
        out.append('    %s %s%s;' % (ty.cpp(ft), fn, init))
    out += ['',
            '    binder_status_t readFromParcel(const AParcel* _parcel);',
            '    binder_status_t writeToParcel(AParcel* _parcel) const;',
            '    static const ::ndk::parcelable_stability_t _aidl_stability = ::ndk::STABILITY_VINTF;',
            '};', '']
    return out


def gen_parcelable_cpp(d, pkg):
    n = d['name']
    out = ['inline binder_status_t %s::readFromParcel(const AParcel* _parcel) {' % n,
           '    binder_status_t st = STATUS_OK;',
           '    int32_t _start = AParcel_getDataPosition(_parcel);',
           '    int32_t _size = 0;',
           '    st = AParcel_readInt32(_parcel, &_size);',
           '    if (st != STATUS_OK) return st;',
           '    if (_size < 4) return STATUS_BAD_VALUE;',
           '    if (_start > INT32_MAX - _size) return STATUS_BAD_VALUE;']
    for _ft, fn in d['fields']:
        out += ['    if (AParcel_getDataPosition(_parcel) - _start >= _size) {',
                '        AParcel_setDataPosition(_parcel, _start + _size);',
                '        return STATUS_OK;',
                '    }',
                '    st = ::ndk::AParcel_readData(_parcel, &%s);' % fn,
                '    if (st != STATUS_OK) return st;']
    out += ['    AParcel_setDataPosition(_parcel, _start + _size);',
            '    return STATUS_OK;', '}', '',
            'inline binder_status_t %s::writeToParcel(AParcel* _parcel) const {' % n,
            '    binder_status_t st = STATUS_OK;',
            '    int32_t _start = AParcel_getDataPosition(_parcel);',
            '    st = AParcel_writeInt32(_parcel, 0);',
            '    if (st != STATUS_OK) return st;']
    for _ft, fn in d['fields']:
        out += ['    st = ::ndk::AParcel_writeData(_parcel, %s);' % fn,
                '    if (st != STATUS_OK) return st;']
    out += ['    int32_t _end = AParcel_getDataPosition(_parcel);',
            '    AParcel_setDataPosition(_parcel, _start);',
            '    AParcel_writeInt32(_parcel, _end - _start);',
            '    AParcel_setDataPosition(_parcel, _end);',
            '    return STATUS_OK;', '}', '']
    return out


def write_type_header(outdir, name, deps, ns_open, ns_close, body):
    h = ['// GENERATED by gen_ndk_stubs.py -- do not edit.', '#pragma once', '',
         '#include <android/binder_parcel_utils.h>', '#include <android/binder_parcelable_utils.h>',
         '#include <android/binder_status.h>', '',
         '#include <climits>', '#include <cstdint>', '#include <string>',
         '#include <type_traits>', '#include <vector>', '']
    h += ['#include "%s.h"' % d for d in deps]
    h += ['', ns_open, ''] + body + [ns_close, '']
    open(os.path.join(outdir, name + '.h'), 'w', encoding='utf-8').write('\n'.join(h))


def main():
    aidl, outroot = sys.argv[1], sys.argv[2]
    version = int(sys.argv[3]) if len(sys.argv) > 3 else 1
    frozen = sys.argv[4] if len(sys.argv) > 4 else 'notfrozen'
    iface = parse_decl_file(aidl)
    assert iface and iface['kind'] == 'interface', aidl
    ty = Types(os.path.dirname(aidl))
    pkg, iname, methods = iface['pkg'], iface['name'], iface['methods']
    ns_parts = ['aidl'] + pkg.split('.')
    ns_open = ' '.join('namespace %s {' % p for p in ns_parts)
    ns_close = '}' * len(ns_parts) + '  // namespace ' + '::'.join(ns_parts)
    bn, bp = 'Bn' + iname[1:], 'Bp' + iname[1:]
    outdir = os.path.join(outroot, 'aidl', *pkg.split('.'))
    os.makedirs(outdir, exist_ok=True)

    def usable(m):
        return all(ty.known(t) for t in [m['ret']] + [p[0] for p in m['params']])

    decls, opaque, iface_refs = {}, set(), set()
    for m in methods:
        for t in [m['ret']] + [p[0] for p in m['params']]:
            k = ty.kind(t)
            if k in ('parcelable', 'enum'):
                ty.referenced(t, decls)
            elif k == 'opaque':
                opaque.add(ty.base(t))
            elif k == 'interface' and ty.base(t) != iname:
                iface_refs.add(ty.base(t))

    # ----------------------------------------------------------------- header
    h = ['// GENERATED by gen_ndk_stubs.py from %s -- do not edit.' % os.path.basename(aidl),
         '#pragma once', '',
         '#include <android/binder_auto_utils.h>',
         '#include <android/binder_ibinder.h>',
         '#include <android/binder_interface_utils.h>',
         '#include <android/binder_parcel_utils.h>',
         '#include <android/binder_status.h>', '',
         '#include <cstdint>', '#include <memory>', '#include <string>',
         '#include <type_traits>', '#include <vector>', '']
    # Each parcelable / enum / opaque type gets its own header (as AOSP does), so
    # two interfaces of one package that both use a type can include each other.
    type_headers = []
    for name, d in decls.items():
        deps = sorted({ty.base(ft) for ft, _ in d.get('fields', [])
                       if ty.kind(ft) in ('parcelable', 'enum')})
        body = gen_enum(d) if d['kind'] == 'enum' else gen_parcelable_h(d, ty) + gen_parcelable_cpp(d, pkg)
        write_type_header(outdir, name, deps, ns_open, ns_close, body)
        type_headers.append(name)
    for o in sorted(opaque):
        body = ['// Layout NOT recovered: refused on the wire rather than misparsed.',
                'class %s {' % o, '  public:',
                '    binder_status_t readFromParcel(const AParcel*) { return STATUS_BAD_VALUE; }',
                '    binder_status_t writeToParcel(AParcel*) const { return STATUS_BAD_VALUE; }',
                '};', '']
        write_type_header(outdir, o, [], ns_open, ns_close, body)
        type_headers.append(o)
    h += ['#include "%s.h"' % r for r in sorted(set(type_headers) | iface_refs)]
    h += ['', ns_open, '']

    def sig(m, qualified=None):
        ps = [ty.param(t, 'in_' + nm) for t, nm in m['params']]
        if m['ret'] != 'void':
            ps.append('%s* _aidl_return' % ty.cpp(m['ret']))
        return '::ndk::ScopedAStatus %s%s(%s)' % (qualified + '::' if qualified else '',
                                                 m['name'], ', '.join(ps))

    h += ['class %s;' % bp, '',
          'class %s : public ::ndk::ICInterface {' % iname, '  public:',
          '    static const char* descriptor;',
          '    %s();' % iname, '    virtual ~%s();' % iname, '']
    h += ['    static constexpr uint32_t TRANSACTION_%s = FIRST_CALL_TRANSACTION + %d;'
          % (m['name'], i) for i, m in enumerate(methods)]
    h += ['',
          '    // Frozen hash of the upstream interface when known (clients may',
          '    // compare it); "notfrozen" otherwise.',
          '    static inline const int32_t version = %d;' % version,
          '    static inline const std::string hash = "%s";' % frozen, '',
          '    static std::shared_ptr<%s> fromBinder(const ::ndk::SpAIBinder& binder);' % iname, '']
    h += ['    virtual %s = 0;' % sig(m) for m in methods]
    h += ['    virtual ::ndk::ScopedAStatus getInterfaceVersion(int32_t* _aidl_return);',
          '    virtual ::ndk::ScopedAStatus getInterfaceHash(std::string* _aidl_return);',
          '};', '',
          'class %s : public ::ndk::BnCInterface<%s> {' % (bn, iname), '  public:',
          '    %s();' % bn, '    virtual ~%s();' % bn, '',
          '  protected:', '    ::ndk::SpAIBinder createBinder() override;', '};', '',
          'class %s : public ::ndk::BpCInterface<%s> {' % (bp, iname), '  public:',
          '    explicit %s(const ::ndk::SpAIBinder& binder);' % bp,
          '    virtual ~%s();' % bp, '']
    h += ['    %s override;' % sig(m) for m in methods]
    h += ['};', '', ns_close]
    open(os.path.join(outdir, iname + '.h'), 'w', encoding='utf-8').write('\n'.join(h) + '\n')

    # ------------------------------------------------------------------- impl
    c = ['// GENERATED by gen_ndk_stubs.py from %s -- do not edit.' % os.path.basename(aidl),
         '#include "%s.h"' % iname, '',
         '#include <android/binder_parcel.h>', '',
         '#include <climits>', '',
         '#include "BinderPlatform.h"  // AIBinder_markVintfStability', '',
         ns_open, '']

    c += ['const char* %s::descriptor = "%s.%s";' % (iname, pkg, iname),
          '%s::%s() {}' % (iname, iname), '%s::~%s() {}' % (iname, iname), '',
          '::ndk::ScopedAStatus %s::getInterfaceVersion(int32_t* _aidl_return) {' % iname,
          '    *_aidl_return = version;', '    return ::ndk::ScopedAStatus::ok();', '}',
          '::ndk::ScopedAStatus %s::getInterfaceHash(std::string* _aidl_return) {' % iname,
          '    *_aidl_return = hash;', '    return ::ndk::ScopedAStatus::ok();', '}', '',
          'static binder_status_t _aidl_onTransact(AIBinder* _aidl_binder, transaction_code_t _aidl_code,',
          '                                        const AParcel* _aidl_in, AParcel* _aidl_out);',
          'static AIBinder_Class* _aidl_clazz() {',
          '    static AIBinder_Class* c = ::ndk::ICInterface::defineClass(%s::descriptor, _aidl_onTransact);' % iname,
          '    return c;', '}', '',
          'static binder_status_t _aidl_onTransact(AIBinder* _aidl_binder, transaction_code_t _aidl_code,',
          '                                        const AParcel* _aidl_in, AParcel* _aidl_out) {',
          '    binder_status_t st = STATUS_UNKNOWN_TRANSACTION;',
          '    std::shared_ptr<%s> _aidl_impl = std::static_pointer_cast<%s>(' % (bn, bn),
          '        ::ndk::ICInterface::asInterface(_aidl_binder));',
          '    if (_aidl_impl == nullptr) return STATUS_DEAD_OBJECT;',
          '    switch (_aidl_code) {']
    refused = []
    for i, m in enumerate(methods):
        c.append('        case (FIRST_CALL_TRANSACTION + %d): {  // %s%s'
                 % (i, m['name'], ' (oneway)' if m['oneway'] else ''))
        if not usable(m):
            refused.append(m['name'])
            c += ['            // uses a type whose layout was not recovered', '            break;', '        }']
            continue
        args = []
        for t, nm in m['params']:
            if ty.kind(t) == 'interface':
                c += ['            ::ndk::SpAIBinder _b_%s;' % nm,
                      '            st = ::ndk::AParcel_readNullableStrongBinder(_aidl_in, &_b_%s);' % nm,
                      '            if (st != STATUS_OK) break;',
                      '            std::shared_ptr<%s> in_%s = _b_%s.get() == nullptr ? nullptr : %s::fromBinder(_b_%s);'
                      % (t, nm, nm, t, nm)]
            else:
                c += ['            %s in_%s;' % (ty.cpp(t), nm),
                      '            st = ::ndk::AParcel_readData(_aidl_in, &in_%s);' % nm,
                      '            if (st != STATUS_OK) break;']
            args.append('in_' + nm)
        if m['ret'] != 'void':
            c.append('            %s _aidl_return;' % ty.cpp(m['ret']))
            args.append('&_aidl_return')
        c.append('            ::ndk::ScopedAStatus _aidl_status = _aidl_impl->%s(%s);'
                 % (m['name'], ', '.join(args)))
        if m['oneway']:
            c += ['            (void)_aidl_status;', '            st = STATUS_OK;']
        else:
            c += ['            st = AParcel_writeStatusHeader(_aidl_out, _aidl_status.get());',
                  '            if (st != STATUS_OK) break;',
                  '            if (!AStatus_isOk(_aidl_status.get())) break;']
            if m['ret'] != 'void':
                c.append('            st = ::ndk::AParcel_writeData(_aidl_out, _aidl_return);')
        c += ['            break;', '        }']
    c += ['        case (FIRST_CALL_TRANSACTION + 16777214): {  // getInterfaceVersion',
          '            int32_t _aidl_return;',
          '            ::ndk::ScopedAStatus _aidl_status = _aidl_impl->getInterfaceVersion(&_aidl_return);',
          '            st = AParcel_writeStatusHeader(_aidl_out, _aidl_status.get());',
          '            if (st != STATUS_OK || !AStatus_isOk(_aidl_status.get())) break;',
          '            st = ::ndk::AParcel_writeData(_aidl_out, _aidl_return);',
          '            break;', '        }',
          '        case (FIRST_CALL_TRANSACTION + 16777213): {  // getInterfaceHash',
          '            std::string _aidl_return;',
          '            ::ndk::ScopedAStatus _aidl_status = _aidl_impl->getInterfaceHash(&_aidl_return);',
          '            st = AParcel_writeStatusHeader(_aidl_out, _aidl_status.get());',
          '            if (st != STATUS_OK || !AStatus_isOk(_aidl_status.get())) break;',
          '            st = ::ndk::AParcel_writeData(_aidl_out, _aidl_return);',
          '            break;', '        }',
          '    }', '    return st;', '}', '',
          'std::shared_ptr<%s> %s::fromBinder(const ::ndk::SpAIBinder& binder) {' % (iname, iname),
          '    if (!AIBinder_associateClass(binder.get(), _aidl_clazz())) return nullptr;',
          '    std::shared_ptr<::ndk::ICInterface> local = ::ndk::ICInterface::asInterface(binder.get());',
          '    if (local != nullptr) return std::static_pointer_cast<%s>(local);' % iname,
          '    return ::ndk::SharedRefBase::make<%s>(binder);' % bp, '}', '',
          '%s::%s() {}' % (bn, bn), '%s::~%s() {}' % (bn, bn), '',
          '::ndk::SpAIBinder %s::createBinder() {' % bn,
          '    AIBinder* binder = AIBinder_new(_aidl_clazz(), static_cast<void*>(this));',
          '    if (::oplus_compat::g_mark_vintf_stability) AIBinder_markVintfStability(binder);',
          '    return ::ndk::SpAIBinder(binder);', '}', '',
          '%s::%s(const ::ndk::SpAIBinder& binder) : BpCInterface(binder) {}' % (bp, bp),
          '%s::~%s() {}' % (bp, bp), '']
    for i, m in enumerate(methods):
        c.append('%s {' % sig(m, bp))
        if not usable(m):
            c += ['    return ::ndk::ScopedAStatus::fromStatus(STATUS_UNKNOWN_TRANSACTION);', '}', '']
            continue
        c += ['    ::ndk::ScopedAParcel _aidl_in;', '    ::ndk::ScopedAParcel _aidl_out;',
              '    ::ndk::SpAIBinder _b = asBinder();',
              '    binder_status_t st = AIBinder_prepareTransaction(_b.get(), _aidl_in.getR());',
              '    if (st != STATUS_OK) return ::ndk::ScopedAStatus::fromStatus(st);']
        for t, nm in m['params']:
            if ty.kind(t) == 'interface':
                c.append('    st = ::ndk::AParcel_writeNullableStrongBinder(_aidl_in.get(), '
                         'in_%s == nullptr ? ::ndk::SpAIBinder() : in_%s->asBinder());' % (nm, nm))
            else:
                c.append('    st = ::ndk::AParcel_writeData(_aidl_in.get(), in_%s);' % nm)
            c.append('    if (st != STATUS_OK) return ::ndk::ScopedAStatus::fromStatus(st);')
        c.append('    st = AIBinder_transact(_b.get(), FIRST_CALL_TRANSACTION + %d, _aidl_in.getR(), '
                 '_aidl_out.getR(), %s);' % (i, 'FLAG_ONEWAY' if m['oneway'] else '0'))
        c.append('    if (st != STATUS_OK) return ::ndk::ScopedAStatus::fromStatus(st);')
        if m['oneway']:
            c += ['    return ::ndk::ScopedAStatus::ok();', '}', '']
            continue
        c += ['    ::ndk::ScopedAStatus _aidl_status;',
              '    st = AParcel_readStatusHeader(_aidl_out.get(), _aidl_status.getR());',
              '    if (st != STATUS_OK) return ::ndk::ScopedAStatus::fromStatus(st);',
              '    if (!AStatus_isOk(_aidl_status.get())) return _aidl_status;']
        if m['ret'] != 'void':
            c += ['    st = ::ndk::AParcel_readData(_aidl_out.get(), _aidl_return);',
                  '    if (st != STATUS_OK) return ::ndk::ScopedAStatus::fromStatus(st);']
        c += ['    return _aidl_status;', '}', '']
    c.append(ns_close)
    open(os.path.join(outdir, iname + '.cpp'), 'w', encoding='utf-8').write('\n'.join(c) + '\n')
    # AOSP-style Bn/Bp forwarding headers.
    for fwd in (bn, bp):
        open(os.path.join(outdir, fwd + '.h'), 'w', encoding='utf-8').write(
            '// GENERATED forwarding header.\n#pragma once\n#include "%s.h"\n' % iname)

    print('%s v%d: %d methods (%d oneway), %d parcelable/enum types%s'
          % (iname, version, len(methods), sum(m['oneway'] for m in methods), len(decls),
             ('; REFUSED (layout unknown): ' + ', '.join(refused)) if refused else ''))


if __name__ == '__main__':
    main()
