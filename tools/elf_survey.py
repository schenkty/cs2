#!/usr/bin/env python3
"""Survey the ELF import surface of a Linux game install.

Walks a directory (e.g. a Linux CS2 install), parses every x86-64 ELF it
finds with nothing but the standard library, and reports:

  * each module: type, SONAME, DT_NEEDED, RPATH/RUNPATH, TLS, text relocs
  * which needed libraries are provided by the install and which come from
    the host system (these are what the macOS shim has to provide)
  * every external symbol the install imports, grouped by providing library
    and symbol version (e.g. GLIBC_2.17)
  * Vulkan extension names found in the binaries, to diff against MoltenVK

Only symbol names and metadata are written out, never code or data from the
binaries, so the reports are safe to commit.

Usage:
  elf_survey.py <install-dir> [--json out.json] [--markdown out.md]
"""

import argparse
import json
import os
import re
import struct
import sys
from collections import defaultdict

ELF_MAGIC = b"\x7fELF"
EM_X86_64 = 62

PT_LOAD, PT_DYNAMIC, PT_INTERP, PT_TLS = 1, 2, 3, 7
PF_X = 0x1

SHT_DYNSYM = 11

DT_NULL, DT_NEEDED, DT_HASH, DT_STRTAB, DT_SYMTAB = 0, 1, 4, 5, 6
DT_STRSZ, DT_SONAME, DT_RPATH, DT_TEXTREL, DT_FLAGS = 10, 14, 15, 22, 30
DT_RUNPATH = 29
DT_GNU_HASH = 0x6FFFFEF5
DT_VERSYM = 0x6FFFFFF0
DT_VERNEED = 0x6FFFFFFE
DT_VERNEEDNUM = 0x6FFFFFFF
DT_FLAGS_1 = 0x6FFFFFFB

DF_TEXTREL = 0x4
DF_STATIC_TLS = 0x10

STB_GLOBAL, STB_WEAK = 1, 2
STT_TLS = 6
SHN_UNDEF = 0

ET_NAMES = {2: "exec", 3: "dyn"}

VULKAN_EXT_RE = re.compile(rb"VK_(?:KHR|EXT|AMD|NV|NVX|INTEL|VALVE|GOOGLE|ARM|MESA)_[A-Za-z0-9_]+")


class ElfError(Exception):
    pass


class Elf:
    """Minimal little-endian ELF64 reader for dynamic linking metadata."""

    def __init__(self, path):
        self.path = path
        with open(path, "rb") as f:
            self.data = f.read()
        d = self.data
        if d[:4] != ELF_MAGIC:
            raise ElfError("not an ELF file")
        if d[4] != 2 or d[5] != 1:
            raise ElfError("not little-endian ELF64")
        (self.e_type, self.e_machine, _, _, self.e_phoff, self.e_shoff, _,
         _, self.e_phentsize, self.e_phnum, self.e_shentsize, self.e_shnum,
         _) = struct.unpack_from("<HHIQQQIHHHHHH", d, 16)
        self.phdrs = [
            struct.unpack_from("<IIQQQQQQ", d, self.e_phoff + i * self.e_phentsize)
            for i in range(self.e_phnum)
        ]
        self.loads = [p for p in self.phdrs if p[0] == PT_LOAD]
        self.dyn = self._read_dynamic()

    # -- address translation -------------------------------------------------

    def off(self, vaddr):
        for (_, _, p_offset, p_vaddr, _, p_filesz, _, _) in self.loads:
            if p_vaddr <= vaddr < p_vaddr + p_filesz:
                return p_offset + (vaddr - p_vaddr)
        raise ElfError("vaddr 0x%x not in any PT_LOAD" % vaddr)

    def cstr(self, offset):
        end = self.data.index(b"\0", offset)
        return self.data[offset:end].decode("utf-8", "replace")

    # -- dynamic section -----------------------------------------------------

    def _read_dynamic(self):
        dyn = defaultdict(list)
        for p in self.phdrs:
            if p[0] != PT_DYNAMIC:
                continue
            pos, end = p[2], p[2] + p[5]
            while pos + 16 <= end:
                tag, val = struct.unpack_from("<qQ", self.data, pos)
                if tag == DT_NULL:
                    break
                dyn[tag].append(val)
                pos += 16
        return dyn

    def _dynstr(self, index):
        return self.cstr(self.off(self.dyn[DT_STRTAB][0]) + index)

    @property
    def is_dynamic(self):
        return DT_STRTAB in self.dyn

    @property
    def interp(self):
        for p in self.phdrs:
            if p[0] == PT_INTERP:
                return self.cstr(p[2])
        return None

    @property
    def code_bytes(self):
        """Bytes of executable segments, a proxy for how much code a module has."""
        return sum(p[5] for p in self.loads if p[1] & PF_X)

    @property
    def tls_size(self):
        for p in self.phdrs:
            if p[0] == PT_TLS:
                return p[6]  # p_memsz
        return 0

    def strings(self, tag):
        return [self._dynstr(v) for v in self.dyn.get(tag, [])]

    def flags(self):
        f = self.dyn.get(DT_FLAGS, [0])[0]
        return {
            "textrel": bool(f & DF_TEXTREL) or DT_TEXTREL in self.dyn,
            "static_tls": bool(f & DF_STATIC_TLS),
        }

    # -- symbols ---------------------------------------------------------------

    def _symbol_count(self):
        # Prefer the section header, which is exact.
        symtab = self.dyn[DT_SYMTAB][0]
        if self.e_shoff and self.e_shnum:
            for i in range(self.e_shnum):
                sh = struct.unpack_from("<IIQQQQIIQQ", self.data,
                                        self.e_shoff + i * self.e_shentsize)
                if sh[1] == SHT_DYNSYM and sh[3] == symtab:
                    return sh[5] // (sh[9] or 24)
        if DT_HASH in self.dyn:
            return struct.unpack_from("<II", self.data, self.off(self.dyn[DT_HASH][0]))[1]
        if DT_GNU_HASH in self.dyn:
            return self._gnu_hash_count()
        raise ElfError("cannot size dynamic symbol table")

    def _gnu_hash_count(self):
        base = self.off(self.dyn[DT_GNU_HASH][0])
        nbuckets, symoffset, bloom_size, _ = struct.unpack_from("<IIII", self.data, base)
        buckets_off = base + 16 + bloom_size * 8
        buckets = struct.unpack_from("<%dI" % nbuckets, self.data, buckets_off)
        last = max(buckets) if buckets else 0
        if last < symoffset:
            return symoffset
        chain_off = buckets_off + nbuckets * 4
        while True:
            h = struct.unpack_from("<I", self.data, chain_off + (last - symoffset) * 4)[0]
            last += 1
            if h & 1:
                return last

    def _version_needs(self):
        """Map version index -> (library, version name) from DT_VERNEED."""
        needs = {}
        if DT_VERNEED not in self.dyn:
            return needs
        pos = self.off(self.dyn[DT_VERNEED][0])
        for _ in range(self.dyn[DT_VERNEEDNUM][0]):
            _, cnt, vn_file, vn_aux, vn_next = struct.unpack_from("<HHIII", self.data, pos)
            lib = self._dynstr(vn_file)
            apos = pos + vn_aux
            for _ in range(cnt):
                _, _, other, name, anext = struct.unpack_from("<IHHII", self.data, apos)
                needs[other] = (lib, self._dynstr(name))
                apos += anext
            pos += vn_next
        return needs

    def symbols(self):
        """Yield (name, defined, bind, type, (lib, version) or None)."""
        if not self.is_dynamic or DT_SYMTAB not in self.dyn:
            return
        count = self._symbol_count()
        symoff = self.off(self.dyn[DT_SYMTAB][0])
        stroff = self.off(self.dyn[DT_STRTAB][0])
        versym = self.off(self.dyn[DT_VERSYM][0]) if DT_VERSYM in self.dyn else None
        needs = self._version_needs()
        for i in range(1, count):
            st_name, st_info, _, st_shndx, _, _ = struct.unpack_from(
                "<IBBHQQ", self.data, symoff + i * 24)
            if not st_name:
                continue
            bind, typ = st_info >> 4, st_info & 0xF
            if bind not in (STB_GLOBAL, STB_WEAK):
                continue
            ver = None
            if versym is not None:
                idx = struct.unpack_from("<H", self.data, versym + i * 2)[0] & 0x7FFF
                ver = needs.get(idx)
            yield (self.cstr(stroff + st_name), st_shndx != SHN_UNDEF, bind, typ, ver)

    def vulkan_extensions(self):
        return sorted({m.decode() for m in VULKAN_EXT_RE.findall(self.data)})


def find_elves(root):
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames.sort()
        for name in sorted(filenames):
            path = os.path.join(dirpath, name)
            if os.path.islink(path) or not os.path.isfile(path):
                continue
            try:
                with open(path, "rb") as f:
                    if f.read(4) != ELF_MAGIC:
                        continue
            except OSError:
                continue
            yield path


def survey(root):
    modules = {}
    errors = {}
    for path in find_elves(root):
        rel = os.path.relpath(path, root)
        try:
            elf = Elf(path)
            if elf.e_machine != EM_X86_64:
                errors[rel] = "machine %d, not x86-64" % elf.e_machine
                continue
            syms = list(elf.symbols())
            modules[rel] = {
                "type": ET_NAMES.get(elf.e_type, str(elf.e_type)),
                "interp": elf.interp,
                "soname": (elf.strings(DT_SONAME) or [None])[0],
                "needed": elf.strings(DT_NEEDED),
                "rpath": elf.strings(DT_RPATH) + elf.strings(DT_RUNPATH),
                "tls_bytes": elf.tls_size,
                "code_bytes": elf.code_bytes,
                **elf.flags(),
                "exports": sorted(n for n, d, _, _, _ in syms if d),
                "imports": [
                    {"name": n, "weak": b == STB_WEAK, "tls": t == STT_TLS,
                     "lib": v[0] if v else None, "version": v[1] if v else None}
                    for n, d, b, t, v in syms if not d
                ],
                "vulkan_extensions": elf.vulkan_extensions(),
            }
        except (ElfError, struct.error, ValueError, KeyError, IndexError) as e:
            errors[rel] = str(e)
    return modules, errors


def analyze(modules):
    """Split imports into ones satisfied inside the install and external ones."""
    provided_libs = {}
    for rel, m in modules.items():
        provided_libs[m["soname"] or os.path.basename(rel)] = rel
        provided_libs.setdefault(os.path.basename(rel), rel)

    exporters = defaultdict(list)
    for rel, m in modules.items():
        for name in m["exports"]:
            exporters[name].append(rel)

    external_libs = defaultdict(set)  # lib -> modules needing it
    for rel, m in modules.items():
        for lib in m["needed"]:
            if lib not in provided_libs:
                external_libs[lib].add(rel)

    # lib -> symbol -> {"versions": set, "users": set, "weak": bool, "tls": bool}
    external_syms = defaultdict(dict)
    internal_count = 0
    for rel, m in modules.items():
        for imp in m["imports"]:
            if imp["lib"] in provided_libs or (
                    imp["lib"] is None and imp["name"] in exporters):
                internal_count += 1
                continue
            lib = imp["lib"] or "(unversioned)"
            entry = external_syms[lib].setdefault(
                imp["name"], {"versions": set(), "users": set(), "weak": True, "tls": False})
            if imp["version"]:
                entry["versions"].add(imp["version"])
            entry["users"].add(rel)
            entry["weak"] &= imp["weak"]
            entry["tls"] |= imp["tls"]

    vulkan = sorted({e for m in modules.values() for e in m["vulkan_extensions"]})
    return {
        "external_libs": {k: sorted(v) for k, v in sorted(external_libs.items())},
        "external_symbols": {
            lib: {n: {"versions": sorted(e["versions"]), "users": sorted(e["users"]),
                      "weak": e["weak"], "tls": e["tls"]}
                  for n, e in sorted(syms.items())}
            for lib, syms in sorted(external_syms.items())
        },
        "internal_import_count": internal_count,
        "vulkan_extensions": vulkan,
    }


def version_key(v):
    m = re.match(r"([A-Za-z_]+?)_?([\d.]+)$", v)
    if not m:
        return (v, ())
    return (m.group(1), tuple(int(x) for x in m.group(2).split(".") if x))


def to_markdown(root, modules, errors, result):
    out = []
    w = out.append
    w("# ELF import survey\n")
    w("Install scanned: `%s`\n" % os.path.basename(os.path.abspath(root)))
    total_ext = sum(len(s) for s in result["external_symbols"].values())
    w("* Modules: **%d** (%d executables)" % (
        len(modules), sum(1 for m in modules.values() if m["type"] == "exec")))
    w("* Executable code: **%.1f MB**" % (
        sum(m["code_bytes"] for m in modules.values()) / 1e6))
    w("* External libraries: **%d**" % len(result["external_libs"]))
    w("* External symbols (the shim's to-do list): **%d**" % total_ext)
    w("* Imports satisfied inside the install: %d" % result["internal_import_count"])
    w("* Modules using ELF TLS: %d\n" % sum(1 for m in modules.values() if m["tls_bytes"]))

    w("## External libraries\n")
    w("| Library | Symbols | Highest version | Needed by |")
    w("|---|---:|---|---|")
    rows = dict(result["external_libs"])
    if "(unversioned)" in result["external_symbols"]:
        rows["(unversioned)"] = sorted({u for e in result["external_symbols"]["(unversioned)"].values()
                                        for u in e["users"]})
    for lib, users in rows.items():
        syms = result["external_symbols"].get(lib, {})
        versions = {v for e in syms.values() for v in e["versions"]}
        top = max(versions, key=version_key) if versions else ""
        shown = ", ".join("`%s`" % os.path.basename(u) for u in users[:4])
        if len(users) > 4:
            shown += " +%d" % (len(users) - 4)
        w("| `%s` | %d | %s | %s |" % (lib, len(syms), top, shown))
    w("")

    w("## Modules\n")
    w("| Module | Type | Code KB | TLS bytes | Imports | Exports | Needed |")
    w("|---|---|---:|---:|---:|---:|---|")
    for rel, m in sorted(modules.items(), key=lambda kv: -kv[1]["code_bytes"]):
        w("| `%s` | %s | %d | %d | %d | %d | %s |" % (
            rel, m["type"], m["code_bytes"] // 1024, m["tls_bytes"],
            len(m["imports"]), len(m["exports"]),
            ", ".join(m["needed"])))
    w("")

    w("## External symbols by library\n")
    for lib, syms in result["external_symbols"].items():
        w("<details><summary><code>%s</code> (%d)</summary>\n" % (lib, len(syms)))
        w("```")
        for name, e in syms.items():
            tags = ",".join(e["versions"])
            if e["weak"]:
                tags += " weak"
            if e["tls"]:
                tags += " tls"
            w("%s %s" % (name, tags.strip()))
        w("```\n</details>\n")

    if result["vulkan_extensions"]:
        w("## Vulkan extensions referenced\n")
        w("```")
        w("\n".join(result["vulkan_extensions"]))
        w("```\n")

    if errors:
        w("## Skipped files\n")
        for rel, err in sorted(errors.items()):
            w("* `%s`: %s" % (rel, err))
        w("")
    return "\n".join(out)


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("root", help="install directory to scan")
    ap.add_argument("--json", help="write the full report as JSON")
    ap.add_argument("--markdown", help="write a markdown summary (default: stdout)")
    args = ap.parse_args(argv)

    if not os.path.isdir(args.root):
        ap.error("%s is not a directory" % args.root)
    modules, errors = survey(args.root)
    if not modules:
        print("no x86-64 ELF files found under %s" % args.root, file=sys.stderr)
        return 1
    result = analyze(modules)

    if args.json:
        with open(args.json, "w") as f:
            json.dump({"modules": modules, "errors": errors, **result}, f, indent=1)
    md = to_markdown(args.root, modules, errors, result)
    if args.markdown:
        with open(args.markdown, "w") as f:
            f.write(md + "\n")
    else:
        print(md)
    return 0


if __name__ == "__main__":
    sys.exit(main())
