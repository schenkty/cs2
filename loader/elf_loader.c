/* ELF loader for x86-64 Linux modules. See elf_loader.h.
 *
 * Portable C (Linux and macOS hosts). Segments are copied into anonymous
 * memory rather than mmapped from the file, so the loader does not depend on
 * the host page size matching the ELF segment alignment (macOS on Apple
 * Silicon uses 16K pages). */
#define _GNU_SOURCE
#include "elf_loader.h"

#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

#define MAX_SEARCH_PATHS 32
#define PT_INTERP_ 3

#ifdef PTHREAD_RECURSIVE_MUTEX_INITIALIZER_NP
#define RECURSIVE_MUTEX_INIT PTHREAD_RECURSIVE_MUTEX_INITIALIZER_NP
#else
#define RECURSIVE_MUTEX_INIT PTHREAD_RECURSIVE_MUTEX_INITIALIZER
#endif

struct elf_module {
    char *path;            /* file it was loaded from */
    const char *soname;    /* DT_SONAME, or basename of path */
    uint8_t *base;         /* load bias: runtime address = base + vaddr */
    uint8_t *map_start;
    size_t map_size;
    const Elf64_Phdr_ *phdr;
    uint16_t phnum;
    int is_exec;   /* ET_EXEC: fixed load address */
    int runnable;  /* has PT_INTERP: a program with an entry point */
    uint64_t entry;
    void *eh_frame_hdr;

    /* dynamic section */
    const Elf64_Sym_ *symtab;
    const char *strtab;
    const uint32_t *gnu_hash;
    const uint32_t *sysv_hash;
    const uint16_t *versym;
    const Elf64_Verneed_ *verneed;
    uint64_t verneednum;
    const Elf64_Verdef_ *verdef;
    uint64_t verdefnum;
    const Elf64_Rela_ *rela, *jmprel;
    size_t relasz, pltrelsz;
    uint64_t init, fini;
    uint64_t *init_array, *fini_array;
    size_t init_arraysz, fini_arraysz;
    const char *rpath;

    /* TLS */
    size_t tls_modid;
    const void *tls_image;
    size_t tls_filesz, tls_memsz, tls_align;

    elf_module **needed;
    int n_needed;
    int refcount;
    int initialized;
    elf_module *next;
};

/* ---- global state ------------------------------------------------------- */

static elf_host g_host;
static elf_module *g_modules, *g_modules_tail;
static char *g_search[MAX_SEARCH_PATHS];
static int g_nsearch;
static int g_strict, g_verbose;
static size_t g_unresolved;
static pthread_mutex_t g_lock = RECURSIVE_MUTEX_INIT;
static __thread char g_error[512];
static __thread int g_error_pending;
static char g_host_handle; /* dlopen handle for libraries the host provides */
static elf_module **g_init_order; /* modules in initializer order, for fini */
static size_t g_ninit, g_init_cap;

static void set_error(const char *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(g_error, sizeof g_error, fmt, ap);
    va_end(ap);
    g_error_pending = 1;
}

const char *elf_loader_error(void) { return g_error; }
size_t elf_loader_unresolved_count(void) { return g_unresolved; }
int elf_module_is_exec(const elf_module *m) { return m->runnable; }
void elf_loader_set_strict(int strict) { g_strict = strict; }
void elf_loader_set_verbose(int verbose) { g_verbose = verbose; }

static void vlog(const char *fmt, ...) {
    if (!g_verbose) return;
    va_list ap;
    va_start(ap, fmt);
    fputs("[elfload] ", stderr);
    vfprintf(stderr, fmt, ap);
    fputc('\n', stderr);
    va_end(ap);
}

void elf_loader_add_search_path(const char *dir) {
    if (g_nsearch < MAX_SEARCH_PATHS) g_search[g_nsearch++] = strdup(dir);
}

static void *xcalloc(size_t n, size_t sz) {
    void *p = calloc(n, sz);
    if (!p) { perror("calloc"); abort(); }
    return p;
}

/* ---- TLS (general dynamic model via __tls_get_addr) --------------------- */

typedef struct { unsigned long ti_module, ti_offset; } tls_index;

static elf_module **g_tls_modules; /* indexed by modid */
static size_t g_tls_count, g_tls_cap;
static pthread_key_t g_dtv_key;

typedef struct { size_t n; void **blocks; } dtv_t;

static void dtv_free(void *p) {
    dtv_t *dtv = p;
    for (size_t i = 0; i < dtv->n; i++) free(dtv->blocks[i]);
    free(dtv->blocks);
    free(dtv);
}

static void *tls_block(size_t modid) {
    dtv_t *dtv = pthread_getspecific(g_dtv_key);
    if (!dtv) {
        dtv = xcalloc(1, sizeof *dtv);
        pthread_setspecific(g_dtv_key, dtv);
    }
    if (modid >= dtv->n) {
        size_t n = modid + 8;
        void **b = realloc(dtv->blocks, n * sizeof *b);
        if (!b) abort();
        memset(b + dtv->n, 0, (n - dtv->n) * sizeof *b);
        dtv->blocks = b;
        dtv->n = n;
    }
    if (!dtv->blocks[modid]) {
        elf_module *m = g_tls_modules[modid];
        size_t align = m->tls_align < sizeof(void *) ? sizeof(void *) : m->tls_align;
        void *blk = NULL;
        if (posix_memalign(&blk, align, m->tls_memsz ? m->tls_memsz : 1)) abort();
        memcpy(blk, m->tls_image, m->tls_filesz);
        memset((char *)blk + m->tls_filesz, 0, m->tls_memsz - m->tls_filesz);
        dtv->blocks[modid] = blk;
    }
    return dtv->blocks[modid];
}

static void *ov_tls_get_addr(tls_index *ti) {
    return (char *)tls_block(ti->ti_module) + ti->ti_offset;
}

static void register_tls(elf_module *m) {
    if (g_tls_count + 1 >= g_tls_cap) {
        g_tls_cap = g_tls_cap ? g_tls_cap * 2 : 16;
        g_tls_modules = realloc(g_tls_modules, g_tls_cap * sizeof *g_tls_modules);
        if (!g_tls_modules) abort();
        if (g_tls_count == 0) g_tls_modules[g_tls_count++] = NULL; /* modid 0 unused */
    }
    m->tls_modid = g_tls_count;
    g_tls_modules[g_tls_count++] = m;
}

/* ---- stubs for unresolved functions -------------------------------------- */

static _Noreturn void unresolved_called(const char *name) {
    fprintf(stderr, "[elfload] called unresolved symbol '%s'\n", name);
    abort();
}

static uint8_t *g_stub_page;
static size_t g_stub_used, g_stub_cap;

/* movabs rdi, name; movabs rax, handler; jmp rax */
static void *make_stub(const char *name) {
    const size_t sz = 32;
    long pg = sysconf(_SC_PAGESIZE);
    if (!g_stub_page || g_stub_used + sz > g_stub_cap) {
        g_stub_page = mmap(NULL, (size_t)pg, PROT_READ | PROT_WRITE,
                           MAP_PRIVATE | MAP_ANON, -1, 0);
        if (g_stub_page == MAP_FAILED) abort();
        g_stub_used = 0;
        g_stub_cap = (size_t)pg;
    } else {
        mprotect(g_stub_page, g_stub_cap, PROT_READ | PROT_WRITE);
    }
    uint8_t *p = g_stub_page + g_stub_used;
    char *copy = strdup(name);
    uint64_t a = (uint64_t)(uintptr_t)copy, h = (uint64_t)(uintptr_t)unresolved_called;
    p[0] = 0x48; p[1] = 0xBF; memcpy(p + 2, &a, 8);
    p[10] = 0x48; p[11] = 0xB8; memcpy(p + 12, &h, 8);
    p[20] = 0xFF; p[21] = 0xE0;
    memset(p + 22, 0xCC, sz - 22);
    g_stub_used += sz;
    mprotect(g_stub_page, g_stub_cap, PROT_READ | PROT_EXEC);
    return p;
}

/* ---- symbol lookup -------------------------------------------------------- */

static uint32_t gnu_hash(const char *s) {
    uint32_t h = 5381;
    for (const unsigned char *p = (const unsigned char *)s; *p; p++) h = h * 33 + *p;
    return h;
}

static uint32_t sysv_hash(const char *s) {
    uint32_t h = 0, g;
    for (const unsigned char *p = (const unsigned char *)s; *p; p++) {
        h = (h << 4) + *p;
        if ((g = h & 0xf0000000)) h ^= g >> 24;
        h &= ~g;
    }
    return h;
}

static int sym_defined(const Elf64_Sym_ *s) {
    int bind = ELF64_ST_BIND_(s->st_info);
    return s->st_shndx != SHN_UNDEF_ &&
           (bind == STB_GLOBAL_ || bind == STB_WEAK_ || bind == STB_GNU_UNIQUE_);
}

/* Name of the version a module defines at a version index, or NULL. */
static const char *verdef_name(const elf_module *m, uint16_t idx) {
    const Elf64_Verdef_ *vd = m->verdef;
    for (uint64_t i = 0; vd && i < m->verdefnum; i++) {
        if (vd->vd_ndx == idx) {
            const Elf64_Verdaux_ *aux = (const Elf64_Verdaux_ *)((const char *)vd + vd->vd_aux);
            return m->strtab + aux->vda_name;
        }
        vd = (const Elf64_Verdef_ *)((const char *)vd + vd->vd_next);
    }
    return NULL;
}

/* A hidden (non-default, name@VER) definition only satisfies an import that
 * asks for exactly that version. */
static int version_ok(const elf_module *m, uint32_t i, const char *want) {
    if (!m->versym || !(m->versym[i] & 0x8000)) return 1;
    const char *have = verdef_name(m, m->versym[i] & 0x7fff);
    return want && have && strcmp(want, have) == 0;
}

/* Find a defined symbol in one module, honouring the requested version. */
static const Elf64_Sym_ *module_lookup_v(const elf_module *m, const char *name, const char *want) {
    if (m->gnu_hash) {
        const uint32_t *gh = m->gnu_hash;
        uint32_t nbuckets = gh[0], symoffset = gh[1], bloom_size = gh[2], shift = gh[3];
        const uint64_t *bloom = (const uint64_t *)(gh + 4);
        const uint32_t *buckets = (const uint32_t *)(bloom + bloom_size);
        const uint32_t *chain = buckets + nbuckets;
        uint32_t h = gnu_hash(name);
        uint64_t word = bloom[(h / 64) % bloom_size];
        uint64_t mask = (1ULL << (h % 64)) | (1ULL << ((h >> shift) % 64));
        if ((word & mask) != mask) return NULL;
        uint32_t i = buckets[h % nbuckets];
        if (i < symoffset) return NULL;
        for (;; i++) {
            uint32_t h2 = chain[i - symoffset];
            const Elf64_Sym_ *s = &m->symtab[i];
            if ((h | 1) == (h2 | 1) && sym_defined(s) &&
                strcmp(name, m->strtab + s->st_name) == 0 && version_ok(m, i, want))
                return s;
            if (h2 & 1) break;
        }
        return NULL;
    }
    if (m->sysv_hash) {
        uint32_t nbucket = m->sysv_hash[0];
        const uint32_t *bucket = m->sysv_hash + 2, *chain = bucket + nbucket;
        for (uint32_t i = bucket[sysv_hash(name) % nbucket]; i; i = chain[i]) {
            const Elf64_Sym_ *s = &m->symtab[i];
            if (sym_defined(s) && strcmp(name, m->strtab + s->st_name) == 0 &&
                version_ok(m, i, want))
                return s;
        }
    }
    return NULL;
}

static const Elf64_Sym_ *module_lookup(const elf_module *m, const char *name) {
    return module_lookup_v(m, name, NULL);
}

static void *sym_address(const elf_module *m, const Elf64_Sym_ *s) {
    void *addr = m->base + s->st_value;
    if (ELF64_ST_TYPE_(s->st_info) == STT_GNU_IFUNC_) addr = ((void *(*)(void))addr)();
    return addr;
}

/* Version requested by an import, from the importer's verneed table. */
static const char *verdef_name(const elf_module *m, uint16_t idx);

static const char *import_version(const elf_module *m, uint32_t symidx) {
    if (!m->versym) return NULL;
    uint16_t idx = m->versym[symidx] & 0x7fff;
    if (idx < 2) return NULL;
    /* A module importing one of its own versioned symbols uses its verdef. */
    const char *own = verdef_name(m, idx);
    if (own) return own;
    const Elf64_Verneed_ *vn = m->verneed;
    for (uint64_t i = 0; i < m->verneednum; i++) {
        const Elf64_Vernaux_ *aux = (const Elf64_Vernaux_ *)((const char *)vn + vn->vn_aux);
        for (uint16_t j = 0; j < vn->vn_cnt; j++) {
            if (aux->vna_other == idx) return m->strtab + aux->vna_name;
            aux = (const Elf64_Vernaux_ *)((const char *)aux + aux->vna_next);
        }
        vn = (const Elf64_Verneed_ *)((const char *)vn + vn->vn_next);
    }
    return NULL;
}

static void *lookup_override(const char *name);

typedef struct {
    void *addr;
    const elf_module *module; /* NULL when the host or an override provides it */
    const Elf64_Sym_ *sym;
} resolved;

static int resolve(const char *name, const char *version, const elf_module *skip, resolved *out) {
    memset(out, 0, sizeof *out);
    if ((out->addr = lookup_override(name))) return 1;
    for (elf_module *m = g_modules; m; m = m->next) {
        if (m == skip) continue;
        const Elf64_Sym_ *s = module_lookup_v(m, name, version);
        if (s) {
            out->module = m;
            out->sym = s;
            out->addr = ELF64_ST_TYPE_(s->st_info) == STT_TLS_ ? NULL : sym_address(m, s);
            return 1;
        }
    }
    if (g_host.lookup && (out->addr = g_host.lookup(name, version))) return 1;
    return 0;
}

/* ---- loading -------------------------------------------------------------- */

static int load_deps_and_link(elf_module *m);

static const char *basename_of(const char *path) {
    const char *s = strrchr(path, '/');
    return s ? s + 1 : path;
}

static elf_module *find_loaded(const char *name) {
    for (elf_module *m = g_modules; m; m = m->next) {
        if (strcmp(m->soname, name) == 0 || strcmp(m->path, name) == 0 ||
            strcmp(basename_of(m->path), basename_of(name)) == 0)
            return m;
    }
    return NULL;
}

static void *dyn_ptr(elf_module *m, uint64_t vaddr) { return m->base + vaddr; }

static elf_module *map_file(const char *path) {
    int fd = open(path, O_RDONLY);
    if (fd < 0) { set_error("%s: %s", path, strerror(errno)); return NULL; }
    struct stat st;
    Elf64_Ehdr_ eh;
    if (fstat(fd, &st) || pread(fd, &eh, sizeof eh, 0) != (ssize_t)sizeof eh ||
        memcmp(eh.e_ident, "\x7f" "ELF", 4) != 0) {
        set_error("%s: not an ELF file", path);
        close(fd);
        return NULL;
    }
    if (eh.e_ident[4] != ELFCLASS64_ || eh.e_ident[5] != ELFDATA2LSB_ ||
        eh.e_machine != EM_X86_64_ || (eh.e_type != ET_DYN_ && eh.e_type != ET_EXEC_)) {
        set_error("%s: not an x86-64 ELF executable or shared object", path);
        close(fd);
        return NULL;
    }
    size_t phsz = (size_t)eh.e_phnum * sizeof(Elf64_Phdr_);
    Elf64_Phdr_ *ph = malloc(phsz);
    if (!ph || pread(fd, ph, phsz, (off_t)eh.e_phoff) != (ssize_t)phsz) {
        set_error("%s: cannot read program headers", path);
        free(ph);
        close(fd);
        return NULL;
    }

    uint64_t lo = UINT64_MAX, hi = 0;
    for (int i = 0; i < eh.e_phnum; i++) {
        if (ph[i].p_type != PT_LOAD_) continue;
        if (ph[i].p_vaddr < lo) lo = ph[i].p_vaddr;
        if (ph[i].p_vaddr + ph[i].p_memsz > hi) hi = ph[i].p_vaddr + ph[i].p_memsz;
    }
    long pg = sysconf(_SC_PAGESIZE);
    lo &= ~(uint64_t)(pg - 1);
    hi = (hi + (uint64_t)pg - 1) & ~(uint64_t)(pg - 1);

    int is_exec = eh.e_type == ET_EXEC_;
    void *want = is_exec ? (void *)(uintptr_t)lo : NULL;
    int flags = MAP_PRIVATE | MAP_ANON;
#ifdef MAP_FIXED_NOREPLACE
    if (is_exec) flags |= MAP_FIXED_NOREPLACE;
#endif
    uint8_t *map = mmap(want, hi - lo, PROT_READ | PROT_WRITE, flags, -1, 0);
    if (map == MAP_FAILED || (is_exec && map != want)) {
        set_error("%s: cannot reserve %zu bytes%s", path, (size_t)(hi - lo),
                  is_exec ? " at its fixed address" : "");
        if (map != MAP_FAILED) munmap(map, hi - lo);
        free(ph);
        close(fd);
        return NULL;
    }

    elf_module *m = xcalloc(1, sizeof *m);
    m->path = strdup(path);
    m->map_start = map;
    m->map_size = hi - lo;
    m->base = map - lo;
    m->is_exec = is_exec;
    m->entry = eh.e_entry;
    m->refcount = 1;

    for (int i = 0; i < eh.e_phnum; i++) {
        const Elf64_Phdr_ *p = &ph[i];
        if (p->p_type == PT_LOAD_ && p->p_filesz &&
            pread(fd, m->base + p->p_vaddr, p->p_filesz, (off_t)p->p_offset) != (ssize_t)p->p_filesz) {
            set_error("%s: short read of segment %d", path, i);
            munmap(map, m->map_size);
            free(m->path);
            free(m);
            free(ph);
            close(fd);
            return NULL;
        }
    }
    close(fd);

    /* Program headers as mapped: PT_PHDR, or inside the first segment. */
    m->phdr = NULL;
    for (int i = 0; i < eh.e_phnum; i++)
        if (ph[i].p_type == PT_PHDR_) m->phdr = (const Elf64_Phdr_ *)(m->base + ph[i].p_vaddr);
    if (!m->phdr) {
        for (int i = 0; i < eh.e_phnum; i++)
            if (ph[i].p_type == PT_LOAD_ && ph[i].p_offset == 0) {
                m->phdr = (const Elf64_Phdr_ *)(m->base + ph[i].p_vaddr + eh.e_phoff);
                break;
            }
    }
    if (!m->phdr) m->phdr = ph; /* keep our copy */
    else free(ph);
    m->phnum = eh.e_phnum;
    return m;
}

static int parse_dynamic(elf_module *m) {
    const Elf64_Dyn_ *dyn = NULL;
    for (int i = 0; i < m->phnum; i++) {
        const Elf64_Phdr_ *p = &m->phdr[i];
        if (p->p_type == PT_DYNAMIC_) dyn = (const Elf64_Dyn_ *)(m->base + p->p_vaddr);
        if (p->p_type == PT_INTERP_) m->runnable = 1;
        if (p->p_type == PT_GNU_EH_FRAME_) m->eh_frame_hdr = m->base + p->p_vaddr;
        if (p->p_type == PT_TLS_) {
            m->tls_image = m->base + p->p_vaddr;
            m->tls_filesz = p->p_filesz;
            m->tls_memsz = p->p_memsz;
            m->tls_align = p->p_align;
        }
    }
    if (!dyn) { set_error("%s: no dynamic section (static binary?)", m->path); return 0; }

    uint64_t soname = 0, rpath = 0, runpath = 0;
    int nneeded = 0;
    for (const Elf64_Dyn_ *d = dyn; d->d_tag != DT_NULL_; d++) {
        switch (d->d_tag) {
        case DT_NEEDED_: nneeded++; break;
        case DT_STRTAB_: m->strtab = dyn_ptr(m, d->d_val); break;
        case DT_SYMTAB_: m->symtab = dyn_ptr(m, d->d_val); break;
        case DT_GNU_HASH_: m->gnu_hash = dyn_ptr(m, d->d_val); break;
        case DT_HASH_: m->sysv_hash = dyn_ptr(m, d->d_val); break;
        case DT_VERSYM_: m->versym = dyn_ptr(m, d->d_val); break;
        case DT_VERNEED_: m->verneed = dyn_ptr(m, d->d_val); break;
        case DT_VERNEEDNUM_: m->verneednum = d->d_val; break;
        case DT_VERDEF_: m->verdef = dyn_ptr(m, d->d_val); break;
        case DT_VERDEFNUM_: m->verdefnum = d->d_val; break;
        case DT_RELA_: m->rela = dyn_ptr(m, d->d_val); break;
        case DT_RELASZ_: m->relasz = d->d_val; break;
        case DT_JMPREL_: m->jmprel = dyn_ptr(m, d->d_val); break;
        case DT_PLTRELSZ_: m->pltrelsz = d->d_val; break;
        case DT_INIT_: m->init = d->d_val; break;
        case DT_FINI_: m->fini = d->d_val; break;
        case DT_INIT_ARRAY_: m->init_array = dyn_ptr(m, d->d_val); break;
        case DT_INIT_ARRAYSZ_: m->init_arraysz = d->d_val / 8; break;
        case DT_FINI_ARRAY_: m->fini_array = dyn_ptr(m, d->d_val); break;
        case DT_FINI_ARRAYSZ_: m->fini_arraysz = d->d_val / 8; break;
        case DT_SONAME_: soname = d->d_val; break;
        case DT_RPATH_: rpath = d->d_val; break;
        case DT_RUNPATH_: runpath = d->d_val; break;
        }
    }
    if (!m->strtab || !m->symtab) { set_error("%s: missing symbol tables", m->path); return 0; }
    m->soname = soname ? m->strtab + soname : basename_of(m->path);
    m->rpath = runpath ? m->strtab + runpath : rpath ? m->strtab + rpath : NULL;
    m->needed = xcalloc((size_t)nneeded + 1, sizeof *m->needed);
    if (m->tls_memsz) register_tls(m);
    return 1;
}

static void link_module(elf_module *m) {
    m->next = NULL;
    if (g_modules_tail) g_modules_tail->next = m;
    else g_modules = m;
    g_modules_tail = m;
}

/* Try "dir/name" for each dir in a ':'-separated list, expanding $ORIGIN. */
static char *search_list(const char *list, const char *origin, const char *name) {
    char buf[4096];
    const char *p = list;
    while (p && *p) {
        const char *end = strchr(p, ':');
        size_t len = end ? (size_t)(end - p) : strlen(p);
        char dir[2048];
        size_t o = 0;
        for (size_t i = 0; i < len && o + 1 < sizeof dir;) {
            if (origin && strncmp(p + i, "$ORIGIN", 7) == 0) {
                o += (size_t)snprintf(dir + o, sizeof dir - o, "%s", origin); i += 7;
            } else if (origin && strncmp(p + i, "${ORIGIN}", 9) == 0) {
                o += (size_t)snprintf(dir + o, sizeof dir - o, "%s", origin); i += 9;
            } else {
                dir[o++] = p[i++];
            }
        }
        dir[o < sizeof dir ? o : sizeof dir - 1] = 0;
        snprintf(buf, sizeof buf, "%s/%s", dir, name);
        if (access(buf, R_OK) == 0) return strdup(buf);
        p = end ? end + 1 : NULL;
    }
    return NULL;
}

static char *find_library(const char *name, const elf_module *requester) {
    if (strchr(name, '/')) return access(name, R_OK) == 0 ? strdup(name) : NULL;
    char *found = NULL;
    if (requester && requester->rpath) {
        char origin[2048];
        snprintf(origin, sizeof origin, "%s", requester->path);
        char *slash = strrchr(origin, '/');
        if (slash) *slash = 0; else strcpy(origin, ".");
        found = search_list(requester->rpath, origin, name);
    }
    for (int i = 0; !found && i < g_nsearch; i++) found = search_list(g_search[i], NULL, name);
    if (!found && requester) {
        char origin[2048];
        snprintf(origin, sizeof origin, "%s", requester->path);
        char *slash = strrchr(origin, '/');
        if (slash) { *slash = 0; found = search_list(origin, NULL, name); }
    }
    return found;
}

/* Returns the module, or &g_host_handle (cast) for host libraries. */
static elf_module *load_one(const char *name, const elf_module *requester, int *is_host) {
    *is_host = 0;
    elf_module *m = find_loaded(name);
    if (m) { m->refcount++; return m; }
    if (!strchr(name, '/') && g_host.has_library && g_host.has_library(name)) {
        *is_host = 1;
        return NULL;
    }
    char *path = find_library(name, requester);
    if (!path) { set_error("%s: library not found", name); return NULL; }
    m = map_file(path);
    free(path);
    if (!m) return NULL;
    if (!parse_dynamic(m)) return NULL;
    link_module(m);
    vlog("mapped %s at %p (%zu KB)", m->path, (void *)m->map_start, m->map_size / 1024);
    if (!load_deps_and_link(m)) return NULL;
    return m;
}

static int apply_relocs(elf_module *m, const Elf64_Rela_ *rel, size_t size) {
    size_t n = size / sizeof *rel;
    for (size_t i = 0; i < n; i++) {
        const Elf64_Rela_ *r = &rel[i];
        uint32_t type = ELF64_R_TYPE_(r->r_info), symidx = ELF64_R_SYM_(r->r_info);
        uint64_t *where = (uint64_t *)(m->base + r->r_offset);
        resolved res = {0};
        const Elf64_Sym_ *sym = symidx ? &m->symtab[symidx] : NULL;
        const char *name = sym ? m->strtab + sym->st_name : "";

        if (type == R_X86_64_NONE_ || type == R_X86_64_RELATIVE_ || type == R_X86_64_IRELATIVE_) {
            /* no symbol */
        } else if (sym && sym->st_shndx != SHN_UNDEF_ && ELF64_ST_BIND_(sym->st_info) == 0) {
            /* local symbol (e.g. TLS in the module itself) */
            res.module = m; res.sym = sym;
            res.addr = ELF64_ST_TYPE_(sym->st_info) == STT_TLS_ ? NULL : sym_address(m, sym);
        } else if (symidx) {
            if (!resolve(name, import_version(m, symidx),
                         type == R_X86_64_COPY_ ? m : NULL, &res)) {
                if (ELF64_ST_BIND_(sym->st_info) == STB_WEAK_) {
                    res.addr = NULL;
                } else if (g_strict) {
                    set_error("%s: unresolved symbol '%s'", m->path, name);
                    return 0;
                } else if (type == R_X86_64_JUMP_SLOT_ || type == R_X86_64_GLOB_DAT_ ||
                           type == R_X86_64_64_) {
                    vlog("unresolved: %s (%s)", name, m->soname);
                    g_unresolved++;
                    res.addr = make_stub(name);
                } else {
                    set_error("%s: unresolved symbol '%s' (reloc %u)", m->path, name, type);
                    return 0;
                }
            }
        }

        switch (type) {
        case R_X86_64_NONE_: break;
        case R_X86_64_RELATIVE_: *where = (uint64_t)(uintptr_t)m->base + (uint64_t)r->r_addend; break;
        case R_X86_64_IRELATIVE_:
            *where = (uint64_t)(uintptr_t)((void *(*)(void))(m->base + r->r_addend))();
            break;
        case R_X86_64_64_: *where = (uint64_t)(uintptr_t)res.addr + (uint64_t)r->r_addend; break;
        case R_X86_64_GLOB_DAT_:
        case R_X86_64_JUMP_SLOT_: *where = (uint64_t)(uintptr_t)res.addr; break;
        case R_X86_64_PC32_: {
            int64_t v = (int64_t)(uintptr_t)res.addr + r->r_addend - (int64_t)(uintptr_t)where;
            *(int32_t *)where = (int32_t)v;
            break;
        }
        case R_X86_64_COPY_:
            if (res.addr) memcpy(where, res.addr, sym->st_size);
            break;
        case R_X86_64_DTPMOD64_:
            if (symidx && !res.module) {
                set_error("%s: TLS symbol '%s' is not in a loaded module", m->path, name);
                return 0;
            }
            *where = symidx ? res.module->tls_modid : m->tls_modid;
            break;
        case R_X86_64_DTPOFF64_:
            *where = (res.sym ? res.sym->st_value : 0) + (uint64_t)r->r_addend;
            break;
        case R_X86_64_TPOFF64_:
            set_error("%s: initial-exec TLS (R_X86_64_TPOFF64) is not supported yet", m->path);
            return 0;
        default:
            set_error("%s: unsupported relocation type %u", m->path, type);
            return 0;
        }
    }
    return 1;
}

static void protect_segments(elf_module *m) {
    long pg = sysconf(_SC_PAGESIZE);
    for (int i = 0; i < m->phnum; i++) {
        const Elf64_Phdr_ *p = &m->phdr[i];
        if (p->p_type != PT_LOAD_) continue;
        uintptr_t start = (uintptr_t)(m->base + p->p_vaddr) & ~(uintptr_t)(pg - 1);
        uintptr_t end = ((uintptr_t)(m->base + p->p_vaddr + p->p_memsz) + (uintptr_t)pg - 1) &
                        ~(uintptr_t)(pg - 1);
        /* Pages shared with a neighbouring segment get the union of both
         * segments' permissions (matters when host pages exceed 4K). */
        int prot = 0;
        for (int j = 0; j < m->phnum; j++) {
            const Elf64_Phdr_ *q = &m->phdr[j];
            if (q->p_type != PT_LOAD_) continue;
            uintptr_t qs = (uintptr_t)(m->base + q->p_vaddr), qe = qs + q->p_memsz;
            if (qs < end && qe > start) {
                if (q->p_flags & PF_R_) prot |= PROT_READ;
                if (q->p_flags & PF_W_) prot |= PROT_WRITE;
                if (q->p_flags & PF_X_) prot |= PROT_EXEC;
            }
        }
        if (mprotect((void *)start, end - start, prot))
            vlog("mprotect %s segment %d failed: %s", m->path, i, strerror(errno));
    }
}

static int load_deps_and_link(elf_module *m) {
    const Elf64_Dyn_ *dyn = NULL;
    for (int i = 0; i < m->phnum; i++)
        if (m->phdr[i].p_type == PT_DYNAMIC_) dyn = (const Elf64_Dyn_ *)(m->base + m->phdr[i].p_vaddr);
    for (const Elf64_Dyn_ *d = dyn; d->d_tag != DT_NULL_; d++) {
        if (d->d_tag != DT_NEEDED_) continue;
        const char *dep = m->strtab + d->d_val;
        int is_host;
        elf_module *dm = load_one(dep, m, &is_host);
        if (!dm && !is_host) {
            char inner[512];
            snprintf(inner, sizeof inner, "%s", g_error);
            set_error("%s (needed by %s)", inner, m->soname);
            return 0;
        }
        if (dm) m->needed[m->n_needed++] = dm;
        else vlog("%s: %s provided by host", m->soname, dep);
    }
    if (!apply_relocs(m, m->rela, m->relasz)) return 0;
    if (!apply_relocs(m, m->jmprel, m->pltrelsz)) return 0;
    protect_segments(m);
    return 1;
}

/* ---- initializers / finalizers --------------------------------------------- */

typedef void (*init_fn)(int, char **, char **);

static void run_init(elf_module *m, int argc, char **argv, char **envp) {
    if (m->initialized) return;
    m->initialized = 1;
    for (int i = 0; i < m->n_needed; i++) run_init(m->needed[i], argc, argv, envp);
    vlog("init %s", m->soname);
    if (m->init) ((init_fn)(m->base + m->init))(argc, argv, envp);
    for (size_t i = 0; i < m->init_arraysz; i++) {
        uint64_t f = m->init_array[i];
        if (f && f != (uint64_t)-1) ((init_fn)(uintptr_t)f)(argc, argv, envp);
    }
    if (g_ninit == g_init_cap) {
        g_init_cap = g_init_cap ? g_init_cap * 2 : 16;
        g_init_order = realloc(g_init_order, g_init_cap * sizeof *g_init_order);
        if (!g_init_order) abort();
    }
    g_init_order[g_ninit++] = m;
}

static void run_finalizers(void) {
    while (g_ninit) {
        elf_module *m = g_init_order[--g_ninit];
        for (size_t i = m->fini_arraysz; i > 0; i--) {
            uint64_t f = m->fini_array[i - 1];
            if (f && f != (uint64_t)-1) ((void (*)(void))(uintptr_t)f)();
        }
        if (m->fini) ((void (*)(void))(m->base + m->fini))();
    }
}

elf_module *elf_load(const char *name, int argc, char **argv, char **envp) {
    pthread_mutex_lock(&g_lock);
    int is_host;
    elf_module *m = load_one(name, NULL, &is_host);
    if (m) run_init(m, argc, argv, envp);
    else if (is_host) set_error("%s is provided by the host", name);
    pthread_mutex_unlock(&g_lock);
    return m;
}

void *elf_module_sym(elf_module *m, const char *name) {
    const Elf64_Sym_ *s = module_lookup(m, name);
    return s ? sym_address(m, s) : NULL;
}

static elf_module *module_containing(const void *addr) {
    for (elf_module *m = g_modules; m; m = m->next)
        if ((const uint8_t *)addr >= m->map_start && (const uint8_t *)addr < m->map_start + m->map_size)
            return m;
    return NULL;
}

/* ---- overrides: what the loader itself provides to loaded code ------------- */

#define L_RTLD_NOLOAD 4
#define L_RTLD_NEXT ((void *)-1)

static int g_main_argc;
static char **g_main_argv, **g_main_envp;

static void *ov_dlopen(const char *name, int flags) {
    if (!name) return &g_host_handle; /* global scope */
    pthread_mutex_lock(&g_lock);
    g_error_pending = 0;
    void *ret;
    elf_module *m = find_loaded(name);
    if (m) {
        m->refcount++;
        ret = m;
    } else if (flags & L_RTLD_NOLOAD) {
        ret = NULL;
    } else {
        int is_host;
        elf_module *req = module_containing(__builtin_return_address(0));
        m = load_one(name, req, &is_host);
        if (m) run_init(m, g_main_argc, g_main_argv, g_main_envp);
        ret = m ? (void *)m : is_host ? (void *)&g_host_handle : NULL;
    }
    pthread_mutex_unlock(&g_lock);
    vlog("dlopen(%s) -> %p", name, ret);
    return ret;
}

static void *dep_tree_lookup(elf_module *m, const char *name, int depth) {
    const Elf64_Sym_ *s = module_lookup(m, name);
    if (s) return ELF64_ST_TYPE_(s->st_info) == STT_TLS_ ? NULL : sym_address(m, s);
    if (depth > 64) return NULL;
    for (int i = 0; i < m->n_needed; i++) {
        void *a = dep_tree_lookup(m->needed[i], name, depth + 1);
        if (a) return a;
    }
    return NULL;
}

static void *ov_dlsym(void *handle, const char *name) {
    void *addr = NULL;
    pthread_mutex_lock(&g_lock);
    g_error_pending = 0;
    if (handle == NULL || handle == &g_host_handle || handle == L_RTLD_NEXT) {
        resolved r;
        if (resolve(name, NULL, NULL, &r)) addr = r.addr;
    } else {
        addr = dep_tree_lookup(handle, name, 0);
        if (!addr) addr = lookup_override(name);
        if (!addr && g_host.lookup) addr = g_host.lookup(name, NULL);
    }
    pthread_mutex_unlock(&g_lock);
    if (!addr) set_error("undefined symbol: %s", name);
    return addr;
}

static int ov_dlclose(void *handle) {
    /* Modules stay mapped: unloading game modules is never needed and makes
     * dangling function pointers far more likely. */
    (void)handle;
    return 0;
}

static char *ov_dlerror(void) {
    if (!g_error_pending) return NULL;
    g_error_pending = 0;
    return g_error;
}

static int ov_dladdr(const void *addr, linux_Dl_info *info) {
    elf_module *m = module_containing(addr);
    if (!m) return 0;
    info->dli_fname = m->path;
    info->dli_fbase = m->map_start;
    info->dli_sname = NULL;
    info->dli_saddr = NULL;
    /* nearest preceding defined symbol */
    size_t nsyms = 0;
    if (m->sysv_hash) nsyms = m->sysv_hash[1];
    else if (m->gnu_hash) {
        const uint32_t *gh = m->gnu_hash;
        uint32_t nb = gh[0], so = gh[1];
        const uint32_t *buckets = (const uint32_t *)((const uint64_t *)(gh + 4) + gh[2]);
        uint32_t last = 0;
        for (uint32_t b = 0; b < nb; b++) if (buckets[b] > last) last = buckets[b];
        if (last >= so) {
            const uint32_t *chain = buckets + nb;
            while (!(chain[last - so] & 1)) last++;
            nsyms = last + 1;
        } else nsyms = so;
    }
    uintptr_t best = 0;
    for (size_t i = 1; i < nsyms; i++) {
        const Elf64_Sym_ *s = &m->symtab[i];
        if (!sym_defined(s) || ELF64_ST_TYPE_(s->st_info) == STT_TLS_) continue;
        uintptr_t a = (uintptr_t)(m->base + s->st_value);
        if (a <= (uintptr_t)addr && a > best) {
            best = a;
            info->dli_sname = m->strtab + s->st_name;
            info->dli_saddr = (void *)a;
        }
    }
    return 1;
}

static int ov_dl_iterate_phdr(int (*cb)(struct linux_dl_phdr_info *, size_t, void *), void *data) {
    int ret = 0;
    for (elf_module *m = g_modules; m && !ret; m = m->next) {
        struct linux_dl_phdr_info info = {
            .dlpi_addr = (uint64_t)(uintptr_t)m->base,
            .dlpi_name = m->path,
            .dlpi_phdr = m->phdr,
            .dlpi_phnum = m->phnum,
            .dlpi_adds = 1,
            .dlpi_subs = 0,
            .dlpi_tls_modid = m->tls_modid,
            .dlpi_tls_data = NULL,
        };
        ret = cb(&info, sizeof info, data);
    }
    if (!ret && g_host.iterate_phdr) ret = g_host.iterate_phdr(cb, data);
    return ret;
}

static int ov_dl_find_object(void *pc, struct linux_dl_find_object *res) {
    elf_module *m = module_containing(pc);
    if (!m) return g_host.find_object ? g_host.find_object(pc, res) : -1;
    memset(res, 0, sizeof *res);
    res->dlfo_map_start = m->map_start;
    res->dlfo_map_end = m->map_start + m->map_size;
    res->dlfo_link_map = m;
    res->dlfo_eh_frame = m->eh_frame_hdr;
    return 0;
}

/* glibc >= 2.34 _start calls this; older crt1 passes init/fini too. */
static int ov_libc_start_main(int (*main_fn)(int, char **, char **), int argc, char **argv,
                              void (*init)(void), void (*fini)(void), void (*rtld_fini)(void),
                              void *stack_end) {
    (void)init; (void)fini; (void)rtld_fini; (void)stack_end;
    exit(main_fn(argc, argv, argv + argc + 1));
}

static const struct { const char *name; void *addr; } g_overrides[] = {
    {"dlopen", (void *)ov_dlopen},
    {"dlsym", (void *)ov_dlsym},
    {"dlvsym", (void *)ov_dlsym},
    {"dlclose", (void *)ov_dlclose},
    {"dlerror", (void *)ov_dlerror},
    {"dladdr", (void *)ov_dladdr},
    {"dl_iterate_phdr", (void *)ov_dl_iterate_phdr},
    {"_dl_find_object", (void *)ov_dl_find_object},
    {"__tls_get_addr", (void *)ov_tls_get_addr},
    {"__libc_start_main", (void *)ov_libc_start_main},
};

static void *lookup_override(const char *name) {
    for (size_t i = 0; i < sizeof g_overrides / sizeof g_overrides[0]; i++)
        if (strcmp(name, g_overrides[i].name) == 0) return g_overrides[i].addr;
    return NULL;
}

/* ---- entry ------------------------------------------------------------------ */

void elf_loader_init(const elf_host *host) {
    g_host = *host;
    pthread_key_create(&g_dtv_key, dtv_free);
    atexit(run_finalizers);
}

_Noreturn void elf_exec(elf_module *exe, int argc, char **argv, char **envp) {
    g_main_argc = argc;
    g_main_argv = argv;
    g_main_envp = envp;
    int envc = 0;
    while (envp[envc]) envc++;

    const size_t stack_size = 8u << 20;
    uint8_t *stack = mmap(NULL, stack_size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANON, -1, 0);
    if (stack == MAP_FAILED) { perror("mmap stack"); abort(); }

    uint8_t *top = stack + stack_size - 64;
    uint8_t *random_bytes = top;
    for (int i = 0; i < 16; i++) random_bytes[i] = (uint8_t)rand();

    uint64_t auxv[] = {
        AT_PHDR_, (uint64_t)(uintptr_t)exe->phdr,
        AT_PHENT_, sizeof(Elf64_Phdr_),
        AT_PHNUM_, exe->phnum,
        AT_PAGESZ_, 4096,
        AT_BASE_, 0,
        AT_ENTRY_, (uint64_t)(uintptr_t)(exe->base + exe->entry),
        AT_RANDOM_, (uint64_t)(uintptr_t)random_bytes,
        AT_NULL_, 0,
    };
    size_t words = 1 + (size_t)argc + 1 + (size_t)envc + 1 + sizeof auxv / 8;
    uint64_t *sp = (uint64_t *)(((uintptr_t)(top - words * 8 - 16)) & ~(uintptr_t)15);
    uint64_t *w = sp;
    *w++ = (uint64_t)argc;
    for (int i = 0; i < argc; i++) *w++ = (uint64_t)(uintptr_t)argv[i];
    *w++ = 0;
    for (int i = 0; i < envc; i++) *w++ = (uint64_t)(uintptr_t)envp[i];
    *w++ = 0;
    memcpy(w, auxv, sizeof auxv);

    void *entry = exe->base + exe->entry;
    vlog("jumping to entry %p", entry);
    __asm__ volatile(
        "mov %0, %%rsp\n\t"
        "xor %%edx, %%edx\n\t" /* no rtld_fini */
        "xor %%ebp, %%ebp\n\t"
        "jmp *%1\n\t"
        :
        : "D"(sp), "a"(entry) /* fixed registers: edx/ebp are cleared above */
        : "memory");
    __builtin_unreachable();
}
