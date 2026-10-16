/* Linux test host: the "shim" is the real glibc, reached with dlsym. This lets
 * the loader be developed and tested on Linux with the same ELF files before
 * the macOS shim exists. */
#define _GNU_SOURCE
#include <dlfcn.h>
#include <link.h>
#include <string.h>

#include "host.h"

#define MAX_HOST_LIBS 32
static const char *g_libs[MAX_HOST_LIBS] = {
    "libc.so.6", "libm.so.6", "libdl.so.2", "libpthread.so.0", "librt.so.1",
    "ld-linux-x86-64.so.2", "libresolv.so.2", "libutil.so.1",
};
static int g_nlibs = 8;

void host_add_library(const char *soname) {
    if (g_nlibs < MAX_HOST_LIBS) g_libs[g_nlibs++] = soname;
}

static int has_library(const char *soname) {
    for (int i = 0; i < g_nlibs; i++) {
        if (strcmp(g_libs[i], soname) == 0) {
            /* Make its symbols visible to RTLD_DEFAULT lookups. */
            return dlopen(soname, RTLD_NOW | RTLD_GLOBAL) != NULL;
        }
    }
    return 0;
}

static void *lookup(const char *name, const char *version) {
    void *p = version ? dlvsym(RTLD_DEFAULT, name, version) : NULL;
    return p ? p : dlsym(RTLD_DEFAULT, name);
}

static int iterate_phdr(int (*cb)(struct linux_dl_phdr_info *, size_t, void *), void *data) {
    /* glibc's struct dl_phdr_info has the same layout. */
    return dl_iterate_phdr((int (*)(struct dl_phdr_info *, size_t, void *))cb, data);
}

static int find_object(void *pc, struct linux_dl_find_object *result) {
    static int (*real)(void *, struct linux_dl_find_object *);
    if (!real) real = (int (*)(void *, struct linux_dl_find_object *))dlsym(RTLD_DEFAULT, "_dl_find_object");
    return real ? real(pc, result) : -1;
}

const elf_host *host_get(void) {
    static const elf_host host = {has_library, lookup, iterate_phdr, find_object};
    return &host;
}
