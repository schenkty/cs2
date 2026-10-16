/* ELF loader: maps x86-64 Linux shared objects and executables into the
 * current process and links them without the system's ld.so.
 *
 * Imports are resolved, in order, against the loader's own overrides
 * (dlopen family, TLS, unwinder hooks, __libc_start_main), then the modules
 * already loaded (global scope, load order), then the host. The host is the
 * Linux ABI shim on macOS, or plain dlsym passthrough when testing on Linux. */
#ifndef ELF_LOADER_H
#define ELF_LOADER_H

#include <stddef.h>
#include "elf_defs.h"

typedef struct elf_module elf_module;

typedef struct elf_host {
    /* Nonzero if the host provides this library itself (e.g. libc.so.6),
     * so the loader should not look for an ELF file for it. */
    int (*has_library)(const char *soname);
    /* Address of a host symbol, or NULL. version is the ELF symbol version
     * the importer asked for (e.g. "GLIBC_2.3.2"), or NULL. */
    void *(*lookup)(const char *name, const char *version);
    /* Optional: chain to the host's own dl_iterate_phdr / _dl_find_object
     * for addresses that are not in a loaded module. */
    int (*iterate_phdr)(int (*cb)(struct linux_dl_phdr_info *, size_t, void *), void *data);
    int (*find_object)(void *pc, struct linux_dl_find_object *result);
} elf_host;

void elf_loader_init(const elf_host *host);
void elf_loader_add_search_path(const char *dir);
/* strict: fail the load on an unresolved strong symbol. Otherwise it binds to
 * a stub that reports the symbol's name and aborts only if it is called,
 * which lets the shim be filled in incrementally. */
void elf_loader_set_strict(int strict);
void elf_loader_set_verbose(int verbose);

/* Load a module and its dependencies, relocate them, and run their
 * initializers (deps first). name may be a path or a bare soname.
 * Returns NULL and sets elf_loader_error() on failure. */
elf_module *elf_load(const char *name, int argc, char **argv, char **envp);
const char *elf_loader_error(void);

void *elf_module_sym(elf_module *m, const char *name);
int elf_module_is_exec(const elf_module *m);
size_t elf_loader_unresolved_count(void);

/* Transfer control to an executable's entry point with a Linux-style initial
 * stack. Its _start reaches our __libc_start_main, which calls main and exits. */
_Noreturn void elf_exec(elf_module *exe, int argc, char **argv, char **envp);

#endif
