/* elfload: run a Linux x86-64 program, or call a function in a Linux shared
 * library, through our own ELF loader instead of ld.so.
 *
 *   elfload [options] program [args...]
 *   elfload [options] --call symbol library.so
 *
 * Options:
 *   -L dir           add a library search directory
 *   --host-lib name  treat a soname as provided by the host
 *   --strict         fail on unresolved symbols instead of stubbing them
 *   -v               log loading steps to stderr
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "elf_loader.h"
#include "host.h"

extern char **environ;

static int usage(void) {
    fprintf(stderr,
            "usage: elfload [-v] [--strict] [-L dir]... [--host-lib soname]... program [args...]\n"
            "       elfload [options] --call symbol library.so\n");
    return 2;
}

int main(int argc, char **argv) {
    const char *call = NULL;
    int i = 1;
    for (; i < argc && argv[i][0] == '-'; i++) {
        if (strcmp(argv[i], "-v") == 0) elf_loader_set_verbose(1);
        else if (strcmp(argv[i], "--strict") == 0) elf_loader_set_strict(1);
        else if (strcmp(argv[i], "-L") == 0 && i + 1 < argc) elf_loader_add_search_path(argv[++i]);
        else if (strcmp(argv[i], "--host-lib") == 0 && i + 1 < argc) host_add_library(argv[++i]);
        else if (strcmp(argv[i], "--call") == 0 && i + 1 < argc) call = argv[++i];
        else return usage();
    }
    if (i >= argc) return usage();

    elf_loader_init(host_get());
    int pargc = argc - i;
    char **pargv = argv + i;
    elf_module *m = elf_load(pargv[0], pargc, pargv, environ);
    if (!m) {
        fprintf(stderr, "elfload: %s\n", elf_loader_error());
        return 127;
    }
    if (elf_loader_unresolved_count())
        fprintf(stderr, "elfload: %zu unresolved symbols bound to aborting stubs\n",
                elf_loader_unresolved_count());

    if (call) {
        int (*fn)(void) = (int (*)(void))elf_module_sym(m, call);
        if (!fn) {
            fprintf(stderr, "elfload: %s: no symbol '%s'\n", pargv[0], call);
            return 127;
        }
        return fn();
    }
    if (!elf_module_is_exec(m)) {
        fprintf(stderr, "elfload: %s is a library; use --call\n", pargv[0]);
        return 2;
    }
    elf_exec(m, pargc, pargv, environ);
}
