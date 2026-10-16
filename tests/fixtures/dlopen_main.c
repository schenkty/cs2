// Program that loads a library at runtime with dlopen, as game engines do.
#define _GNU_SOURCE
#include <dlfcn.h>
#include <stdio.h>

int main(int argc, char **argv) {
    if (argc < 2) return 100;
    void *h = dlopen(argv[1], RTLD_NOW);
    if (!h) { printf("dlopen failed: %s\n", dlerror()); return 101; }
    int (*run)(void) = (int (*)(void))dlsym(h, "cxx_run");
    void (*thrower)(int) = (void (*)(int))dlsym(h, "cxx_throw");
    if (!run || !thrower) { printf("dlsym failed\n"); return 102; }
    if (dlsym(h, "no_such_symbol") || !dlerror()) return 103;
    Dl_info info;
    if (!dladdr((void *)run, &info) || !info.dli_sname) return 104;
    printf("dladdr: %s\n", info.dli_sname);
    return run();
}
