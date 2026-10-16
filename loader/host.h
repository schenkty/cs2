/* The host side of the loader: which libraries and symbols the platform
 * provides. host_linux.c passes through to glibc; the macOS shim comes in
 * Phase 2. */
#ifndef HOST_H
#define HOST_H

#include "elf_loader.h"

const elf_host *host_get(void);
/* Treat another soname as host-provided (e.g. libstdc++.so.6). */
void host_add_library(const char *soname);

#endif
