CC ?= cc
CFLAGS ?= -O2 -g -Wall -Wextra -std=c11
UNAME := $(shell uname -s)

ifeq ($(UNAME),Linux)
HOST_SRC = host_linux.c
LDLIBS = -ldl -lpthread
else
$(error macOS host shim is Phase 2; build on x86-64 Linux for now)
endif

elfload: main.c elf_loader.c $(HOST_SRC) elf_loader.h elf_defs.h host.h
	$(CC) $(CFLAGS) -o $@ main.c elf_loader.c $(HOST_SRC) $(LDLIBS)

clean:
	rm -f elfload

.PHONY: clean
