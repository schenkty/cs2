/* Minimal ELF64 / x86-64 definitions, so the loader builds on macOS, which
 * has no <elf.h>. Layouts follow the System V gABI and the x86-64 psABI. */
#ifndef ELF_DEFS_H
#define ELF_DEFS_H

#include <stddef.h>
#include <stdint.h>

typedef struct {
    unsigned char e_ident[16];
    uint16_t e_type, e_machine;
    uint32_t e_version;
    uint64_t e_entry, e_phoff, e_shoff;
    uint32_t e_flags;
    uint16_t e_ehsize, e_phentsize, e_phnum, e_shentsize, e_shnum, e_shstrndx;
} Elf64_Ehdr_;

typedef struct {
    uint32_t p_type, p_flags;
    uint64_t p_offset, p_vaddr, p_paddr, p_filesz, p_memsz, p_align;
} Elf64_Phdr_;

typedef struct {
    int64_t d_tag;
    uint64_t d_val;
} Elf64_Dyn_;

typedef struct {
    uint32_t st_name;
    unsigned char st_info, st_other;
    uint16_t st_shndx;
    uint64_t st_value, st_size;
} Elf64_Sym_;

typedef struct {
    uint64_t r_offset, r_info;
    int64_t r_addend;
} Elf64_Rela_;

typedef struct {
    uint16_t vn_version, vn_cnt;
    uint32_t vn_file, vn_aux, vn_next;
} Elf64_Verneed_;

typedef struct {
    uint32_t vna_hash;
    uint16_t vna_flags, vna_other;
    uint32_t vna_name, vna_next;
} Elf64_Vernaux_;

typedef struct {
    uint16_t vd_version, vd_flags, vd_ndx, vd_cnt;
    uint32_t vd_hash, vd_aux, vd_next;
} Elf64_Verdef_;

typedef struct {
    uint32_t vda_name, vda_next;
} Elf64_Verdaux_;

#define ELFCLASS64_ 2
#define ELFDATA2LSB_ 1
#define ET_EXEC_ 2
#define ET_DYN_ 3
#define EM_X86_64_ 62

#define PT_LOAD_ 1
#define PT_DYNAMIC_ 2
#define PT_PHDR_ 6
#define PT_TLS_ 7
#define PT_GNU_EH_FRAME_ 0x6474e550
#define PF_X_ 1
#define PF_W_ 2
#define PF_R_ 4

#define DT_NULL_ 0
#define DT_NEEDED_ 1
#define DT_PLTRELSZ_ 2
#define DT_HASH_ 4
#define DT_STRTAB_ 5
#define DT_SYMTAB_ 6
#define DT_RELA_ 7
#define DT_RELASZ_ 8
#define DT_STRSZ_ 10
#define DT_INIT_ 12
#define DT_FINI_ 13
#define DT_SONAME_ 14
#define DT_RPATH_ 15
#define DT_JMPREL_ 23
#define DT_INIT_ARRAY_ 25
#define DT_FINI_ARRAY_ 26
#define DT_INIT_ARRAYSZ_ 27
#define DT_FINI_ARRAYSZ_ 28
#define DT_RUNPATH_ 29
#define DT_GNU_HASH_ 0x6ffffef5
#define DT_VERSYM_ 0x6ffffff0
#define DT_VERDEF_ 0x6ffffffc
#define DT_VERDEFNUM_ 0x6ffffffd
#define DT_VERNEED_ 0x6ffffffe
#define DT_VERNEEDNUM_ 0x6fffffff

#define STB_GLOBAL_ 1
#define STB_WEAK_ 2
#define STB_GNU_UNIQUE_ 10
#define STT_TLS_ 6
#define STT_GNU_IFUNC_ 10
#define SHN_UNDEF_ 0

#define R_X86_64_NONE_ 0
#define R_X86_64_64_ 1
#define R_X86_64_PC32_ 2
#define R_X86_64_COPY_ 5
#define R_X86_64_GLOB_DAT_ 6
#define R_X86_64_JUMP_SLOT_ 7
#define R_X86_64_RELATIVE_ 8
#define R_X86_64_DTPMOD64_ 16
#define R_X86_64_DTPOFF64_ 17
#define R_X86_64_TPOFF64_ 18
#define R_X86_64_IRELATIVE_ 37

#define ELF64_R_SYM_(i) ((uint32_t)((i) >> 32))
#define ELF64_R_TYPE_(i) ((uint32_t)(i))
#define ELF64_ST_BIND_(i) ((i) >> 4)
#define ELF64_ST_TYPE_(i) ((i) & 0xf)

#define AT_NULL_ 0
#define AT_PHDR_ 3
#define AT_PHENT_ 4
#define AT_PHNUM_ 5
#define AT_PAGESZ_ 6
#define AT_BASE_ 7
#define AT_ENTRY_ 9
#define AT_RANDOM_ 25

/* glibc's struct dl_phdr_info and struct dl_find_object, as Linux code sees
 * them. Defined here because the macOS host has neither. */
struct linux_dl_phdr_info {
    uint64_t dlpi_addr;
    const char *dlpi_name;
    const Elf64_Phdr_ *dlpi_phdr;
    uint16_t dlpi_phnum;
    unsigned long long dlpi_adds, dlpi_subs;
    size_t dlpi_tls_modid;
    void *dlpi_tls_data;
};

struct linux_dl_find_object {
    unsigned long long dlfo_flags;
    void *dlfo_map_start, *dlfo_map_end;
    void *dlfo_link_map;
    void *dlfo_eh_frame;
    unsigned long long reserved[7];
};

/* glibc's Dl_info, used by dladdr. */
typedef struct {
    const char *dli_fname;
    void *dli_fbase;
    const char *dli_sname;
    void *dli_saddr;
} linux_Dl_info;

#endif
