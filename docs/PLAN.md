# CS2 on Apple Silicon: port plan

Goal: run Counter-Strike 2 on Apple Silicon Macs as natively as possible.
This repo holds **only our own code and docs**. Valve's binaries and game
assets never go in it; each user points the tooling at their own install.

## 1. Where things stand

* Valve ships CS2 for **Windows (Direct3D 11)** and **Linux (Vulkan, SDL3,
  Steam Linux Runtime "sniper")**. There is no macOS build and no public source.
* **No Wine, CrossOver or Game Porting Toolkit.** This project builds its own
  macOS client from the **Linux** build only.
* "REA" ([morluto/rea](https://github.com/morluto/rea)) is an MCP server that
  gives coding agents disassembly and pseudocode (via Hopper, Ghidra or IDA)
  plus xrefs and strings. Its showcases rebuild small games function by
  function from that pseudocode and verify the result against the original.
  We use it the same way: to understand and reconstruct specific modules,
  not to regenerate the whole game at once (see section 2).

## 2. What "native" can and can't mean

| Layer | Fully native arm64 | Realistic best |
|---|---|---|
| GPU | Metal | Vulkan → Metal via **MoltenVK** (native arm64 driver path) |
| OS APIs | Cocoa / libSystem | Linux ABI shim over libSystem (no Wine) |
| Windowing/input/audio | Cocoa / CoreAudio | **Swap Valve's SDL3 for a macOS SDL3 build** |
| CPU code | arm64 machine code | x86-64 under **Rosetta 2** (AVX2 supported since macOS 15) |

A full arm64 rebuild means turning the whole game back into compilable source.
Decompiling everything with REA and recompiling is the end state we work
toward, but not the first step: matching decompilation projects take years for
games a few MB in size, while CS2's Linux client is many times larger and
updates weekly, so a decompile-everything-first plan would not boot for a very
long time. The survey (`code_bytes` per module) will put an exact size on it.
Instead the plan **runs the original Linux code first**, then replaces it with
REA-reconstructed native code one module at a time (Phase 7). macOS also can't mix arm64 and x86-64
code in one process, so every module we load runs under Rosetta; the GPU work,
the Metal driver and the kernel are native either way.

**The chosen path:** load the **Linux** build directly in a small x86-64
Mach-O host process, with no Wine and no D3D translation. Linux and macOS
both use the System V x86-64 calling convention, so most calls can pass
straight through; we only translate where data layouts or semantics differ
(`stat`, `dirent`, pthread types, errno values, signals, `epoll`, TLS...).
There is no Win32 layer and no D3D11 translation, leaving only Rosetta (CPU)
and MoltenVK (Vulkan→Metal) until reconstructed modules start replacing the
x86 code.

## 3. Constraints

* **VAC / anti-cheat.** A loader that injects shims into the game process is
  exactly what anti-cheat looks for. Development and testing stay on
  `-insecure`, offline maps, and private servers. Do not take a modified
  client onto VAC-secured servers; a ban is permanent and account-wide.
* **Legal.** Users supply their own legally obtained game files. We don't
  redistribute or patch Valve binaries on disk; any fixups happen in memory.
* **Updates.** CS2 updates often. The shim targets *library interfaces*
  (glibc, SDL3, Vulkan, Steamworks), which change rarely, never game internals.

## 4. Phases

Each phase ends with something measurable before the next starts.

### Phase 0: Recon
* Get the **Linux** depot onto the Mac (SteamCMD/DepotDownloader with the
  user's own account, `+@sSteamCmdForcePlatformType linux`).
* Run `tools/elf_survey.py` over it (**done: first concrete step**). It
  reports every ELF module, which libraries come from outside the install,
  and every external symbol the game needs, grouped by library. That list
  *is* the shim's to-do list and sizes the work for Phase 2.
* Extract the Vulkan extensions/features the renderer asks for and diff
  against MoltenVK's support matrix (output of the same tool).

**Exit:** a committed report (no Valve code in it, only symbol names) with
the external import surface and a Vulkan gap list.

### Phase 1: ELF loader on macOS
* `loader/`: an x86-64 Mach-O executable (runs under Rosetta) that maps ELF
  shared objects, applies relocations (`R_X86_64_RELATIVE`, `GLOB_DAT`,
  `JUMP_SLOT`, `64`, TLS relocs), runs `DT_INIT`/`init_array`, and resolves
  imports from an in-process symbol table instead of `ld.so`.
* ELF TLS: implement static TLS block + `__tls_get_addr` on top of a macOS
  pthread key, since Mach-O TLS works differently.
* Developed and unit-tested on Linux first (same code, same ELF files), then
  built for macOS.

**Exit:** a test `.so` compiled on Linux, calling `printf`, `pthread_create`
and using `__thread`, runs inside the loader on an M-series Mac.

### Phase 2: Linux ABI shim
* Implement the glibc/libstdc++/libm/libdl/libpthread/librt symbols from the
  Phase 0 report, mapping to libSystem with struct and constant translation.
  Pass-through by default; translate only where layouts differ.
* Linux-only APIs (`epoll`, `eventfd`, `inotify`, `/proc` reads) get kqueue /
  FSEvents / sysctl implementations.
* `dlopen` of game modules routes back to our loader; `dlopen` of
  system libraries routes to the shim.

**Exit:** `cs2` reaches the engine's own console output and loads every game
module without unresolved symbols (run with `-dedicated` first: a dedicated
server needs no GPU, window or audio, so it isolates the ABI work).

### Phase 3: Platform layer via SDL3
* Point the game's `libSDL3.so` import at a macOS x86-64 SDL3 build. SDL's
  public ABI is platform independent, so window, input, audio and
  `SDL_Vulkan_CreateSurface` (→ `VK_EXT_metal_surface`) come for free.
* Raw mouse input and high-refresh cursor capture checked specifically,
  since CS2 is very sensitive to them.

### Phase 4: Vulkan → Metal
* Route `libvulkan.so.1` to MoltenVK (x86-64 slice, so it can live in the
  same process; Metal itself runs natively).
* Close the gaps from the Phase 0 diff: feature emulation, extension stubs,
  and SPIR-V → MSL issues found via `MVK_CONFIG_LOG_LEVEL` and Metal capture.
* Shader cache warming, since first-run SPIR-V→MSL conversion causes stutter.

**Exit:** reaches the main menu, then loads an offline map.

### Phase 5: Steam integration
* Route `libsteam_api.so` imports to the macOS `libsteam_api.dylib` from the
  Steamworks SDK (flat C API, same ABI) so the game talks to the native
  macOS Steam client. Offline/insecure play first.

### Phase 6: Performance and polish
* Profile with Instruments: Rosetta JIT hot spots, Metal frame capture,
  shim overhead per call, thread QoS (pin render/main threads to P-cores).
* Benchmark a fixed demo against the same build on a Linux PC as reference.
* App bundle + launcher script that points at the user's install.

### Phase 7: REA reconstruction to native arm64
The step from "runs on macOS" to "native macOS client".
* **Switch the host to arm64.** A Rosetta process can't mix arm64 and x86-64
  code, so the host becomes a native arm64 process with an embedded x86-64
  translator for whatever Valve code remains. [box64](https://github.com/ptitSeb/box64)
  (MIT) already does this on arm64 Linux, including calling native libraries
  from translated code; we port its dynarec to Darwin (`MAP_JIT`, W^X
  toggling, 16K pages). The shim, SDL3, MoltenVK and Steam then run as native
  arm64, and only game modules are translated.
* **Replace modules one at a time.** For each module, starting with small
  leaf libraries and the hottest code from Phase 6 profiles: decompile with
  REA, rebuild as C/C++, compile for arm64, and load it in place of the x86
  module through the same export table. Each reconstructed function is
  checked against the original by differential tests (same inputs, same
  outputs, run through the translator vs native), as REA's own showcases do.
* Track progress as "% of code bytes native" from `elf_survey.py`.
* Reconstructed code is derived from Valve's binaries. It stays out of this
  repo unless and until its legal status is clear; the repo holds the
  tooling, tests and the host.

## 5. Fallback

* If Phase 2 stalls: run the Linux build in a lightweight Linux VM
  (Rosetta for Linux + virtio-gpu Venus → MoltenVK). Slower, but proves the
  Vulkan path and reuses Phase 4 work.

## 6. Repo layout (planned)

```
docs/        plan, survey reports, decisions
tools/       recon scripts (elf_survey.py, ...)
loader/      Phase 1 ELF loader (C)
shim/        Phase 2 Linux ABI shim (C)
tests/       ELF fixtures built from our own sources
```
