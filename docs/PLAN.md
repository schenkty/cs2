# CS2 on Apple Silicon: port plan

Goal: run Counter-Strike 2 on Apple Silicon Macs as natively as possible.
This repo holds **only our own code and docs**. Valve's binaries and game
assets never go in it; each user points the tooling at their own install.

## 1. Where things stand

* Valve ships CS2 for **Windows (Direct3D 11)** and **Linux (Vulkan, SDL3,
  Steam Linux Runtime "sniper")**. There is no macOS build and no public source.
* The working option today is **CrossOver / Game Porting Toolkit**: the Windows
  build runs under Wine, x86-64 code goes through Rosetta 2, and D3D11 is
  translated to Metal by D3DMetal (or DXVK + MoltenVK). It works, but with
  three translation layers in the way (Win32 API, x86 CPU, D3D11).
* "REA" ([morluto/rea](https://github.com/morluto/rea)) is an MCP server that
  gives coding agents Hopper-backed disassembly. It helps answer targeted
  questions about specific functions. It does not recover source code, so it is
  a supporting tool here, not a foundation.

## 2. What "native" can and can't mean

| Layer | Fully native arm64 | Realistic best |
|---|---|---|
| GPU | Metal | Vulkan → Metal via **MoltenVK** (native arm64 driver path) |
| OS APIs | Cocoa / libSystem | Linux ABI shim over libSystem (no Wine) |
| Windowing/input/audio | Cocoa / CoreAudio | **Swap Valve's SDL3 for a macOS SDL3 build** |
| CPU code | arm64 machine code | x86-64 under **Rosetta 2** (AVX2 supported since macOS 15) |

A true arm64 recompile of the game code needs Valve's source. Static binary
translation (lifting x86-64 to LLVM IR and recompiling) of ~1 GB of
multithreaded SSE/AVX code that updates weekly is research, not a plan, so it
is parked as an optional late phase. macOS also can't mix arm64 and x86-64
code in one process, so every module we load runs under Rosetta; the GPU work,
the Metal driver and the kernel are native either way.

**The chosen path:** load the **Linux** build directly in a small x86-64
Mach-O host process, with no Wine and no D3D translation. Linux and macOS
both use the System V x86-64 calling convention, so most calls can pass
straight through; we only translate where data layouts or semantics differ
(`stat`, `dirent`, pthread types, errno values, signals, `epoll`, TLS...).
Compared with CrossOver this removes the Win32 layer and the D3D11→Metal
layer, leaving Rosetta (CPU) and MoltenVK (Vulkan→Metal), which is as close
to native as is possible without source.

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

### Phase 0: Baseline and recon
* Install CS2 via CrossOver on the target Mac; record FPS on a fixed demo
  (`timedemo`-style run, same settings) as the number to beat.
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
* Compare against the Phase 0 CrossOver baseline.
* App bundle + launcher script that points at the user's install.

### Phase 7 (optional, research): arm64 for hot paths
* Investigate static translation of a single module (e.g. a math-heavy one)
  to arm64 running out-of-process or via a full arm64 host, only if Phase 6
  shows Rosetta is the bottleneck.

## 5. Fallbacks

* If Phase 2 stalls: run the Linux build in a lightweight Linux VM
  (Rosetta for Linux + virtio-gpu Venus → MoltenVK). Slower, but proves the
  Vulkan path and reuses Phase 4 work.
* CrossOver / GPTK stays the "it just runs" option throughout.

## 6. Repo layout (planned)

```
docs/        plan, survey reports, decisions
tools/       recon scripts (elf_survey.py, ...)
loader/      Phase 1 ELF loader (C)
shim/        Phase 2 Linux ABI shim (C)
tests/       ELF fixtures built from our own sources
```
