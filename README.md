# cs2

Running Counter-Strike 2 on Apple Silicon as natively as possible: the Linux
(Vulkan) build loaded in a macOS host process, with a Linux ABI shim, a macOS
SDL3, and MoltenVK for Vulkan → Metal. See [docs/PLAN.md](docs/PLAN.md).

This repo contains only our own code. Bring your own copy of the game; never
commit Valve binaries or assets.

## Phase 0: survey the Linux build

1. Download just the Linux binaries (about 1 GB rather than the whole game)
   with [DepotDownloader](https://github.com/SteamRE/DepotDownloader), using
   your own Steam account:

   ```sh
   DepotDownloader -app 730 -os linux -osarch 64 -username <you> \
     -filelist tools/cs2_linux_binaries.txt -dir cs2-linux
   ```

   (Or the full install: `steamcmd +@sSteamCmdForcePlatformType linux
   +force_install_dir $PWD/cs2-linux +login <you> +app_update 730 +quit`.)

2. Run the survey (Python 3.9+, no dependencies):

   ```sh
   python3 tools/elf_survey.py cs2-linux --markdown survey.md --json survey.json
   ```

   The report lists every module, the system libraries it needs, every
   external symbol grouped by library and version, and the Vulkan extensions
   the renderer references. It contains names only, no Valve code.

## Phase 1: the loader

`loader/elfload` runs Linux x86-64 programs through our own ELF loader
instead of the system `ld.so` (Linux for now; the macOS build needs the
Phase 2 shim):

```sh
make -C loader
loader/elfload -L /path/to/libs program [args...]
loader/elfload --call symbol library.so     # call int symbol(void)
```

`-v` logs mapping and linking; `--strict` fails on unresolved symbols
instead of stubbing them.

## Tests

```sh
python3 -m unittest discover -s tests   # needs gcc, g++, make on x86-64 Linux
```
