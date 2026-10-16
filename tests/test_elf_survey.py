"""Tests for tools/elf_survey.py, built from our own fixture sources.

Needs gcc on an x86-64 Linux host; skipped elsewhere.
Run: python3 -m unittest discover -s tests
"""

import os
import platform
import shutil
import subprocess
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "..", "tools"))

import elf_survey  # noqa: E402

FIXTURES = os.path.join(HERE, "fixtures")


@unittest.skipUnless(shutil.which("gcc") and platform.system() == "Linux"
                     and platform.machine() == "x86_64", "needs gcc on x86-64 Linux")
class SurveyTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.mkdtemp()
        bindir = os.path.join(cls.tmp, "game", "bin")
        os.makedirs(bindir)
        cc = ["gcc", "-O1", "-fPIC"]
        subprocess.check_call(cc + ["-shared", "-Wl,-soname,libgame.so", "-o",
                                    os.path.join(bindir, "libgame.so"),
                                    os.path.join(FIXTURES, "libgame.c"), "-lpthread"])
        for hash_style in ("gnu", "sysv"):
            subprocess.check_call(cc + ["-Wl,--hash-style=" + hash_style, "-o",
                                        os.path.join(bindir, "launcher_" + hash_style),
                                        os.path.join(FIXTURES, "launcher.c"),
                                        "-L" + bindir, "-lgame", "-lm"])
        with open(os.path.join(bindir, "readme.txt"), "w") as f:
            f.write("not an elf")
        cls.modules, cls.errors = elf_survey.survey(cls.tmp)
        cls.result = elf_survey.analyze(cls.modules)

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.tmp)

    def test_finds_only_elves(self):
        self.assertEqual(sorted(self.modules), [
            "game/bin/launcher_gnu", "game/bin/launcher_sysv", "game/bin/libgame.so"])
        self.assertEqual(self.errors, {})

    def test_module_metadata(self):
        lib = self.modules["game/bin/libgame.so"]
        self.assertEqual(lib["soname"], "libgame.so")
        self.assertGreater(lib["tls_bytes"], 0)
        self.assertIn("game_tick", lib["exports"])
        exe = self.modules["game/bin/launcher_gnu"]
        self.assertIn(exe["type"], ("exec", "dyn"))
        self.assertIn("libgame.so", exe["needed"])
        self.assertTrue(exe["interp"].startswith("/lib"))

    def test_internal_imports_not_external(self):
        all_external = {n for syms in self.result["external_symbols"].values() for n in syms}
        self.assertNotIn("game_tick", all_external)
        self.assertNotIn("game_spawn", all_external)
        self.assertNotIn("libgame.so", self.result["external_libs"])

    def test_external_symbols_grouped_by_versioned_lib(self):
        ext = self.result["external_symbols"]
        self.assertIn("pthread_create", ext["libc.so.6"])
        self.assertTrue(all(v.startswith("GLIBC_")
                            for v in ext["libc.so.6"]["pthread_create"]["versions"]))
        self.assertIn("sqrt", ext["libm.so.6"])
        self.assertIn("libc.so.6", self.result["external_libs"])

    def test_both_hash_styles_agree(self):
        gnu = {i["name"] for i in self.modules["game/bin/launcher_gnu"]["imports"]}
        sysv = {i["name"] for i in self.modules["game/bin/launcher_sysv"]["imports"]}
        self.assertEqual(gnu, sysv)
        self.assertIn("game_tick", gnu)

    def test_vulkan_extensions(self):
        self.assertIn("VK_KHR_swapchain", self.result["vulkan_extensions"])

    def test_matches_readelf(self):
        if not shutil.which("readelf"):
            self.skipTest("readelf not installed")
        path = os.path.join(self.tmp, "game", "bin", "libgame.so")
        out = subprocess.check_output(["readelf", "--dyn-syms", "-W", path], text=True)
        undef = set()
        for line in out.splitlines():
            parts = line.split()
            if len(parts) >= 8 and parts[6] == "UND" and parts[4] in ("GLOBAL", "WEAK"):
                undef.add(parts[7].split("@")[0])
        ours = {i["name"] for i in self.modules["game/bin/libgame.so"]["imports"]}
        self.assertEqual(ours, undef)

    def test_markdown_renders(self):
        md = elf_survey.to_markdown(self.tmp, self.modules, self.errors, self.result)
        self.assertIn("## External libraries", md)
        self.assertIn("`libc.so.6`", md)


if __name__ == "__main__":
    unittest.main()
