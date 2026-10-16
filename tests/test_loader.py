"""End-to-end tests for loader/elfload, using fixtures built from our sources.

Each fixture runs once natively (system ld.so) and once through elfload, and
the results must match. Needs gcc/g++/make on x86-64 Linux; skipped elsewhere.
Run: python3 -m unittest discover -s tests
"""

import os
import platform
import shutil
import subprocess
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
FIX = os.path.join(HERE, "fixtures")
ELFLOAD = os.path.join(ROOT, "loader", "elfload")
LIBDIR = "/usr/lib/x86_64-linux-gnu"


@unittest.skipUnless(platform.system() == "Linux" and platform.machine() == "x86_64"
                     and shutil.which("gcc") and shutil.which("g++") and shutil.which("make"),
                     "needs gcc, g++ and make on x86-64 Linux")
class LoaderTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        subprocess.check_call(["make", "-s", "-C", os.path.join(ROOT, "loader")])
        cls.tmp = tempfile.mkdtemp()
        t = cls.tmp

        def cc(*args):
            subprocess.check_call(list(args))

        cc("gcc", "-O1", "-fPIC", "-shared", "-Wl,-soname,libgame.so", "-o", t + "/libgame.so",
           FIX + "/libgame.c", "-lpthread")
        cc("gcc", "-O1", "-fPIE", "-pie", "-o", t + "/launcher", FIX + "/launcher.c",
           "-L" + t, "-lgame", "-lm")
        cc("g++", "-O1", "-fPIC", "-shared", "-o", t + "/libcxx.so", FIX + "/libcxx.cpp")
        cc("gcc", "-O1", "-fPIE", "-pie", "-o", t + "/dlopen_main", FIX + "/dlopen_main.c")
        cc("gcc", "-O1", "-fPIC", "-shared", "-o", t + "/libmissing.so", FIX + "/libmissing.c")

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.tmp)

    def native(self, *args):
        env = dict(os.environ, LD_LIBRARY_PATH=self.tmp)
        return subprocess.run(list(args), env=env, capture_output=True, text=True)

    def loader(self, *args):
        return subprocess.run([ELFLOAD, "-L", self.tmp, "-L", LIBDIR, *args],
                              capture_output=True, text=True)

    def assertSameAsNative(self, *args):
        n, l = self.native(*args), self.loader(*args)
        self.assertEqual((l.returncode, l.stdout), (n.returncode, n.stdout), l.stderr)
        return l

    def test_pie_executable_with_tls_and_threads(self):
        r = self.assertSameAsNative(self.tmp + "/launcher", "a", "b")
        self.assertEqual(r.returncode, 8)
        self.assertIn("tick 1", r.stdout)

    def test_call_library_function(self):
        r = self.loader("--call", "game_tick", self.tmp + "/libgame.so")
        self.assertEqual(r.returncode, 7)
        self.assertEqual(r.stdout, "tick 1\n")

    def test_cxx_runtime_via_dlopen(self):
        # libstdc++ and libgcc_s are loaded by elfload, not the system:
        # exercises symbol versioning, unwinding through _dl_find_object,
        # thread_local, std::thread, iostreams and static destructors.
        r = self.assertSameAsNative(self.tmp + "/dlopen_main", "libcxx.so")
        self.assertEqual(r.returncode, 7)
        self.assertEqual(r.stdout, "dladdr: cxx_run\niostream ok\nglobal dtor\n")

    def test_unresolved_symbol_is_stubbed(self):
        lib = self.tmp + "/libmissing.so"
        ok = self.loader("--call", "does_not_call_missing", lib)
        self.assertEqual(ok.returncode, 5)
        self.assertIn("1 unresolved symbols", ok.stderr)
        bad = self.loader("--call", "calls_missing", lib)
        self.assertNotEqual(bad.returncode, 0)
        self.assertIn("called unresolved symbol 'missing_fn'", bad.stderr)

    def test_strict_mode_fails_at_load(self):
        r = self.loader("--strict", "--call", "does_not_call_missing", self.tmp + "/libmissing.so")
        self.assertEqual(r.returncode, 127)
        self.assertIn("unresolved symbol 'missing_fn'", r.stderr)

    def test_real_world_python(self):
        # A large non-PIE executable (fixed load address) that dlopens
        # extension modules, which pull in OpenSSL, SQLite and libffi.
        py = os.path.realpath(shutil.which("python3") or "")
        if not py:
            self.skipTest("no python3")
        code = ("import json, ssl, sqlite3, ctypes, hashlib, threading\n"
                "t = [threading.Thread(target=hashlib.sha256, args=(b'x' * 99999,)) for _ in range(4)]\n"
                "[x.start() for x in t]; [x.join() for x in t]\n"
                "print(json.dumps([ctypes.CDLL(None).abs(-3), sqlite3.connect(':memory:')"
                ".execute('select 6*7').fetchone()[0]]))")
        r = self.loader(py, "-c", code)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(r.stdout, "[3, 42]\n")

    def test_missing_file_fails(self):
        r = self.loader(self.tmp + "/launcher.nope")
        self.assertEqual(r.returncode, 127)


if __name__ == "__main__":
    unittest.main()
