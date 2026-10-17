"""Generators must reproduce their committed outputs byte for byte
(run: python3 -m unittest discover tests/scripts)."""
import glob
import pathlib
import re
import shutil
import subprocess
import sys
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[2]


def run(script, *args, cwd=ROOT):
    return subprocess.run([sys.executable, str(ROOT / "scripts" / script), *args],
                          cwd=cwd, check=True, capture_output=True, text=True)


class RegenTest(unittest.TestCase):
    def regen_next_to_inputs(self, script, vec_dir, ext):
        inputs = sorted(glob.glob(str(ROOT / vec_dir / ("*" + ext))))
        self.assertTrue(inputs)
        with tempfile.TemporaryDirectory() as d:
            copies = [shutil.copy(p, d) for p in inputs]
            run(script, *copies)
            for p in inputs:
                h = pathlib.Path(p).with_suffix(".h")
                got = pathlib.Path(d, h.name).read_bytes()
                self.assertEqual(got, h.read_bytes(), h.name)

    def test_bssl_vectors(self):
        self.regen_next_to_inputs("gen_bssl_vectors.py", "tests/vectors/boringssl", ".txt")

    def test_wycheproof_vectors(self):
        self.regen_next_to_inputs("gen_wycheproof_vectors.py", "tests/vectors/wycheproof", ".json")

    def test_moqt_golden(self):
        with tempfile.TemporaryDirectory() as d:
            out = pathlib.Path(d, "g.h")
            run("gen_moqt_golden.py", str(out))
            # the committed header is clang-formatted: compare modulo whitespace
            def squash(b):
                return re.sub(rb"\s+", b"", re.sub(rb"\n\s*\*(?!/)", b"", b))
            self.assertEqual(squash(out.read_bytes()),
                             squash((ROOT / "tests/app/moqt_golden.h").read_bytes()))


class BsslParseTest(unittest.TestCase):
    def parse(self, text):
        with tempfile.TemporaryDirectory() as d:
            p = pathlib.Path(d, "v.txt")
            p.write_text(text)
            run("gen_bssl_vectors.py", str(p))
            return pathlib.Path(d, "v.h").read_text()

    def test_instruction_comment_and_cases(self):
        h = self.parse("# c\n[K = 1]\n\nA = 01\nB: \"x\"\n\n\nA = 02\n")
        self.assertIn('{"[K", "1"},\n  {"A", "01"},\n  {"B", "\\"x\\""},', h)
        self.assertIn("{4, 5, 0, 3},\n  {8, 8, 3, 2},", h)

    def test_unparsed_line_fails(self):
        with tempfile.TemporaryDirectory() as d:
            p = pathlib.Path(d, "v.txt")
            p.write_text("junk\n")
            r = subprocess.run([sys.executable, str(ROOT / "scripts/gen_bssl_vectors.py"), str(p)],
                               capture_output=True, text=True)
            self.assertNotEqual(r.returncode, 0)
            self.assertIn(":1: unparsed line", r.stderr)


if __name__ == "__main__":
    unittest.main()
