"""Tests for scripts/halstead.py (run: python3 -m unittest discover tests/scripts)."""
import importlib.util
import io
import json
import os
import pathlib
import tempfile
import unittest
from contextlib import redirect_stdout

ROOT = pathlib.Path(__file__).resolve().parents[2]


def load_module():
    spec = importlib.util.spec_from_file_location(
        "halstead", ROOT / "scripts" / "halstead.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def metrics(volume=10.0, difficulty=1.0, bugs=0.01, mi=120.0):
    return {"halstead": {"volume": volume, "difficulty": difficulty,
                         "effort": 1.0, "bugs": bugs},
            "mi": {"mi_original": mi, "mi_sei": mi, "mi_visual_studio": mi / 1.71},
            "nexits": {"sum": 0.0}, "nargs": {"total_functions": 1.0}}


def unit(name, fn_metrics):
    return {"name": name, "kind": "unit", "metrics": metrics(),
            "spaces": [{"name": "f", "kind": "function", "start_line": 3,
                        "metrics": fn_metrics, "spaces": []}]}


class CheckTest(unittest.TestCase):
    def setUp(self):
        self.h = load_module()

    def run_check(self, u):
        with tempfile.TemporaryDirectory() as d:
            with open(os.path.join(d, "u.json"), "w") as f:
                json.dump(u, f)
            out = io.StringIO()
            with redirect_stdout(out):
                n = self.h.check(self.h.load(d))
        return n, out.getvalue()

    def test_clean_function_passes(self):
        self.assertEqual(self.run_check(unit("a.c", metrics()))[0], 0)

    def test_volume_over_limit_is_reported(self):
        n, out = self.run_check(unit("a.c", metrics(volume=1001.0)))
        self.assertEqual(n, 1)
        self.assertIn("a.c:3: warning: f has volume", out)

    def test_null_difficulty_is_not_a_crash(self):
        # rust-code-analysis emits null for a function with no operands
        # (seen for TS/JS); null means nothing to measure, not a violation.
        m = metrics()
        m["halstead"]["difficulty"] = None
        m["halstead"]["bugs"] = None
        self.assertEqual(self.run_check(unit("a.ts", m))[0], 0)


class ReportTest(unittest.TestCase):
    def test_null_values_print_a_dash(self):
        h = load_module()
        m = metrics()
        m["halstead"]["difficulty"] = None
        out = io.StringIO()
        with redirect_stdout(out):
            h.report([unit("a.ts", m)])
        self.assertIn("f@3@a.ts", out.getvalue())


if __name__ == "__main__":
    unittest.main()
