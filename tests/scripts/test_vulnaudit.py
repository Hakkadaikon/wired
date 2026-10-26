"""Tests for scripts/vulnaudit/*.py (run: python3 -m unittest discover tests/scripts)."""

import io
import json
import os
import pathlib
import sys
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout

ROOT = pathlib.Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts" / "vulnaudit"))

import apply_triage  # noqa: E402
import ledger_check  # noqa: E402
import ledger_table  # noqa: E402
import merge  # noqa: E402
import reach  # noqa: E402


def row(**kw):
    d = {
        "id": "V-0001",
        "status": "open",
        "verdict": "?",
        "test": "",
        "commit": "",
        "why": "",
    }
    d.update(kw)
    return d


def line(**kw):
    return ledger_table.format_row(row(**kw))


class InTmp(unittest.TestCase):
    def setUp(self):
        self.old = os.getcwd()
        self.tmp = tempfile.TemporaryDirectory()
        os.chdir(self.tmp.name)

    def tearDown(self):
        os.chdir(self.old)
        self.tmp.cleanup()

    def write(self, path, text):
        os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
        pathlib.Path(path).write_text(text)


class LedgerTableTest(unittest.TestCase):
    def test_roundtrip_with_pipe(self):
        d = row(summary="a|b")
        got = ledger_table.parse_row(ledger_table.format_row(d))
        self.assertEqual(got["summary"], "a|b")
        self.assertEqual(got["id"], "V-0001")

    def test_non_row_and_wrong_width(self):
        self.assertIsNone(ledger_table.parse_row("| X | y |"))
        self.assertIsNone(ledger_table.parse_row("| V-0001 | open |"))

    def test_parse_tags_sections(self):
        rows = ledger_table.parse(["| V-0000 |", line(), "## A b ", line(id="V-0002")])
        self.assertEqual(
            [(r["id"], r["section"]) for r in rows],
            [("V-0001", "(none)"), ("V-0002", "A b")],
        )


class LedgerCheckTest(InTmp):
    def test_violations(self):
        v = ledger_check.violations
        self.assertEqual(v(row()), [])
        self.assertEqual(
            v(row(status="done", verdict="fixed", test="t", commit="c")), []
        )
        self.assertEqual(v(row(status="done", verdict="n/a", why="w")), [])
        self.assertEqual(len(v(row(status="done", verdict="fixed", test="t"))), 1)
        self.assertEqual(len(v(row(status="done", verdict="n/a"))), 1)

    def test_test_missing(self):
        m = ledger_check.test_missing
        done = dict(status="done", verdict="fixed")
        self.assertEqual(m(row(test="test_a"), set()), [])
        self.assertEqual(m(row(test="audit output", **done), set()), [])
        self.assertEqual(m(row(test="test_a", **done), {"test_a"}), [])
        self.assertEqual(
            m(row(test="test_a test_b", **done), {"test_a"}),
            ["V-0001: cited test not found in tests/: test_b"],
        )

    def test_main_counts_and_errors(self):
        self.write("tests/x/a.c", "void test_ok(void) {}\n")
        self.write("tests/run.c", "int main(void) { test_ok(); }\n")
        self.write(
            "l.md",
            "\n".join(
                [
                    "## S1",
                    line(),
                    line(
                        id="V-0002",
                        status="done",
                        verdict="fixed",
                        test="test_ok",
                        commit="c",
                    ),
                    "## S2",
                    line(id="V-0002", status="triaged"),
                ]
            )
            + "\n",
        )
        out = io.StringIO()
        with redirect_stdout(out):
            rc = ledger_check.main("l.md")
        self.assertEqual(rc, 1)
        self.assertEqual(
            out.getvalue(),
            "S1: open=1 triaged=0 done=1\nS2: open=0 triaged=1 done=0\n"
            "TOTAL 3 rows, 1 done\nERROR duplicate id V-0002\n",
        )

    def test_main_clean(self):
        self.write("tests/a.c", "")
        self.write("l.md", line() + "\n")
        with redirect_stdout(io.StringIO()):
            self.assertEqual(ledger_check.main("l.md"), 0)


class ReachTest(InTmp):
    def setUp(self):
        super().setUp()
        self.write(
            "src/m/m.c",
            "/* dead_fn() in a comment is no call */\n"
            "static int helper(int x) { return x; }\n"
            "int live_fn(int x) { return helper(x); }\n"
            "int dead_fn(void) { return 0; }\n"
            "#define VIA_MACRO(x) tabled_fn(x)\n"
            "int tabled_fn(int x) { return x; }\n"
            "static int (*const tbl[])(int) = {live_fn};\n",
        )
        self.write(
            "examples/e/main.c",
            "__attribute__((noreturn)) void entry(void) { tbl[0](1); VIA_MACRO(2); }\n",
        )
        self.write("tests/m_test.c", "void test_live(void) { live_fn(1); }\n")
        self.write("tests/u_test.c", "void test_unwired(void) { live_fn(1); }\n")
        self.write("tests/d_test.c", "void test_dead(void) { dead_fn(); }\n")
        self.write("tests/run.c", "int main(void) { test_live(); test_dead(); }\n")

    def errors(self, ours, test):
        r = row(status="done", verdict="already-safe", ours=ours, test=test)
        return reach.check([r])

    def test_live_code_and_reaching_test_pass(self):
        self.assertEqual(self.errors("src/m/m.c:live_fn (helper)", "test_live"), [])
        self.assertEqual(self.errors("m.c:tabled_fn", ""), [])

    def test_dead_code_flagged(self):
        self.assertEqual(
            self.errors("src/m/m.c:dead_fn", "test_dead"),
            ["V-0001: not on production path: dead_fn"],
        )

    def test_dead_pointers_flagged(self):
        self.assertEqual(
            self.errors("src/m/gone.c:gone_fn", ""),
            [
                "V-0001: cited file missing: src/m/gone.c",
                "V-0001: unknown symbol: gone_fn",
            ],
        )

    def test_test_wiring_and_reach(self):
        self.assertEqual(
            self.errors("live_fn", "test_unwired"),
            ["V-0001: test not wired into tests/run.c: test_unwired"],
        )
        self.assertEqual(
            self.errors("tabled_fn", "test_live"),
            ["V-0001: test does not reach cited code: test_live"],
        )

    def test_open_and_na_rows_skipped(self):
        r = row(status="done", verdict="n/a", ours="dead_fn")
        self.assertEqual(reach.check([r, row(ours="dead_fn")]), [])


class ApplyTriageTest(InTmp):
    def run_triage(self, rows, ledger_rows):
        self.write("t/a.json", json.dumps({"rows": rows}))
        self.write("l.md", "## S\n" + "\n".join(ledger_rows) + "\n")
        out = io.StringIO()
        with redirect_stdout(out):
            apply_triage.main("l.md", "t")
        return out.getvalue(), ledger_table.parse(
            pathlib.Path("l.md").read_text().splitlines()
        )

    def test_verdicts(self):
        out, rows = self.run_triage(
            [
                {
                    "vid": "V-0001",
                    "verdict": "already-safe",
                    "existing_test": True,
                    "test": "test_x",
                    "ours": "src/a.c",
                    "layer": "unit",
                    "priority": "P2",
                    "reason": "r",
                },
                {"vid": "V-0002", "verdict": "n/a", "test": "test_y"},
                {"vid": "V-0003", "verdict": "needs-fix", "layer": "fuzz"},
                {"vid": "V-0004", "verdict": "n/a"},
            ],
            [
                line(),
                line(id="V-0002"),
                line(id="V-0003"),
                line(id="V-0004", status="done", verdict="fixed"),
                line(id="V-0005"),
            ],
        )
        self.assertEqual(out, "applied 3 triage rows\n")
        r = {d["id"]: d for d in rows}
        self.assertEqual(
            (
                r["V-0001"]["status"],
                r["V-0001"]["commit"],
                r["V-0001"]["layer"],
                r["V-0001"]["test"],
                r["V-0001"]["why"],
                r["V-0001"]["ours"],
            ),
            ("done", "existing", "unit P2", "test_x", "r", "src/a.c"),
        )
        self.assertEqual(
            (
                r["V-0002"]["status"],
                r["V-0002"]["test"],
                r["V-0002"]["commit"],
                r["V-0002"]["why"],
            ),
            ("done", "", "", "n/a"),
        )
        self.assertEqual(
            (
                r["V-0003"]["status"],
                r["V-0003"]["ours"],
                r["V-0003"]["layer"],
                r["V-0003"]["why"],
            ),
            ("triaged", "?", "fuzz", ""),
        )
        self.assertEqual(r["V-0004"]["verdict"], "fixed")
        self.assertEqual(r["V-0005"]["status"], "open")

    def test_already_safe_without_existing_test_is_triaged(self):
        _, rows = self.run_triage(
            [{"vid": "V-0001", "verdict": "already-safe"}], [line()]
        )
        self.assertEqual((rows[0]["status"], rows[0]["commit"]), ("triaged", ""))


class MergeTest(InTmp):
    def test_load_raw(self):
        self.write("raw/a.json", json.dumps({"records": [{"id": "CVE-1"}]}))
        self.write(
            "raw/b.json", json.dumps({"records": {"p1": [{"id": "S-x"}], "p2": None}})
        )
        self.write("raw/c.json", "{bad")
        self.write("raw/d.json", json.dumps({}))
        err = io.StringIO()
        with redirect_stderr(err):
            recs = merge.load_raw("raw")
        self.assertEqual(
            recs,
            [
                {"id": "CVE-1", "_source_file": "a.json"},
                {"id": "S-x", "_source_file": "b.json"},
            ],
        )
        self.assertIn("skip raw/c.json", err.getvalue())

    def test_dedup(self):
        recs = merge.dedup(
            [{"id": "A"}, {"id": "B", "aliases": ["A", "C"]}, {"id": "C"}, {"id": "D"}]
        )
        # a merged record's own aliases are not registered: C stays separate
        self.assertEqual(
            recs, [{"id": "A", "aliases": ["A", "B", "C"]}, {"id": "C"}, {"id": "D"}]
        )

    def test_ledger_ids(self):
        self.assertEqual(merge.ledger_ids("missing.md"), (set(), 0))
        self.write("l.md", "| V-0007 | x | CVE-2024-1 GHSA-ab-cd S-9.1 L-3 | V-0012 |")
        self.assertEqual(
            merge.ledger_ids("l.md"), ({"CVE-2024-1", "GHSA-ab-cd", "S-9.1", "L-3"}, 12)
        )

    def test_class_and_summary(self):
        cs = merge.class_and_summary
        self.assertEqual(
            cs({"id": "S-1", "title": "T", "defense": "d" * 100}), ("T", "d" * 90)
        )
        self.assertEqual(cs({"id": "S-1", "attack": "a" * 80}), ("a" * 70, ""))
        self.assertEqual(
            cs({"id": "CVE-1", "bug_class": "oob", "summary": None}), ("oob", "")
        )
        self.assertEqual(cs({"id": "CVE-1"}), ("?", ""))

    def test_row(self):
        d = ledger_table.parse_row(
            merge.row(3, {"id": "CVE-1", "spec": "RFC", "bug_class": "oob"})
        )
        self.assertEqual(
            (d["id"], d["target"], d["ours"], d["verdict"]),
            ("V-0003", "RFC", "oob", "?"),
        )
        d = ledger_table.parse_row(merge.row(4, {"id": "CVE-2", "title": "t" * 40}))
        self.assertEqual((d["target"], d["ours"]), ("t" * 30, "?"))

    def test_main(self):
        self.write(
            "raw/a.json",
            json.dumps(
                {
                    "records": [
                        {"id": "CVE-1", "area": "tls"},
                        {"id": "CVE-2", "area": "zzz"},
                        {"id": "CVE-3", "area": "tls"},
                        {"id": "CVE-2024-9"},
                    ]
                }
            ),
        )
        self.write("l.md", "V-0005 CVE-2024-9")
        out, err = io.StringIO(), io.StringIO()
        with redirect_stdout(out), redirect_stderr(err):
            merge.main(["--ledger", "l.md", "--raw", "raw"])
        heads = [x for x in out.getvalue().splitlines() if x.startswith("## ")]
        self.assertEqual(heads, ["## TLS 1.3  (2 new)", "## Unmapped area  (1 new)"])
        ids = [
            x.split(" | ")[0] for x in out.getvalue().splitlines() if x.startswith("| ")
        ]
        self.assertEqual(ids, ["| V-0006", "| V-0007", "| V-0008"])
        self.assertTrue(err.getvalue().endswith("\ncatalog: 4 records; new rows: 3\n"))
        self.assertEqual(json.load(open("tasks/vuln/catalog.json"))["count"], 4)


if __name__ == "__main__":
    unittest.main()
