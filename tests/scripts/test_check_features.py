"""Tests for scripts/check_features.py (run: python3 -m unittest discover tests/scripts)."""

import pathlib
import sys
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts"))

import check_features as cf  # noqa: E402

LEDGER = """**Coverage: 1/3 tested, 1 indirect, 1 untested.**

- [x] T-001 (§1) The server shall a.
  - test: `tests/scripts/test_check_features.py` —
    `test_counts_stop_at_out_of_scope`
- [~] T-003 (§1) The server shall b.
  - evidence: read.
- [ ] T-002 (§2) The server shall c.

## Out of scope

- [ ] T-009 not counted.
"""


class LedgerTest(unittest.TestCase):
    def test_counts_stop_at_out_of_scope(self):
        self.assertEqual(cf.counts(LEDGER), (1, 1, 1))
        self.assertIn(cf.cov_line((1, 1, 1)), LEDGER)

    def test_gaps_and_out_of_order_ids_pass(self):
        self.assertEqual(cf.dup_ids(LEDGER), [])

    def test_reused_id_fails(self):
        self.assertEqual(
            cf.dup_ids(LEDGER + "- [x] T-001 again\n"), ["ID used twice: T-001"]
        )

    def test_placeholder_ids_skip_uniqueness(self):
        self.assertEqual(cf.dup_ids("- [x] 9000-XXX a\n- [ ] 9000-XXX b\n"), [])

    def test_wrapped_test_line_resolves(self):
        joined = cf.join_wrapped(LEDGER)
        self.assertEqual(cf.ref_errors(joined) + cf.malformed(joined), [])
        self.assertEqual(cf.untested_x(joined), [])

    def test_missing_function_and_untested_x_fail(self):
        bad = "- [x] T-004 a.\n  - test: `scripts/check_features.py` — `nope_fn`\n"
        self.assertEqual(len(cf.ref_errors(bad)), 1)
        self.assertEqual(
            cf.untested_x("- [x] T-005 a.\n  - evidence: x\n"),
            ["[x] T-005 has no test line"],
        )

    def test_readme_rows_and_total(self):
        readme = "| [A](a.md) | 0/0 | 0 | 0 | 0 |\n**Total: 0/1 requirements demonstrated (0.0%) — 0 directly tested,\n0 indirect, 1 untested.**"
        out = cf.readme_text(readme, {"a.md": (1, 1, 1)})
        self.assertIn("| [A](a.md) | 2/3 | 1 | 1 | 1 |", out)
        self.assertIn("**Total: 2/3 requirements demonstrated (66.7%)", out)


if __name__ == "__main__":
    unittest.main()
