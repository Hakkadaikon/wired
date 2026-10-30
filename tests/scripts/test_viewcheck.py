"""Tests for scripts/viewcheck.py (run: python3 -m unittest discover tests/scripts)."""

import pathlib
import sys
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts"))

import viewcheck as vc  # noqa: E402

HEADER = """typedef struct {
  wired_span name;
  u64        n;
} cfg_part;

/** The long-lived state.
 * views: key=own */
typedef struct {
  cfg_part part;
  const u8* key;
} wired_srvrun_env;

typedef struct {
  wired_span data;
} frame_in;
"""

SOURCE = """void bad(wired_srvrun_env* env) {
  u8 buf[8] = {0};
  env->key = buf;
}

void fine(wired_srvrun_env* env, frame_in* in) {
  static u8 keep[8];
  u8        tmp[8];
  env->key = keep;
  in->data = wired_span_of(tmp, 8);
  env->key = tmp; /* view-ok: test of the escape hatch */
}

void nested(wired_srvrun_env* env) {
  u8 buf[4];
  env->part.name = wired_span_of(buf, 4);
}

void many(wired_srvrun_env* envs) {
  const char* s = "{ not a brace";
  u8          a[4], late[8];
  envs[1].key = late;
}
"""


class TagTest(unittest.TestCase):
    def test_untagged_stored_struct_fails(self):
        errs = vc.check([("a.h", HEADER)], [])
        self.assertEqual(len(errs), 1)
        self.assertIn("cfg_part: views without", errs[0])
        self.assertIn(": name;", errs[0])

    def test_tagged_and_call_scoped_structs_pass(self):
        tagged = HEADER.replace(
            "typedef struct {\n  wired_span name;",
            "/* views: name=slot */\ntypedef struct {\n  wired_span name;",
        )
        self.assertEqual(vc.check([("a.h", tagged)], []), [])

    def test_unknown_class_fails(self):
        bad = HEADER.replace("key=own", "key=heap")
        self.assertTrue(
            any("wired_srvrun_env" in e for e in vc.check([("a.h", bad)], []))
        )

    def test_void_context_is_not_a_view(self):
        h = "typedef struct {\n  void* ctx;\n} wired_moqt_hub;\n"
        self.assertEqual(vc.check([("a.h", h)], []), [])


class AssignTest(unittest.TestCase):
    def errs(self):
        tagged = HEADER.replace(
            "typedef struct {\n  wired_span name;",
            "/* views: name=slot */\ntypedef struct {\n  wired_span name;",
        )
        return vc.check([("a.h", tagged)], [("a.c", SOURCE)])

    def test_local_array_into_stored_view_fails(self):
        self.assertIn(
            "a.c:3: stored view `key` set from local array `buf`", self.errs()
        )

    def test_field_base_resolves_through_struct_field(self):
        self.assertIn(
            "a.c:16: stored view `name` set from local array `buf`", self.errs()
        )

    def test_array_element_base_and_second_declarator(self):
        self.assertIn(
            "a.c:22: stored view `key` set from local array `late`", self.errs()
        )

    def test_static_call_scoped_and_view_ok_pass(self):
        self.assertEqual(len(self.errs()), 3)

    def test_new_member_on_tagged_struct_fails(self):
        grown = HEADER.replace("  const u8* key;", "  const u8* key;\n  u8* extra;")
        errs = vc.check([("a.h", grown)], [])
        self.assertTrue(any("views without" in e and ": extra;" in e for e in errs))

    def test_entry_for_no_member_fails(self):
        left = HEADER.replace("key=own */", "key=own, gone=own */")
        errs = vc.check([("a.h", left)], [])
        self.assertTrue(any("naming no view member: gone" in e for e in errs))

    def test_local_scope_wins_over_file_scope(self):
        src = "int g(int q) { return q; }\nvoid f(wired_srvrun_env* q) {\n  u8 buf[8];\n  q->key = buf;\n}\n"
        errs = vc.check([("a.h", HEADER)], [("b.c", src)])
        self.assertIn("b.c:4: stored view `key` set from local array `buf`", errs)


if __name__ == "__main__":
    unittest.main()
