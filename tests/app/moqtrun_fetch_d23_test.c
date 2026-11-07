/* draft-ietf-moq-transport-23 FETCH as the hub serves it, against
 * draft-22 on the same scenario: the fetch stream encoding (11.4). Every
 * scenario runs once per draft with the draft-22 FETCH layout. */

/* 11.4.1.1: consecutive Objects of a Group leave the Object ID Delta out
 * (a present one would mean prior + Delta + 2 on draft-23), a new Group
 * carries Group ID Delta; the stream decodes under B's own draft. */
static void test_moqtrun_fetch_d23_stream(void) {
  mf_init(sizeof mf_arena);
  mf_obj(0, 0, 1);
  mf_obj(0, 1, 1);
  mf_obj(1, 0, 1);
  mf_fetch_v(g_moqtrun_test_ver, 0);
  CHECK(mf_read() && mf_n == 3);
  CHECK(mf_is_obj(0, 0, 0, 1) && mf_is_obj(1, 0, 1, 1));
  CHECK(mf_is_obj(2, 1, 0, 1));
}

static void mtall_fetch_d23(void) { test_moqtrun_fetch_d23_stream(); }

void test_moqtrun_fetch_d23(void) {
  moqtrun_test_vers(MOQVER_CAP_FETCH_BODY_V22, 0, mtall_fetch_d23);
}
