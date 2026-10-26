/* Session-level error handling of the hub (issue #20): malformed peer
 * input closes the MOQT session with the draft's code, through the
 * moqsess model. Shares the recording io stubs and fixtures of
 * moqtrun_test.c, moqtrun_sub_test.c and moqtrun_ctlfix_test.c (same
 * unity TU). */

/* Delivers b on SESS_A's uni stream sid (fin as given). */
static void mtss_uni(u64 sid, const u8* b, usz n, int fin) {
  wired_moqt_on_stream_data(&mtst_hub, SESS_A, sid, wired_span_of(b, n), fin);
}

/* 1 iff the hub's last session close used code. */
static int mtss_closed_with(u64 code) {
  return moqtrun_test_close_code() == code;
}

/* draft-18/19 3.4, draft-22 6.4.1: an unknown uni Stream Type (0x01: bit 4
 * clear, not FETCH_HEADER) closes the session PROTOCOL_VIOLATION, recorded
 * by the moqsess model. */
static void test_mtss_unknown_uni_closes(void) {
  static const u8 b[] = {0x01, 0x01, 0x00, 0x00};
  mtrq_setup();
  mtss_uni(14, b, sizeof b, 0);
  CHECK(mtss_closed_with(WIRED_MOQTRUN_CLOSE_PROTOCOL_VIOLATION));
  CHECK(
      moqtrun_find_by_wt(&mtst_hub, SESS_A)->sess.close_reason ==
      MOQSESS_CLOSE_PROTOCOL_VIOLATION);
}

/* SUBGROUP_ID_MODE 0b11 (Type 0x16) is no SUBGROUP_HEADER either
 * (draft-19 11.4.2): the same close. */
static void test_mtss_subgroup_mode3_closes(void) {
  static const u8 b[] = {0x16, 0x01, 0x00, 0x00, 0x00};
  mtrq_setup();
  mtss_uni(14, b, sizeof b, 0);
  CHECK(mtss_closed_with(WIRED_MOQTRUN_CLOSE_PROTOCOL_VIOLATION));
}

/* Regression guard: a PADDING stream (0x132B3E28, 11.5.1) is known and
 * discarded, the session stays open. */
static void test_mtss_padding_stream_kept(void) {
  u8  b[16];
  usz n  = moqvi_encode(b, MOQDATA_TYPE_PADDING);
  b[n++] = 0xAA;
  mtrq_setup();
  mtss_uni(14, b, n, 1);
  CHECK(moqtrun_test_count_kind(11) == 0);
}

void test_moqtrun_sess(void) {
  test_mtss_unknown_uni_closes();
  test_mtss_subgroup_mode3_closes();
  test_mtss_padding_stream_kept();
}
