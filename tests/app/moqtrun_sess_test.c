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

/* draft-19 10.1 (draft-18 10.1, draft-22 6.4.2.1): a client Request ID
 * with the server's (odd) parity closes the session INVALID_REQUEST_ID,
 * recorded by the moqsess model; nothing is answered. */
static void test_mtss_rid_parity_closes(void) {
  moqctl_ftn f = mtrq_setup();
  mtst_subscribe_p(SESS_B, MTRQ_S1, &f, 3, 0);
  CHECK(mtss_closed_with(WIRED_MOQTRUN_CLOSE_INVALID_REQUEST_ID));
  CHECK(
      moqtrun_find_by_wt(&mtst_hub, SESS_B)->sess.close_reason ==
      MOQSESS_CLOSE_INVALID_REQUEST_ID);
  CHECK(moqtrun_test_count_kind(12) == 0);
}

/* The same Request ID on a second request stream is a duplicate. */
static void test_mtss_rid_duplicate_closes(void) {
  moqctl_ftn f = mtrq_setup();
  mtst_subscribe_p(SESS_B, MTRQ_S1, &f, 2, 0);
  CHECK(moqtrun_test_count_kind(11) == 0);
  mtst_subscribe_p(SESS_B, MTRQ_S2, &f, 2, 0);
  CHECK(mtss_closed_with(WIRED_MOQTRUN_CLOSE_INVALID_REQUEST_ID));
}

/* Request streams are independent (RFC 9000 2.2): Request ID 4 arriving
 * before 2 is no duplicate, both are answered and the session stays
 * open; a later 2 or 4 is one. */
static void test_mtss_rid_out_of_order_ok(void) {
  moqctl_ftn f = mtrq_setup();
  mtst_subscribe_p(SESS_B, MTRQ_S2, &f, 4, 0);
  mtst_subscribe_p(SESS_B, MTRQ_S1, &f, 2, 0);
  CHECK(moqtrun_test_count_kind(11) == 0);
  CHECK(mtrq_type_on(12, MTRQ_S1) == MOQCTL_T_SUBSCRIBE_OK);
  CHECK(mtrq_type_on(12, MTRQ_S2) == MOQCTL_T_SUBSCRIBE_OK);
  mtst_subscribe_p(SESS_B, 12, &f, 4, 0);
  CHECK(mtss_closed_with(WIRED_MOQTRUN_CLOSE_INVALID_REQUEST_ID));
}

static void mtss_noop(
    wired_moqt_hub* hub, wired_moqtrun_peer* p, usz peer_idx, wired_span body) {
  (void)hub;
  (void)p;
  (void)peer_idx;
  (void)body;
}

/* 1 iff a SUBSCRIBE with Request ID rid from p passes the Request ID
 * check. */
static int mtss_rid_ok(wired_moqtrun_peer* p, u64 rid) {
  u8  b[9];
  usz n = moqvi_encode(b, rid);
  return moqtrun_rid_gate(
             p, MOQCTL_OK, MOQCTL_T_SUBSCRIBE, wired_span_of(b, n),
             mtss_noop) == mtss_noop;
}

/* A gap the client never fills (Request ID 0, consumed but never sent)
 * does not wedge the check: 64 requests on, the window slides past it,
 * and only then does a late 0 read as used. */
static void test_mtss_rid_window_slides(void) {
  wired_moqtrun_peer* b;
  int                 all = 1;
  mtrq_setup();
  b = moqtrun_find_by_wt(&mtst_hub, SESS_B);
  for (u64 rid = 2; rid <= 140; rid += 2) {
    all &= mtss_rid_ok(b, rid);
  }
  CHECK(all);
  CHECK(!mtss_rid_ok(b, 0));
  CHECK(!mtss_rid_ok(b, 140));
  CHECK(mtss_rid_ok(b, 142));
}

void test_moqtrun_sess(void) {
  test_mtss_unknown_uni_closes();
  test_mtss_subgroup_mode3_closes();
  test_mtss_padding_stream_kept();
  test_mtss_rid_parity_closes();
  test_mtss_rid_duplicate_closes();
  test_mtss_rid_out_of_order_ok();
  test_mtss_rid_window_slides();
}
