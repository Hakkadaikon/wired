/* Upstream FETCH: a FETCH (or fill) whose range the hub cache cannot
 * vouch for is completed by one FETCH the hub sends to a matching
 * publisher (draft-ietf-moq-transport-22 3.2.3, 7.6, 9.11/9.12, 11.4,
 * 12.1). Shares the recording io stubs (moqtrun_test.c) and the fixtures
 * of moqtrun_sub_test.c, moqtrun_fetch_test.c, moqtrun_ns_test.c,
 * moqtrun_rdv_test.c and moqtrun_upsub_test.c (same unity TU). */

/* ===================== GOAWAY'd peers are not asked ===================== */

/* draft-22 9.2: after a GOAWAY on the control stream, either way, no new
 * request goes to that peer -- not even the hub's upstream SUBSCRIBE. */
static void mupf_upsub_goaway(int recv) {
  mups_init();
  wired_moqtrun_peer* a = moqtrun_find_by_wt(&mtst_hub, SESS_A);
  a->sess.goaway_recv   = recv;
  a->sess.goaway_sent   = !recv;
  mups_sub(SESS_B, MRDV_S1);
  CHECK(mups_n_up(SESS_A) == 0);
}

static void test_moqtrun_upfetch_upsub_skips_goaway(void) {
  mupf_upsub_goaway(1);
  mupf_upsub_goaway(0);
}

void test_moqtrun_upfetch(void) { test_moqtrun_upfetch_upsub_skips_goaway(); }
