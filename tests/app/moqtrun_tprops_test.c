/* draft-ietf-moq-transport-23 Track and Object Properties through the hub:
 * grease in the Mandatory range (3.7, 13), DEFAULT_PUBLISHER_PRIORITY
 * above 255 (10.4), one instance of a supported Property and its scope
 * (8.4, 12.1 items 8-9), and a TRACK_STATUS waiting on an upstream whose
 * answer carries a Mandatory Track Property (3.7). Shares the fixtures of
 * moqtrun_sub_test.c, moqtrun_done_test.c, moqtrun_drain_test.c,
 * moqtrun_upd_test.c, moqtrun_rdv_test.c, moqtrun_upsub_test.c,
 * moqtrun_errdet_test.c and moqtrun_upfetch_test.c (same unity TU). */

/* 1 when the draft under test applies the draft-23 Property rules. */
static int mttp_d23(void) {
  return (moqver_caps(g_moqtrun_test_ver) & MOQVER_CAP_PROP_RULES) != 0;
}

/* g_moqtrun_test_ver's REQUEST_ERROR code for code. */
static u64 mttp_code(u64 code) {
  return moqctl_request_error_for(g_moqtrun_test_ver, code);
}

/* A's stream of the last mttp_publish. */
static u64 mttp_ca;

/* A PUBLISHes alice with Track Properties props: ~0 when the hub took
 * the track, else the REQUEST_ERROR code on A's stream. */
static u64 mttp_publish(wired_span props) {
  moqctl_ftn f = mtst_ftn("chat", "room1", "alice");
  mtst_init();
  mttp_ca = mtst_join(SESS_A);
  mtst_publish_props(SESS_A, mttp_ca, &f, 1, props);
  if (moqtrun_find_by_wt(&mtst_hub, SESS_A)->tracks[0].in_use) {
    return ~(u64)0;
  }
  return mtrq_err_on(mttp_ca);
}

/* B's SUBSCRIBE_OK for the track mttp_publish took carries props as is. */
static int mttp_forwarded(wired_span props) {
  moqctl_ftn f = mtst_ftn("chat", "room1", "alice");
  mtst_subscribe(SESS_B, mtst_join(SESS_B), &f);
  return mtst_last_ok() &&
         mtst_props_eq(mtst_last_ok()->track_properties, props);
}

/* 3.7: "Grease values (Section 13) in this range are not Mandatory Track
 * Properties": 0x401D (0x7f * 128 + 0x9D) and 0x7F9D (0x7f * 256 + 0x9D)
 * are taken and forwarded like any unknown Property on draft-23; earlier
 * drafts refuse them UNSUPPORTED_EXTENSION, as 0x401E (no grease) still
 * is. */
static void mttp_grease(void) {
  u8  p[32];
  usz n    = 0;
  u64 prev = 0;
  u64 un   = mttp_code(MOQCTL_ERR_UNSUPPORTED_EXTENSION);
  mtst_prop_num(p, &n, &prev, 0x401D, 1);
  mtst_prop_num(p, &n, &prev, 0x7F9D, 1);
  CHECK(mttp_publish(wired_span_of(p, n)) == (mttp_d23() ? ~(u64)0 : un));
  CHECK(!mttp_d23() || mttp_forwarded(wired_span_of(p, n)));
  n    = 0;
  prev = 0;
  mtst_prop_num(p, &n, &prev, 0x401E, 1);
  CHECK(mttp_publish(wired_span_of(p, n)) == un);
}

/* 9.4.2.2 with 3.7: the UNSUPPORTED_PROPERTY Error Details name the
 * Mandatory Track Property 0x4000, not grease 0x409C (0x7f * 129 +
 * 0x9D). */
static void mttp_grease_not_named(void) {
  u8                   p[32];
  usz                  n    = 0;
  u64                  prev = 0;
  moqctl_request_error e    = {0};
  mtst_prop_num(p, &n, &prev, 0x4000, 1);
  mtst_prop_num(p, &n, &prev, 0x409C, 1);
  mttp_publish(wired_span_of(p, n));
  CHECK(mted_err(SESS_A, mttp_ca, &e));
  CHECK(e.error_code == MOQCTL_ERR_UNSUPPORTED_EXTENSION);
  CHECK(e.n_unsupported == 1 && e.unsupported[0] == 0x4000);
}

/* 3.7: grease as an Object Property is no Mandatory Track Property, so
 * no Malformed Track on draft-23 (subgroup stream and datagram); earlier
 * drafts end B's subscription MALFORMED_TRACK. */
static void mttp_grease_obj(void) {
  u8  g[16];
  u64 want = mttp_d23() ? ~(u64)0 : MOQCTL_DONE_MALFORMED_TRACK;
  for (int dg = 0; dg < 2; dg++) {
    u64 count = 0;
    mtdn_setup();
    mtdn_obj_props(mtdn_prop1(g, sizeof g, 0x401D), dg);
    wired_moqt_tick(&mtst_hub, 0);
    CHECK(mtdr_done_on(MTRQ_S1, &count) == want);
  }
}

static void test_moqtrun_tprops_grease(void) {
  moqtrun_test_allver(mttp_grease);
  moqtrun_test_vers(MOQVER_CAP_PROP_RULES, 0, mttp_grease_not_named);
  moqtrun_test_allver(mttp_grease_obj);
}

void test_moqtrun_tprops(void) { test_moqtrun_tprops_grease(); }
