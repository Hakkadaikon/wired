/* draft-ietf-moq-transport-23 Track and Object Properties through the hub:
 * grease in the Mandatory range (3.7, 13), DEFAULT_PUBLISHER_PRIORITY
 * above 255 (10.4), one instance of a supported Property and its scope
 * (8.4, 12.1 items 8-9). Shares the fixtures of moqtrun_sub_test.c,
 * moqtrun_done_test.c, moqtrun_drain_test.c, moqtrun_rdv_test.c,
 * moqtrun_upsub_test.c,
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

/* A's track's DEFAULT_PUBLISHER_PRIORITY as the hub keeps it. */
static u8 mttp_prio(void) {
  return moqtrun_find_by_wt(&mtst_hub, SESS_A)->tracks[0].default_pub_prio;
}

/* 10.4: DEFAULT_PUBLISHER_PRIORITY "above 255, it MUST close the session
 * with MALFORMED_KEY_VALUE" on draft-23, mutable or inside Immutable
 * Properties; 255 is kept. Earlier drafts take 256 as the default 128
 * (draft-22 10.4: "Priorities above 255 are invalid"). */
static void mttp_prio_above_255(void) {
  CHECK(mtst_publish_prop_closes(0x0E, 255, 0) == 0 && mttp_prio() == 255);
  CHECK(mtst_publish_prop_closes(0x0E, 256, 1) == (usz)mttp_d23());
  CHECK(mtst_publish_prop_closes(0x0E, 256, 0) == (usz)mttp_d23());
  CHECK(mttp_d23() || mttp_prio() == 128);
}

static void test_moqtrun_tprops_prio(void) {
  moqtrun_test_allver(mttp_prio_above_255);
}

/* Track Properties t1 = 1 then t2 = 1, t2 inside Immutable Properties
 * when imm, into buf. */
static wired_span mttp_two(u8* buf, u64 t1, u64 t2, int imm) {
  u8  in[16];
  usz n = 0, ni = 0;
  u64 prev = 0, pi = 0;
  mtst_prop_num(buf, &n, &prev, t1, 1);
  if (!imm) {
    mtst_prop_num(buf, &n, &prev, t2, 1);
    return wired_span_of(buf, n);
  }
  mtst_prop_num(in, &ni, &pi, t2, 1);
  mtst_prop_imm(buf, &n, &prev, wired_span_of(in, ni));
  return wired_span_of(buf, n);
}

/* What a PUBLISH of props gets on draft-23 (want) and earlier (taken). */
static u64 mttp_d23_or_taken(u64 want) {
  return mttp_d23() ? mttp_code(want) : ~(u64)0;
}

/* 8.4: a supported Property "MUST NOT contain more than one instance",
 * and one that "receives more instances of it than allowed MUST treat
 * the Track as malformed" (12.1 item 9): two MAX_CACHE_DURATION, also one
 * mutable and one inside Immutable Properties (10.7), are refused
 * MALFORMED_TRACK on draft-23; earlier drafts take the track. */
static void mttp_twice(void) {
  u8  p[32];
  u64 want = mttp_d23_or_taken(MOQCTL_ERR_MALFORMED_TRACK);
  CHECK(mttp_publish(mttp_two(p, 0x04, 0x04, 0)) == want);
  CHECK(mttp_publish(mttp_two(p, 0x04, 0x04, 1)) == want);
  CHECK(mttp_publish(mttp_two(p, 0x22, 0x22, 0)) == want);
  CHECK(mttp_publish(mttp_two(p, 0x04, 0x22, 1)) == ~(u64)0);
}

/* 8.4: an unsupported Property "MUST allow multiple instances": two
 * 0x3800 are taken and forwarded as they are, in every draft. */
static void mttp_unknown_twice(void) {
  u8         p[32];
  wired_span s = mttp_two(p, 0x3800, 0x3800, 0);
  CHECK(mttp_publish(s) == ~(u64)0);
  CHECK(mttp_forwarded(s));
}

/* 8.4: a supported Property received "outside its scope ... MUST treat
 * the Track as malformed" (12.1 item 8): the Object-only PRIOR_GROUP_ID_GAP
 * (0x3C) or PRIOR_OBJECT_ID_GAP (0x3E) as a Track Property is refused
 * MALFORMED_TRACK on draft-23; OBJECT_DELIVERY_TIMEOUT (0x02, Track and
 * Object) is not. */
static void mttp_track_scope(void) {
  u8  p[32];
  u64 want = mttp_d23_or_taken(MOQCTL_ERR_MALFORMED_TRACK);
  CHECK(mttp_publish(mttp_two(p, 0x02, 0x3C, 0)) == want);
  CHECK(mttp_publish(mttp_two(p, 0x02, 0x3E, 1)) == want);
  CHECK(mttp_publish(mttp_two(p, 0x02, 0x06, 1)) == ~(u64)0);
}

/* 12.1 with 3.7: the upstream SUBSCRIBE_OK with PRIOR_GROUP_ID_GAP as a
 * Track Property is a Malformed Track: the waiter is refused
 * MALFORMED_TRACK on draft-23 and gets SUBSCRIBE_OK before. */
static void mttp_upsub_scope(void) {
  mups_init();
  mups_sub(SESS_B, MRDV_S1);
  mups_ok_prop((u64)mups_up_sid(), 0x3C, 1);
  if (mttp_d23()) {
    CHECK(mrdv_err(SESS_B, MRDV_S1).error_code == MOQCTL_ERR_MALFORMED_TRACK);
    return;
  }
  CHECK(mrdv_is(SESS_B, MRDV_S1, "SOK|"));
}

static void test_moqtrun_tprops_once_in_scope(void) {
  moqtrun_test_allver(mttp_twice);
  moqtrun_test_allver(mttp_unknown_twice);
  moqtrun_test_allver(mttp_track_scope);
  moqtrun_test_allver(mttp_upsub_scope);
}

void test_moqtrun_tprops(void) {
  test_moqtrun_tprops_grease();
  test_moqtrun_tprops_prio();
  test_moqtrun_tprops_once_in_scope();
}
