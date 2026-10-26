/* Several publishers of one Track (hub->multi_publisher; draft-18 9.3,
 * draft-22 7.6 "Relays MUST send SUBSCRIBE messages to all matching
 * publishers", "SHOULD attempt to deduplicate Objects"). Scenarios map to
 * tasks/loopeng/MoqtMultiPub (NoDup, NoStaleClaim, NoFwdAfterCancel,
 * Complete). Reuses moqtrun_upsub_test.c's fixtures (same unity TU):
 * A and C both announce chat/room1, B subscribes. */

/* A, B, C joined, merging on; A and C announced chat/room1. */
static void mpub_init(void) {
  mups_init();
  mtst_join(SESS_C);
  mtst_hub.multi_publisher = 1;
  mtns_pub(SESS_C, MRDV_S1, "chat/room1");
  mups_sids();
}

/* s answers SUBSCRIBE_OK (alias MUPS_ALIAS) on stream sid. */
static void mpub_ok(wired_wt_session* s, u64 sid) {
  static moqctl_subscribe_ok ok;
  ok.track_alias = MUPS_ALIAS;
  mtst_send(s, sid, MOQCTL_T_SUBSCRIBE_OK, mups_enc_ok, &ok);
}

static i64 mpub_up_sid(wired_wt_session* s) {
  moqctl_subscribe m;
  return mups_up(s, 0, &m);
}

/* mpub_init, B subscribed, A and C both answered SUBSCRIBE_OK. */
static void mpub_both(void) {
  mpub_init();
  mups_sub(SESS_B, MRDV_S1);
  mpub_ok(SESS_A, (u64)mpub_up_sid(SESS_A));
  mpub_ok(SESS_C, (u64)mpub_up_sid(SESS_C));
}

/* s pushes a whole Subgroup stream (Group g, one Object) on sid. */
static void mpub_push(wired_wt_session* s, u64 sid, u64 g) {
  u8             buf[MOQTRUN_TEST_MAX_PAYLOAD];
  moqdata_subhdr h   = {0};
  usz            off = 0;
  u8             b   = 0x5a;
  wired_mspan    out = wired_mspan_of(buf, sizeof buf);
  h.type             = 0x30;
  h.track_alias      = MUPS_ALIAS;
  h.group_id         = g;
  moqdata_subhdr_put(out, &off, &h);
  moqdata_obj_put(out, &off, 0, wired_span_of(&b, 1));
  wired_moqt_on_stream_data(&mtst_hub, s, sid, wired_span_of(buf, off), 1);
}

/* s sends OBJECT_DATAGRAM (Group g, Object o). */
static void mpub_dg(wired_wt_session* s, u8 g, u8 o) {
  u8 dg[] = {0x08, MUPS_ALIAS, g, o, 'x'};
  wired_moqt_on_datagram(&mtst_hub, s, wired_span_of(dg, sizeof dg));
}

/* Uni streams (kinds 4/5/8) or datagrams (kind 9) the hub sent B. */
static usz mpub_to_b(int dgram) {
  usz n = 0;
  for (usz i = 0; i < g_n_calls; i++) {
    const moqtrun_test_call* c = &g_calls[i];
    int                      k = c->kind == 4 || c->kind == 5 || c->kind == 8;
    n += c->s == SESS_B && (dgram ? c->kind == 9 : k);
  }
  return n;
}

/* 7.6: B's SUBSCRIBE goes upstream to BOTH announcers; the first
 * SUBSCRIBE_OK answers B, the second only mirrors B's subscription onto
 * C's track under the same Track Alias -- B hears one SUBSCRIBE_OK. */
static void test_moqtrun_mpub_subscribes_every_announcer(void) {
  mpub_init();
  mups_sub(SESS_B, MRDV_S1);
  CHECK(mups_n_up(SESS_A) == 1);
  CHECK(mups_n_up(SESS_C) == 1);
  mpub_ok(SESS_A, (u64)mpub_up_sid(SESS_A));
  CHECK(mrdv_is(SESS_B, MRDV_S1, "SOK|"));
  mpub_ok(SESS_C, (u64)mpub_up_sid(SESS_C));
  CHECK(mrdv_is(SESS_B, MRDV_S1, "SOK|"));
  CHECK(mtst_sub(SESS_A, SESS_B) != 0);
  CHECK(mtst_sub(SESS_C, SESS_B) != 0);
  CHECK(
      mtst_sub(SESS_C, SESS_B)->track_alias ==
      mtst_sub(SESS_A, SESS_B)->track_alias);
  CHECK(mups_used() == 2);
}

/* NoDup (streams): both publishers send Group 0 -- B gets it once; C's
 * Group 1 (A never sent it) still reaches B: interleaved sources merge. */
static void test_moqtrun_mpub_dedup_streams(void) {
  mpub_both();
  mpub_push(SESS_A, MUPS_DATA_SID, 0);
  CHECK(mpub_to_b(0) == 1);
  mpub_push(SESS_C, MUPS_DATA_SID, 0);
  CHECK(mpub_to_b(0) == 1);
  mpub_push(SESS_C, MUPS_DATA_SID + 4, 1);
  CHECK(mpub_to_b(0) == 2);
  mpub_push(SESS_A, MUPS_DATA_SID + 4, 1);
  CHECK(mpub_to_b(0) == 2);
}

/* NoDup (datagrams): a Location sent by both goes out once. */
static void test_moqtrun_mpub_dedup_datagrams(void) {
  mpub_both();
  mpub_dg(SESS_A, 0, 0);
  mpub_dg(SESS_C, 0, 0);
  CHECK(mpub_to_b(1) == 1);
  mpub_dg(SESS_C, 0, 1);
  mpub_dg(SESS_A, 0, 2);
  CHECK(mpub_to_b(1) == 3);
}

/* Complete: A leaving folds its mirror into C's with no PUBLISH_DONE and
 * no wait for a new path; C's Objects keep reaching B. Only the last
 * publisher's end ends B's subscription. */
static void test_moqtrun_mpub_publisher_leaves(void) {
  mpub_both();
  wired_moqt_on_session_close(&mtst_hub, SESS_A);
  wired_moqt_tick(&mtst_hub, WIRED_MOQTRUN_RDV_MAX_MS);
  CHECK(mrdv_is(SESS_B, MRDV_S1, "SOK|"));
  CHECK(mtst_sub(SESS_C, SESS_B) != 0);
  mpub_push(SESS_C, MUPS_DATA_SID, 3);
  CHECK(mpub_to_b(0) == 1);
  wired_moqt_on_session_close(&mtst_hub, SESS_C);
  wired_moqt_tick(&mtst_hub, 2 * WIRED_MOQTRUN_RDV_MAX_MS);
  CHECK(mrdv_is(SESS_B, MRDV_S1, "SOK|Tb|FIN|"));
}

/* NoFwdAfterCancel: B's cancel drops both mirrors and both upstream
 * subscriptions; nothing more reaches B. */
static void test_moqtrun_mpub_subscriber_cancel(void) {
  u64 sa;
  mpub_both();
  sa = (u64)mpub_up_sid(SESS_A);
  wired_moqt_on_stream_reset(&mtst_hub, SESS_B, MRDV_S1, 0, 0);
  CHECK(mups_up_is(sa, "RST1|STOP1|"));
  CHECK(mups_used() == 0);
  mpub_push(SESS_C, MUPS_DATA_SID, 0);
  CHECK(mpub_to_b(0) == 0);
}

/* A refusal from one publisher is not B's answer while another may still
 * serve; the refusing one is not asked again (a refusal record). */
static void test_moqtrun_mpub_one_refuses(void) {
  mpub_init();
  mups_sub(SESS_B, MRDV_S1);
  mtst_pub_err(SESS_A, (u64)mpub_up_sid(SESS_A), MOQCTL_ERR_DOES_NOT_EXIST);
  CHECK(mrdv_is(SESS_B, MRDV_S1, ""));
  mpub_ok(SESS_C, (u64)mpub_up_sid(SESS_C));
  CHECK(mrdv_is(SESS_B, MRDV_S1, "SOK|"));
  wired_moqt_tick(&mtst_hub, 1);
  CHECK(mups_n_up(SESS_A) == 1);
}

/* 7.6 Established subscriptions: an announcer arriving after B's
 * subscription is Established is asked too. */
static void test_moqtrun_mpub_late_announcer(void) {
  mups_init();
  mtst_join(SESS_C);
  mtst_hub.multi_publisher = 1;
  mups_sub(SESS_B, MRDV_S1);
  mpub_ok(SESS_A, (u64)mpub_up_sid(SESS_A));
  CHECK(mups_n_up(SESS_C) == 0);
  mtns_pub(SESS_C, MRDV_S1, "chat/room1");
  CHECK(mups_n_up(SESS_C) == 1);
}

/* 9.3 PUBLISH from two publishers: the second joins (no supersede), B's
 * SUBSCRIBE is carried by both tracks, the shared Group goes out once. */
static void test_moqtrun_mpub_two_publish(void) {
  moqctl_ftn f = mrdv_f();
  mrdv_init();
  mtst_join(SESS_C);
  mtst_hub.multi_publisher = 1;
  mtst_publish(SESS_A, MRDV_S1, &f, MUPS_ALIAS);
  mtst_publish(SESS_C, MRDV_S1, &f, MUPS_ALIAS);
  CHECK(moqtrun_find_by_wt(&mtst_hub, SESS_A)->tracks[0].in_use);
  CHECK(moqtrun_find_by_wt(&mtst_hub, SESS_C)->tracks[0].in_use);
  mups_sub(SESS_B, MRDV_S2);
  CHECK(mtst_sub(SESS_A, SESS_B) != 0);
  CHECK(mtst_sub(SESS_C, SESS_B) != 0);
  mpub_push(SESS_A, MUPS_DATA_SID, 0);
  mpub_push(SESS_C, MUPS_DATA_SID, 0);
  CHECK(mpub_to_b(0) == 1);
}

/* Off (the default): a second PUBLISH still supersedes the first. */
static void test_moqtrun_mpub_off_supersedes(void) {
  moqctl_ftn f = mrdv_f();
  mrdv_init();
  mtst_join(SESS_C);
  mtst_publish(SESS_A, MRDV_S1, &f, MUPS_ALIAS);
  mtst_publish(SESS_C, MRDV_S1, &f, MUPS_ALIAS);
  CHECK(!moqtrun_find_by_wt(&mtst_hub, SESS_A)->tracks[0].in_use);
}

void test_moqtrun_mpub(void) {
  test_moqtrun_mpub_subscribes_every_announcer();
  test_moqtrun_mpub_dedup_streams();
  test_moqtrun_mpub_dedup_datagrams();
  test_moqtrun_mpub_publisher_leaves();
  test_moqtrun_mpub_subscriber_cancel();
  test_moqtrun_mpub_one_refuses();
  test_moqtrun_mpub_late_announcer();
  test_moqtrun_mpub_two_publish();
  test_moqtrun_mpub_off_supersedes();
}
