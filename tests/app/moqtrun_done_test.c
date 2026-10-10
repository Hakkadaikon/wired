/* The hub relays a publisher's PUBLISH_DONE (draft-ietf-moq-transport-18/19
 * 10.11, draft-22 9.9) to each subscriber of the track: the publisher's
 * Status Code in the subscriber's own draft, and the Stream Count of the
 * streams the HUB opened toward that subscriber -- sent only once every
 * stream the publisher counted has reached the hub and been relayed to
 * its end (a sender MUST NOT send PUBLISH_DONE before closing all its
 * streams). Shares the recording io stubs (moqtrun_test.c), subscription
 * fixtures (moqtrun_sub_test.c) and PUBLISH_DONE readers
 * (moqtrun_drain_test.c) of the same unity TU. */

/* A's PUBLISH request stream (client bidi). */
#define MTDN_PUB MTRQ_ID(1)

/* A (draft pv) PUBLISHes alice on MTDN_PUB; B (draft sv) SUBSCRIBEs on
 * MTRQ_S1. */
static moqctl_ftn mtdn_setup_v(int pv, int sv) {
  moqctl_ftn f = mtst_ftn("chat", "room1", "alice");
  mtst_init();
  mtst_join(SESS_A);
  mtst_join(SESS_B);
  moqtrun_find_by_wt(&mtst_hub, SESS_A)->ver = pv;
  moqtrun_find_by_wt(&mtst_hub, SESS_B)->ver = sv;
  mtst_publish(SESS_A, MTDN_PUB, &f, 1);
  mtst_subscribe_p(SESS_B, MTRQ_S1, &f, 2, 0);
  CHECK(mtrq_type_on(12, MTRQ_S1) == MOQCTL_T_SUBSCRIBE_OK);
  return f;
}

static moqctl_ftn mtdn_setup(void) {
  return mtdn_setup_v(g_moqtrun_test_ver, g_moqtrun_test_ver);
}

static int mtdn_enc_done(wired_mspan buf, usz* off, const void* m) {
  return moqctl_publish_done_encode(buf, off, m);
}

/* A's PUBLISH_DONE(status, count) on its PUBLISH stream. */
static void mtdn_done(u64 status, u64 count) {
  moqctl_publish_done d = {0};
  d.status_code         = status;
  d.stream_count        = count;
  mtst_send(SESS_A, MTDN_PUB, MOQCTL_T_PUBLISH_DONE, mtdn_enc_done, &d);
}

/* Group g as one whole SUBGROUP stream sid of A, FINed in one delivery. */
static void mtdn_group(u64 sid, u64 g) {
  u8  buf[MOQTRUN_TEST_MAX_PAYLOAD];
  usz n = mtst_stream(g, 1, 1, buf);
  wired_moqt_on_stream_data(&mtst_hub, SESS_A, sid, wired_span_of(buf, n), 1);
}

/* Tracks A still publishes. */
static usz mtdn_published(void) {
  wired_moqtrun_peer* a = moqtrun_find_by_wt(&mtst_hub, SESS_A);
  usz                 n = 0;
  for (usz t = 0; t < WIRED_MOQTRUN_MAX_TRACKS_PER_PEER; t++)
    n += a->tracks[t].in_use != 0;
  return n;
}

/* One stream relayed, then PUBLISH_DONE: B gets TRACK_ENDED with count 1,
 * its request stream FINed, no relay stream reset; the track is gone and
 * the hub FINs its side of A's PUBLISH stream. */
static void test_moqtrun_pubdone_one_sub(void) {
  u64 count = 0;
  mtdn_setup();
  mtdn_group(2002, 1);
  mtdn_done(MOQCTL_DONE_TRACK_ENDED, 1);
  CHECK(mtdr_done_on(MTRQ_S1, &count) == MOQCTL_DONE_TRACK_ENDED);
  CHECK(count == 1);
  CHECK(mtrq_fin_on(MTRQ_S1) == 1);
  CHECK(moqtrun_test_count_kind(7) == 0);
  CHECK(mtdn_published() == 0);
  CHECK(mtrq_fin_on(MTDN_PUB) == 1);
}

/* Two subscribers each get their own PUBLISH_DONE and count. */
static void test_moqtrun_pubdone_two_subs(void) {
  moqctl_ftn f  = mtdn_setup();
  u64        cb = 0, cc = 0;
  mtst_join(SESS_C);
  mtst_subscribe_p(SESS_C, MTRQ_S2, &f, 2, 0);
  mtdn_group(2002, 1);
  mtdn_group(2006, 2);
  mtdn_done(MOQCTL_DONE_TRACK_ENDED, 2);
  CHECK(mtdr_done_on(MTRQ_S1, &cb) == MOQCTL_DONE_TRACK_ENDED);
  CHECK(mtdr_done_on(MTRQ_S2, &cc) == MOQCTL_DONE_TRACK_ENDED);
  CHECK(cb == 2 && cc == 2);
}

/* Subgroup-per-group, N groups: Stream Count N. */
static void test_moqtrun_pubdone_n_groups(void) {
  u64 count = 0;
  mtdn_setup();
  for (u64 g = 0; g < 4; g++) mtdn_group(2002 + 4 * g, g);
  mtdn_done(MOQCTL_DONE_TRACK_ENDED, 4);
  CHECK(mtdr_done_on(MTRQ_S1, &count) == MOQCTL_DONE_TRACK_ENDED);
  CHECK(count == 4);
}

/* Datagram-only track: no stream either side, Stream Count 0. */
static void test_moqtrun_pubdone_datagram_only(void) {
  u64 count = 9;
  mtdn_setup();
  wired_moqt_on_datagram(
      &mtst_hub, SESS_A,
      wired_span_of(MOQTRUN_TEST_DG_CHAT, sizeof MOQTRUN_TEST_DG_CHAT));
  CHECK(moqtrun_test_count_kind(9) == 1);
  mtdn_done(MOQCTL_DONE_TRACK_ENDED, 0);
  CHECK(mtdr_done_on(MTRQ_S1, &count) == MOQCTL_DONE_TRACK_ENDED);
  CHECK(count == 0);
}

/* The publisher's count names a stream that has not reached the hub yet:
 * PUBLISH_DONE waits for it (10.11: it may precede late-opening streams),
 * then goes out counting it. */
static void test_moqtrun_pubdone_waits_late_stream(void) {
  u64 count = 0;
  mtdn_setup();
  mtdn_done(MOQCTL_DONE_TRACK_ENDED, 1);
  CHECK(mtdr_done_on(MTRQ_S1, &count) == ~(u64)0);
  mtdn_group(2002, 1);
  CHECK(mtdr_done_on(MTRQ_S1, &count) == MOQCTL_DONE_TRACK_ENDED);
  CHECK(count == 1);
}

/* A counted stream that carried only its SUBGROUP header and FIN still
 * reached the hub: PUBLISH_DONE goes out without the wait cap. */
static void test_moqtrun_pubdone_counts_header_only(void) {
  u8  buf[MOQTRUN_TEST_MAX_PAYLOAD];
  u64 count = 0;
  mtdn_setup();
  mtdn_done(MOQCTL_DONE_TRACK_ENDED, 1);
  usz n = mtst_stream(1, 0, 1, buf);
  wired_moqt_on_stream_data(&mtst_hub, SESS_A, 2002, wired_span_of(buf, n), 1);
  CHECK(mtdr_done_on(MTRQ_S1, &count) == MOQCTL_DONE_TRACK_ENDED);
}

/* A keep-open stream still being relayed is not cut: PUBLISH_DONE waits
 * for its FIN to be relayed, and nothing is reset. */
static void test_moqtrun_pubdone_waits_open_stream(void) {
  u8  buf[MOQTRUN_TEST_MAX_PAYLOAD];
  u64 count = 0;
  mtdn_setup();
  usz n = mtst_stream(1, 1, 1, buf);
  wired_moqt_on_stream_data(&mtst_hub, SESS_A, 2002, wired_span_of(buf, n), 0);
  mtdn_done(MOQCTL_DONE_TRACK_ENDED, 1);
  wired_moqt_tick(&mtst_hub, 1);
  CHECK(mtdr_done_on(MTRQ_S1, &count) == ~(u64)0);
  n = mtst_stream(1, 1, 0, buf);
  wired_moqt_on_stream_data(&mtst_hub, SESS_A, 2002, wired_span_of(buf, n), 1);
  CHECK(mtdr_done_on(MTRQ_S1, &count) == MOQCTL_DONE_TRACK_ENDED);
  CHECK(count == 1);
  CHECK(moqtrun_test_count_kind(7) == 0);
}

/* A Stream Count the hub never reaches (2^62-1, "unknown") does not hang
 * the subscriber: past WIRED_MOQTRUN_PUBDONE_WAIT_MS it goes out with
 * the hub's own count. */
static void test_moqtrun_pubdone_wait_bounded(void) {
  u64 count = 0;
  mtdn_setup();
  mtdn_group(2002, 1);
  mtdn_done(MOQCTL_DONE_TRACK_ENDED, ((u64)1 << 62) - 1);
  wired_moqt_tick(&mtst_hub, WIRED_MOQTRUN_PUBDONE_WAIT_MS - 1);
  CHECK(mtdr_done_on(MTRQ_S1, &count) == ~(u64)0);
  wired_moqt_tick(&mtst_hub, WIRED_MOQTRUN_PUBDONE_WAIT_MS);
  CHECK(mtdr_done_on(MTRQ_S1, &count) == MOQCTL_DONE_TRACK_ENDED);
  CHECK(count == 1);
}

/* The publisher's Status Code passes through, spelled for the
 * subscriber's draft. */
static void test_moqtrun_pubdone_status_passthrough(void) {
  u64 count = 0;
  mtdn_setup();
  mtdn_done(MOQCTL_DONE_SUBSCRIPTION_ENDED, 0);
  CHECK(
      mtdr_done_on(MTRQ_S1, &count) ==
      moqctl_publish_done_for(
          g_moqtrun_test_ver, MOQCTL_DONE_SUBSCRIPTION_ENDED));
  mtdn_setup();
  mtdn_done(MOQCTL_DONE_GOING_AWAY, 0);
  CHECK(mtdr_done_on(MTRQ_S1, &count) == MOQCTL_DONE_GOING_AWAY);
}

/* Group g of A on stream sid, FINed: n Normal Objects (IDs 0..n-1), then
 * one with status (ID n) when status is not Normal. */
static void mtdn_status_group(u64 sid, u64 g, usz n, u64 status) {
  u8  buf[MOQTRUN_TEST_MAX_PAYLOAD];
  usz off = mtst_stream(g, n, 1, buf);
  if (status != MOQDATA_STATUS_NORMAL)
    moqdata_obj_put_status(wired_mspan_of(buf, sizeof buf), &off, 0, status);
  wired_moqt_on_stream_data(&mtst_hub, SESS_A, sid, wired_span_of(buf, off), 1);
}

/* 1 iff the hub did io op kind (7 reset, 13 stop) on A's stream sid. */
static int mtdn_op_on(int kind, u64 sid) {
  for (usz i = 0; i < g_n_calls; i++)
    if (g_calls[i].kind == kind && g_calls[i].s == SESS_A &&
        g_calls[i].stream_id == sid)
      return 1;
  return 0;
}

/* d22 12.1 #5: an Object past the track's END_OF_TRACK makes it a
 * Malformed Track: B's subscription ends PUBLISH_DONE MALFORMED_TRACK at
 * once, the hub cancels A's PUBLISH (RESET + STOP_SENDING) and the track
 * is gone. */
static void test_moqtrun_pubdone_malformed_after_end_of_track(void) {
  u64 count = 0;
  mtdn_setup();
  mtdn_status_group(2002, 1, 1, MOQDATA_STATUS_END_OF_TRACK);
  CHECK(mtdr_done_on(MTRQ_S1, &count) == ~(u64)0);
  mtdn_status_group(2006, 2, 1, MOQDATA_STATUS_NORMAL);
  CHECK(mtdr_done_on(MTRQ_S1, &count) == MOQCTL_DONE_MALFORMED_TRACK);
  CHECK(mtdn_op_on(7, MTDN_PUB) && mtdn_op_on(13, MTDN_PUB));
  CHECK(mtdn_published() == 0);
}

/* d22 12.1 #4: an Object of a Group past that Group's END_OF_GROUP is a
 * Malformed Track; the next Group is not. */
static void test_moqtrun_pubdone_malformed_after_end_of_group(void) {
  u64 count = 0;
  mtdn_setup();
  mtdn_status_group(2002, 1, 1, MOQDATA_STATUS_END_OF_GROUP);
  mtdn_status_group(2006, 2, 1, MOQDATA_STATUS_NORMAL);
  CHECK(mtdr_done_on(MTRQ_S1, &count) == ~(u64)0);
  mtdn_status_group(2010, 2, 1, MOQDATA_STATUS_END_OF_GROUP);
  mtdn_status_group(2014, 2, 3, MOQDATA_STATUS_NORMAL);
  CHECK(mtdr_done_on(MTRQ_S1, &count) == MOQCTL_DONE_MALFORMED_TRACK);
}

/* d22 12.1: a relay that detects a Malformed Track resets its fetch
 * streams of the track MALFORMED_TRACK. */
static void test_moqtrun_pubdone_malformed_resets_fetch(void) {
  u8             buf[MOQTRUN_TEST_MAX_PAYLOAD];
  usz            off = 0;
  moqdata_subhdr h   = {0};
  u64            sid = mf_stuck_fetch();
  h.type             = 0x30;
  h.track_alias      = MF_ALIAS;
  h.group_id         = 1;
  moqdata_subhdr_put(wired_mspan_of(buf, sizeof buf), &off, &h);
  moqdata_obj_put_status(
      wired_mspan_of(buf, sizeof buf), &off, 0, MOQDATA_STATUS_END_OF_TRACK);
  wired_moqt_on_stream_data(
      &mtst_hub, SESS_A, 9002, wired_span_of(buf, off), 1);
  mf_obj(2, 0, 1);
  CHECK(mfill_reset_code(sid) == MOQTRUN_RESET_MALFORMED_TRACK);
  CHECK(mf_no_fetch());
  g_stream_send_ok_n = -1;
}

/* The publisher's session closes with the PUBLISH_DONE still waiting:
 * it goes out at once with the publisher's status, not TRACK_ENDED. */
static void test_moqtrun_pubdone_session_close_pending(void) {
  u64 count = 0;
  mtdn_setup();
  mtdn_group(2002, 1);
  mtdn_done(MOQCTL_DONE_GOING_AWAY, 3);
  wired_moqt_on_session_close(&mtst_hub, SESS_A);
  CHECK(mtdr_done_on(MTRQ_S1, &count) == MOQCTL_DONE_GOING_AWAY);
  CHECK(count == 1);
}

/* The publisher resets its PUBLISH stream with the PUBLISH_DONE still
 * waiting: it goes out at once, the publisher's status kept. */
static void test_moqtrun_pubdone_reset_pending(void) {
  u64 count = 0;
  mtdn_setup();
  mtdn_done(MOQCTL_DONE_GOING_AWAY, 3);
  wired_moqt_on_stream_reset(&mtst_hub, SESS_A, MTDN_PUB, 1, 0);
  CHECK(mtdr_done_on(MTRQ_S1, &count) == MOQCTL_DONE_GOING_AWAY);
  CHECK(count == 0);
  CHECK(mtdn_published() == 0);
}

/* After PUBLISH_DONE the publisher FINs its PUBLISH stream (3.3.2): both
 * sides ended, the request slot is freed; a new SUBSCRIBE finds no track. */
static void test_moqtrun_pubdone_fin_after(void) {
  moqctl_ftn f    = mtdn_setup();
  usz        used = mtrq_used();
  mtdn_done(MOQCTL_DONE_TRACK_ENDED, 0);
  wired_moqt_on_stream_data(
      &mtst_hub, SESS_A, MTDN_PUB, wired_span_of(0, 0), 1);
  CHECK(mtrq_used() == used - 1); /* A's PUBLISH slot */
  mtst_subscribe_p(SESS_B, MTRQ_S2, &f, 4, 0);
  CHECK(mtrq_type_on(12, MTRQ_S2) != MOQCTL_T_SUBSCRIBE_OK);
}

/* PUBLISH_DONE on the control stream names no PUBLISH: ignored. */
static void test_moqtrun_pubdone_ctl_ignored(void) {
  moqctl_publish_done d = {0};
  mtdn_setup();
  mtst_send(SESS_A, mtdr_ctl(SESS_A), MOQCTL_T_PUBLISH_DONE, mtdn_enc_done, &d);
  CHECK(mtdn_published() == 1);
  CHECK(mtrq_closes() == 0);
}

static void mtall_pubdone(void) {
  test_moqtrun_pubdone_one_sub();
  test_moqtrun_pubdone_two_subs();
  test_moqtrun_pubdone_n_groups();
  test_moqtrun_pubdone_datagram_only();
  test_moqtrun_pubdone_waits_late_stream();
  test_moqtrun_pubdone_counts_header_only();
  test_moqtrun_pubdone_waits_open_stream();
  test_moqtrun_pubdone_wait_bounded();
  test_moqtrun_pubdone_status_passthrough();
  test_moqtrun_pubdone_malformed_after_end_of_track();
  test_moqtrun_pubdone_malformed_after_end_of_group();
  test_moqtrun_pubdone_session_close_pending();
  test_moqtrun_pubdone_reset_pending();
  test_moqtrun_pubdone_fin_after();
  test_moqtrun_pubdone_ctl_ignored();
}

/* Publisher and subscriber on different drafts: B's PUBLISH_DONE decodes
 * in B's draft, its status spelled for B. */
static void test_moqtrun_pubdone_xver(void) {
  for (int pv = 0; pv < MOQVER_COUNT; pv++)
    for (int sv = 0; sv < MOQVER_COUNT; sv++) {
      u64 count = 0;
      mtdn_setup_v(pv, sv);
      mtdn_group(2002, 1);
      mtdn_done(MOQCTL_DONE_SUBSCRIPTION_ENDED, 1);
      CHECK(
          mtdr_done_on(MTRQ_S1, &count) ==
          moqctl_publish_done_for(sv, MOQCTL_DONE_SUBSCRIPTION_ENDED));
      CHECK(count == 1);
    }
}

void test_moqtrun_done(void) {
  moqtrun_test_allver(mtall_pubdone);
  /* mf_stuck_fetch parks a draft-18/19-layout FETCH */
  moqtrun_test_vers(
      0, MOQVER_CAP_FETCH_BODY_V22,
      test_moqtrun_pubdone_malformed_resets_fetch);
  test_moqtrun_pubdone_xver();
}
