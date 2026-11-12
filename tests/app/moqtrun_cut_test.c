/* Relay cut-through (draft-18 5.1: "A publisher SHOULD begin sending
 * incomplete objects when available") and nonexistent Objects on a
 * Subgroup stream (draft-18/19 9.1). Each framing case fails when the
 * reset or the skip is dropped.
 * Shares the recording io stubs and the mtst/mf fixtures of
 * moqtrun_test.c, moqtrun_sub_test.c and moqtrun_fetch_test.c (same
 * unity TU). */

#define MCUT_SID 2002 /* A's keep-open stream (client uni: 2 mod 4) */

/* A's stream of Group g, Subgroup sg (mode 0b10): its header, then
 * Objects ids[0..k) with 4-byte payloads, deltas chained; ends[j] is
 * the offset right after Object j. Returns the header's length. */
static usz mcut_stream(
    u8* buf, u64 g, u64 sg, const u64* ids, usz k, usz* ends) {
  static const u8 pl[4] = {7, 7, 7, 7};
  usz             off   = 0;
  moqdata_subhdr  h     = {0};
  h.type                = 0x34; /* explicit Subgroup ID, default priority */
  h.track_alias         = MF_ALIAS;
  h.group_id            = g;
  h.subgroup_id         = sg;
  moqdata_subhdr_put(wired_mspan_of(buf, MOQTRUN_TEST_MAX_PAYLOAD), &off, &h);
  usz hdr = off;
  for (usz j = 0; j < k; j++) {
    u64 d = j ? ids[j] - ids[j - 1] - 1 : ids[j];
    moqdata_obj_put(
        wired_mspan_of(buf, MOQTRUN_TEST_MAX_PAYLOAD), &off, d,
        wired_span_of(pl, 4));
    ends[j] = off;
  }
  return hdr;
}

static void mcut_send(const u8* p, usz a, usz b, int fin) {
  mt_feed(&mtst_hub, SESS_A, MCUT_SID, wired_span_of(p + a, b - a), fin);
}

/* B subscribes to alice; A's stream (Objects 0, 1, 2 of Group 1) is
 * built into buf. reliable sets the track ring-backed. */
static void mcut_init(u8* buf, usz* ends, int reliable) {
  static const u64 ids[3] = {0, 1, 2};
  mf_init(sizeof mf_arena);
  mf_obj(0, 0, 1);
  mf_subscribe(0);
  mtst_hub.reliable_alias_limit = reliable ? 100 : 0;
  mcut_stream(buf, 1, 0, ids, 3, ends);
  moqtrun_test_reset();
}

/* B's stream of the relay: the last one opened. */
static u64 mcut_sub_sid(void) { return moqtrun_test_last_kind(5)->stream_id; }

/* A lossy round refused after part of its Object went out
 * cannot be dropped and stay framed -- the stream is reset instead. */
static void test_moqtrun_cut_lossy_refusal_mid_object_resets(void) {
  u8  buf[MOQTRUN_TEST_MAX_PAYLOAD];
  usz ends[3];
  mcut_init(buf, ends, 0);
  mcut_send(buf, 0, ends[0] + 3, 0); /* Object 1's header + 1 byte */
  u64 sid = mcut_sub_sid();
  CHECK(moqtrun_test_sends_are(buf + ends[0], 3)); /* cut through */
  moqtrun_test_reset();
  g_stream_send_reject_n = 1;
  mcut_send(buf, ends[0] + 3, ends[2], 0);
  CHECK(moqtrun_test_count_kind(7) == 1);
  CHECK(moqtrun_test_last_kind(7)->stream_id == sid);
  for (usz i = 0; i < g_n_calls; i++) { /* nothing more on the torn one */
    CHECK(
        g_calls[i].kind != 3 || g_calls[i].stream_id != sid ||
        g_calls[i].refused);
  }
}

/* A refused cut-through send before any of the Object went out loses
 * nothing: no reset, and the completing round carries it whole. */
static void test_moqtrun_cut_refused_head_resent_whole(void) {
  u8  buf[MOQTRUN_TEST_MAX_PAYLOAD];
  usz ends[3];
  mcut_init(buf, ends, 0);
  mcut_send(buf, 0, ends[0], 0);
  moqtrun_test_reset();
  g_stream_send_reject_n = 1;
  mcut_send(buf, ends[0], ends[0] + 3, 0); /* the push is refused */
  mcut_send(buf, ends[0] + 3, ends[1], 0);
  CHECK(moqtrun_test_count_kind(7) == 0);
  CHECK(moqtrun_test_sends_are(buf + ends[0], ends[1] - ends[0]));
}

/* Until the Object's header is whole, nothing of it goes out. */
static void test_moqtrun_cut_waits_for_header(void) {
  u8  buf[MOQTRUN_TEST_MAX_PAYLOAD];
  usz ends[3];
  mcut_init(buf, ends, 0);
  mcut_send(buf, 0, ends[0], 0);
  moqtrun_test_reset();
  mcut_send(buf, ends[0], ends[0] + 1, 0); /* the ID Delta alone */
  CHECK(moqtrun_test_count_kind(3) == 0);
  mcut_send(buf, ends[0] + 1, ends[1], 0);
  CHECK(moqtrun_test_sends_are(buf + ends[0], ends[1] - ends[0]));
}

/* Ring-backed: a refused send is retried from the exact byte
 * after the part already sent -- nothing twice, nothing lost. */
static void test_moqtrun_cut_reliable_resumes_at_byte(void) {
  u8  buf[MOQTRUN_TEST_MAX_PAYLOAD];
  usz ends[3];
  mcut_init(buf, ends, 1);
  mcut_send(buf, 0, ends[0], 0);
  moqtrun_test_reset();
  mcut_send(buf, ends[0], ends[0] + 3, 0); /* head cut through */
  g_stream_send_ok_n = 0;
  mcut_send(buf, ends[0] + 3, ends[2], 0); /* rest held in the ring */
  g_stream_send_ok_n = -1;
  wired_moqt_tick(&mtst_hub, 5);
  CHECK(moqtrun_test_count_kind(7) == 0);
  CHECK(moqtrun_test_sends_are(buf + ends[0], ends[2] - ends[0]));
}

/* A FIN inside an Object part of which already went out: the
 * subscriber's stream is reset, never FIN'd torn (draft-19 11.4). */
static void test_moqtrun_cut_torn_fin_resets(void) {
  u8  buf[MOQTRUN_TEST_MAX_PAYLOAD];
  usz ends[3];
  mcut_init(buf, ends, 0);
  mcut_send(buf, 0, ends[0] + 3, 0);
  u64 sid = mcut_sub_sid();
  moqtrun_test_reset();
  mcut_send(buf, ends[0] + 3, ends[0] + 3, 1);
  CHECK(moqtrun_test_count_kind(6) == 0);
  CHECK(moqtrun_test_count_kind(7) == 1);
  CHECK(moqtrun_test_last_kind(7)->stream_id == sid);
}

/* draft-18/19 9.1 on a stream: Group 1 closed with Objects 0, 1, 5
 * cached, A's stream then brings 2 (recorded nonexistent: not
 * forwarded) and 5 (kept): 5 goes out re-chained onto 1 (delta 3). */
static void test_moqtrun_stream_skips_gone_object(void) {
  static const u64 ids[4] = {0, 1, 2, 5}, five[1] = {5};
  u8               buf[MOQTRUN_TEST_MAX_PAYLOAD], one[MOQTRUN_TEST_MAX_PAYLOAD];
  usz              ends[4], e1[1];
  mcut_init(buf, ends, 0);
  mcut_stream(buf, 1, 0, ids, 4, ends);
  mcut_send(buf, 0, ends[1], 0);
  u64 sid = mcut_sub_sid();
  usz h   = mcut_stream(one, 1, 1, five, 1, e1); /* Subgroup 1: Object 5 */
  mt_feed(&mtst_hub, SESS_A, MCUT_SID + 4, wired_span_of(one, e1[0]), 1);
  mf_obj(2, 0, 1); /* Group 1 is closed */
  moqtrun_test_reset();
  mcut_send(buf, ends[1], ends[3], 0);
  u8  want[MOQTRUN_TEST_MAX_PAYLOAD];
  usz n = 0;
  moqdata_obj_put(
      wired_mspan_of(want, sizeof want), &n, 3, wired_span_of(one + h + 2, 4));
  CHECK(moqtrun_test_count_kind(3) == 1);
  CHECK(moqtrun_test_last_kind(3)->stream_id == sid);
  CHECK(moqtrun_test_sends_are(want, n));
}

/* A's relay of stream MCUT_SID. */
static const wired_moqtrun_relay* mcut_relay(void) {
  const wired_moqtrun_track* t =
      &moqtrun_find_by_wt(&mtst_hub, SESS_A)->tracks[0];
  for (usz r = 0; r < WIRED_MOQTRUN_MAX_RELAYS; r++) {
    if (t->relays[r].in_use && t->relays[r].pub_stream_id == MCUT_SID) {
      return &t->relays[r];
    }
  }
  return 0;
}

/* The same torn round, but the transport's reset latch is full this
 * step (stream_reset refused): the subscriber's stream is marked expired
 * so the reset is not lost, and nothing more goes on it. */
static void test_moqtrun_cut_reset_refused_expires(void) {
  u8  buf[MOQTRUN_TEST_MAX_PAYLOAD];
  usz ends[3];
  mcut_init(buf, ends, 0);
  mcut_send(buf, 0, ends[0] + 3, 0);
  moqtrun_test_reset();
  g_stream_send_reject_n = 1;
  g_stream_reset_ret     = 0;
  mcut_send(buf, ends[0] + 3, ends[2], 0);
  CHECK(moqtrun_test_count_kind(7) == 1);
  CHECK(mcut_relay() && mcut_relay()->sub_expired != 0);
}

/* draft-18/19 9.1: a fresh keep-open stream whose first Object is
 * recorded nonexistent relays nothing at all (no stream is opened). */
static void test_moqtrun_stream_starts_at_gone_object(void) {
  static const u64 ids[2] = {0, 1}, five[1] = {5}, two[1] = {2};
  u8               buf[MOQTRUN_TEST_MAX_PAYLOAD], one[MOQTRUN_TEST_MAX_PAYLOAD];
  usz              ends[3], e1[1];
  mcut_init(buf, ends, 0);
  mcut_stream(buf, 1, 0, ids, 2, ends);
  mcut_send(buf, 0, ends[1], 1);
  mcut_stream(one, 1, 1, five, 1, e1);
  mt_feed(&mtst_hub, SESS_A, MCUT_SID + 4, wired_span_of(one, e1[0]), 1);
  mf_obj(2, 0, 1); /* Group 1 is closed: Object 2 does not exist */
  mcut_stream(one, 1, 2, two, 1, e1);
  moqtrun_test_reset();
  mt_feed(&mtst_hub, SESS_A, MCUT_SID + 8, wired_span_of(one, e1[0]), 0);
  CHECK(moqtrun_test_count_kind(5) == 0 && moqtrun_test_count_kind(4) == 0);
}

/* draft-18/19 9.1 / 11.4.2: A's keep-open stream opened with its header
 * alone (the relay opened B's stream header-only); its first Object is
 * then one recorded nonexistent, so nothing sent can carry the next
 * Object's re-chained delta: B's stream is reset, nothing of the round
 * goes out. */
static void test_moqtrun_stream_header_then_gone_object(void) {
  static const u64 ids[2] = {0, 1}, five[1] = {5}, two[2] = {2, 5};
  u8               buf[MOQTRUN_TEST_MAX_PAYLOAD], one[MOQTRUN_TEST_MAX_PAYLOAD];
  usz              ends[3], e1[1];
  mcut_init(buf, ends, 0);
  mcut_stream(one, 1, 1, ids, 2, ends);
  mt_feed(&mtst_hub, SESS_A, MCUT_SID + 4, wired_span_of(one, ends[1]), 1);
  mcut_stream(one, 1, 2, five, 1, e1);
  mt_feed(&mtst_hub, SESS_A, MCUT_SID + 8, wired_span_of(one, e1[0]), 1);
  mf_obj(2, 0, 1); /* Group 1 is closed: Objects 2..4 do not exist */
  usz h = mcut_stream(buf, 1, 0, two, 2, ends);
  mcut_send(buf, 0, h, 0);
  u64 sid = mcut_sub_sid();
  moqtrun_test_reset();
  mcut_send(buf, h, ends[1], 0);
  const moqtrun_test_call* r = moqtrun_test_last_kind(7);
  CHECK(moqtrun_test_count_kind(3) == 0);
  CHECK(moqtrun_test_count_kind(7) == 1 && r && r->stream_id == sid);
}

/* draft-18/19 9.1 / 11.4.2: after the hub cut nonexistent Object 2 from
 * A's stream (Group 1 closed, 0, 1 and 5 cached), its next round is one
 * re-chained Object 5 of 65532 bytes -- a fragment just under
 * WIRED_MOQTRUN_RELAY_FRAG_MAX plus one full WT delivery. moqtrun_gone_put
 * budgets 8 bytes for the new Object ID Delta, so an Object that fills
 * relay_scratch to within that is not re-framed: the round is poisoned and
 * B's stream reset, never sent torn. */
static void test_moqtrun_stream_gone_round_too_big(void) {
  static const u64 ids[2] = {0, 1}, five[1] = {5};
  static u8 big[WIRED_MOQTRUN_RELAY_FRAG_MAX + WIRED_SRVLOOP_WT_BUF_CAP + 64];
  static u8 pl[sizeof big];
  const usz frag = WIRED_MOQTRUN_RELAY_FRAG_MAX - 4;
  u8        buf[MOQTRUN_TEST_MAX_PAYLOAD], one[MOQTRUN_TEST_MAX_PAYLOAD];
  usz       ends[3], e1[1], n = 0;
  mcut_init(buf, ends, 0);
  mcut_stream(buf, 1, 0, ids, 2, ends);
  mcut_send(buf, 0, ends[1], 0);
  u64 sid = mcut_sub_sid();
  mcut_stream(one, 1, 1, five, 1, e1);
  mt_feed(&mtst_hub, SESS_A, MCUT_SID + 4, wired_span_of(one, e1[0]), 1);
  mf_obj(2, 0, 1); /* Group 1 is closed: Objects 2..4 do not exist */
  moqdata_obj_put(wired_mspan_of(big, sizeof big), &n, 0, wired_span_of(pl, 4));
  usz at = n; /* Object 2 (delta 0 after 1), then Object 5 (delta 2) */
  moqdata_obj_put(
      wired_mspan_of(big, sizeof big), &n, 2,
      wired_span_of(pl, frag + WIRED_SRVLOOP_WT_BUF_CAP - 5));
  moqtrun_test_reset();
  mt_feed(&mtst_hub, SESS_A, MCUT_SID, wired_span_of(big, at + frag), 0);
  CHECK(moqtrun_test_count_kind(7) == 0);
  mt_feed(
      &mtst_hub, SESS_A, MCUT_SID,
      wired_span_of(big + at + frag, n - at - frag), 0);
  const moqtrun_test_call* r = moqtrun_test_last_kind(7);
  CHECK(n - at - frag <= WIRED_SRVLOOP_WT_BUF_CAP + 1);
  CHECK(r && r->stream_id == sid && moqtrun_test_count_kind(3) == 0);
}

/* A mode-0b01 stream (Subgroup ID = its first Object's ID, draft-22
 * 11.4.2) whose first delivery tears inside that Object: no Subgroup ID
 * is known yet, so no header is saved for late joiners. */
static void test_moqtrun_stream_mode1_torn_first_object(void) {
  static const u8 pl[4] = {7, 7, 7, 7};
  u8              buf[MOQTRUN_TEST_MAX_PAYLOAD];
  usz             ends[3], off = 0;
  moqdata_subhdr  h = {0};
  mcut_init(buf, ends, 0);
  h.type        = 0x32;
  h.track_alias = MF_ALIAS;
  h.group_id    = 1;
  moqdata_subhdr_put(wired_mspan_of(buf, sizeof buf), &off, &h);
  moqdata_obj_put(
      wired_mspan_of(buf, sizeof buf), &off, 0, wired_span_of(pl, 4));
  mcut_send(buf, 0, off - 2, 0);
  CHECK(mcut_relay() != 0);
  CHECK(mcut_relay() && mcut_relay()->hdr_len == 0);
}

static void test_moqtrun_cut(void) {
  test_moqtrun_stream_gone_round_too_big();
  test_moqtrun_stream_header_then_gone_object();
  test_moqtrun_stream_mode1_torn_first_object();
  test_moqtrun_cut_reset_refused_expires();
  test_moqtrun_stream_starts_at_gone_object();
  test_moqtrun_cut_lossy_refusal_mid_object_resets();
  test_moqtrun_cut_refused_head_resent_whole();
  test_moqtrun_cut_waits_for_header();
  test_moqtrun_cut_reliable_resumes_at_byte();
  test_moqtrun_cut_torn_fin_resets();
  test_moqtrun_stream_skips_gone_object();
}
