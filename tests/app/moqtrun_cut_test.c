/* Relay cut-through (draft-18 5.1: "A publisher SHOULD begin sending
 * incomplete objects when available") and nonexistent Objects on a
 * Subgroup stream (draft-18/19 9.1). Each framing case is a
 * counterexample of tasks/loopeng/MoqtCutThrough.tla's mutants: drop the
 * reset (MutNoReset) or the skip (MutNoSkip) and one of these fails.
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
  wired_moqt_on_stream_data(
      &mtst_hub, SESS_A, MCUT_SID, wired_span_of(p + a, b - a), fin);
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

/* MutNoReset: a lossy round refused after part of its Object went out
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

/* MutNoSkip, ring-backed: a refused send is retried from the exact byte
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
  wired_moqt_on_stream_data(
      &mtst_hub, SESS_A, MCUT_SID + 4, wired_span_of(one, e1[0]), 1);
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

static void test_moqtrun_cut(void) {
  test_moqtrun_cut_lossy_refusal_mid_object_resets();
  test_moqtrun_cut_refused_head_resent_whole();
  test_moqtrun_cut_waits_for_header();
  test_moqtrun_cut_reliable_resumes_at_byte();
  test_moqtrun_cut_torn_fin_resets();
  test_moqtrun_stream_skips_gone_object();
}
