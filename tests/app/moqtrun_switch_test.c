/* Hub side of SWITCH_FROM (0x24, moqtail-compatible experimental track
 * switching, draft-22 only, opt-in wired_moqt_hub.switch_track): the
 * predicates of tasks/loopeng/moqt/TrackSwitch/RESULT.md's invariant ->
 * test table (TS-n of design.md). Every SWITCH_FROM goes out as its pinned
 * wire bytes `24 03 <rid> <mode> <flags>` (plan 1), built by hand here, not
 * by the codec under test. Shares the recording io stubs (moqtrun_test.c),
 * the subscription / request-stream fixtures (moqtrun_sub_test.c) and the
 * PUBLISH_DONE reader (moqtrun_drain_test.c) of the same unity TU.
 *
 * Fixture: A publishes two variants of one content, "hi" (alias 1, on
 * request stream MTSW_PUB_HI) and "lo" (alias 2, MTSW_PUB_LO); B holds hi
 * on MTRQ_S1 (Request ID 2) and switches to lo on MTRQ_S2 (Request ID 4).
 * The aliases are free in B's session, so B sees them unchanged. */

#define MTSW_PUB_LO MTRQ_ID(1)
#define MTSW_PUB_HI MTRQ_ID(2)
#define MTSW_HI 1 /* alias */
#define MTSW_LO 2
#define MTSW_RID_HI 2
#define MTSW_RID_LO 4
#define MTSW_HARD 0x00
#define MTSW_SOFT 0x01
#define MTSW_DONE 0x80

/* ===================== fixtures ===================== */

static moqctl_ftn mtsw_ftn(const char* name) {
  return mtst_ftn("chat", "room1", name);
}

/* Joins A and B (draft g_moqtrun_test_ver), switching on; A publishes hi
 * and lo; B subscribes hi on MTRQ_S1. */
static void mtsw_setup(void) {
  moqctl_ftn hi = mtsw_ftn("hi"), lo = mtsw_ftn("lo");
  mtst_init();
  mtst_hub.switch_track = 1;
  mtst_join(SESS_A);
  mtst_join(SESS_B);
  mtst_publish(SESS_A, MTSW_PUB_HI, &hi, MTSW_HI);
  mtst_publish(SESS_A, MTSW_PUB_LO, &lo, MTSW_LO);
  mtst_subscribe_p(SESS_B, MTRQ_S1, &hi, MTSW_RID_HI, 0);
  CHECK(mtrq_type_on(12, MTRQ_S1) == MOQCTL_T_SUBSCRIBE_OK);
}

/* SUBSCRIBE {chat, room1}/name, Request ID rid, whose only parameter is
 * the pinned SWITCH_FROM 24 03 <old> <mode> <flags> (rid/old < 64: one
 * varint byte each) -- the draft-22 body as plan 1 spells it. */
static usz mtsw_sub_body(
    u8* b, u64 rid, const char* name, u64 old, u8 mode, u8 flags) {
  static const u8 ns[] = {0x02, 0x04, 'c', 'h', 'a', 't',
                          0x05, 'r',  'o', 'o', 'm', '1'};
  usz             n    = 0;
  b[n++]               = (u8)rid;
  for (usz i = 0; i < sizeof ns; i++) b[n++] = ns[i];
  wired_span nm = mtst_z(name);
  b[n++]        = (u8)nm.n;
  for (usz i = 0; i < nm.n; i++) b[n++] = nm.p[i];
  b[n++] = 0x01; /* one parameter */
  b[n++] = 0x24; /* SWITCH_FROM, Type delta from 0 */
  b[n++] = 0x03;
  b[n++] = (u8)old;
  b[n++] = mode;
  b[n++] = flags;
  return n;
}

/* B: SUBSCRIBE lo on MTRQ_S2 switching from hi. */
static void mtsw_switch(u8 mode, u8 flags) {
  u8  b[64];
  usz n = mtsw_sub_body(b, MTSW_RID_LO, "lo", MTSW_RID_HI, mode, flags);
  mtrq_raw(SESS_B, MTRQ_S2, MOQCTL_T_SUBSCRIBE, b, n);
}

/* Header (Type 0x30, alias, Group g, Subgroup 0) + n one-byte Objects. */
static usz mtsw_bytes(u64 alias, u64 g, usz n, int hdr, u8* buf) {
  moqdata_subhdr h   = {0};
  usz            off = 0;
  h.type             = 0x30;
  h.track_alias      = alias;
  h.group_id         = g;
  if (hdr)
    moqdata_subhdr_put(wired_mspan_of(buf, MOQTRUN_TEST_MAX_PAYLOAD), &off, &h);
  for (usz i = 0; i < n; i++) {
    u8 v = (u8)i;
    moqdata_obj_put(
        wired_mspan_of(buf, MOQTRUN_TEST_MAX_PAYLOAD), &off, 0,
        wired_span_of(&v, 1));
  }
  return off;
}

/* A's publisher stream sid opens Group g of alias with one Object; fin 1
 * delivers it whole (one-shot), fin 0 keeps it open. */
static void mtsw_group(u64 sid, u64 alias, u64 g, int fin) {
  u8  buf[MOQTRUN_TEST_MAX_PAYLOAD];
  usz n = mtsw_bytes(alias, g, 1, 1, buf);
  wired_moqt_on_stream_data(&mtst_hub, SESS_A, sid, wired_span_of(buf, n), fin);
}

/* One more Object on A's open stream sid (fin ends it with it). */
static void mtsw_more(u64 sid, int fin) {
  u8  buf[MOQTRUN_TEST_MAX_PAYLOAD];
  usz n = mtsw_bytes(0, 0, 1, 0, buf);
  wired_moqt_on_stream_data(&mtst_hub, SESS_A, sid, wired_span_of(buf, n), fin);
}

/* A's publisher stream ids, one per (alias, group): client uni (2 mod 4). */
static u64 mtsw_sid(u64 alias, u64 g) { return 3002 + 400 * alias + 4 * g; }

/* Index of the open (one-shot kind 4 or keep-open kind 5) of a stream to
 * B carrying alias / Group g, from call `from` on; g_n_calls if none. */
static usz mtsw_open_at(u64 alias, u64 g, usz from) {
  for (usz i = from; i < g_n_calls; i++) {
    const moqtrun_test_call* c = &g_calls[i];
    moqdata_subhdr           h;
    usz                      off = 0;
    if ((c->kind != 4 && c->kind != 5) || c->s != SESS_B) continue;
    if (moqdata_subhdr_take(
            wired_span_of(c->payload, c->payload_len), &off, &h) != MOQDATA_OK)
      continue;
    if (h.track_alias == alias && h.group_id == g) return i;
  }
  return g_n_calls;
}

/* Streams opened to B for alias / Group g. */
static usz mtsw_opened(u64 alias, u64 g) {
  usz n = 0;
  for (usz i = mtsw_open_at(alias, g, 0); i < g_n_calls;
       i     = mtsw_open_at(alias, g, i + 1))
    n++;
  return n;
}

/* B's subscriber stream id for alias / Group g (the first one). */
static u64 mtsw_sub_sid(u64 alias, u64 g) {
  usz i = mtsw_open_at(alias, g, 0);
  return i < g_n_calls ? g_calls[i].stream_id : ~(u64)0;
}

/* Index of the first call of kind on sid; g_n_calls if none. */
static usz mtsw_call_at(int kind, u64 sid) {
  for (usz i = 0; i < g_n_calls; i++)
    if (g_calls[i].kind == kind && g_calls[i].stream_id == sid) return i;
  return g_n_calls;
}

/* 1 iff B's stream sid ended with a FIN (stream_fin, or a fin=1 send). */
static int mtsw_fin_seen(u64 sid) {
  for (usz i = 0; i < g_n_calls; i++)
    if (g_calls[i].stream_id == sid &&
        (g_calls[i].kind == 6 || (g_calls[i].kind == 3 && g_calls[i].fin)))
      return 1;
  return 0;
}

/* PUBLISH_DONE messages sent on request stream sid, and the index of the
 * first one (g_n_calls if none). */
static usz mtsw_dones(u64 sid, usz* first) {
  usz n  = 0;
  *first = g_n_calls;
  for (usz i = 0; i < g_n_calls; i++) {
    u64 count;
    if ((g_calls[i].kind != 3 && g_calls[i].kind != 12) ||
        g_calls[i].stream_id != sid)
      continue;
    if (mtdr_done_in(&g_calls[i], &count) == ~(u64)0) continue;
    if (!n) *first = i;
    n++;
  }
  return n;
}

static usz mtsw_done_n(u64 sid) {
  usz first;
  return mtsw_dones(sid, &first);
}

/* B's live subscription on A's track i (0 hi, 1 lo), else 0. */
static wired_moqtrun_sub* mtsw_sub(usz i) {
  wired_moqtrun_peer* a = moqtrun_find_by_wt(&mtst_hub, SESS_A);
  return moqtrun_track_sub_of_peer(&a->tracks[i], mtst_idx(SESS_B));
}

static wired_moqtrun_sub* mtsw_hi(void) { return mtsw_sub(0); }
static wired_moqtrun_sub* mtsw_lo(void) { return mtsw_sub(1); }

/* The SWITCH_FROM was refused INVALID_SWITCH on MTRQ_S2: no lo
 * subscription, hi untouched, the session open. */
static void mtsw_check_refused(void) {
  CHECK(mtrq_err_on(MTRQ_S2) == MOQCTL_ERR_INVALID_SWITCH);
  CHECK(mtsw_lo() == 0);
  CHECK(mtrq_closes() == 0);
}

/* ===================== boundary (TS-1) ===================== */

/* hi Largest 3, lo Largest 2: G = 4 -> hi ends at 3, lo starts {4, 0};
 * the aliases stay each subscription's own. */
static void test_moqtrun_switch_boundary_plus_one(void) {
  mtsw_setup();
  mtsw_group(mtsw_sid(MTSW_HI, 3), MTSW_HI, 3, 0);
  mtsw_group(mtsw_sid(MTSW_LO, 2), MTSW_LO, 2, 1);
  mtsw_switch(MTSW_SOFT, MTSW_DONE);
  CHECK(mtrq_type_on(12, MTRQ_S2) == MOQCTL_T_SUBSCRIBE_OK);
  wired_moqtrun_sub* hi = mtsw_hi();
  wired_moqtrun_sub* lo = mtsw_lo();
  CHECK(hi && hi->has_end_group && hi->end_group == 3);
  CHECK(lo && lo->start.group == 4 && lo->start.object == 0);
  CHECK(hi && hi->track_alias == MTSW_HI);
  CHECK(lo && lo->track_alias == MTSW_LO);
}

/* B ahead: hi Largest 1, lo Largest 3 -> G = 4; hi still delivers its
 * groups 2 and 3 (Soft), not 4, then ends. */
static void test_moqtrun_switch_boundary_b_ahead(void) {
  mtsw_setup();
  mtsw_group(mtsw_sid(MTSW_HI, 1), MTSW_HI, 1, 1);
  mtsw_group(mtsw_sid(MTSW_LO, 3), MTSW_LO, 3, 1);
  mtsw_switch(MTSW_SOFT, MTSW_DONE);
  CHECK(mtsw_hi() && mtsw_hi()->end_group == 3);
  CHECK(mtsw_lo() && mtsw_lo()->start.group == 4);
  CHECK(mtsw_done_n(MTRQ_S1) == 0);
  mtsw_group(mtsw_sid(MTSW_HI, 2), MTSW_HI, 2, 1);
  CHECK(mtsw_done_n(MTRQ_S1) == 0); /* G-1 = 3 not reached yet */
  mtsw_group(mtsw_sid(MTSW_HI, 3), MTSW_HI, 3, 1);
  mtsw_group(mtsw_sid(MTSW_HI, 4), MTSW_HI, 4, 1);
  CHECK(mtsw_opened(MTSW_HI, 2) == 1 && mtsw_opened(MTSW_HI, 3) == 1);
  CHECK(mtsw_opened(MTSW_HI, 4) == 0);
  CHECK(mtsw_done_n(MTRQ_S1) == 1);
}

/* ===================== gate (TS-2) ===================== */

/* After the switch hi's Group >= G opens nothing to B, lo's Group < G
 * opens nothing, lo's G does. */
static void test_moqtrun_switch_soft_cut_at_boundary(void) {
  mtsw_setup();
  mtsw_group(mtsw_sid(MTSW_HI, 3), MTSW_HI, 3, 1);
  mtsw_switch(MTSW_SOFT, MTSW_DONE); /* G = 4 */
  mtsw_group(mtsw_sid(MTSW_HI, 4), MTSW_HI, 4, 1);
  mtsw_group(mtsw_sid(MTSW_LO, 3), MTSW_LO, 3, 1);
  mtsw_group(mtsw_sid(MTSW_LO, 4), MTSW_LO, 4, 1);
  CHECK(mtsw_opened(MTSW_HI, 3) == 1);
  CHECK(mtsw_opened(MTSW_HI, 4) == 0);
  CHECK(mtsw_opened(MTSW_LO, 3) == 0);
  CHECK(mtsw_opened(MTSW_LO, 4) == 1);
}

/* Both variants publish Groups 0..5, the switch lands after Group 2:
 * every Group reaches B on exactly one stream. */
static void test_moqtrun_switch_no_group_twice(void) {
  mtsw_setup();
  for (u64 g = 0; g < 3; g++) {
    mtsw_group(mtsw_sid(MTSW_HI, g), MTSW_HI, g, 1);
    mtsw_group(mtsw_sid(MTSW_LO, g), MTSW_LO, g, 1);
  }
  mtsw_switch(MTSW_SOFT, MTSW_DONE);
  for (u64 g = 3; g < 6; g++) {
    mtsw_group(mtsw_sid(MTSW_HI, g), MTSW_HI, g, 1);
    mtsw_group(mtsw_sid(MTSW_LO, g), MTSW_LO, g, 1);
  }
  for (u64 g = 0; g < 6; g++)
    CHECK(mtsw_opened(MTSW_HI, g) + mtsw_opened(MTSW_LO, g) == 1);
}

/* NoGap (Soft): hi for g < G, lo for g >= G, every Group FINned (one-shot
 * streams carry their FIN). */
static void test_moqtrun_switch_soft_no_gap(void) {
  mtsw_setup();
  for (u64 g = 0; g < 2; g++) mtsw_group(mtsw_sid(MTSW_HI, g), MTSW_HI, g, 1);
  mtsw_group(mtsw_sid(MTSW_LO, 1), MTSW_LO, 1, 1);
  mtsw_switch(MTSW_SOFT, MTSW_DONE); /* G = 2 */
  for (u64 g = 2; g < 5; g++) {
    mtsw_group(mtsw_sid(MTSW_LO, g), MTSW_LO, g, 1);
    mtsw_group(mtsw_sid(MTSW_HI, g), MTSW_HI, g, 1);
  }
  for (u64 g = 0; g < 5; g++) {
    CHECK(mtsw_opened(MTSW_HI, g) == (g < 2));
    CHECK(mtsw_opened(MTSW_LO, g) == (g >= 2));
  }
}

/* ===================== Soft (TS-3, TS-6) ===================== */

/* hi's open G-1 stream keeps relaying while lo's G is open: no reset on
 * it, no PUBLISH_DONE yet. */
static void test_moqtrun_switch_soft_drains_old(void) {
  mtsw_setup();
  mtsw_group(mtsw_sid(MTSW_HI, 3), MTSW_HI, 3, 0);
  u64 hs = mtsw_sub_sid(MTSW_HI, 3);
  mtsw_switch(MTSW_SOFT, MTSW_DONE);
  mtsw_group(mtsw_sid(MTSW_LO, 4), MTSW_LO, 4, 0);
  CHECK(mtsw_opened(MTSW_LO, 4) == 1);
  usz before = moqtrun_test_count_kind(3);
  mtsw_more(mtsw_sid(MTSW_HI, 3), 0);
  CHECK(moqtrun_test_count_kind(3) == before + 1);
  CHECK(
      moqtrun_test_last_kind(3) && moqtrun_test_last_kind(3)->stream_id == hs);
  CHECK(mtrq_reset_code(hs) == -1);
  CHECK(mtsw_done_n(MTRQ_S1) == 0);
}

/* PUBLISH_DONE never precedes hi's last stream: it follows right after
 * its G-1 stream's FIN, once, status byte 0x3 ("switched", d22 raw --
 * never remapped to TRACK_ENDED), Stream Count the streams B got for hi;
 * the request stream FINs. */
static void test_moqtrun_switch_soft_done_after_fin(void) {
  u64 count = 0;
  usz first;
  mtsw_setup();
  mtsw_group(mtsw_sid(MTSW_HI, 2), MTSW_HI, 2, 1);
  mtsw_group(mtsw_sid(MTSW_HI, 3), MTSW_HI, 3, 0);
  u64 hs = mtsw_sub_sid(MTSW_HI, 3);
  mtsw_switch(MTSW_SOFT, MTSW_DONE);
  mtsw_more(mtsw_sid(MTSW_HI, 3), 0);
  CHECK(mtsw_done_n(MTRQ_S1) == 0);
  wired_moqt_on_stream_data(
      &mtst_hub, SESS_A, mtsw_sid(MTSW_HI, 3), wired_span_of(0, 0), 1);
  CHECK(mtsw_fin_seen(hs));
  CHECK(mtsw_dones(MTRQ_S1, &first) == 1);
  CHECK(mtsw_call_at(6, hs) < first);
  CHECK(mtdr_done_on(MTRQ_S1, &count) == 0x3);
  CHECK(count == 2);
  CHECK(mtrq_fin_on(MTRQ_S1) == 1);
  CHECK(mtsw_hi() == 0);
}

/* flags 0x00: no PUBLISH_DONE and no FIN on hi's stream -- hi is
 * suspended as moqtail does (FORWARD 0, kept, nothing more delivered);
 * flags 0x80: exactly one, even as more data and ticks pass. */
static void test_moqtrun_switch_no_flag_no_done(void) {
  mtsw_setup();
  mtsw_group(mtsw_sid(MTSW_HI, 3), MTSW_HI, 3, 1);
  mtsw_switch(MTSW_SOFT, 0x00);
  CHECK(mtsw_done_n(MTRQ_S1) == 0);
  CHECK(mtrq_fin_on(MTRQ_S1) == 0);
  CHECK(mtsw_hi() && mtsw_hi()->forward_off == 1);
  mtsw_group(mtsw_sid(MTSW_HI, 4), MTSW_HI, 4, 1);
  CHECK(mtsw_opened(MTSW_HI, 4) == 0);
  wired_moqt_tick(&mtst_hub, 100000);
  CHECK(mtsw_done_n(MTRQ_S1) == 0);

  mtsw_setup();
  mtsw_group(mtsw_sid(MTSW_HI, 3), MTSW_HI, 3, 1);
  mtsw_switch(MTSW_SOFT, MTSW_DONE);
  mtsw_group(mtsw_sid(MTSW_HI, 4), MTSW_HI, 4, 1);
  mtsw_group(mtsw_sid(MTSW_LO, 4), MTSW_LO, 4, 1);
  wired_moqt_tick(&mtst_hub, 100000);
  CHECK(mtsw_done_n(MTRQ_S1) == 1);
}

/* Soft, hi stalls before G-1: the deadline gives up (only with no hi
 * stream open), and a hi Group < G arriving later opens nothing. */
static void test_moqtrun_switch_soft_deadline_giveup(void) {
  mtsw_setup();
  wired_moqt_tick(&mtst_hub, 1000);
  mtsw_group(mtsw_sid(MTSW_HI, 1), MTSW_HI, 1, 1);
  mtsw_group(mtsw_sid(MTSW_LO, 3), MTSW_LO, 3, 1);
  mtsw_switch(MTSW_SOFT, MTSW_DONE); /* G = 4, hi at 1 */
  wired_moqt_tick(&mtst_hub, 1000 + WIRED_MOQTSW_SOFT_WAIT_MS - 1);
  CHECK(mtsw_done_n(MTRQ_S1) == 0);
  wired_moqt_tick(&mtst_hub, 1000 + WIRED_MOQTSW_SOFT_WAIT_MS);
  CHECK(mtsw_done_n(MTRQ_S1) == 1);
  mtsw_group(mtsw_sid(MTSW_HI, 2), MTSW_HI, 2, 1);
  CHECK(mtsw_opened(MTSW_HI, 2) == 0);
}

/* G = 0 (nothing published on either): Soft ends hi at once. */
static void test_moqtrun_switch_soft_g0_ends_now(void) {
  mtsw_setup();
  mtsw_switch(MTSW_SOFT, MTSW_DONE);
  CHECK(mtsw_lo() && mtsw_lo()->start.group == 0);
  CHECK(mtsw_done_n(MTRQ_S1) == 1);
  CHECK(mtsw_hi() == 0);
  mtsw_group(mtsw_sid(MTSW_HI, 0), MTSW_HI, 0, 1);
  mtsw_group(mtsw_sid(MTSW_LO, 0), MTSW_LO, 0, 1);
  CHECK(mtsw_opened(MTSW_HI, 0) == 0 && mtsw_opened(MTSW_LO, 0) == 1);
}

/* ===================== Hard (TS-4) ===================== */

/* In the dispatch lo's Group G opens to B, hi's open stream is reset
 * CANCELLED and PUBLISH_DONE 0x3 follows the reset. */
static void test_moqtrun_switch_hard_resets_old(void) {
  usz first;
  mtsw_setup();
  mtsw_group(mtsw_sid(MTSW_HI, 3), MTSW_HI, 3, 0);
  u64 hs = mtsw_sub_sid(MTSW_HI, 3);
  mtsw_switch(MTSW_HARD, MTSW_DONE); /* G = 4 */
  mtsw_more(mtsw_sid(MTSW_HI, 3), 0);
  CHECK(mtrq_reset_code(hs) == -1);
  CHECK(mtsw_done_n(MTRQ_S1) == 0);
  mtsw_group(mtsw_sid(MTSW_LO, 4), MTSW_LO, 4, 0);
  CHECK(mtsw_opened(MTSW_LO, 4) == 1);
  CHECK(mtrq_reset_code(hs) == 0x1);
  CHECK(mtsw_dones(MTRQ_S1, &first) == 1);
  CHECK(mtsw_call_at(7, hs) < first);
  u64 count = 0;
  CHECK(mtdr_done_on(MTRQ_S1, &count) == 0x3);
  CHECK(mtsw_hi() == 0);
}

/* Hard with no hi stream open: hi waits (still delivers Groups < G) until
 * lo's Group G arrives, then ends with no further input. */
static void test_moqtrun_switch_hard_ends_on_b_boundary(void) {
  mtsw_setup();
  mtsw_group(mtsw_sid(MTSW_LO, 3), MTSW_LO, 3, 1);
  mtsw_switch(MTSW_HARD, MTSW_DONE); /* G = 4, hi ahead of nothing */
  mtsw_group(mtsw_sid(MTSW_HI, 3), MTSW_HI, 3, 1);
  CHECK(mtsw_opened(MTSW_HI, 3) == 1);
  CHECK(mtsw_done_n(MTRQ_S1) == 0);
  mtsw_group(mtsw_sid(MTSW_LO, 4), MTSW_LO, 4, 1);
  CHECK(mtsw_done_n(MTRQ_S1) == 1);
  CHECK(mtsw_hi() == 0);
}

/* NoGap (Hard): every hi Group < G B saw is FINned or RESET, never left
 * open; every lo Group >= G FINned. */
static void test_moqtrun_switch_hard_no_silent_gap(void) {
  mtsw_setup();
  mtsw_group(mtsw_sid(MTSW_HI, 2), MTSW_HI, 2, 1);
  mtsw_group(mtsw_sid(MTSW_HI, 3), MTSW_HI, 3, 0);
  u64 hs = mtsw_sub_sid(MTSW_HI, 3);
  mtsw_switch(MTSW_HARD, MTSW_DONE);
  mtsw_group(mtsw_sid(MTSW_LO, 4), MTSW_LO, 4, 1);
  mtsw_group(mtsw_sid(MTSW_LO, 5), MTSW_LO, 5, 1);
  CHECK(mtsw_opened(MTSW_HI, 2) == 1); /* one-shot: carried its FIN */
  CHECK(mtrq_reset_code(hs) == 0x1);
  CHECK(mtsw_opened(MTSW_LO, 4) == 1 && mtsw_opened(MTSW_LO, 5) == 1);
  usz n = moqtrun_test_count_kind(3);
  mtsw_more(mtsw_sid(MTSW_HI, 3), 1); /* late hi bytes go nowhere */
  CHECK(moqtrun_test_count_kind(3) == n);
}

/* Hard, lo cancelled before its Group G: hi is cut then (open stream
 * reset, PUBLISH_DONE); the same when lo's publisher ends it. */
static void test_moqtrun_switch_hard_b_gone_cuts_old(void) {
  mtsw_setup();
  mtsw_group(mtsw_sid(MTSW_HI, 3), MTSW_HI, 3, 0);
  u64 hs = mtsw_sub_sid(MTSW_HI, 3);
  mtsw_switch(MTSW_HARD, MTSW_DONE);
  CHECK(mtsw_done_n(MTRQ_S1) == 0);
  wired_moqt_on_stream_reset(&mtst_hub, SESS_B, MTRQ_S2, 0, 0);
  CHECK(mtrq_reset_code(hs) == 0x1);
  CHECK(mtsw_done_n(MTRQ_S1) == 1);
  CHECK(mtsw_hi() == 0);

  moqctl_publish_done d = {0};
  mtsw_setup();
  mtsw_group(mtsw_sid(MTSW_HI, 3), MTSW_HI, 3, 0);
  mtsw_switch(MTSW_HARD, MTSW_DONE);
  d.status_code = MOQCTL_DONE_TRACK_ENDED;
  mtst_send(SESS_A, MTSW_PUB_LO, MOQCTL_T_PUBLISH_DONE, mtdn_enc_done, &d);
  CHECK(mtsw_done_n(MTRQ_S2) == 1);
  CHECK(mtsw_done_n(MTRQ_S1) == 1);
  CHECK(mtsw_hi() == 0);
}

/* ===================== one PUBLISH_DONE (TS-5, TS-8) ===================== */

/* Switch done first, then hi's publisher ends: no second PUBLISH_DONE.
 * Reverse: hi's publisher ends while the Soft switch still waits -- its
 * TRACK_ENDED is the one PUBLISH_DONE, the switch's is dropped. */
static void test_moqtrun_switch_done_once_track_ended(void) {
  moqctl_publish_done d = {0};
  u64                 count;
  d.status_code = MOQCTL_DONE_TRACK_ENDED;
  mtsw_setup();
  mtsw_group(mtsw_sid(MTSW_HI, 3), MTSW_HI, 3, 1);
  mtsw_switch(MTSW_SOFT, MTSW_DONE);
  CHECK(mtsw_done_n(MTRQ_S1) == 1);
  d.stream_count = 1;
  mtst_send(SESS_A, MTSW_PUB_HI, MOQCTL_T_PUBLISH_DONE, mtdn_enc_done, &d);
  wired_moqt_tick(&mtst_hub, 100000);
  CHECK(mtsw_done_n(MTRQ_S1) == 1);
  CHECK(mtdr_done_on(MTRQ_S1, &count) == 0x3);

  mtsw_setup();
  mtsw_group(mtsw_sid(MTSW_HI, 1), MTSW_HI, 1, 1);
  mtsw_group(mtsw_sid(MTSW_LO, 3), MTSW_LO, 3, 1);
  mtsw_switch(MTSW_SOFT, MTSW_DONE); /* G = 4: hi waits for 3 */
  d.stream_count = 1;
  mtst_send(SESS_A, MTSW_PUB_HI, MOQCTL_T_PUBLISH_DONE, mtdn_enc_done, &d);
  CHECK(mtsw_done_n(MTRQ_S1) == 1);
  CHECK(
      mtdr_done_on(MTRQ_S1, &count) ==
      moqctl_publish_done_for(MOQVER_D22, MOQCTL_DONE_TRACK_ENDED));
  wired_moqt_tick(&mtst_hub, 100000);
  CHECK(mtsw_done_n(MTRQ_S1) == 1);
}

/* ===================== cancel / leak (TS-7, TS-10) ===================== */

/* lo cancelled mid Soft switch: hi is not revived (its end stays G-1),
 * still drains its G-1 stream and ends normally. */
static void test_moqtrun_switch_cancel_new_soft_keeps_draining(void) {
  mtsw_setup();
  mtsw_group(mtsw_sid(MTSW_HI, 3), MTSW_HI, 3, 0);
  u64 hs = mtsw_sub_sid(MTSW_HI, 3);
  mtsw_switch(MTSW_SOFT, MTSW_DONE);
  mtsw_group(mtsw_sid(MTSW_LO, 4), MTSW_LO, 4, 0);
  wired_moqt_on_stream_reset(&mtst_hub, SESS_B, MTRQ_S2, 0, 0);
  CHECK(mtsw_lo() == 0);
  CHECK(mtsw_hi() && mtsw_hi()->end_group == 3);
  CHECK(mtsw_done_n(MTRQ_S1) == 0);
  mtsw_more(mtsw_sid(MTSW_HI, 3), 1);
  CHECK(mtsw_fin_seen(hs));
  CHECK(mtrq_reset_code(hs) == -1);
  CHECK(mtsw_done_n(MTRQ_S1) == 1);
}

static usz mtsw_open_relays(void) {
  wired_moqtrun_peer* a = moqtrun_find_by_wt(&mtst_hub, SESS_A);
  usz                 n = 0;
  for (usz t = 0; t < WIRED_MOQTRUN_MAX_TRACKS_PER_PEER; t++)
    for (usz r = 0; r < WIRED_MOQTRUN_MAX_RELAYS; r++)
      n += a->tracks[t].relays[r].in_use != 0;
  return n;
}

/* Both publishers FIN everything and PUBLISH_DONE: nothing of hi or lo is
 * left open, hi's slot is free, the switch is no longer tracked. */
static void test_moqtrun_switch_no_leak(void) {
  moqctl_publish_done d = {0};
  d.status_code         = MOQCTL_DONE_TRACK_ENDED;
  mtsw_setup();
  mtsw_group(mtsw_sid(MTSW_HI, 3), MTSW_HI, 3, 0);
  mtsw_switch(MTSW_SOFT, MTSW_DONE);
  mtsw_group(mtsw_sid(MTSW_LO, 4), MTSW_LO, 4, 0);
  mtsw_more(mtsw_sid(MTSW_HI, 3), 1);
  mtsw_more(mtsw_sid(MTSW_LO, 4), 1);
  d.stream_count = 1;
  mtst_send(SESS_A, MTSW_PUB_HI, MOQCTL_T_PUBLISH_DONE, mtdn_enc_done, &d);
  mtst_send(SESS_A, MTSW_PUB_LO, MOQCTL_T_PUBLISH_DONE, mtdn_enc_done, &d);
  wired_moqt_tick(&mtst_hub, 100000);
  CHECK(mtsw_open_relays() == 0);
  CHECK(mtsw_done_n(MTRQ_S1) == 1 && mtsw_done_n(MTRQ_S2) == 1);
  CHECK(mtrq_fin_on(MTRQ_S1) && mtrq_fin_on(MTRQ_S2));
  CHECK(mtst_hub.sw_live == 0);
  wired_moqt_on_session_close(&mtst_hub, SESS_B);
  CHECK(mtrq_used() == 2); /* A's two PUBLISH streams wait for A's FIN */
}

/* Re-PUBLISH of both variants re-attaches each subscription with its
 * switch bound and its alias. */
static void test_moqtrun_switch_reattach_keeps_bounds(void) {
  moqctl_ftn hi = mtsw_ftn("hi"), lo = mtsw_ftn("lo");
  mtsw_setup();
  mtsw_group(mtsw_sid(MTSW_HI, 3), MTSW_HI, 3, 0);
  mtsw_switch(MTSW_SOFT, MTSW_DONE); /* G = 4, hi waits on its open 3 */
  wired_moqt_on_stream_reset(&mtst_hub, SESS_A, MTSW_PUB_HI, 0, 0);
  wired_moqt_on_stream_reset(&mtst_hub, SESS_A, MTSW_PUB_LO, 0, 0);
  mtst_publish(SESS_A, MTRQ_ID(3), &hi, MTSW_HI);
  mtst_publish(SESS_A, MTRQ_ID(4), &lo, MTSW_LO);
  wired_moqtrun_sub* h = mtsw_hi();
  wired_moqtrun_sub* l = mtsw_lo();
  CHECK(h && h->has_end_group && h->end_group == 3);
  CHECK(h && h->sw_role == MOQTSW_ROLE_OLD);
  CHECK(l && l->start.group == 4);
  CHECK(h && h->track_alias == MTSW_HI);
  CHECK(l && l->track_alias == MTSW_LO);
  mtsw_group(mtsw_sid(MTSW_HI, 4), MTSW_HI, 4, 1);
  mtsw_group(mtsw_sid(MTSW_LO, 4), MTSW_LO, 4, 1);
  CHECK(mtsw_opened(MTSW_HI, 4) == 0 && mtsw_opened(MTSW_LO, 4) == 1);
}

/* ===================== rejection (TS-9) ===================== */

static void mtsw_switch_from(u64 old) {
  u8  b[64];
  usz n = mtsw_sub_body(b, MTSW_RID_LO, "lo", old, MTSW_SOFT, MTSW_DONE);
  mtrq_raw(SESS_B, MTRQ_S2, MOQCTL_T_SUBSCRIBE, b, n);
}

/* INVALID_SWITCH 0x32, B not created, hi untouched, session open: an
 * unknown / ended / own Request ID, SWITCH_FROM with FORWARD, a second
 * switch away from the same subscription, the same track. */
static void test_moqtrun_switch_rejects_ended_old(void) {
  mtsw_setup();
  mtsw_switch_from(40); /* unknown */
  mtsw_check_refused();
  CHECK(mtsw_hi() && !mtsw_hi()->has_end_group);

  mtsw_setup();
  mtsw_switch_from(MTSW_RID_LO); /* itself */
  mtsw_check_refused();

  mtsw_setup();
  wired_moqt_on_stream_reset(&mtst_hub, SESS_B, MTRQ_S1, 0, 0);
  mtsw_switch_from(MTSW_RID_HI); /* ended */
  mtsw_check_refused();

  /* FORWARD 1 (0x10) then SWITCH_FROM (delta 0x14) */
  static const u8 fwd[] = {0x04, 0x02, 0x04, 'c',  'h',  'a',  't',  0x05,
                           'r',  'o',  'o',  'm',  '1',  0x02, 'l',  'o',
                           0x02, 0x10, 0x01, 0x14, 0x03, 0x02, 0x01, 0x80};
  mtsw_setup();
  mtrq_raw(SESS_B, MTRQ_S2, MOQCTL_T_SUBSCRIBE, fwd, sizeof fwd);
  mtsw_check_refused();
  CHECK(mtsw_hi() && !mtsw_hi()->has_end_group);

  mtsw_setup();
  mtsw_group(mtsw_sid(MTSW_HI, 3), MTSW_HI, 3, 0);
  mtsw_switch(MTSW_SOFT, MTSW_DONE); /* hi switching away, waits */
  u8         b[64];
  usz        n = mtsw_sub_body(b, 6, "mid", MTSW_RID_HI, MTSW_SOFT, MTSW_DONE);
  moqctl_ftn mid = mtsw_ftn("mid");
  mtst_publish(SESS_A, MTRQ_ID(5), &mid, 3);
  mtrq_raw(SESS_B, MTRQ_ID(6), MOQCTL_T_SUBSCRIBE, b, n);
  CHECK(mtrq_err_on(MTRQ_ID(6)) == MOQCTL_ERR_INVALID_SWITCH);
  CHECK(mtrq_closes() == 0);

  mtsw_setup();
  n = mtsw_sub_body(b, MTSW_RID_LO, "hi", MTSW_RID_HI, MTSW_SOFT, MTSW_DONE);
  mtrq_raw(SESS_B, MTRQ_S2, MOQCTL_T_SUBSCRIBE, b, n); /* same track */
  CHECK(mtrq_err_on(MTRQ_S2) == MOQCTL_ERR_INVALID_SWITCH);
  CHECK(mtsw_hi() && mtsw_hi()->request_id == MTSW_RID_HI);
  CHECK(mtrq_closes() == 0);
}

/* ===================== opt-in, drafts, REQUEST_UPDATE ===================== */

/* Switching off: SWITCH_FROM closes the session PROTOCOL_VIOLATION, as
 * before the extension -- on SUBSCRIBE and on REQUEST_UPDATE. */
static void test_moqtrun_switch_off_closes(void) {
  static const u8 upd[] = {0x06, 0x01, 0x24, 0x03, 0x02, 0x01, 0x80};
  mtsw_setup();
  mtst_hub.switch_track = 0;
  mtsw_switch(MTSW_SOFT, MTSW_DONE);
  CHECK(mtrq_closes() == 1);
  CHECK(mtsw_lo() == 0);

  moqctl_ftn lo = mtsw_ftn("lo");
  mtsw_setup();
  mtst_hub.switch_track = 0;
  mtst_subscribe_p(SESS_B, MTRQ_S2, &lo, MTSW_RID_LO, 0);
  mtrq_raw(SESS_B, MTRQ_S2, MOQTSTAT_T_REQUEST_UPDATE, upd, sizeof upd);
  CHECK(mtrq_closes() == 1);
}

/* REQUEST_UPDATE of an existing lo subscription carrying SWITCH_FROM hi:
 * REQUEST_OK, lo activated from G, hi bounded and ended like a SUBSCRIBE's
 * switch. An invalid one is refused INVALID_SWITCH and leaves lo as it
 * was (not ended UPDATE_FAILED). */
static void test_moqtrun_switch_update(void) {
  static const u8 upd[] = {0x06, 0x01, 0x24, 0x03, 0x02, 0x01, 0x80};
  static const u8 bad[] = {0x08, 0x01, 0x24, 0x03, 0x28, 0x01, 0x80};
  moqctl_params   p0    = mtst_params_u8(MOQCTL_PARAM_FORWARD, 0);
  moqctl_ftn      lo    = mtsw_ftn("lo");
  mtsw_setup();
  mtst_subscribe_p(SESS_B, MTRQ_S2, &lo, MTSW_RID_LO, &p0);
  mtsw_group(mtsw_sid(MTSW_HI, 3), MTSW_HI, 3, 1);
  mtrq_raw(SESS_B, MTRQ_S2, MOQTSTAT_T_REQUEST_UPDATE, bad, sizeof bad);
  CHECK(mtrq_err_on(MTRQ_S2) == MOQCTL_ERR_INVALID_SWITCH);
  CHECK(mtsw_lo() && mtsw_lo()->forward_off == 1);
  CHECK(mtsw_done_n(MTRQ_S2) == 0);
  mtrq_raw(SESS_B, MTRQ_S2, MOQTSTAT_T_REQUEST_UPDATE, upd, sizeof upd);
  CHECK(mtrq_type_on(3, MTRQ_S2) == MOQCTL_T_REQUEST_OK);
  CHECK(mtsw_lo() && mtsw_lo()->forward_off == 0);
  CHECK(mtsw_lo() && mtsw_lo()->start.group == 4);
  CHECK(mtsw_done_n(MTRQ_S1) == 1); /* hi at 3 already: drained */
  mtsw_group(mtsw_sid(MTSW_LO, 4), MTSW_LO, 4, 1);
  CHECK(mtsw_opened(MTSW_LO, 4) == 1);
}

/* ===================== review round 1 ===================== */

/* B's subscription on A's track named name (any slot), else 0. */
static wired_moqtrun_sub* mtsw_sub_named(const char* name) {
  wired_moqtrun_peer* a = moqtrun_find_by_wt(&mtst_hub, SESS_A);
  for (usz t = 0; t < WIRED_MOQTRUN_MAX_TRACKS_PER_PEER; t++)
    if (moqtrun_track_name_matches(&a->tracks[t], mtst_z(name)))
      return moqtrun_track_sub_of_peer(&a->tracks[t], mtst_idx(SESS_B));
  return 0;
}

/* params plus SWITCH_FROM (old, mode, flags) as its last item. */
static moqctl_params mtsw_with_sw(moqctl_params p, u64 old, u8 mode, u8 fl) {
  p.items[p.n].type            = MOQCTL_PARAM_SWITCH_FROM;
  p.items[p.n].enc             = MOQCTL_PENC_SWITCHFROM;
  p.items[p.n].sw.request_id   = old;
  p.items[p.n].sw.mode         = mode;
  p.items[p.n].sw.publish_done = (u8)(fl != 0);
  p.n++;
  return p;
}

/* REQUEST_UPDATE (Request ID rid) on sid whose only parameter is the
 * pinned SWITCH_FROM 24 03 <old> <mode> <flags>. */
static void mtsw_update_sw(u64 sid, u64 rid, u64 old, u8 mode, u8 flags) {
  const u8 b[] = {(u8)rid, 0x01, 0x24, 0x03, (u8)old, mode, flags};
  mtrq_raw(SESS_B, sid, MOQTSTAT_T_REQUEST_UPDATE, b, sizeof b);
}

/* B1: the open of hi's G-1 stream to B was refused (no credit), so the
 * relay owes B a late open: Soft waits for it, B gets the group, and
 * PUBLISH_DONE follows only its FIN. */
static void test_moqtrun_switch_soft_waits_late_open(void) {
  mtsw_setup();
  g_open_uni_fail_n = 1;
  mtsw_group(mtsw_sid(MTSW_HI, 3), MTSW_HI, 3, 0);
  CHECK(mtsw_opened(MTSW_HI, 3) == 1); /* the refused attempt */
  mtsw_switch(MTSW_SOFT, MTSW_DONE);
  CHECK(mtsw_done_n(MTRQ_S1) == 0);
  mtsw_more(mtsw_sid(MTSW_HI, 3), 0);
  CHECK(mtsw_opened(MTSW_HI, 3) == 2); /* the late open */
  CHECK(mtsw_done_n(MTRQ_S1) == 0);
  mtsw_more(mtsw_sid(MTSW_HI, 3), 1);
  CHECK(mtsw_done_n(MTRQ_S1) == 1);
}

/* S1: A withdraws both variants, two other names take their slots (the
 * sweep forgets the switch), then hi/lo come back: the re-attached hi
 * still ends by its deadline. */
static void test_moqtrun_switch_reattach_after_slot_reuse(void) {
  moqctl_ftn hi = mtsw_ftn("hi"), lo = mtsw_ftn("lo");
  moqctl_ftn x = mtsw_ftn("x"), y = mtsw_ftn("y");
  mtsw_setup();
  wired_moqt_tick(&mtst_hub, 1000);
  mtsw_group(mtsw_sid(MTSW_HI, 3), MTSW_HI, 3, 0);
  mtsw_group(mtsw_sid(MTSW_LO, 5), MTSW_LO, 5, 1);
  mtsw_switch(MTSW_SOFT, MTSW_DONE); /* G = 6: hi waits */
  wired_moqt_on_stream_reset(&mtst_hub, SESS_A, MTSW_PUB_HI, 0, 0);
  wired_moqt_on_stream_reset(&mtst_hub, SESS_A, MTSW_PUB_LO, 0, 0);
  mtst_publish(SESS_A, MTRQ_ID(5), &x, 5);
  mtst_publish(SESS_A, MTRQ_ID(6), &y, 6);
  wired_moqt_tick(&mtst_hub, 1001);
  wired_moqt_on_stream_reset(&mtst_hub, SESS_A, MTRQ_ID(5), 0, 0);
  wired_moqt_on_stream_reset(&mtst_hub, SESS_A, MTRQ_ID(6), 0, 0);
  mtst_publish(SESS_A, MTRQ_ID(7), &hi, MTSW_HI);
  mtst_publish(SESS_A, MTRQ_ID(8), &lo, MTSW_LO);
  CHECK(mtsw_sub_named("hi") && mtsw_sub_named("hi")->sw_role == 1);
  CHECK(mtsw_done_n(MTRQ_S1) == 0);
  wired_moqt_tick(&mtst_hub, 1000 + WIRED_MOQTSW_SOFT_WAIT_MS);
  CHECK(mtsw_done_n(MTRQ_S1) == 1);
}

/* S2: FILL_PARAMETERS beside SWITCH_FROM (a fill of the activating side
 * would deliver Groups below G): INVALID_SWITCH, on SUBSCRIBE and on
 * REQUEST_UPDATE alike. */
static void test_moqtrun_switch_fill_refused(void) {
  moqfetch_fill fill = {0};
  moqctl_ftn    lo   = mtsw_ftn("lo");
  moqctl_params p =
      mtsw_with_sw(mfill_params(&fill, 0), MTSW_RID_HI, MOQCTL_SWITCH_SOFT, 1);
  mtsw_setup();
  mtst_subscribe_p(SESS_B, MTRQ_S2, &lo, MTSW_RID_LO, &p);
  mtsw_check_refused();
  CHECK(mtsw_hi() && !mtsw_hi()->has_end_group);

  moqctl_params p0 = mtst_params_u8(MOQCTL_PARAM_FORWARD, 0);
  mtsw_setup();
  mtst_subscribe_p(SESS_B, MTRQ_S2, &lo, MTSW_RID_LO, &p0);
  p = mtsw_with_sw(mfill_params(&fill, 0), MTSW_RID_HI, MOQCTL_SWITCH_HARD, 1);
  mtup_update(SESS_B, MTRQ_S2, &p);
  CHECK(mtrq_err_on(MTRQ_S2) == MOQCTL_ERR_INVALID_SWITCH);
  CHECK(mtsw_lo() && mtsw_lo()->forward_off == 1);
  CHECK(mtsw_hi() && !mtsw_hi()->has_end_group);
}

/* Hard without the flag: the cut resets hi's open stream, hi stays with
 * FORWARD 0, no PUBLISH_DONE, no FIN. */
static void test_moqtrun_switch_hard_no_flag_suspends(void) {
  mtsw_setup();
  mtsw_group(mtsw_sid(MTSW_HI, 3), MTSW_HI, 3, 0);
  u64 hs = mtsw_sub_sid(MTSW_HI, 3);
  mtsw_switch(MTSW_HARD, 0x00);
  mtsw_group(mtsw_sid(MTSW_LO, 4), MTSW_LO, 4, 0);
  CHECK(mtrq_reset_code(hs) == 0x1);
  CHECK(mtsw_hi() && mtsw_hi()->forward_off == 1);
  CHECK(mtsw_done_n(MTRQ_S1) == 0);
  CHECK(mtrq_fin_on(MTRQ_S1) == 0);
}

/* Switch back: a REQUEST_UPDATE on the suspended hi carrying SWITCH_FROM
 * lo is REQUEST_OK, hi restarts at the new boundary with no end bound
 * left, and lo ends. */
static void test_moqtrun_switch_back(void) {
  mtsw_setup();
  mtsw_group(mtsw_sid(MTSW_HI, 3), MTSW_HI, 3, 1);
  mtsw_switch(MTSW_SOFT, 0x00); /* G = 4, hi suspended */
  CHECK(mtsw_hi() && mtsw_hi()->forward_off == 1);
  mtsw_group(mtsw_sid(MTSW_LO, 4), MTSW_LO, 4, 1);
  mtsw_group(mtsw_sid(MTSW_LO, 5), MTSW_LO, 5, 1);
  mtsw_update_sw(MTRQ_S1, 6, MTSW_RID_LO, MTSW_SOFT, MTSW_DONE);
  CHECK(mtrq_type_on(3, MTRQ_S1) == MOQCTL_T_REQUEST_OK);
  wired_moqtrun_sub* h = mtsw_hi();
  CHECK(h && h->forward_off == 0 && h->start.group == 6);
  CHECK(h && !h->has_end_group);
  CHECK(mtsw_done_n(MTRQ_S2) == 1); /* lo at 5 = G-1: drained */
  mtsw_group(mtsw_sid(MTSW_HI, 6), MTSW_HI, 6, 1);
  CHECK(mtsw_opened(MTSW_HI, 6) == 1);
}

/* Hard via REQUEST_UPDATE on a lo that already delivered streams: hi is
 * not cut by lo's earlier streams, only by lo's Group G. */
static void test_moqtrun_switch_hard_update_busy_b(void) {
  moqctl_ftn lo = mtsw_ftn("lo");
  mtsw_setup();
  mtst_subscribe_p(SESS_B, MTRQ_S2, &lo, MTSW_RID_LO, 0);
  mtsw_group(mtsw_sid(MTSW_LO, 2), MTSW_LO, 2, 1);
  mtsw_group(mtsw_sid(MTSW_HI, 3), MTSW_HI, 3, 1);
  CHECK(mtsw_lo() && mtsw_lo()->stream_count == 1);
  mtsw_update_sw(MTRQ_S2, 6, MTSW_RID_HI, MTSW_HARD, MTSW_DONE); /* G 4 */
  CHECK(mtrq_type_on(3, MTRQ_S2) == MOQCTL_T_REQUEST_OK);
  wired_moqt_tick(&mtst_hub, 10);
  CHECK(mtsw_done_n(MTRQ_S1) == 0);
  mtsw_group(mtsw_sid(MTSW_LO, 4), MTSW_LO, 4, 1);
  CHECK(mtsw_done_n(MTRQ_S1) == 1);
}

/* N5: lo arriving as datagrams cuts a Hard switch too. */
static void test_moqtrun_switch_hard_datagram_b(void) {
  u8        buf[64];
  usz       off = 0;
  moqdg_obj o   = {0x08, MTSW_LO, 4, 0, 0, 0, {0, 0}, {(const u8*)"v", 1}};
  mtsw_setup();
  mtsw_group(mtsw_sid(MTSW_HI, 3), MTSW_HI, 3, 0);
  u64 hs = mtsw_sub_sid(MTSW_HI, 3);
  mtsw_switch(MTSW_HARD, MTSW_DONE);
  CHECK(moqdg_put(wired_mspan_of(buf, sizeof buf), &off, &o) == MOQDATA_OK);
  wired_moqt_on_datagram(&mtst_hub, SESS_A, wired_span_of(buf, off));
  CHECK(moqtrun_test_count_kind(9) == 1);
  CHECK(mtrq_reset_code(hs) == 0x1);
  CHECK(mtsw_done_n(MTRQ_S1) == 1);
}

/* A LOCATION_FILTER update mid-switch re-resolves start/end, then the
 * switch bound applies again: hi still ends at G-1, lo starts at G. */
static void test_moqtrun_switch_filter_update_keeps_bounds(void) {
  moqctl_params f = mtst_params_filter(MOQCTL_FILTER_ABS_START);
  mtsw_setup();
  mtsw_group(mtsw_sid(MTSW_HI, 3), MTSW_HI, 3, 0);
  mtsw_switch(MTSW_SOFT, MTSW_DONE); /* G = 4, hi waits */
  mtup_update(SESS_B, MTRQ_S1, &f);
  mtup_update(SESS_B, MTRQ_S2, &f);
  CHECK(mtsw_hi() && mtsw_hi()->has_end_group && mtsw_hi()->end_group == 3);
  CHECK(mtsw_lo() && mtsw_lo()->start.group == 4);
}

/* N3: once hi ended, lo is no longer clamped to G -- a later filter
 * update moves its start freely. */
static void test_moqtrun_switch_new_role_cleared(void) {
  moqctl_params f     = mtst_params_filter(MOQCTL_FILTER_ABS_START);
  f.items[0].lf.start = moqctl_loc_of(1, 0);
  mtsw_setup();
  mtsw_group(mtsw_sid(MTSW_HI, 3), MTSW_HI, 3, 1);
  mtsw_switch(MTSW_SOFT, MTSW_DONE); /* G = 4, hi drained at once */
  CHECK(mtsw_done_n(MTRQ_S1) == 1);
  CHECK(mtsw_lo() && mtsw_lo()->sw_role == MOQTSW_ROLE_NONE);
  mtup_update(SESS_B, MTRQ_S2, &f);
  CHECK(mtsw_lo() && mtsw_lo()->start.group == 1);
}

/* A suspended hi stays suspended across its publisher's re-PUBLISH. */
static void test_moqtrun_switch_suspended_survives_reattach(void) {
  moqctl_ftn hi = mtsw_ftn("hi");
  mtsw_setup();
  mtsw_group(mtsw_sid(MTSW_HI, 3), MTSW_HI, 3, 1);
  mtsw_switch(MTSW_SOFT, 0x00);
  CHECK(mtsw_hi() && mtsw_hi()->forward_off == 1);
  wired_moqt_on_stream_reset(&mtst_hub, SESS_A, MTSW_PUB_HI, 0, 0);
  mtst_publish(SESS_A, MTRQ_ID(7), &hi, MTSW_HI);
  wired_moqtrun_sub* h = mtsw_sub_named("hi");
  CHECK(h && h->forward_off == 1 && h->sw_role == MOQTSW_ROLE_NONE);
  mtsw_group(mtsw_sid(MTSW_HI, 1), MTSW_HI, 1, 1);
  CHECK(mtsw_opened(MTSW_HI, 1) == 0);
  CHECK(mtsw_done_n(MTRQ_S1) == 0);
}

/* The subscriber's session closes mid-switch: nothing more goes to it,
 * and the switch is forgotten. */
static void test_moqtrun_switch_subscriber_closes(void) {
  mtsw_setup();
  mtsw_group(mtsw_sid(MTSW_HI, 3), MTSW_HI, 3, 0);
  mtsw_switch(MTSW_SOFT, MTSW_DONE);
  wired_moqt_on_session_close(&mtst_hub, SESS_B);
  usz n = g_n_calls;
  mtsw_more(mtsw_sid(MTSW_HI, 3), 1);
  mtsw_group(mtsw_sid(MTSW_LO, 4), MTSW_LO, 4, 1);
  wired_moqt_tick(&mtst_hub, 100000);
  for (usz i = n; i < g_n_calls; i++) CHECK(g_calls[i].s != SESS_B);
  CHECK(mtst_hub.sw_live == 0);
}

/* N1: SWITCH_FROM on a SUBSCRIBE to the hub's own blob track:
 * INVALID_SWITCH, no blob sent. */
static void test_moqtrun_switch_hub_track_refused(void) {
  u8 b[64];
  mtsw_setup();
  CHECK(moqtrun_test_publish_small_blob(&mtst_hub, 10) != 0);
  moqtrun_test_reset();
  usz n = mtsw_sub_body(b, MTSW_RID_LO, "movie", MTSW_RID_HI, MTSW_SOFT, 0);
  mtrq_raw(SESS_B, MTRQ_S2, MOQCTL_T_SUBSCRIBE, b, n);
  CHECK(mtrq_err_on(MTRQ_S2) == MOQCTL_ERR_INVALID_SWITCH);
  CHECK(moqtrun_test_count_kind(4) == 0);
  CHECK(mtsw_hi() && !mtsw_hi()->has_end_group);
}

/* N2: a REQUEST_UPDATE of A's own PUBLISH carrying SWITCH_FROM is
 * INVALID_SWITCH, not silently ignored. */
static void test_moqtrun_switch_publish_update_refused(void) {
  moqctl_params p = mtsw_with_sw((moqctl_params){0}, 2, MOQCTL_SWITCH_SOFT, 1);
  mtsw_setup();
  mtup_update(SESS_A, MTSW_PUB_HI, &p);
  CHECK(mtrq_err_on(MTSW_PUB_HI) == MOQCTL_ERR_INVALID_SWITCH);
  CHECK(mtrq_closes() == 0);
}

/* W4b review N3: SWITCH_FROM and SSTS are not combined -- the old or
 * the activating subscription in a switching set, or a
 * SWITCHING_SET_ASSIGNMENT beside SWITCH_FROM, is INVALID_SWITCH. */
static void test_moqtrun_switch_ssts_member_refused(void) {
  static const u64 algs[] = {MOQCTL_SSTS_ALG_DEFAULT};
  moqctl_ftn       lo     = mtsw_ftn("lo");
  mtsw_setup();
  mtst_hub.ssts_algs  = algs;
  mtst_hub.ssts_alg_n = 1;
  CHECK(mtsw_hi() != 0);
  if (mtsw_hi()) mtsw_hi()->ssts_on = 1; /* hi is a set member */
  mtsw_switch(MTSW_SOFT, MTSW_DONE);
  mtsw_check_refused();

  /* SWITCH_FROM (0x24) before the assignment (0x41): ascending types */
  moqctl_params p =
      mtsw_with_sw((moqctl_params){0}, MTSW_RID_HI, MOQCTL_SWITCH_SOFT, 1);
  p.items[1].type               = MOQCTL_PARAM_SWITCHING_SET_ASSIGNMENT;
  p.items[1].enc                = MOQCTL_PENC_SSA;
  p.items[1].ssa.set_id         = 7;
  p.items[1].ssa.algorithm_id   = MOQCTL_SSTS_ALG_DEFAULT;
  p.items[1].ssa.threshold_kbps = 500;
  p.items[1].ssa.weight         = 1;
  p.n                           = 2;
  mtsw_setup();
  mtst_hub.ssts_algs  = algs;
  mtst_hub.ssts_alg_n = 1;
  mtst_subscribe_p(SESS_B, MTRQ_S2, &lo, MTSW_RID_LO, &p);
  mtsw_check_refused();
  CHECK(mtsw_hi() && !mtsw_hi()->has_end_group);

  mtsw_setup();
  mtst_hub.ssts_algs  = algs;
  mtst_hub.ssts_alg_n = 1;
  mtst_subscribe_p(SESS_B, MTRQ_S2, &lo, MTSW_RID_LO, 0);
  CHECK(mtsw_lo() != 0);
  if (mtsw_lo()) mtsw_lo()->ssts_on = 1; /* the activating side */
  mtsw_update_sw(MTRQ_S2, 6, MTSW_RID_HI, MTSW_SOFT, MTSW_DONE);
  CHECK(mtrq_err_on(MTRQ_S2) == MOQCTL_ERR_INVALID_SWITCH);
  CHECK(mtsw_hi() && !mtsw_hi()->has_end_group);
}

/* B1 (group bound): hi's Group G relay (never B's) stays open while its
 * G-1 stream FINs -- only Groups below G hold the Soft end back. */
static void test_moqtrun_switch_soft_ignores_group_g(void) {
  mtsw_setup();
  mtsw_group(mtsw_sid(MTSW_HI, 3), MTSW_HI, 3, 0);
  mtsw_switch(MTSW_SOFT, MTSW_DONE); /* G = 4 */
  mtsw_group(mtsw_sid(MTSW_HI, 4), MTSW_HI, 4, 0);
  CHECK(mtsw_opened(MTSW_HI, 4) == 0);
  CHECK(mtsw_done_n(MTRQ_S1) == 0);
  mtsw_more(mtsw_sid(MTSW_HI, 3), 1);
  CHECK(mtsw_done_n(MTRQ_S1) == 1);
}

/* B1 (expired bit): hi's G-1 stream is reset DELIVERY_TIMEOUT while its
 * relay lives on -- nothing more is owed to B, so hi ends. */
static void test_moqtrun_switch_soft_expired_ends(void) {
  u8  buf[MOQTRUN_TEST_MAX_PAYLOAD];
  usz n   = mtsw_bytes(MTSW_HI, 3, 2, 1, buf);
  u64 sid = mtsw_sid(MTSW_HI, 3);
  mtsw_setup();
  CHECK(mtsw_hi() != 0);
  if (mtsw_hi()) {
    mtsw_hi()->delivery_timeout     = 100;
    mtsw_hi()->has_delivery_timeout = 1;
  }
  wired_moqt_tick(&mtst_hub, 1000);
  /* Object 0 whole (Largest {3, 0}), Object 1 torn: its last byte later */
  wired_moqt_on_stream_data(
      &mtst_hub, SESS_A, sid, wired_span_of(buf, n - 1), 0);
  u64 hs = mtsw_sub_sid(MTSW_HI, 3);
  mtsw_switch(MTSW_SOFT, MTSW_DONE); /* G = 4 */
  CHECK(mtsw_done_n(MTRQ_S1) == 0);
  wired_moqt_tick(&mtst_hub, 2000);
  wired_moqt_on_stream_data(
      &mtst_hub, SESS_A, sid, wired_span_of(buf + n - 1, 1), 0);
  CHECK(mtrq_reset_code(hs) == MOQTRUN_RESET_DELIVERY_TIMEOUT);
  CHECK(mtsw_done_n(MTRQ_S1) == 1);
}

/* N3 (remembered): lo released from its start clamp stays released
 * across a re-attach -- its start resolves from its own filter, and a
 * later filter update is not clamped to G. */
static void test_moqtrun_switch_release_survives_reattach(void) {
  moqctl_ftn    lo    = mtsw_ftn("lo");
  moqctl_params f     = mtst_params_filter(MOQCTL_FILTER_ABS_START);
  f.items[0].lf.start = moqctl_loc_of(1, 0);
  mtsw_setup();
  mtsw_group(mtsw_sid(MTSW_HI, 3), MTSW_HI, 3, 1);
  mtsw_switch(MTSW_SOFT, MTSW_DONE); /* G = 4, hi ends at once */
  CHECK(mtsw_done_n(MTRQ_S1) == 1);
  wired_moqt_on_stream_reset(&mtst_hub, SESS_A, MTSW_PUB_LO, 0, 0);
  mtst_publish(SESS_A, MTRQ_ID(7), &lo, MTSW_LO);
  wired_moqtrun_sub* l = mtsw_sub_named("lo");
  CHECK(l && l->sw_role == MOQTSW_ROLE_NONE && l->start.group == 0);
  mtup_update(SESS_B, MTRQ_S2, &f);
  l = mtsw_sub_named("lo");
  CHECK(l && l->start.group == 1);
}

static void test_moqtrun_switch_review1(void) {
  test_moqtrun_switch_soft_waits_late_open();
  test_moqtrun_switch_reattach_after_slot_reuse();
  test_moqtrun_switch_fill_refused();
  test_moqtrun_switch_hard_no_flag_suspends();
  test_moqtrun_switch_back();
  test_moqtrun_switch_hard_update_busy_b();
  test_moqtrun_switch_hard_datagram_b();
  test_moqtrun_switch_filter_update_keeps_bounds();
  test_moqtrun_switch_new_role_cleared();
  test_moqtrun_switch_suspended_survives_reattach();
  test_moqtrun_switch_subscriber_closes();
  test_moqtrun_switch_hub_track_refused();
  test_moqtrun_switch_publish_update_refused();
  test_moqtrun_switch_ssts_member_refused();
  test_moqtrun_switch_soft_ignores_group_g();
  test_moqtrun_switch_soft_expired_ends();
  test_moqtrun_switch_release_survives_reattach();
}

/* W4b review round 2: hi (A) ending any other way than its switch --
 * cancelled, or its publisher's TRACK_ENDED -- releases lo (B) from
 * MOQTSW_ROLE_NEW on the next sweep, so B may later join a switching set
 * or switch again. */
static void test_moqtrun_switch_old_gone_releases_new(void) {
  moqctl_publish_done d = {0};
  mtsw_setup();
  mtsw_group(mtsw_sid(MTSW_HI, 3), MTSW_HI, 3, 0);
  mtsw_switch(MTSW_HARD, MTSW_DONE);
  CHECK(mtsw_lo() && mtsw_lo()->sw_role == MOQTSW_ROLE_NEW);
  wired_moqt_on_stream_reset(&mtst_hub, SESS_B, MTRQ_S1, 0, 0);
  wired_moqt_tick(&mtst_hub, 0);
  CHECK(mtsw_lo() && mtsw_lo()->sw_role == MOQTSW_ROLE_NONE);

  mtsw_setup();
  mtsw_group(mtsw_sid(MTSW_HI, 3), MTSW_HI, 3, 0);
  mtsw_switch(MTSW_HARD, MTSW_DONE);
  d.status_code = MOQCTL_DONE_TRACK_ENDED;
  mtst_send(SESS_A, MTSW_PUB_HI, MOQCTL_T_PUBLISH_DONE, mtdn_enc_done, &d);
  wired_moqt_tick(&mtst_hub, 0);
  wired_moqt_tick(&mtst_hub, 5000);
  CHECK(mtsw_lo() && mtsw_lo()->sw_role == MOQTSW_ROLE_NONE);
}

static void test_moqtrun_switch_d22(void) {
  test_moqtrun_switch_boundary_plus_one();
  test_moqtrun_switch_boundary_b_ahead();
  test_moqtrun_switch_soft_cut_at_boundary();
  test_moqtrun_switch_no_group_twice();
  test_moqtrun_switch_soft_no_gap();
  test_moqtrun_switch_soft_drains_old();
  test_moqtrun_switch_soft_done_after_fin();
  test_moqtrun_switch_no_flag_no_done();
  test_moqtrun_switch_soft_deadline_giveup();
  test_moqtrun_switch_soft_g0_ends_now();
  test_moqtrun_switch_hard_resets_old();
  test_moqtrun_switch_hard_ends_on_b_boundary();
  test_moqtrun_switch_hard_no_silent_gap();
  test_moqtrun_switch_hard_b_gone_cuts_old();
  test_moqtrun_switch_done_once_track_ended();
  test_moqtrun_switch_cancel_new_soft_keeps_draining();
  test_moqtrun_switch_no_leak();
  test_moqtrun_switch_reattach_keeps_bounds();
  test_moqtrun_switch_rejects_ended_old();
  test_moqtrun_switch_off_closes();
  test_moqtrun_switch_update();
  test_moqtrun_switch_review1();
  test_moqtrun_switch_old_gone_releases_new();
}

/* draft-18/19: 0x24 is no parameter there -- the SUBSCRIBE closes the
 * session as before, even with switching on. */
static void test_moqtrun_switch_old_drafts_close(void) {
  mtsw_setup();
  mtsw_switch(MTSW_SOFT, MTSW_DONE);
  CHECK(mtrq_closes() == 1);
  CHECK(mtsw_lo() == 0);
}

void test_moqtrun_switch(void) {
  g_moqtrun_test_ver = MOQVER_D22;
  test_moqtrun_switch_d22();
  g_moqtrun_test_ver = MOQVER_D19;
  moqtrun_test_vers(
      0, MOQVER_CAP_FILL_FETCH, test_moqtrun_switch_old_drafts_close);
}
