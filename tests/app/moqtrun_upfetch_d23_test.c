/* draft-ietf-moq-transport-23 FETCH response through the hub as a relay
 * (3.2, 7.6, 9.3): a moqt-23 announcer answers the hub's upstream FETCH
 * with a REQUEST_OK, and B -- on draft-22 or draft-23 -- gets it in its
 * own draft. Shares the fixtures of moqtrun_upfetch_test.c. */

static int mupf23_enc_ok(wired_mspan buf, usz* off, const void* m) {
  return moqctl_request_ok_encode(buf, off, m);
}

/* s (draft-23) answers REQUEST_OK on sid: LARGEST_OBJECT {g, o} when
 * largest, Track Properties props. */
static void mupf23_up_ok(
    wired_wt_session* s, i64 sid, int largest, u64 g, u64 o, wired_span props) {
  static moqctl_request_ok ok;
  ok = (moqctl_request_ok){0};
  if (largest) {
    ok.params.n             = 1;
    ok.params.items[0].type = MOQCTL_PARAM_LARGEST_OBJECT;
    ok.params.items[0].enc  = MOQCTL_PENC_LOCATION;
    ok.params.items[0].loc  = mf_loc(g, o);
  }
  ok.track_properties = props;
  mtst_send(s, (u64)sid, MOQCTL_T_REQUEST_OK, mupf23_enc_ok, &ok);
}

/* B's answer: draft-23 a REQUEST_OK with LARGEST_OBJECT {g, o} iff
 * largest, draft-22 a FETCH_OK ending at {g, o}; props copied (7.6). */
static int mupf23_b_ok_is(u64 g, u64 o, int largest, u8 prop) {
  moqctl_loc end  = {~0ULL, ~0ULL};
  int        has  = 0;
  u64        code = 0;
  u64        t    = mfd23_reply(&end, &has, &code);
  if (mtst_ver(SESS_B) != MOQVER_D23) {
    moqfetch_ok          ok = {0};
    moqctl_request_error e;
    return mupf_reply(&ok, &e) == MOQFETCH_T_FETCH_OK &&
           mf_loc_eq(ok.end, g, o) && ok.track_properties.n == 2 &&
           ok.track_properties.p[1] == prop;
  }
  return t == MOQCTL_T_REQUEST_OK && has == largest &&
         (!largest || mf_loc_eq(end, g, o));
}

/* draft-23 3.2 / 9.3: C's LARGEST_OBJECT ends the response there; without
 * it the response ends at the requested End Location {5, 0}. 0x18 is not
 * a FETCH response on a moqt-23 stream (9 Table 5): B hears nothing. */
static void mupf23_relay(int bv) {
  static const u8 props[] = {0x0C, 0x05};
  moqfetch_req    m       = {0};
  i64             sid;
  mupf_init_v(bv);
  mupf_vers(MOQVER_D23);
  mupf_fetch_on(SESS_B, mupf_bob(), mupf_rl(0, 0, 5, 0), 0);
  sid = mupf_up(SESS_C, 0, &m);
  CHECK(sid >= 0);
  mupf_up_ok_p(SESS_C, sid, mf_loc(2, 3), 0, wired_span_of(props, 2));
  CHECK(
      mupf_n_msgs(MOQFETCH_T_FETCH_OK) + mupf_n_msgs(MOQCTL_T_REQUEST_OK) == 0);
  mupf23_up_ok(SESS_C, sid, 1, 2, 3, wired_span_of(props, 2));
  CHECK(mupf23_b_ok_is(2, 3, 1, 0x05));
  mupf_init_v(bv);
  mupf_vers(MOQVER_D23);
  mupf_fetch_on(SESS_B, mupf_bob(), mupf_rl(0, 0, 5, 0), 0);
  sid = mupf_up(SESS_C, 0, &m);
  mupf23_up_ok(SESS_C, sid, 0, 0, 0, wired_span_of(props, 2));
  CHECK(mupf23_b_ok_is(5, 0, 0, 0x05));
}

static void test_moqtrun_upfetch_d23_relay(void) {
  mupf23_relay(MOQVER_D23);
  mupf23_relay(MOQVER_D22);
}

/* B's relayed stream: {0,0}, End of Group, {1,0}, Gone through {1,5}
 * from a moqt-23 announcer -- as is on draft-23; on draft-22 (no 0x80,
 * no 0x40C, 11.4.1) the marker is left out and Gone reads Unknown. */
static int mupf23_relayed_ok(void) {
  if (mtst_ver(SESS_B) == MOQVER_D23) {
    return mupf_read(0) && mf_n == 4 && mf_is_obj(0, 0, 0, 1) &&
           mf_items[1].flags == MOQFETCH_END_OF_GROUP &&
           mf_is_obj(2, 1, 0, 1) && mf_items[3].flags == MOQFETCH_EOR_GONE &&
           mf_items[3].object == 5;
  }
  return mupf_read(0) && mf_n == 3 && mf_is_obj(0, 0, 0, 1) &&
         mf_is_obj(1, 1, 0, 1) && mf_is_unknown(2, 1, 5);
}

/* draft-23 3.2.3: the hub never originates Gone but relays the
 * announcer's; End of Group is relayed in place (3.2.2). */
static void mupf23_markers(int bv) {
  moqfetch_req m   = {0};
  moqfetch_obj eog = {0};
  i64          sid;
  mupf_init_v(bv);
  mupf_vers(MOQVER_D23);
  mupf_fetch_on(SESS_B, mupf_bob(), mupf_rl(0, 0, 5, 0), 0);
  sid = mupf_up(SESS_C, 0, &m);
  mupf_hdr(m.request_id, 0);
  mupf_seq.d23 = 1;
  mupf_obj(0, 0, 1);
  eog.flags = MOQFETCH_END_OF_GROUP;
  mupf_put(&eog);
  mupf_obj(1, 0, 1);
  mupf_eor(MOQFETCH_EOR_GONE, 1, 5);
  mupf_send_on(SESS_C, MUPF_DATA_SID, 1);
  mupf23_up_ok(SESS_C, sid, 0, 0, 0, wired_span_of(0, 0));
  CHECK(mupf23_relayed_ok());
}

static void test_moqtrun_upfetch_d23_markers(void) {
  mupf23_markers(MOQVER_D23);
  mupf23_markers(MOQVER_D22);
}

/* A moqt-22 announcer C serves {0,0} {0,1} and answers FETCH_OK End
 * {0,1} with End Of Track 1 (draft-22 9.12: the final Object in the
 * Track). draft-23 3.2.2: toward a moqt-23 requester the hub follows that
 * Object with End of Track; a moqt-22 one has End Of Track in its
 * FETCH_OK. */
static void mupf23_eot(int bv) {
  moqfetch_req         m  = {0};
  moqfetch_ok          ok = {0};
  moqctl_request_error e;
  i64                  sid;
  mupf_init_v(bv);
  mupf_vers(MOQVER_D22);
  mupf_fetch_on(SESS_B, mupf_bob(), mupf_rl(0, 0, 5, 0), 0);
  sid = mupf_up(SESS_C, 0, &m);
  mupf_hdr(m.request_id, 0);
  mupf_obj(0, 0, 1);
  mupf_obj(0, 1, 1);
  mupf_send_on(SESS_C, MUPF_DATA_SID, 1);
  mupf_up_ok_p(SESS_C, sid, mf_loc(0, 1), 1, wired_span_of(0, 0));
  if (bv != MOQVER_D23) {
    CHECK(mupf_read(0) && mf_n == 2 && mf_fin && mf_is_obj(1, 0, 1, 1));
    CHECK(mupf_reply(&ok, &e) == MOQFETCH_T_FETCH_OK && ok.end_of_track);
    return;
  }
  CHECK(mupf_read(0) && mf_n == 3 && mf_fin && mf_is_obj(1, 0, 1, 1));
  CHECK(mf_items[2].flags == MOQFETCH_END_OF_TRACK);
}

static void test_moqtrun_upfetch_d23_eot(void) {
  mupf23_eot(MOQVER_D23);
  mupf23_eot(MOQVER_D22);
}

/* draft-23 3.2.3: an upstream FETCH that fails once the response went
 * out leaves the rest of the range Unknown -- End of Unknown Range, then
 * FIN; the stream is not reset (12.5 drops UNKNOWN_OBJECT_STATUS). */
static void test_moqtrun_upfetch_d23_leg_fails(void) {
  moqfetch_req m = {0};
  i64          sid;
  mupf_init_v(MOQVER_D23);
  mupf_vers(MOQVER_D23);
  mupf_fetch_on(SESS_B, mupf_bob(), mupf_rl(0, 0, 5, 0), 0);
  sid = mupf_up(SESS_C, 0, &m);
  mupf_hdr(m.request_id, 0);
  mupf_seq.d23 = 1;
  mupf_obj(0, 0, 1);
  mupf_send_on(SESS_C, MUPF_DATA_SID, 0);
  mupf23_up_ok(SESS_C, sid, 0, 0, 0, wired_span_of(0, 0));
  wired_moqt_on_stream_reset(&mtst_hub, SESS_C, MUPF_DATA_SID, 1, 0);
  wired_moqt_tick(&mtst_hub, 1);
  CHECK(mupf_read(0) && mf_fin && mf_n == 2 && mf_is_obj(0, 0, 0, 1));
  CHECK(mf_items[1].flags == MOQFETCH_EOR_UNKNOWN && mf_items[1].group == 5);
}

/* ===== Gone ranges cached (draft-23 7.1, 10.3) ===== */

/* B (on bv) FETCHes {2, 0}..{3, 0} of A's track (group 3 cached, group 2
 * not): the hub asks A for group 2, A (draft-23) answers it with End of
 * Range eor through {2, max}. */
static void mupf23_gone_first(int bv, u64 eor) {
  moqfetch_req m = {0};
  i64          sid;
  mupf_init_v(bv);
  mupf_vers(MOQVER_D23);
  mupf_cache_group(3, 1);
  mupf_fetch(mupf_rl(2, 0, 3, 0), 0);
  sid = mupf_up(SESS_A, 0, &m);
  CHECK(sid >= 0 && m.range.start_group == 2 && m.range.end_group == 2);
  mupf_hdr(m.request_id, 0);
  mupf_seq.d23 = 1;
  mupf_eor(eor, 2, MOQCACHE_OBJ_ID_MAX);
  mupf_send(1);
  mupf23_up_ok(SESS_A, sid, 0, 0, 0, wired_span_of(0, 0));
}

/* B's last stream: group 2 as one End of Range want (draft-22 has no
 * 0x40C: Unknown), then {3, 0}, FIN. */
static int mupf23_gone_read(u64 want) {
  u64 w = mtst_ver(SESS_B) == MOQVER_D23 ? want : MOQFETCH_EOR_UNKNOWN;
  return mupf_read(0) && mf_fin && mf_n == 2 && mf_items[0].flags == w &&
         mf_items[0].group == 2 && mf_is_obj(1, 3, 0, 1);
}

/* An upstream Gone range is kept: a later FETCH of it is answered Gone
 * by the hub with no upstream FETCH (3.2.3: "It does not issue upstream
 * FETCHes for Objects it has cached as Gone"); no MAX_CACHE_DURATION, so
 * it does not expire (10.3). */
static void mupf23_gone_cached(int bv) {
  mupf23_gone_first(bv, MOQFETCH_EOR_GONE);
  CHECK(mupf23_gone_read(MOQFETCH_EOR_GONE));
  wired_moqt_tick(&mtst_hub, 1000000);
  mupf_fetch(mupf_rl(2, 0, 3, 0), 0);
  CHECK(mupf_n_up(SESS_A) == 1);
  CHECK(mupf23_gone_read(MOQFETCH_EOR_GONE));
}

static void test_moqtrun_upfetch_d23_gone_cached(void) {
  mupf23_gone_cached(MOQVER_D23);
  mupf23_gone_cached(MOQVER_D22);
}

/* 10.3: with MAX_CACHE_DURATION 100 the range kept at 1000 answers Gone
 * until 1099; at 1100 it is Unknown again and goes upstream. */
static void test_moqtrun_upfetch_d23_gone_expires(void) {
  moqfetch_req m = {0};
  mupf_init_v(MOQVER_D23);
  moqtrun_pubst_track(&mtst_hub, mtst_hub.cache_tag_next)->max_cache_ms = 100;
  wired_moqt_tick(&mtst_hub, 1000);
  mupf_vers(MOQVER_D23);
  mupf_cache_group(3, 1);
  mupf_fetch(mupf_rl(2, 0, 3, 0), 0);
  i64 sid = mupf_up(SESS_A, 0, &m);
  mupf_hdr(m.request_id, 0);
  mupf_seq.d23 = 1;
  mupf_eor(MOQFETCH_EOR_GONE, 2, MOQCACHE_OBJ_ID_MAX);
  mupf_send(1);
  mupf23_up_ok(SESS_A, sid, 0, 0, 0, wired_span_of(0, 0));
  wired_moqt_tick(&mtst_hub, 1099);
  mupf_fetch(mupf_rl(2, 0, 3, 0), 0);
  CHECK(mupf_n_up(SESS_A) == 1 && mupf23_gone_read(MOQFETCH_EOR_GONE));
  wired_moqt_tick(&mtst_hub, 1100);
  mupf_fetch(mupf_rl(2, 0, 3, 0), 0);
  CHECK(mupf_n_up(SESS_A) == 2);
}

/* 7.1: "A relay does not cache Unknown or timed out ranges" -- the next
 * FETCH of them goes upstream again. */
static void test_moqtrun_upfetch_d23_gone_only(void) {
  static const u64 eors[] = {MOQFETCH_EOR_UNKNOWN, MOQFETCH_EOR_TIMED_OUT};
  for (usz i = 0; i < 2; i++) {
    mupf23_gone_first(MOQVER_D23, eors[i]);
    CHECK(mupf23_gone_read(eors[i]));
    mupf_fetch(mupf_rl(2, 0, 3, 0), 0);
    CHECK(mupf_n_up(SESS_A) == 2);
  }
}

/* A FETCH {1, 0}..{3, 0} over the cached Gone group 2: only group 1 goes
 * upstream (the span stops where the Gone range starts), then Gone from
 * the hub, then the cached {3, 0}. */
static void test_moqtrun_upfetch_d23_gone_partial(void) {
  moqfetch_req m = {0};
  i64          sid;
  mupf23_gone_first(MOQVER_D23, MOQFETCH_EOR_GONE);
  mupf_fetch(mupf_rl(1, 0, 3, 0), 0);
  sid = mupf_up(SESS_A, 1, &m);
  CHECK(sid >= 0 && m.range.start_group == 1 && m.range.end_group == 1);
  CHECK(m.range.ek == MOQCTL_REK_GROUP);
  mupf_hdr(m.request_id, 0);
  mupf_seq.d23 = 1;
  mupf_obj(1, 0, 1);
  mupf_send(1);
  mupf23_up_ok(SESS_A, sid, 0, 0, 0, wired_span_of(0, 0));
  CHECK(mupf_read(0) && mf_fin && mf_n == 3 && mf_is_obj(0, 1, 0, 1));
  CHECK(mf_items[1].flags == MOQFETCH_EOR_GONE && mf_items[1].group == 2);
  CHECK(mf_is_obj(2, 3, 0, 1));
}

/* ===== GOAWAY on the hub's upstream FETCH stream (draft-23 9.2) ===== */

/* A (on the draft under test) holds the hub's upstream FETCH; its
 * request stream id. */
static i64 mupf23_goaway_setup(void) {
  moqfetch_req m = {0};
  mupf_init();
  mupf_vers(g_moqtrun_test_ver);
  mupf_cache_group(3, 1);
  mupf_fetch(mupf_rl(1, 0, 4, 0), 0);
  return mupf_up(SESS_A, 0, &m);
}

/* A sends msg (16-bit Length envelope, mt_feed re-spells it) on sid. */
static void mupf23_goaway_feed(i64 sid, const u8* msg, usz n) {
  mt_feed(&mtst_hub, SESS_A, (u64)sid, wired_span_of(msg, n), 0);
}

/* The hub's session closes with code (1), or stays up (0 closes). */
static int mupf23_closed_with(u32 code) {
  const moqtrun_test_call* c = moqtrun_test_last_kind(11);
  return moqtrun_test_count_kind(11) == 1 && c->s == SESS_A &&
         c->stream_id == code;
}

/* GOAWAY, no New Session URI, Timeout 0. */
static const u8 MUPF23_GOAWAY[] = {MOQCTL_T_GOAWAY, 0x00, 0x02, 0x00, 0x00};

/* "more than one GOAWAY ... on a single request stream" is
 * UNEXPECTED_MESSAGE: two in one read, or a second in a later read while
 * the re-issue still waits for a stream (the old one is still open). */
static void mupf23_goaway_twice(void) {
  u8  two[2 * sizeof MUPF23_GOAWAY];
  i64 sid            = mupf23_goaway_setup();
  g_open_bidi_fail_n = 1;
  mupf23_goaway_feed(sid, MUPF23_GOAWAY, sizeof MUPF23_GOAWAY);
  CHECK(moqtrun_test_count_kind(11) == 0);
  CHECK(mupf_log_is(SESS_A, (u64)sid, ""));
  mupf23_goaway_feed(sid, MUPF23_GOAWAY, sizeof MUPF23_GOAWAY);
  CHECK(mupf23_closed_with(WIRED_MOQTRUN_CLOSE_UNEXPECTED_MESSAGE));
  for (usz i = 0; i < sizeof two; i++) {
    two[i] = MUPF23_GOAWAY[i % sizeof MUPF23_GOAWAY];
  }
  mupf23_goaway_feed(mupf23_goaway_setup(), two, sizeof two);
  CHECK(mupf23_closed_with(WIRED_MOQTRUN_CLOSE_UNEXPECTED_MESSAGE));
}

/* A second fetch data stream (client uni, 2 mod 4). */
#define MUPF23_DATA2_SID (MUPF_DATA_SID + 4)

/* A (draft-23) holds the hub's upstream FETCH for groups 1..2 of B's
 * FETCH {1,0}..{4,0} (groups 3, 4 cached) and relayed {1,0} {2,0} on its
 * open data stream; *m is that FETCH, its stream id returned. */
static i64 mupf23_mid_setup(moqfetch_req* m) {
  mupf_init();
  mupf_cache_group(3, 1);
  mupf_cache_group(4, 1);
  mupf_vers(MOQVER_D23);
  mupf_fetch(mupf_rl(1, 0, 4, 0), 0);
  i64 sid = mupf_up(SESS_A, 0, m);
  mupf_hdr(m->request_id, 0);
  mupf_seq.d23 = 1;
  mupf_obj(1, 0, 1);
  mupf_obj(2, 0, 1);
  mupf_send(0);
  return sid;
}

/* m1 asks for the rest of m0's range from {g, o}. */
static int mupf23_rest_of(
    const moqfetch_req* m1, const moqfetch_req* m0, u64 g, u64 o) {
  return m1->range.sk == MOQCTL_RSK_ABS && m1->range.start_group == g &&
         m1->range.start_object == o && m1->range.ek == m0->range.ek &&
         m1->range.end_group == m0->range.end_group &&
         m1->range.end_object == m0->range.end_object;
}

/* B got {1,0} {2,0} {2,1} {3,0} {4,0}, each once, then FIN. */
static int mupf23_all_once(void) {
  return mupf_read(0) && mf_fin && mf_n == 5 && mf_is_obj(0, 1, 0, 1) &&
         mf_is_obj(1, 2, 0, 1) && mf_is_obj(2, 2, 1, 1) &&
         mf_is_obj(3, 3, 0, 1) && mf_is_obj(4, 4, 0, 1);
}

/* "the sender of the request SHOULD re-issue that specific request ...
 * (or the current session if no URI is provided), and close the old
 * request stream": the hub asks A again for the rest of the span, from
 * just past {2,0}, under its next Request ID, and cancels the old request;
 * what still arrives on the old data stream is dropped. B gets every
 * Object once. */
static void mupf23_goaway_reissues(void) {
  moqfetch_req m0 = {0}, m1 = {0};
  i64          old = mupf23_mid_setup(&m0);
  mupf23_goaway_feed(old, MUPF23_GOAWAY, sizeof MUPF23_GOAWAY);
  i64 sid = mupf_up(SESS_A, 1, &m1);
  CHECK(sid >= 0 && sid != old && m1.request_id == m0.request_id + 2);
  CHECK(mupf23_rest_of(&m1, &m0, 2, 1));
  CHECK(mupf_log_is(SESS_A, (u64)old, "RST1|STOP1|"));
  CHECK(mupf_log_is(SESS_A, MUPF_DATA_SID, "STOP1|"));
  mupf_obj(2, 1, 1); /* late, on the old data stream */
  mupf_send(1);
  mupf_hdr(m1.request_id, 0);
  mupf_seq.d23 = 1;
  mupf_obj(2, 1, 1);
  mupf_send_on(SESS_A, MUPF23_DATA2_SID, 1);
  mupf23_up_ok(SESS_A, sid, 0, 0, 0, wired_span_of(0, 0));
  CHECK(moqtrun_test_count_kind(11) == 0);
  CHECK(mupf23_all_once());
}

/* 9.2 "SHOULD NOT initiate new requests" toward a peer that sent GOAWAY
 * on its control stream, nor (draft-19 10.4) one the hub sent its own:
 * nothing is re-issued, the leg ends and the cache side takes over just
 * past {2,0}. */
static void mupf23_goaway_no_reissue(int recv) {
  moqfetch_req        m   = {0};
  i64                 old = mupf23_mid_setup(&m);
  wired_moqtrun_peer* a   = moqtrun_find_by_wt(&mtst_hub, SESS_A);
  a->sess.goaway_recv     = recv;
  a->sess.goaway_sent     = !recv;
  mupf23_goaway_feed(old, MUPF23_GOAWAY, sizeof MUPF23_GOAWAY);
  wired_moqt_tick(&mtst_hub, 1);
  CHECK(mupf_n_up(SESS_A) == 1);
  CHECK(mupf_log_is(SESS_A, (u64)old, "RST1|STOP1|"));
  CHECK(mupf_resumed_after_20());
}

/* With no stream to open the old request stays as it is; the next tick
 * re-issues it under the Request ID the failed open did not use. */
static void mupf23_goaway_pending(void) {
  moqfetch_req m0 = {0}, m1 = {0};
  i64          old   = mupf23_mid_setup(&m0);
  g_open_bidi_fail_n = 1;
  mupf23_goaway_feed(old, MUPF23_GOAWAY, sizeof MUPF23_GOAWAY);
  CHECK(mupf_log_is(SESS_A, (u64)old, ""));
  wired_moqt_tick(&mtst_hub, 1);
  CHECK(mupf_log_is(SESS_A, (u64)old, "RST1|STOP1|"));
  CHECK(mupf_up(SESS_A, 2, &m1) >= 0);
  CHECK(m1.request_id == m0.request_id + 2 && mupf23_rest_of(&m1, &m0, 2, 1));
}

/* MQ23-216: the leg's one budget bounds the re-issued request too -- one
 * sent 1000 ms in is still cancelled when the budget runs out. */
static void mupf23_goaway_budget(void) {
  moqfetch_req m0 = {0}, m1 = {0};
  i64          old   = mupf23_mid_setup(&m0);
  g_open_bidi_fail_n = 1;
  mupf23_goaway_feed(old, MUPF23_GOAWAY, sizeof MUPF23_GOAWAY);
  wired_moqt_tick(&mtst_hub, 1000);
  i64 sid = mupf_up(SESS_A, 2, &m1);
  CHECK(sid >= 0);
  wired_moqt_tick(&mtst_hub, WIRED_MOQTRUN_UPFETCH_BUDGET_MS);
  CHECK(mupf_log_is(SESS_A, (u64)sid, "RST1|STOP1|"));
}

/* A Descending leg relays its top group first: with nothing relayed it is
 * re-issued whole (still Descending); after {2,0} the rest is no one
 * range, so the leg ends and the cache side takes over. */
static void mupf23_goaway_desc(int relayed) {
  moqctl_params desc = mtst_params_u8(MOQCTL_PARAM_GROUP_ORDER, 2);
  moqfetch_req  m0 = {0}, m1 = {0};
  mupf_init_nocache();
  mupf_vers(MOQVER_D23);
  mupf_fetch(mupf_rl(1, 0, 2, 1), &desc);
  i64 old = mupf_up(SESS_A, 0, &m0);
  mupf_hdr(m0.request_id, 1);
  mupf_seq.d23 = 1;
  if (relayed) {
    mupf_obj(2, 0, 1);
  }
  mupf_send(0);
  mupf23_goaway_feed(old, MUPF23_GOAWAY, sizeof MUPF23_GOAWAY);
  CHECK(mupf_log_is(SESS_A, (u64)old, "RST1|STOP1|"));
  CHECK(mupf_n_up(SESS_A) == (usz)(relayed ? 1 : 2));
  if (!relayed) {
    const moqctl_param* go;
    mupf_up(SESS_A, 1, &m1);
    go = moqctl_params_find(&m1.params, MOQCTL_PARAM_GROUP_ORDER);
    CHECK(mupf23_rest_of(&m1, &m0, 1, 0) && go && go->u8v == 2);
  }
}

static void test_moqtrun_upfetch_d23_reissue(void) {
  mupf23_goaway_reissues();
  mupf23_goaway_no_reissue(1);
  mupf23_goaway_no_reissue(0);
  mupf23_goaway_pending();
  mupf23_goaway_budget();
  mupf23_goaway_desc(0);
  mupf23_goaway_desc(1);
}

/* A New Session URI sent to the hub, a server, is ROLE_VIOLATION; a
 * body that does not decode (no Timeout) is MALFORMED_MESSAGE (12.2). */
static void mupf23_goaway_refused(void) {
  static const u8 uri[]    = {MOQCTL_T_GOAWAY, 0x00, 0x03, 0x01, 'x', 0x00};
  static const u8 short_[] = {MOQCTL_T_GOAWAY, 0x00, 0x01, 0x00};
  mupf23_goaway_feed(mupf23_goaway_setup(), uri, sizeof uri);
  CHECK(mupf23_closed_with(WIRED_MOQTRUN_CLOSE_ROLE_VIOLATION));
  mupf23_goaway_feed(mupf23_goaway_setup(), short_, sizeof short_);
  CHECK(mupf23_closed_with(WIRED_MOQTRUN_CLOSE_MALFORMED_MESSAGE));
}

static void test_moqtrun_upfetch_d23_goaway(void) {
  moqtrun_test_vers(MOQVER_CAP_REQ_GOAWAY23, 0, mupf23_goaway_twice);
  moqtrun_test_vers(MOQVER_CAP_REQ_GOAWAY23, 0, mupf23_goaway_refused);
}

/* One Property list: type t with value num. */
static wired_span mupf23_prop(u64 t, u64 num) {
  static u8 b[16];
  usz       n    = 0;
  u64       prev = 0;
  moqkvp    kv   = {0};
  kv.type        = t;
  kv.num         = num;
  CHECK(moqkvp_put(wired_mspan_of(b, sizeof b), &n, &prev, &kv));
  return wired_span_of(b, n);
}

/* C (on cv) answers the hub's upstream FETCH with Track Properties: type
 * t, value num; C's session close code, ~0 for none. */
static u64 mupf23_props_close(int cv, u64 t, u64 num) {
  moqfetch_req m = {0};
  i64          sid;
  mupf_init_v(MOQVER_D22);
  mupf_vers(cv);
  mupf_fetch_on(SESS_B, mupf_bob(), mupf_rl(0, 0, 5, 0), 0);
  sid = mupf_up(SESS_C, 0, &m);
  if (moqver_caps(cv) & MOQVER_CAP_FETCH_REQUEST_OK) {
    mupf23_up_ok(SESS_C, sid, 0, 0, 0, mupf23_prop(t, num));
  } else {
    mupf_up_ok_p(SESS_C, sid, mf_loc(2, 3), 0, mupf23_prop(t, num));
  }
  return moqtrun_test_close_code();
}

/* draft-23 10.5 / 10.6 (draft-18 12.5 / 12.6): DEFAULT_PUBLISHER_GROUP_ORDER
 * outside 1-2 or DYNAMIC_GROUPS above 1 in the upstream FETCH response
 * closes C -- MALFORMED_KEY_VALUE on draft-23, else PROTOCOL_VIOLATION --
 * and B is refused; draft-23 10.4: DEFAULT_PUBLISHER_PRIORITY above 255
 * too (draft-22 took it as 128). In range, nothing closes. */
static void test_moqtrun_upfetch_d23_props_close(void) {
  for (int v = 0; v < MOQVER_COUNT; v++) {
    u64 want = v == MOQVER_D23 ? WIRED_MOQTRUN_CLOSE_MALFORMED_KEY_VALUE
                               : WIRED_MOQTRUN_CLOSE_PROTOCOL_VIOLATION;
    CHECK(mupf23_props_close(v, 0x22, 3) == want);
    CHECK(mupf_refused(MOQCTL_ERR_INTERNAL_ERROR));
    CHECK(mupf23_props_close(v, 0x22, 2) == ~(u64)0);
    CHECK(mupf23_props_close(v, 0x30, 2) == want);
    CHECK(mupf23_props_close(v, 0x30, 1) == ~(u64)0);
    CHECK(
        mupf23_props_close(v, 0x0E, 256) == (v == MOQVER_D23 ? want : ~(u64)0));
    CHECK(mupf23_props_close(v, 0x0E, 255) == ~(u64)0);
  }
}

/* Object {g, 0}, one byte, whose Object Properties hold one Property of
 * type t. */
static moqfetch_obj mupf23_prop_obj(u64 g, u64 t) {
  static const u8 pl[] = {0x21};
  moqfetch_obj    ob   = {0};
  ob.flags        = MOQFETCH_F_OBJECT | MOQFETCH_F_PRIORITY | MOQFETCH_F_GROUP |
                    MOQFETCH_F_PROPS;
  ob.group        = g;
  ob.has_subgroup = 1;
  ob.priority     = 128;
  ob.has_props    = 1;
  ob.props        = mupf23_prop(t, 1);
  ob.payload      = wired_span_of(pl, 1);
  return ob;
}

/* A (draft-23) relays an Object with a Property of type t on the hub's
 * upstream FETCH -- through its data stream, or, gone, straight to the
 * item step; B's reset code, ~0 for none. */
static u64 mupf23_obj_props(int gone, u64 t) {
  moqfetch_req        m = {0};
  moqfetch_obj        o = mupf23_prop_obj(1, t);
  wired_moqtrun_peer* a;
  mupf_init_v(MOQVER_D23);
  mupf_vers(MOQVER_D23);
  mupf_cache_group(3, 1);
  mupf_fetch(mupf_rl(1, 0, 4, 0), 0);
  CHECK(mupf_up(SESS_A, 0, &m) >= 0);
  if (!gone) {
    mupf_hdr(m.request_id, 0);
    mupf_seq.d23 = 1;
    mupf_put(&o);
    mupf_send(0);
    return mupf_reset_code();
  }
  a     = moqtrun_find_by_wt(&mtst_hub, SESS_A);
  a->wt = SESS_D;
  moqtrun_upf_item(&mtst_hub, &mtst_hub.fetches[0], &o, o.payload);
  a->wt = SESS_A;
  return mupf_reset_code();
}

/* draft-23 3.7: a Mandatory Object Property (0x4000) on the upstream
 * FETCH makes the track Malformed, a grease one (0x409C = 0x9D + 129 *
 * 0x7F) does not -- also once the upstream session is gone (B's draft). */
static void test_moqtrun_upfetch_d23_obj_props(void) {
  CHECK(mupf23_obj_props(0, 0x4000) == MOQTRUN_RESET_MALFORMED_TRACK);
  CHECK(mupf23_obj_props(0, 0x409C) != MOQTRUN_RESET_MALFORMED_TRACK);
  CHECK(mupf23_obj_props(1, 0x409C) != MOQTRUN_RESET_MALFORMED_TRACK);
}

void test_moqtrun_upfetch_d23(void) {
  test_moqtrun_upfetch_d23_goaway();
  test_moqtrun_upfetch_d23_reissue();
  test_moqtrun_upfetch_d23_obj_props();
  test_moqtrun_upfetch_d23_props_close();
  test_moqtrun_upfetch_d23_relay();
  test_moqtrun_upfetch_d23_markers();
  test_moqtrun_upfetch_d23_eot();
  test_moqtrun_upfetch_d23_leg_fails();
  test_moqtrun_upfetch_d23_gone_cached();
  test_moqtrun_upfetch_d23_gone_expires();
  test_moqtrun_upfetch_d23_gone_only();
  test_moqtrun_upfetch_d23_gone_partial();
}
