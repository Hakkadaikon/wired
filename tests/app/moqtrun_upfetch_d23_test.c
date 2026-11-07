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

void test_moqtrun_upfetch_d23(void) { test_moqtrun_upfetch_d23_relay(); }
