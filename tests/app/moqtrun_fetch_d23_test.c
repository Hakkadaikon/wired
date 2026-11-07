/* draft-ietf-moq-transport-23 FETCH as the hub serves it, against
 * draft-22 on the same scenario: the fetch stream encoding (11.4). Every
 * scenario runs once per draft with the draft-22 FETCH layout. */

static int mfd23_is23(void);

/* 11.4.1.1: consecutive Objects of a Group leave the Object ID Delta out
 * (a present one would mean prior + Delta + 2 on draft-23), a new Group
 * carries Group ID Delta; the stream decodes under B's own draft.
 * draft-23 2.1.2 / 3.2.2: the rest of Group 0 is only inferred missing
 * (Group 1 began), so on draft-23 it is End of Unknown Range, not an
 * unmarked gap ("does not exist"). */
static void test_moqtrun_fetch_d23_stream(void) {
  usz g1 = mfd23_is23() ? 3 : 2;
  mf_init(sizeof mf_arena);
  mf_obj(0, 0, 1);
  mf_obj(0, 1, 1);
  mf_obj(1, 0, 1);
  mf_fetch_v(g_moqtrun_test_ver, 0);
  CHECK(mf_read() && mf_n == g1 + 1);
  CHECK(mf_is_obj(0, 0, 0, 1) && mf_is_obj(1, 0, 1, 1));
  CHECK(g1 == 2 || mf_is_unknown(2, 0, MOQCACHE_OBJ_ID_MAX));
  CHECK(mf_is_obj(g1, 1, 0, 1));
}

/* draft-23 2.1.2: a skipped Object ID is Unknown, so on draft-23 the
 * hub marks Object 1 End of Unknown Range; draft-22 leaves the gap. */
static void test_moqtrun_fetch_d23_hole(void) {
  usz last = mfd23_is23() ? 2 : 1;
  mf_init(sizeof mf_arena);
  mf_obj(0, 0, 1);
  mf_obj(0, 2, 1);
  mf_fetch_v(g_moqtrun_test_ver, 0);
  CHECK(mf_read() && mf_n == last + 1);
  CHECK(mf_is_obj(0, 0, 0, 1) && mf_is_obj(last, 0, 2, 1));
  CHECK(last == 1 || mf_is_unknown(1, 0, 1));
}

/* The FETCH response on B's last request stream, decoded independently
 * of moqfetch: its Type; for a draft-23 REQUEST_OK *largest is 1 and *end
 * the LARGEST_OBJECT when one came, for a FETCH_OK *end its End
 * Location; *code a REQUEST_ERROR's code. */
static u64 mfd23_reply(moqctl_loc* end, int* largest, u64* code) {
  moqctl_request_ok ok;
  usz               off = 0;
  u64               t   = mf_reply(code, end);
  *largest              = 0;
  if (t != MOQCTL_T_REQUEST_OK) {
    return t;
  }
  for (usz i = g_n_calls; i-- > 0;) {
    const moqtrun_test_call* c = &g_calls[i];
    u64                      type;
    wired_span               body;
    if (c->kind != 12 || c->stream_id != mf_req_sid) {
      continue;
    }
    mt_peek_type(wired_span_of(c->payload, c->payload_len), &off, &type, &body);
    off = 0;
    CHECK(moqctl_request_ok_take(mtst_ver(c->s), body, &off, &ok) == MOQCTL_OK);
    const moqctl_param* lo =
        moqctl_params_find(&ok.params, MOQCTL_PARAM_LARGEST_OBJECT);
    *largest = lo != 0;
    if (lo) {
      *end = lo->loc;
    }
    break;
  }
  return t;
}

static int mfd23_is23(void) {
  return (moqver_caps(g_moqtrun_test_ver) & MOQVER_CAP_FETCH_REQUEST_OK) != 0;
}

/* B's draft's answer to a FETCH served from the cache ending at {g, o}:
 * draft-23 3.2 / 9.3 a REQUEST_OK with LARGEST_OBJECT {g, o} iff largest
 * (Largest Object is within the range), else draft-22 9.12's FETCH_OK
 * with that inclusive End Location. */
static int mfd23_ok_is(u64 g, u64 o, int largest) {
  moqctl_loc end  = {~0ULL, ~0ULL};
  int        has  = 0;
  u64        code = 0;
  u64        t    = mfd23_reply(&end, &has, &code);
  if (!mfd23_is23()) {
    return t == MOQFETCH_T_FETCH_OK && mf_loc_eq(end, g, o);
  }
  return t == MOQCTL_T_REQUEST_OK && has == largest &&
         (!largest || mf_loc_eq(end, g, o));
}

/* draft-23 3.2: the response ends at Largest Object when it is in the
 * requested range and FETCH_OK carries LARGEST_OBJECT; a range ending
 * before it carries none. */
static void test_moqtrun_fetch_d23_ok(void) {
  moqctl_rangeloc obj00 = mf_rl(MOQCTL_RSK_ABS, 0, 0, MOQCTL_REK_OBJ, 0, 0);
  moqctl_rangeloc to10  = mf_rl(MOQCTL_RSK_ABS, 0, 0, MOQCTL_REK_OBJ, 1, 0);
  moqctl_rangeloc past  = mf_rl(MOQCTL_RSK_ABS, 0, 1, MOQCTL_REK_OBJ, 7, 0);
  mf_init(sizeof mf_arena);
  mf_obj(0, 0, 1);
  mf_obj(0, 1, 1);
  mf_obj(1, 0, 1);
  mf_fetch_v(g_moqtrun_test_ver, 0);
  CHECK(mfd23_ok_is(1, 0, 1));
  mf_fetch_v(g_moqtrun_test_ver, &obj00);
  CHECK(mfd23_ok_is(0, 0, 0));
  mf_fetch_v(g_moqtrun_test_ver, &to10);
  CHECK(mfd23_ok_is(1, 0, 1));
  mf_fetch_v(g_moqtrun_test_ver, &past);
  CHECK(mfd23_ok_is(1, 0, 1));
}

/* draft-23 3.2: a relative Location filter (9.19.9 Type 0x01) on FETCH
 * is INVALID_RANGE; draft-22 serves it from the Largest Group back. */
static void test_moqtrun_fetch_d23_relative(void) {
  moqctl_rangeloc cur =
      mf_rl(MOQCTL_RSK_REL_GROUP, 1, 0, MOQCTL_REK_UNBOUNDED, 0, 0);
  moqctl_loc end  = {0, 0};
  int        has  = 0;
  u64        code = 0;
  mf_init(sizeof mf_arena);
  mf_obj(0, 0, 1);
  mf_obj(1, 0, 1);
  mf_fetch_v(g_moqtrun_test_ver, &cur);
  if (mfd23_is23()) {
    CHECK(mfd23_reply(&end, &has, &code) == MOQCTL_T_REQUEST_ERROR);
    CHECK(code == MOQCTL_ERR_INVALID_RANGE);
    return;
  }
  CHECK(mfd23_ok_is(1, 0, 1));
}

/* A sends Object status st (draft-23 11.1.1: End of Group 0x3, End of
 * Track 0x4) at {g, o} on its own one-shot stream. */
static void mfd23_status(u64 g, u64 o, u64 st) {
  u8             buf[64];
  usz            off = 0;
  moqdata_subhdr h   = {0};
  h.type             = 0x30;
  h.track_alias      = MF_ALIAS;
  h.group_id         = g;
  moqdata_subhdr_put(wired_mspan_of(buf, sizeof buf), &off, &h);
  moqdata_obj_put_status(wired_mspan_of(buf, sizeof buf), &off, o, st);
  mf_pub_sid += 4;
  mt_feed(&mtst_hub, SESS_A, mf_pub_sid, wired_span_of(buf, off), 1);
}

/* Item i is the End of Group / End of Track marker flags of Group g. */
static int mfd23_is_mark(usz i, u64 flags, u64 g) {
  return i < mf_n && mf_items[i].flags == flags && mf_items[i].group == g;
}

/* B's stream: the Objects {0,0} {0,1}, then on draft-23 the marker
 * flags (3.2.2); draft-22 has none. */
static int mfd23_two_then(u64 flags) {
  usz n = mfd23_is23() ? 3 : 2;
  return mf_read() && mf_n == n && mf_is_obj(0, 0, 0, 1) &&
         mf_is_obj(1, 0, 1, 1) && (n == 2 || mfd23_is_mark(2, flags, 0));
}

/* draft-23 3.2.2: the last Object of the response is followed by End of
 * Group when the hub knows it ends its Group -- an End of Group status
 * after it -- and by End of Track when an End of Track status follows
 * it. A Group only closed by a later one is no such record (2.1.2, 12.1
 * item 4), so it gets no marker, like an open Group. */
static void test_moqtrun_fetch_d23_end_marks(void) {
  moqctl_rangeloc g0 = mf_rl(MOQCTL_RSK_ABS, 0, 0, MOQCTL_REK_OBJ, 0, 1);
  mf_init(sizeof mf_arena);
  mf_obj(0, 0, 1);
  mf_obj(0, 1, 1);
  mf_fetch_v(g_moqtrun_test_ver, 0);
  CHECK(mf_read() && mf_n == 2);
  mfd23_status(0, 2, MOQDATA_STATUS_END_OF_GROUP);
  mf_fetch_v(g_moqtrun_test_ver, 0);
  CHECK(mfd23_two_then(MOQFETCH_END_OF_GROUP));
  mf_init(sizeof mf_arena);
  mf_obj(0, 0, 1);
  mf_obj(0, 1, 1);
  mfd23_status(0, 2, MOQDATA_STATUS_END_OF_TRACK);
  mf_fetch_v(g_moqtrun_test_ver, 0);
  CHECK(mfd23_two_then(MOQFETCH_END_OF_TRACK));
  mf_init(sizeof mf_arena);
  mf_obj(0, 0, 1);
  mf_obj(0, 1, 1);
  mf_obj(1, 0, 1);
  mf_fetch_v(g_moqtrun_test_ver, &g0);
  CHECK(mf_read() && mf_n == 2);
}

/* A's track is Malformed: flagged, or already ended by the sweep. */
static int mfd23_a_malformed(void) {
  const wired_moqtrun_peer* a = moqtrun_find_by_wt(&mtst_hub, SESS_A);
  return !a->tracks[0].in_use || a->tracks[0].malformed;
}

/* draft-23 2.1.2 / 7.1: the hub only infers that Group 1's Object 1 does
 * not exist (Group 2 began without it), so its state is Unknown: arriving,
 * it is forwarded and the Track is not Malformed (12.1 item 10 needs a
 * record of non-existence); draft-22 7.1 drops it ("SHOULD NOT cache or
 * forward"). Neither caches it behind a later Group. */
static void test_moqtrun_fetch_d23_late_unknown(void) {
  int fwd = (moqver_caps(g_moqtrun_test_ver) & MOQVER_CAP_LATE_FORWARD) != 0;
  usz used;
  mf_init(sizeof mf_arena);
  mf_obj(1, 0, 1);
  mf_subscribe(0);
  mf_obj(2, 0, 1);
  used = mtst_hub.cache.used;
  mf_obj(1, 1, 1);
  CHECK(mf_relayed(1, 1) == fwd);
  CHECK(!mfd23_a_malformed() && mtst_hub.cache.used == used);
}

/* draft-23 10.3: "The same limit applies to cached Does Not Exist and
 * Gone states"; on expiry the Object returns to Unknown (2.1.2). A
 * 100 ms track's Group 0 ends at {0,2} (End of Group status): 99 ms on,
 * draft-23 serves {0,0} {0,1} then End of Group; from 100 ms on the
 * whole Group, the stretch past End of Group too, is End of Unknown
 * Range. Draft-22 serves the same Unknown range once it expired. */
static void test_moqtrun_fetch_d23_dne_expires(void) {
  u8         buf[16];
  usz        n    = 0;
  u64        prev = 0;
  moqkvp     kv   = {0};
  moqctl_ftn f    = mf_track();
  kv.type         = 0x04; /* MAX_CACHE_DURATION */
  kv.num          = 100;
  CHECK(moqkvp_put(wired_mspan_of(buf, sizeof buf), &n, &prev, &kv));
  mtst_init();
  wired_moqt_cache_attach(&mtst_hub, mf_arena, sizeof mf_arena);
  mf_pub_sid = 2;
  mf_ctrl_a  = mtst_join(SESS_A);
  mf_ctrl_b  = mtst_join(SESS_B);
  mtst_publish_props(SESS_A, mf_ctrl_a, &f, MF_ALIAS, wired_span_of(buf, n));
  wired_moqt_tick(&mtst_hub, 1000);
  mf_obj(0, 0, 1);
  mf_obj(0, 1, 1);
  mfd23_status(0, 2, MOQDATA_STATUS_END_OF_GROUP);
  wired_moqt_tick(&mtst_hub, 1099);
  mf_fetch_v(g_moqtrun_test_ver, 0);
  CHECK(mfd23_two_then(MOQFETCH_END_OF_GROUP));
  wired_moqt_tick(&mtst_hub, 1100);
  g_open_bidi_fail_n = 1;
  mf_fetch_v(g_moqtrun_test_ver, 0);
  CHECK(mf_read() && mf_n == 1 && mf_items[0].flags == MOQFETCH_EOR_UNKNOWN);
  CHECK(mf_items[0].group == 0 && mf_items[0].object >= 2);
}

static void mtall_fetch_d23(void) {
  test_moqtrun_fetch_d23_stream();
  test_moqtrun_fetch_d23_hole();
  test_moqtrun_fetch_d23_ok();
  test_moqtrun_fetch_d23_relative();
  test_moqtrun_fetch_d23_end_marks();
  test_moqtrun_fetch_d23_late_unknown();
  test_moqtrun_fetch_d23_dne_expires();
}

void test_moqtrun_fetch_d23(void) {
  moqtrun_test_vers(MOQVER_CAP_FETCH_BODY_V22, 0, mtall_fetch_d23);
}
