/* Range Filters judged per Object on relayed Subgroup streams
 * (draft-19 5.1.3/5.1.4, draft-22/23 3.3.2/3.3.3: "The publisher MUST
 * forward only objects that pass all filters"). A filtered subscriber's
 * stream carries only its Objects, their Object ID Deltas re-chained
 * (draft-19 11.4.2, draft-22/23 11.3.1: Delta + 1 is added to the
 * previous Object ID on the stream, the first is absolute). Draft-18
 * has no Range Filters. */

#define MTOF_SID 997

/* Header Type 0x30: Subgroup ID 0, DEFAULT_PRIORITY, no Properties. */
static const u8 mtof_abc[] = {0x30, 0x01, 0x00, 0x00, 0x01, 'a',
                              0x00, 0x01, 'b',  0x00, 0x01, 'c'};

/* B and C SUBSCRIBE alice under ver, B with params pb (C unfiltered). */
static void mtof_init(int ver, const moqctl_params* pb) {
  moqctl_ftn f       = mtst_ftn("chat", "room1", "alice");
  g_moqtrun_test_ver = ver;
  mtst_init();
  u64 ca = mtst_join(SESS_A);
  u64 cb = mtst_join(SESS_B);
  u64 cc = mtst_join(SESS_C);
  mtst_publish(SESS_A, ca, &f, 1);
  mtst_subscribe_p(SESS_B, cb, &f, mtst_rid += 4, pb);
  CHECK(mtsub_last_reply_type() == MOQCTL_T_SUBSCRIBE_OK);
  mtst_subscribe(SESS_C, cc, &f);
  CHECK(mtsub_last_reply_type() == MOQCTL_T_SUBSCRIBE_OK);
  moqtrun_test_reset();
}

/* OBJECTID_FILTER of one SetID 0 Range {lo..hi}. */
static moqctl_params mtof_oid(u64 lo, u64 hi) {
  moqctl_params      p = {0};
  moqctl_rangefilter r = mtst_rngf1(0, lo, hi, 1);
  mtst_rngf_param(&p, MOQCTL_PARAM_OBJECTID_FILTER, &r);
  return p;
}

static void mtof_feed(const u8* p, usz n, int fin) {
  mt_feed(&mtst_hub, SESS_A, MTOF_SID, wired_span_of(p, n), fin);
}

/* The last call of kind to s; 0 when none. */
static const moqtrun_test_call* mtof_last(int kind, wired_wt_session* s) {
  for (usz i = g_n_calls; i > 0; i--) {
    if (g_calls[i - 1].kind == kind && g_calls[i - 1].s == s) {
      return &g_calls[i - 1];
    }
  }
  return 0;
}

static usz mtof_count(wired_wt_session* s) {
  usz n = 0;
  for (usz i = 0; i < g_n_calls; i++) {
    n += g_calls[i].s == s;
  }
  return n;
}

/* The last call of kind to s carried exactly want[0..n). */
static int mtof_is(int kind, wired_wt_session* s, const u8* want, usz n) {
  const moqtrun_test_call* c = mtof_last(kind, s);
  return c && c->payload_len == n && !ct_diffn(c->payload, want, n);
}

/* One-shot stream (FIN with its first delivery): B's {1..1} gets Object 1
 * alone, absolute (a late head: its first Object is not the stream's);
 * C, unfiltered, gets the publisher's bytes unchanged. */
static void mtof_oneshot(int ver) {
  static const u8 b_want[] = {0x30, 0x01, 0x00, 0x01, 0x01, 'b'};
  moqctl_params   p        = mtof_oid(1, 1);
  mtof_init(ver, &p);
  mtof_feed(mtof_abc, sizeof mtof_abc, 1);
  CHECK(mtof_is(4, SESS_B, b_want, sizeof b_want));
  CHECK(mtof_is(4, SESS_C, mtof_abc, sizeof mtof_abc));
}

static void test_moqtrun_ofilt_oneshot(void) {
  mtof_oneshot(MOQVER_D19);
  mtof_oneshot(MOQVER_D22);
  mtof_oneshot(MOQVER_D23);
  g_moqtrun_test_ver = MOQVER_D19;
}

/* A keep-open stream across rounds, B's Ranges {0},{2..3}: Object 2's
 * ID Delta is re-chained onto Object 0 (1 = 2 - 0 - 1), Object 3 follows
 * at Delta 0; C's rounds pass unchanged. */
static void mtof_rounds(int ver) {
  static const u8    r1_b[] = {0x30, 0x01, 0x00, 0x00, 0x01, 'a'};
  static const u8    r2[]   = {0x00, 0x01, 'c'};
  static const u8    r2_b[] = {0x01, 0x01, 'c'};
  static const u8    r3[]   = {0x00, 0x01, 'd'};
  moqctl_params      p      = {0};
  moqctl_rangefilter r      = mtst_rngf1(0, 0, 0, 1);
  r.n                       = 2;
  r.r[1].start              = 2;
  r.r[1].end                = 3;
  r.r[1].has_end            = 1;
  mtst_rngf_param(&p, MOQCTL_PARAM_OBJECTID_FILTER, &r);
  mtof_init(ver, &p);
  mtof_feed(mtof_abc, 9, 0); /* header, Objects 0 and 1 */
  CHECK(mtof_is(5, SESS_B, r1_b, sizeof r1_b));
  CHECK(mtof_is(5, SESS_C, mtof_abc, 9));
  mtof_feed(r2, sizeof r2, 0);
  CHECK(mtof_is(3, SESS_B, r2_b, sizeof r2_b));
  CHECK(mtof_is(3, SESS_C, r2, sizeof r2));
  mtof_feed(r3, sizeof r3, 1);
  CHECK(mtof_is(3, SESS_B, r3, sizeof r3));
  CHECK(mtof_last(3, SESS_B) && mtof_last(3, SESS_B)->fin);
}

static void test_moqtrun_ofilt_rounds(void) {
  mtof_rounds(MOQVER_D19);
  mtof_rounds(MOQVER_D22);
  mtof_rounds(MOQVER_D23);
  g_moqtrun_test_ver = MOQVER_D19;
}

/* B's {2..2} on an END_OF_GROUP stream: nothing opens while its rounds
 * carry no passing Object; Object 2 opens it lazily, a head with
 * END_OF_GROUP cleared (the stream no longer carries the Group's last
 * Object before its FIN, draft-22 11.3.1 / 12.1 #4) then the Object
 * under its absolute ID; the FIN round's Object 3 is cut, so only the
 * FIN follows. */
static void mtof_lazy(int ver) {
  static const u8 r1[]   = {0x38, 0x01, 0x00, 0x00, 0x01, 'a', 0x00, 0x01, 'b'};
  static const u8 r2[]   = {0x00, 0x01, 'c'};
  static const u8 hd_b[] = {0x30, 0x01, 0x00};
  static const u8 r2_b[] = {0x02, 0x01, 'c'};
  static const u8 r3[]   = {0x00, 0x01, 'd'};
  moqctl_params   p      = mtof_oid(2, 2);
  mtof_init(ver, &p);
  mtof_feed(r1, sizeof r1, 0);
  CHECK(mtof_count(SESS_B) == 0);
  mtof_feed(r2, sizeof r2, 0);
  CHECK(mtof_is(5, SESS_B, hd_b, sizeof hd_b));
  CHECK(mtof_is(3, SESS_B, r2_b, sizeof r2_b));
  CHECK(mtof_is(3, SESS_C, r2, sizeof r2));
  moqtrun_test_reset();
  mtof_feed(r3, sizeof r3, 1);
  CHECK(mtof_last(3, SESS_B) == 0);
  CHECK(mtof_last(6, SESS_B) != 0);
  CHECK(mtof_is(3, SESS_C, r3, sizeof r3));
}

static void test_moqtrun_ofilt_lazy_open(void) {
  mtof_lazy(MOQVER_D19);
  mtof_lazy(MOQVER_D22);
  mtof_lazy(MOQVER_D23);
  g_moqtrun_test_ver = MOQVER_D19;
}

/* A stream none of whose Objects pass is never opened toward B, neither
 * kept open nor one-shot; C still gets all of it. */
static void test_moqtrun_ofilt_all_cut(void) {
  moqctl_params p = mtof_oid(9, 9);
  mtof_init(MOQVER_D22, &p);
  mtof_feed(mtof_abc, 9, 0);
  mtof_feed(mtof_abc + 9, 3, 1);
  CHECK(mtof_count(SESS_B) == 0);
  CHECK(mtof_is(3, SESS_C, mtof_abc + 9, 3));
  mtof_init(MOQVER_D22, &p);
  mtof_feed(mtof_abc, sizeof mtof_abc, 1);
  CHECK(mtof_count(SESS_B) == 0);
  CHECK(mtof_is(4, SESS_C, mtof_abc, sizeof mtof_abc));
  g_moqtrun_test_ver = MOQVER_D19;
}

/* A refused round is lost to B whole: the next Object's ID Delta chains
 * from the last Object B was actually sent (0), not the refused one. */
static void test_moqtrun_ofilt_refused_round(void) {
  static const u8 r2[]   = {0x00, 0x01, 'b'};
  static const u8 r3[]   = {0x00, 0x01, 'c'};
  static const u8 r3_b[] = {0x01, 0x01, 'c'};
  moqctl_params   p      = mtof_oid(0, 9);
  mtof_init(MOQVER_D22, &p);
  mtof_feed(mtof_abc, 6, 0);
  g_stream_send_reject_sess = SESS_B;
  mtof_feed(r2, sizeof r2, 0);
  g_stream_send_reject_sess = 0;
  mtof_feed(r3, sizeof r3, 0);
  CHECK(mtof_is(3, SESS_B, r3_b, sizeof r3_b));
  g_moqtrun_test_ver = MOQVER_D19;
}

/* A ring-backed (reliable) track: B, filtered, is served per round on
 * its own re-chained stream beside C's ring cursor. */
static void test_moqtrun_ofilt_ring(void) {
  static const u8 r1_b[] = {0x30, 0x01, 0x00, 0x01, 0x01, 'b'};
  static const u8 r2[]   = {0x00, 0x01, 'c'};
  moqctl_params   p      = mtof_oid(1, 1);
  mtof_init(MOQVER_D22, &p);
  mtst_hub.reliable_alias_limit = 100;
  mtof_feed(mtof_abc, 9, 0);
  CHECK(mtof_is(5, SESS_B, r1_b, sizeof r1_b));
  mtof_feed(r2, sizeof r2, 1);
  CHECK(mtof_last(3, SESS_B) == 0);
  CHECK(mtof_last(6, SESS_B) != 0);
  CHECK(mtof_is(3, SESS_C, r2, sizeof r2));
  mtst_hub.reliable_alias_limit = 0;
  g_moqtrun_test_ver            = MOQVER_D19;
}

/* OBJECT_PROPERTY_FILTER (draft-19 10.2.13, draft-22/23 9.20.13):
 * Property 0x2A in {0..9} -- Object 0 (0x2A = 5) passes, Object 1 (none)
 * and Object 2 (0x2A = 10) are cut. Header Type 0x31 carries
 * Properties. */
static void mtof_prop(int ver) {
  static const u8    in[] = {0x31, 0x01, 0x00, 0x00, 0x02, 0x2A, 0x05,
                             0x01, 'a',  0x00, 0x00, 0x01, 'b',  0x00,
                             0x02, 0x2A, 0x0A, 0x01, 'c'};
  moqctl_params      p    = {0};
  moqctl_rangefilter r    = mtst_rngf1(0, 0, 9, 1);
  r.has_prop              = 1;
  r.prop_type             = 0x2A;
  mtst_rngf_param(&p, MOQCTL_PARAM_OBJECT_PROPERTY_FILTER, &r);
  mtof_init(ver, &p);
  mtof_feed(in, sizeof in, 1);
  CHECK(mtof_is(4, SESS_B, in, 9));
  CHECK(mtof_is(4, SESS_C, in, sizeof in));
}

static void test_moqtrun_ofilt_property(void) {
  mtof_prop(MOQVER_D19);
  mtof_prop(MOQVER_D22);
  mtof_prop(MOQVER_D23);
  g_moqtrun_test_ver = MOQVER_D19;
}

/* A datagram without the filtered Property does not pass either. */
static void test_moqtrun_ofilt_property_datagram(void) {
  moqctl_params      p = {0};
  moqctl_rangefilter r = mtst_rngf1(0, 0, 9, 1);
  r.has_prop           = 1;
  r.prop_type          = 0x2A;
  mtst_rngf_param(&p, MOQCTL_PARAM_OBJECT_PROPERTY_FILTER, &r);
  mtof_init(MOQVER_D19, &p);
  wired_moqt_on_datagram(
      &mtst_hub, SESS_A,
      wired_span_of(MOQTRUN_TEST_DG_CHAT, sizeof MOQTRUN_TEST_DG_CHAT));
  CHECK(mtof_last(9, SESS_B) == 0);
  CHECK(mtof_last(9, SESS_C) != 0);
}

/* B on request stream MTRQ_S1 (so a REQUEST_UPDATE can reach it), C on
 * its control stream; reliable sets the track ring-backed. */
static void mtof_init_rq(const moqctl_params* pb, int reliable) {
  moqctl_ftn f       = mtst_ftn("chat", "room1", "alice");
  g_moqtrun_test_ver = MOQVER_D22;
  mtst_init();
  u64 ca = mtst_join(SESS_A);
  mtst_join(SESS_B);
  u64 cc = mtst_join(SESS_C);
  mtst_publish(SESS_A, ca, &f, 1);
  mtst_subscribe_p(SESS_B, MTRQ_S1, &f, mtst_rid += 4, pb);
  mtst_subscribe(SESS_C, cc, &f);
  mtst_hub.reliable_alias_limit = reliable ? 100 : 0;
  moqtrun_test_reset();
}

/* d22 3.3.2: a REQUEST_UPDATE with a zero-Length OBJECTID_FILTER removes
 * it mid-stream. B's stream already skipped Object 1, so Object 2 still
 * chains onto Object 0 (Delta 1): it is never cut through with the
 * publisher's Delta 0 while incomplete, and on a ring-backed track it
 * still reaches B (with the FIN) though B rides no ring cursor. */
static void mtof_unfilter(int reliable) {
  static const u8    o2[]  = {0x00, 0x02, 'c', 'd'};
  static const u8    o2b[] = {0x01, 0x02, 'c', 'd'};
  moqctl_params      p = {0}, del = {0};
  moqctl_rangefilter r = mtst_rngf1(0, 0, 0, 1), none = {0};
  r.n            = 2;
  r.r[1].start   = 2;
  r.r[1].end     = 9;
  r.r[1].has_end = 1;
  none.remove    = 1;
  mtst_rngf_param(&p, MOQCTL_PARAM_OBJECTID_FILTER, &r);
  mtst_rngf_param(&del, MOQCTL_PARAM_OBJECTID_FILTER, &none);
  mtof_init_rq(&p, reliable);
  mtof_feed(mtof_abc, 9, 0); /* header, Objects 0 and 1 */
  mtup_update(SESS_B, MTRQ_S1, &del);
  CHECK(mtst_sub(SESS_A, SESS_B)->rngf_n == 0);
  moqtrun_test_reset();
  mtof_feed(o2, 3, 0); /* Object 2's head and its first byte */
  CHECK(mtof_last(3, SESS_B) == 0);
  mtof_feed(o2 + 3, 1, 1);
  CHECK(mtof_is(3, SESS_B, o2b, sizeof o2b));
  CHECK(mtof_last(3, SESS_B) && mtof_last(3, SESS_B)->fin);
  mtst_hub.reliable_alias_limit = 0;
}

static void test_moqtrun_ofilt_unfilter_mid_stream(void) {
  mtof_unfilter(0);
  mtof_unfilter(1);
  g_moqtrun_test_ver = MOQVER_D19;
}

/* On a ring-backed track B, cut per Object, opens lazily on its first
 * kept Object; a refused round resets its stream (it could not be told
 * from filtering otherwise, d22 11.3.2) and the next kept Object opens a
 * fresh one under its absolute ID. */
static void test_moqtrun_ofilt_ring_lazy_and_refused(void) {
  static const u8 hd_b[] = {0x30, 0x01, 0x00};
  static const u8 o1[]   = {0x00, 0x01, 'b'};
  static const u8 o1_b[] = {0x01, 0x01, 'b'};
  static const u8 o2[]   = {0x00, 0x01, 'c'};
  static const u8 o3_b[] = {0x03, 0x01, 'c'};
  moqctl_params   p      = mtof_oid(1, 9);
  mtof_init(MOQVER_D22, &p);
  mtst_hub.reliable_alias_limit = 100;
  mtof_feed(mtof_abc, 6, 0); /* header, Object 0 (cut) */
  CHECK(mtof_count(SESS_B) == 0);
  mtof_feed(o1, sizeof o1, 0);
  CHECK(mtof_is(5, SESS_B, hd_b, sizeof hd_b));
  CHECK(mtof_is(3, SESS_B, o1_b, sizeof o1_b));
  u64 sid                   = mtof_last(5, SESS_B)->stream_id;
  g_stream_send_reject_sess = SESS_B;
  mtof_feed(o2, sizeof o2, 0);
  g_stream_send_reject_sess = 0;
  CHECK(mtof_last(7, SESS_B) && mtof_last(7, SESS_B)->stream_id == sid);
  moqtrun_test_reset();
  mtof_feed(o2, sizeof o2, 0); /* Object 3 */
  CHECK(mtof_is(5, SESS_B, hd_b, sizeof hd_b));
  CHECK(mtof_last(5, SESS_B)->stream_id != sid);
  CHECK(mtof_is(3, SESS_B, o3_b, sizeof o3_b));
  mtst_hub.reliable_alias_limit = 0;
  g_moqtrun_test_ver            = MOQVER_D19;
}

/* SUBGROUP_ID_MODE 0b01 (the Subgroup ID is the first Object's ID, 5):
 * with Object 5 cut the head names Subgroup 5 explicitly (mode 0b10,
 * Type 0x34) and Object 6 is absolute (d22 11.3.1). */
static void test_moqtrun_ofilt_sgid_first_cut(void) {
  static const u8 in[]   = {0x32, 0x01, 0x00, 0x05, 0x01, 'a',
                            0x00, 0x01, 'b',  0x00, 0x01, 'c'};
  static const u8 want[] = {0x34, 0x01, 0x00, 0x05, 0x06,
                            0x01, 'b',  0x00, 0x01, 'c'};
  moqctl_params   p      = mtof_oid(6, 7);
  mtof_init(MOQVER_D22, &p);
  mtof_feed(in, sizeof in, 1);
  CHECK(mtof_is(4, SESS_B, want, sizeof want));
  g_moqtrun_test_ver = MOQVER_D19;
}

/* A datagram has no Subgroup ID: a set naming SUBGROUP_FILTER passes
 * none. PRIORITY_FILTER judges its Publisher Priority -- the track's
 * default 128 under DEFAULT_PRIORITY (Type 0x08). */
static void test_moqtrun_ofilt_datagram_sg_prio(void) {
  static const u64 ptype[3] = {
      MOQCTL_PARAM_SUBGROUP_FILTER, MOQCTL_PARAM_PRIORITY_FILTER,
      MOQCTL_PARAM_PRIORITY_FILTER};
  static const u64 lo[3]   = {0, 0, 128};
  static const u64 hi[3]   = {9, 127, 128};
  static const int pass[3] = {0, 0, 1};
  for (usz k = 0; k < 3; k++) {
    moqctl_params      p = {0};
    moqctl_rangefilter r = mtst_rngf1(0, lo[k], hi[k], 1);
    mtst_rngf_param(&p, ptype[k], &r);
    mtof_init(MOQVER_D22, &p);
    wired_moqt_on_datagram(
        &mtst_hub, SESS_A,
        wired_span_of(MOQTRUN_TEST_DG_CHAT, sizeof MOQTRUN_TEST_DG_CHAT));
    CHECK((mtof_last(9, SESS_B) != 0) == pass[k]);
    CHECK(mtof_last(9, SESS_C) != 0);
  }
  g_moqtrun_test_ver = MOQVER_D19;
}

/* The largest round (a held fragment plus a whole WT receive window)
 * re-chained at its worst: B was last sent Object 0, so the round's
 * first kept Object (2^56 + 1, Delta 0 on the publisher's chain) goes out
 * under a 9-byte Delta (+8). A cut Object between kept ones never grows
 * the round: its successor's Delta gains at most one byte per 7 bits
 * while the cut one drops at least three. Every passing Object still
 * fits -- none is silently cut. */
#define MTOF_ROUND (WIRED_MOQTRUN_RELAY_FRAG_MAX + WIRED_SRVLOOP_WT_BUF_CAP)
static void test_moqtrun_ofilt_round_bound(void) {
  static u8                  in[MTOF_ROUND];
  static wired_moqtrun_sub   s;
  static wired_moqtrun_relay relay;
  const u64                  a = ((u64)1 << 56) + 1;
  usz                        n = 0;
  n += moqvi_encode(in + n, 0); /* a, kept */
  in[n++] = 1;
  in[n++] = 'a';
  n += moqvi_encode(in + n, 0); /* a + 1, cut */
  in[n++] = 1;
  in[n++] = 'x';
  usz pl  = MTOF_ROUND - n - 1 - 3;
  n += moqvi_encode(in + n, 0); /* a + 2, kept, filling the round */
  n += moqvi_encode(in + n, pl);
  CHECK(n + pl == MTOF_ROUND);
  s.rngf_n = 2;
  s.rngf[0] =
      (wired_moqtrun_rngrow){MOQCTL_PARAM_OBJECTID_FILTER, 0, a, a, 0, 0, 1};
  s.rngf[1] = (wired_moqtrun_rngrow){
      MOQCTL_PARAM_OBJECTID_FILTER, 0, a + 2, a + 2, 0, 0, 1};
  relay.sub_dhave    = 1;
  relay.sub_dprev[0] = 0;
  moqdata_objseq pub = {0, 1, a - 1};
  moqtrun_round  r   = {wired_span_of(in, MTOF_ROUND), pub, 0};
  moqtrun_round  o   = moqtrun_ofilt_round(&mtst_hub, &s, &relay, 0, r);
  CHECK(o.wire.n == MTOF_ROUND + 8 - 3);
  usz         at = 0, kept = 0;
  moqdata_obj obj = {0};
  while (moqdata_obj_take(o.wire, &at, &o.seq0, &obj) == MOQDATA_OK) {
    kept++;
  }
  CHECK(kept == 2 && obj.object_id == a + 2 && obj.payload.n == pl);
}

static void test_moqtrun_ofilt(void) {
  test_moqtrun_ofilt_oneshot();
  test_moqtrun_ofilt_rounds();
  test_moqtrun_ofilt_lazy_open();
  test_moqtrun_ofilt_all_cut();
  test_moqtrun_ofilt_refused_round();
  test_moqtrun_ofilt_ring();
  test_moqtrun_ofilt_property();
  test_moqtrun_ofilt_property_datagram();
  test_moqtrun_ofilt_unfilter_mid_stream();
  test_moqtrun_ofilt_ring_lazy_and_refused();
  test_moqtrun_ofilt_sgid_first_cut();
  test_moqtrun_ofilt_datagram_sg_prio();
  test_moqtrun_ofilt_round_bound();
}
