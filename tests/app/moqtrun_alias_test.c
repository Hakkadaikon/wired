/* Relayed Track Alias per destination session (draft-ietf-moq-transport-22
 * 3.1.3, draft-19 11.1): the alias the hub names in SUBSCRIBE_OK (9.7) or
 * its own PUBLISH (9.8) is the one every SUBGROUP_HEADER (11.3.1) and
 * OBJECT_DATAGRAM (11.2.1) it relays to that session carries, and two
 * Tracks never share an alias within one session. FETCH streams (11.4.1)
 * name a Request ID, not an alias, so they are out of scope here. Shares
 * the io stubs and fixtures of moqtrun_test.c, moqtrun_sub_test.c and
 * moqtrun_subtracks_test.c (same unity TU). */

#define MTAL_PUB_A 2001
#define MTAL_PUB_C 2005

static moqctl_ftn mtal_f(void) { return mtst_ftn("chat", "room1", "alice"); }

static moqctl_ftn mtal_g(void) { return mtst_ftn("chat", "room1", "carol"); }

/* B SUBSCRIBEs f on cb; the Track Alias its SUBSCRIBE_OK names. */
static u64 mtal_sub(u64 cb, moqctl_ftn f) {
  mtst_subscribe(SESS_B, cb, &f);
  const moqctl_subscribe_ok* ok = mtst_last_ok();
  CHECK(ok != 0);
  return ok ? ok->track_alias : (u64)-1;
}

/* SUBGROUP_HEADER (Type 0x30, alias a, Group 0) when hdr, then one
 * 1-byte Object (payload b). */
static usz mtal_stream(u64 a, int hdr, u8 b, u8* buf) {
  moqdata_subhdr h   = {0};
  usz            off = 0;
  wired_mspan    out = wired_mspan_of(buf, MOQTRUN_TEST_MAX_PAYLOAD);
  h.type             = 0x30;
  h.track_alias      = a;
  if (hdr) moqdata_subhdr_put(out, &off, &h);
  moqdata_obj_put(out, &off, 0, wired_span_of(&b, 1));
  return off;
}

/* The last io call of kind addressed to B, else 0. */
static const moqtrun_test_call* mtal_to_b(int kind) {
  for (usz i = g_n_calls; i-- > 0;)
    if (g_calls[i].kind == kind && g_calls[i].s == SESS_B) return &g_calls[i];
  return 0;
}

/* Track Alias of that call's payload: the vi64 right after the Type, in
 * a SUBGROUP_HEADER and an OBJECT_DATAGRAM alike; (u64)-1 for none. */
static u64 mtal_alias_to_b(int kind) {
  const moqtrun_test_call* c   = mtal_to_b(kind);
  u64                      v   = (u64)-1;
  usz                      off = 0;
  if (!c) return v;
  wired_span p = wired_span_of(c->payload, c->payload_len);
  moqvi_take(p, &off, &v);
  moqvi_take(p, &off, &v);
  return v;
}

/* 1 iff B's last kind call is src[0..n) with only the alias re-spelled:
 * the header past the alias and every Object byte intact. */
static int mtal_tail_kept(int kind, const u8* src, usz n) {
  const moqtrun_test_call* c = mtal_to_b(kind);
  usz                      a = 0, b = 0;
  u64                      v;
  if (!c) return 0;
  wired_span p = wired_span_of(c->payload, c->payload_len);
  moqvi_take(p, &a, &v);
  moqvi_take(p, &a, &v);
  moqvi_take(wired_span_of(src, n), &b, &v);
  moqvi_take(wired_span_of(src, n), &b, &v);
  return p.n - a == n - b && !ct_diffn(p.p + a, src + b, n - b);
}

/* A (alice) and C (carol) each PUBLISH under the SAME alias in their own
 * sessions -- legal, aliases are per session (3.1.3). Returns B's ctrl. */
static u64 mtal_two_pubs(u64 alias) {
  moqctl_ftn f = mtal_f(), g = mtal_g();
  mtst_init();
  u64 ca = mtst_join(SESS_A);
  u64 cb = mtst_join(SESS_B);
  u64 cc = mtst_join(SESS_C);
  mtst_publish(SESS_A, ca, &f, alias);
  mtst_publish(SESS_C, cc, &g, alias);
  return cb;
}

static void mtal_push(wired_wt_session* s, u64 sid, wired_span w, int fin) {
  wired_moqt_on_stream_data(&mtst_hub, s, sid, w, fin);
}

/* One publisher (alias 5): the one-shot relayed stream carries the alias
 * B's SUBSCRIBE_OK named, not a hub counter's. */
static void test_mtal_subgroup_matches_subscribe_ok(void) {
  u8         buf[MOQTRUN_TEST_MAX_PAYLOAD];
  moqctl_ftn f = mtal_f();
  mtst_init();
  u64 ca = mtst_join(SESS_A);
  u64 cb = mtst_join(SESS_B);
  mtst_publish(SESS_A, ca, &f, 5);
  u64 a = mtal_sub(cb, f);
  usz n = mtal_stream(5, 1, 9, buf);
  mtal_push(SESS_A, MTAL_PUB_A, wired_span_of(buf, n), 1);
  CHECK(mtal_alias_to_b(4) == a);
}

/* Two tracks whose publishers both chose alias 1: B is told two distinct
 * aliases (MUST NOT share, 3.1.3) and each one-shot stream reaches B under
 * the alias told for its track. */
static void test_mtal_two_tracks_distinct(void) {
  u8  buf[MOQTRUN_TEST_MAX_PAYLOAD];
  u64 cb = mtal_two_pubs(1);
  u64 af = mtal_sub(cb, mtal_f());
  u64 ag = mtal_sub(cb, mtal_g());
  CHECK(af != ag);
  usz n = mtal_stream(1, 1, 9, buf);
  mtal_push(SESS_A, MTAL_PUB_A, wired_span_of(buf, n), 1);
  CHECK(mtal_alias_to_b(4) == af);
  mtal_push(SESS_C, MTAL_PUB_C, wired_span_of(buf, n), 1);
  CHECK(mtal_alias_to_b(4) == ag);
  CHECK(mtal_tail_kept(4, buf, n));
}

/* The same two tracks over OBJECT_DATAGRAM (11.2.1, alias 1). */
static void test_mtal_datagram_distinct(void) {
  u64        cb = mtal_two_pubs(1);
  u64        af = mtal_sub(cb, mtal_f());
  u64        ag = mtal_sub(cb, mtal_g());
  wired_span dg =
      wired_span_of(MOQTRUN_TEST_DG_CHAT, sizeof MOQTRUN_TEST_DG_CHAT);
  wired_moqt_on_datagram(&mtst_hub, SESS_A, dg);
  CHECK(mtal_alias_to_b(9) == af);
  wired_moqt_on_datagram(&mtst_hub, SESS_C, dg);
  CHECK(mtal_alias_to_b(9) == ag);
  CHECK(mtal_tail_kept(9, dg.p, dg.n));
}

/* Keep-open stream with a 2-byte alias (300) re-spelled to B's 1-byte
 * one: the opening round carries B's alias and intact Objects, the
 * header-less continuation passes through unchanged. */
static void mtal_keepopen(u64 limit) {
  u8  buf[MOQTRUN_TEST_MAX_PAYLOAD];
  u64 cb                        = mtal_two_pubs(300);
  mtst_hub.reliable_alias_limit = limit;
  mtal_sub(cb, mtal_f());
  u64 ag = mtal_sub(cb, mtal_g());
  usz n  = mtal_stream(300, 1, 9, buf);
  mtal_push(SESS_C, MTAL_PUB_C, wired_span_of(buf, n), 0);
  CHECK(mtal_alias_to_b(5) == ag);
  CHECK(mtal_tail_kept(5, buf, n));
  n = mtal_stream(300, 0, 7, buf);
  mtal_push(SESS_C, MTAL_PUB_C, wired_span_of(buf, n), 0);
  wired_moqt_tick(&mtst_hub, 0);
  const moqtrun_test_call* c = mtal_to_b(3);
  CHECK(c && c->payload_len == n && !ct_diffn(c->payload, buf, n));
}

static void test_mtal_keepopen_lossy(void) { mtal_keepopen(0); }

static void test_mtal_keepopen_reliable(void) { mtal_keepopen(1000); }

/* B subscribes carol AFTER her stream opened: the late open replays the
 * saved header under B's alias (lossy and ring-backed alike). */
static void mtal_late(u64 limit) {
  u8  buf[MOQTRUN_TEST_MAX_PAYLOAD];
  u64 cb                        = mtal_two_pubs(1);
  mtst_hub.reliable_alias_limit = limit;
  mtal_sub(cb, mtal_f());
  usz n = mtal_stream(1, 1, 9, buf);
  mtal_push(SESS_C, MTAL_PUB_C, wired_span_of(buf, n), 0);
  u64 ag = mtal_sub(cb, mtal_g());
  n      = mtal_stream(1, 0, 7, buf);
  mtal_push(SESS_C, MTAL_PUB_C, wired_span_of(buf, n), 0);
  wired_moqt_tick(&mtst_hub, 0);
  CHECK(mtal_alias_to_b(5) == ag);
}

static void test_mtal_late_lossy(void) { mtal_late(0); }

static void test_mtal_late_reliable(void) { mtal_late(1000); }

/* A re-PUBLISH under a new alias (7) silently re-attaches B (no new
 * SUBSCRIBE_OK): B keeps receiving under the alias it was told. */
static void test_mtal_reattach_keeps_told_alias(void) {
  u8         buf[MOQTRUN_TEST_MAX_PAYLOAD];
  moqctl_ftn f = mtal_f();
  mtst_init();
  u64 ca = mtst_join(SESS_A);
  u64 cb = mtst_join(SESS_B);
  mtst_publish(SESS_A, ca, &f, 1);
  u64 a = mtal_sub(cb, f);
  wired_moqt_on_session_close(&mtst_hub, SESS_A);
  ca = mtst_join(SESS_A);
  mtst_publish(SESS_A, ca, &f, 7);
  usz n = mtal_stream(7, 1, 9, buf);
  mtal_push(SESS_A, MTAL_PUB_A, wired_span_of(buf, n), 1);
  CHECK(mtal_alias_to_b(4) == a);
}

/* SUBSCRIBE_TRACKS (10.19): the hub's PUBLISHes to B for two tracks whose
 * publishers both chose alias 1 name distinct aliases (DUPLICATE_TRACK_
 * ALIAS otherwise, 3.1.3). */
static void test_mtal_hub_publish_distinct(void) {
  moqctl_publish got[4];
  mtal_two_pubs(1);
  mtst_subtracks(SESS_B, MTRQ_S1, "chat");
  wired_moqt_tick(&mtst_hub, 0);
  CHECK(mtst_pub_opens(SESS_B, got, 4) == 2);
  CHECK(got[0].track_alias != got[1].track_alias);
}

void test_moqtrun_alias(void) {
  test_mtal_subgroup_matches_subscribe_ok();
  test_mtal_two_tracks_distinct();
  test_mtal_datagram_distinct();
  test_mtal_keepopen_lossy();
  test_mtal_keepopen_reliable();
  test_mtal_late_lossy();
  test_mtal_late_reliable();
  test_mtal_reattach_keeps_told_alias();
  test_mtal_hub_publish_distinct();
}
