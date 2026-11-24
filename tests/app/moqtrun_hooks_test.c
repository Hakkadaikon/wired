/* The hub's app hooks (moqtrun_hooks.c): SETUP admission, closing any
 * session with a reason, and the read-only Object tap. Shares the
 * recording io stubs and fixtures of moqtrun_test.c, moqtrun_sub_test.c,
 * moqtrun_ctlfix_test.c and moqtrun_sess_test.c (same unity TU). */

/* ===================== SETUP token (moqctl_setup) ===================== */

/* draft-22 9.1.4: the first AUTHORIZATION TOKEN option carrying a value
 * is kept as a view (a later one is not); none leaves has_auth_token 0. */
static void test_mthk_setup_keeps_first_token(void) {
  static const u8 two[] = {
      0x03, 0x03, 0x03, 0x00, 'a', /* USE_VALUE, Token Type 0, "a" */
      0x00, 0x03, 0x03, 0x01, 'b'};
  static const u8 none[] = {0x05, 0x00}; /* an unknown, empty option */
  moqctl_setup    m;
  usz             off = 0;
  CHECK(
      moqctl_setup_take(wired_span_of(two, sizeof two), &off, &m) == MOQCTL_OK);
  CHECK(m.has_auth_token == 1);
  CHECK(m.auth_token.alias_type == MOQCTL_TOKEN_USE_VALUE);
  CHECK(m.auth_token.token_type == 0);
  CHECK(wired_span_eq_cstr(m.auth_token.value, "a"));
  CHECK(m.auth_token.value.p == two + 4); /* a view, not a copy */
  off = 0;
  CHECK(
      moqctl_setup_take(wired_span_of(none, sizeof none), &off, &m) ==
      MOQCTL_OK);
  CHECK(m.has_auth_token == 0);
}

/* An Alias-only token (USE_ALIAS) carries no value: none is kept; a
 * REGISTER is used as USE_VALUE, so its value is kept. */
static void test_mthk_setup_token_alias_types(void) {
  static const u8 alias[] = {0x03, 0x02, 0x02, 0x07};
  static const u8 reg[]   = {0x03, 0x04, 0x01, 0x07, 0x01, 'x'};
  moqctl_setup    m;
  usz             off = 0;
  CHECK(
      moqctl_setup_take(wired_span_of(alias, sizeof alias), &off, &m) ==
      MOQCTL_OK);
  CHECK(m.has_auth_token == 0 && m.token_alias_ref == 1);
  off = 0;
  CHECK(
      moqctl_setup_take(wired_span_of(reg, sizeof reg), &off, &m) == MOQCTL_OK);
  CHECK(m.has_auth_token == 1);
  CHECK(m.auth_token.alias_type == MOQCTL_TOKEN_REGISTER);
  CHECK(m.auth_token.token_type == 1);
  CHECK(wired_span_eq_cstr(m.auth_token.value, "x"));
}

/* ===================== admission ===================== */

static u32               mthk_admit_code;
static int               mthk_admit_calls;
static wired_wt_session* mthk_admit_sess;
static u64               mthk_admit_type;
static usz               mthk_admit_len;

/* Recording admission hook: answers mthk_admit_code, reason "room-full".
 * token==0 is remembered as type (u64)-1. */
static u32 mthk_admit(
    void*               ctx,
    wired_wt_session*   s,
    const moqctl_token* token,
    wired_span*         reason) {
  (void)ctx;
  mthk_admit_calls++;
  mthk_admit_sess = s;
  mthk_admit_type = token ? token->token_type : (u64)-1;
  mthk_admit_len  = token ? token->value.n : 0;
  *reason         = wired_span_cstr("room-full");
  return mthk_admit_code;
}

/* SESS_A's client SETUP carrying opt, judged by mthk_admit answering
 * code; returns the close code, ~0 for none. */
static u64 mthk_setup(u32 code, const u8* opt, usz n) {
  wired_moqt_hub* hub = &mt_hub_shared;
  u8              msg[32];
  usz             len = mtctl_uni_ctl(msg, opt, n);
  mtcf_token_session(hub);
  hub->admit       = mthk_admit;
  mthk_admit_code  = code;
  mthk_admit_calls = 0;
  mtcf_part(hub, 2, msg, 0, len);
  return moqtrun_test_close_code();
}

/* A refusal closes the session with the app's code and reason; the
 * session is not established. */
static void test_mthk_admit_refuses_with_reason(void) {
  static const u8          tok[] = {0x03, 0x04, 0x03, 0x00, 'e', 'v'};
  const moqtrun_test_call* c;
  CHECK(mthk_setup(0x16, tok, sizeof tok) == 0x16);
  c = moqtrun_test_last_kind(11);
  CHECK(c && c->s == SESS_A);
  CHECK(
      c && wired_span_eq_cstr(
               wired_span_of(c->payload, c->payload_len), "room-full"));
  CHECK(mthk_admit_calls == 1 && mthk_admit_sess == SESS_A);
  CHECK(mthk_admit_type == 0 && mthk_admit_len == 2);
  CHECK(moqtrun_find_by_wt(&mt_hub_shared, SESS_A)->setup_recv == 0);
}

/* 0 admits: no close, the session establishes; a SETUP with no token
 * shows the hook 0. */
static void test_mthk_admit_accepts(void) {
  CHECK(mthk_setup(0, 0, 0) == ~(u64)0);
  CHECK(mthk_admit_calls == 1 && mthk_admit_type == (u64)-1);
  CHECK(moqtrun_find_by_wt(&mt_hub_shared, SESS_A)->setup_recv == 1);
}

/* ===================== Object tap ===================== */

static int               mthk_tap_calls;
static wired_wt_session* mthk_tap_sess;
static usz               mthk_tap_fields;
static usz               mthk_tap_name_len;
static u8                mthk_tap_last;

static void mthk_tap(
    void*             ctx,
    wired_wt_session* s,
    wired_span        ns,
    wired_span        name,
    wired_span        payload) {
  moqctl_ns d;
  usz       off = 0;
  (void)ctx;
  mthk_tap_calls++;
  mthk_tap_sess     = s;
  mthk_tap_fields   = moqctl_ns_take(ns, &off, &d) == MOQCTL_OK ? d.n : 0;
  mthk_tap_name_len = name.n;
  mthk_tap_last     = payload.n ? payload.p[payload.n - 1] : 0xFF;
}

/* alice (chat/room1) publishes two 1-byte Objects with the tap on prefix
 * fields f0[/f1] and size cap max; returns the tap's call count. */
static int mthk_tap_run(const char* f0, const char* f1, usz max) {
  static u8  pre[64];
  u8         buf[MOQTRUN_TEST_MAX_PAYLOAD];
  moqctl_ns  ns  = {0};
  usz        off = 0;
  moqctl_ftn f   = mtst_ftn("chat", "room1", "alice");
  ns.fields[0]   = wired_span_cstr(f0);
  ns.fields[1]   = f1 ? wired_span_cstr(f1) : wired_span_of(0, 0);
  ns.n           = f1 ? 2 : 1;
  moqctl_ns_put(wired_mspan_of(pre, sizeof pre), &off, &ns);
  mtst_init();
  mtst_hub.tap        = mthk_tap;
  mtst_hub.tap_prefix = wired_span_of(pre, off);
  mtst_hub.tap_max    = max;
  mthk_tap_calls      = 0;
  u64 ca              = mtst_join(SESS_A);
  mtst_publish(SESS_A, ca, &f, 1);
  usz n = mtst_stream(4, 2, 1, buf);
  mt_feed(&mtst_hub, SESS_A, 1001, wired_span_of(buf, n), 0);
  return mthk_tap_calls;
}

/* Every whole Object under the prefix (field-wise) within the cap reaches
 * the tap with its publisher, namespace and name; others never do. */
static void test_mthk_tap_prefix_and_cap(void) {
  CHECK(mthk_tap_run("chat", 0, 1) == 2);
  CHECK(mthk_tap_sess == SESS_A && mthk_tap_fields == 2);
  CHECK(mthk_tap_name_len == 5 && mthk_tap_last == 1);
  CHECK(mthk_tap_run("chat", "room1", 1) == 2);
  CHECK(mthk_tap_run("chat", "room", 1) == 0); /* not a field prefix */
  CHECK(mthk_tap_run("other", 0, 1) == 0);
  CHECK(mthk_tap_run("chat", 0, 0) == 0); /* over the size cap */
}

/* A client uni stream id (2 mod 4, RFC 9000 2.1) for Object data. */
#define MTHK_UNI 1002

/* ===================== requests after a close ===================== */

/* Authorizer counting its calls; closes the session first when
 * mthk_auth_closes (an app ending a room from inside the hook). */
static int mthk_auth_calls;
static int mthk_auth_closes;
static int mthk_authorize(
    void*               ctx,
    wired_wt_session*   s,
    const moqctl_ftn*   name,
    const moqctl_token* token) {
  (void)name;
  (void)token;
  mthk_auth_calls++;
  if (mthk_auth_closes) {
    wired_moqt_close(ctx, s, 0, wired_span_cstr("room-ended"));
    return mthk_auth_closes == 2; /* 2: closes, yet grants */
  }
  return 1;
}

/* A fresh mtst_hub with mthk_authorize on SUBSCRIBE and PUBLISH. */
static void mthk_init(void) {
  mtst_init();
  mtst_hub.authorize_subscribe = mthk_authorize;
  mtst_hub.authorize_ctx       = &mtst_hub;
  mtst_hub.authorize_publish   = mthk_authorize;
  mtst_hub.authorize_pub_ctx   = &mtst_hub;
  mthk_auth_calls              = 0;
  mthk_auth_closes             = 0;
}

/* s joins with a moqt-NN subprotocol (a token session, requests on their
 * own streams) and sends its client SETUP on uni stream 2. */
static void mthk_join_tok(wired_wt_session* s) {
  u8  msg[8];
  usz n = mtctl_uni_ctl(msg, 0, 0);
  wired_moqt_on_session(
      &mtst_hub, s, wired_span_of(0, 0),
      moqtrun_test_proto(moqtrun_test_ver_tok()));
  mt_feed(&mtst_hub, s, 2, wired_span_of(msg, n), 0);
}

/* Replies (stream_send / reply_open) sent to s since the last reset. */
static usz mthk_sent_to(wired_wt_session* s) {
  usz n = 0;
  for (usz i = 0; i < g_n_calls; i++) {
    n += g_calls[i].s == s && (g_calls[i].kind == 3 || g_calls[i].kind == 12);
  }
  return n;
}

/* Calls toward s since the last reset (any kind but a close). */
static usz mthk_calls_to(wired_wt_session* s) {
  usz n = 0;
  for (usz i = 0; i < g_n_calls; i++) {
    n += g_calls[i].s == s && g_calls[i].kind != 11;
  }
  return n;
}

/* The app closes any session with code + reason, once; an unknown session
 * is refused; the transport's close after it, and a repeat, are no-ops. */
static void test_mthk_close_any_session(void) {
  const moqtrun_test_call* c;
  mthk_init();
  mthk_join_tok(SESS_A);
  mthk_join_tok(SESS_B);
  CHECK(wired_moqt_close(&mtst_hub, SESS_B, 0, wired_span_cstr("room-ended")));
  c = moqtrun_test_last_kind(11);
  CHECK(c && c->s == SESS_B && c->stream_id == 0);
  CHECK(
      c && wired_span_eq_cstr(
               wired_span_of(c->payload, c->payload_len), "room-ended"));
  CHECK(!wired_moqt_close(&mtst_hub, SESS_B, 0, wired_span_of(0, 0)));
  CHECK(!wired_moqt_close(&mtst_hub, SESS_D, 0, wired_span_of(0, 0)));
  CHECK(moqtrun_test_count_kind(11) == 1);
  wired_moqt_on_session_close(&mtst_hub, SESS_B);
  wired_moqt_on_session_close(&mtst_hub, SESS_B);
  CHECK(moqtrun_find_by_wt(&mtst_hub, SESS_B) == 0);
  CHECK(moqtrun_find_by_wt(&mtst_hub, SESS_A) != 0);
}

/* After the close a SUBSCRIBE on a NEW request stream is not read: no
 * authorizer call, no subscription, nothing sent back. */
static void test_mthk_close_drops_new_requests(void) {
  moqctl_ftn f = mtst_ftn("chat", "room1", "alice");
  mthk_init();
  mthk_join_tok(SESS_A);
  mthk_join_tok(SESS_B);
  mtst_publish(SESS_A, MTRQ_ID(1), &f, 1);
  CHECK(mthk_auth_calls == 1);
  wired_moqt_close(&mtst_hub, SESS_B, 0, wired_span_cstr("room-ended"));
  moqtrun_test_reset();
  mtst_subscribe_p(SESS_B, MTRQ_S1, &f, mtst_rid += 4, 0);
  CHECK(mthk_auth_calls == 1);
  CHECK(mtst_sub(SESS_A, SESS_B) == 0);
  CHECK(mthk_calls_to(SESS_B) == 0);
}

/* After the publisher's close its Objects are neither relayed to a live
 * subscriber nor tapped. */
static void test_mthk_close_drops_objects(void) {
  u8         buf[MOQTRUN_TEST_MAX_PAYLOAD];
  moqctl_ftn f = mtst_ftn("chat", "room1", "alice");
  mthk_init();
  mthk_join_tok(SESS_A);
  mthk_join_tok(SESS_B);
  mtst_hub.tap     = mthk_tap;
  mtst_hub.tap_max = 16;
  mthk_tap_calls   = 0;
  mtst_publish(SESS_A, MTRQ_ID(1), &f, 1);
  mtst_subscribe_p(SESS_B, MTRQ_S1, &f, mtst_rid += 4, 0);
  CHECK(mtst_sub(SESS_A, SESS_B) != 0);
  wired_moqt_close(&mtst_hub, SESS_A, 0, wired_span_cstr("room-ended"));
  moqtrun_test_reset();
  usz n = mtst_stream(4, 2, 1, buf);
  mt_feed(&mtst_hub, SESS_A, MTHK_UNI, wired_span_of(buf, n), 0);
  CHECK(mthk_calls_to(SESS_B) == 0);
  CHECK(mthk_tap_calls == 0);
}

/* A refused SETUP: neither the request held before it nor a later one is
 * read. */
static void test_mthk_admit_refusal_drops_requests(void) {
  moqctl_ftn f = mtst_ftn("chat", "room1", "alice");
  u8         msg[8];
  usz        n = mtctl_uni_ctl(msg, 0, 0);
  mthk_init();
  mtst_hub.admit  = mthk_admit;
  mthk_admit_code = 0x2;
  wired_moqt_on_session(
      &mtst_hub, SESS_A, wired_span_of(0, 0),
      moqtrun_test_proto(moqtrun_test_ver_tok()));
  mtst_subscribe_p(SESS_A, MTRQ_S1, &f, mtst_rid += 4, 0); /* held */
  mt_feed(&mtst_hub, SESS_A, 2, wired_span_of(msg, n), 0);
  CHECK(moqtrun_test_close_code() == 0x2);
  mtst_subscribe_p(SESS_A, MTRQ_S2, &f, mtst_rid += 4, 0);
  CHECK(mthk_auth_calls == 0);
  CHECK(mthk_sent_to(SESS_A) == 0);
}

/* ===================== closing from inside a hook ===================== */

/* An authorizer that closes the requesting session: one close with its
 * reason, no REQUEST_ERROR after it, and the next request is not read. */
static void test_mthk_close_inside_authorize(void) {
  moqctl_ftn f = mtst_ftn("chat", "room1", "alice");
  mthk_init();
  mthk_join_tok(SESS_B);
  mthk_auth_closes = 1;
  moqtrun_test_reset();
  mtst_subscribe_p(SESS_B, MTRQ_S1, &f, mtst_rid += 4, 0);
  CHECK(mthk_auth_calls == 1);
  CHECK(moqtrun_test_count_kind(11) == 1 && moqtrun_test_close_code() == 0);
  CHECK(mthk_sent_to(SESS_B) == 0);
  mtst_subscribe_p(SESS_B, MTRQ_S2, &f, mtst_rid += 4, 0);
  CHECK(mthk_auth_calls == 1);
}

/* Admission hook closing the session itself and returning 0. */
static u32 mthk_admit_closing(
    void*               ctx,
    wired_wt_session*   s,
    const moqctl_token* token,
    wired_span*         reason) {
  (void)token;
  (void)reason;
  mthk_admit_calls++;
  wired_moqt_close(ctx, s, 0x10, wired_span_cstr("server-busy"));
  return 0;
}

/* admit closing the session itself refuses it: exactly that close, the
 * session never established, its next request not read. */
static void test_mthk_close_inside_admit(void) {
  moqctl_ftn f = mtst_ftn("chat", "room1", "alice");
  mthk_init();
  mtst_hub.admit     = mthk_admit_closing;
  mtst_hub.admit_ctx = &mtst_hub;
  mthk_admit_calls   = 0;
  mthk_join_tok(SESS_A);
  CHECK(mthk_admit_calls == 1);
  CHECK(moqtrun_test_count_kind(11) == 1 && moqtrun_test_close_code() == 0x10);
  CHECK(moqtrun_find_by_wt(&mtst_hub, SESS_A)->setup_recv == 0);
  mtst_subscribe_p(SESS_A, MTRQ_S1, &f, mtst_rid += 4, 0);
  CHECK(mthk_auth_calls == 0);
}

/* Tap closing the publisher on its mthk_tap_close_at-th call. */
static int  mthk_tap_close_at;
static void mthk_tap_closing(
    void*             ctx,
    wired_wt_session* s,
    wired_span        ns,
    wired_span        name,
    wired_span        payload) {
  (void)ns;
  (void)name;
  (void)payload;
  if (++mthk_tap_calls == mthk_tap_close_at) {
    wired_moqt_close(ctx, s, 0, wired_span_cstr("room-ended"));
  }
}

/* Objects or datagrams the hub sent s since the last reset. */
static usz mthk_objs_to(wired_wt_session* s) {
  usz n = 0;
  for (usz i = 0; i < g_n_calls; i++) {
    int k = g_calls[i].kind;
    n += g_calls[i].s == s && (k == 4 || k == 5 || k == 8 || k == 9);
  }
  return n;
}

/* Tap closing the publisher on the first of two Objects in one delivery:
 * the second is not tapped, neither is cached, and subscriber B is sent
 * nothing. */
/* A (alice, alias 1) and subscriber B on token sessions, a cache, and
 * mthk_tap_closing closing A on its close_at-th call. */
static void mthk_tap_setup(int close_at) {
  static u8  arena[4096];
  moqctl_ftn f = mtst_ftn("chat", "room1", "alice");
  mthk_init();
  wired_moqt_cache_attach(&mtst_hub, arena, sizeof arena);
  mthk_join_tok(SESS_A);
  mthk_join_tok(SESS_B);
  mtst_hub.tap      = mthk_tap_closing;
  mtst_hub.tap_ctx  = &mtst_hub;
  mtst_hub.tap_max  = 16;
  mthk_tap_calls    = 0;
  mthk_tap_close_at = close_at;
  mtst_publish(SESS_A, MTRQ_ID(1), &f, 1);
  mtst_subscribe_p(SESS_B, MTRQ_S1, &f, mtst_rid += 4, 0);
  CHECK(mtst_sub(SESS_A, SESS_B) != 0);
  moqtrun_test_reset();
}

/* Group 4, n one-byte Objects (with the stream header when hdr) on A's
 * uni stream. */
static void mthk_feed_objs(usz n, int hdr) {
  u8  buf[MOQTRUN_TEST_MAX_PAYLOAD];
  usz len = mtst_stream(4, n, hdr, buf);
  mt_feed(&mtst_hub, SESS_A, MTHK_UNI, wired_span_of(buf, len), 0);
}

/* Closed on the first of two Objects in one delivery: neither is tapped
 * again, cached or sent to B. */
static void test_mthk_close_inside_tap(void) {
  mthk_tap_setup(1);
  mthk_feed_objs(2, 1);
  CHECK(mthk_tap_calls == 1);
  CHECK(moqtrun_test_count_kind(11) == 1);
  CHECK(mthk_objs_to(SESS_B) == 0);
  CHECK(mtst_hub.cache.used == 0);
}

/* Closed on the second Object of one delivery: the first stays cached
 * and counted, the second does not advance the Largest, and B is sent
 * neither live. */
static void test_mthk_close_inside_tap_second_obj(void) {
  const wired_moqtrun_track* t;
  mthk_tap_setup(2);
  mthk_feed_objs(2, 1);
  t = &moqtrun_find_by_wt(&mtst_hub, SESS_A)->tracks[0];
  CHECK(mthk_tap_calls == 2);
  CHECK(mtst_hub.cache.used != 0);
  CHECK(t->has_largest && t->largest.object == 0);
  CHECK(mthk_objs_to(SESS_B) == 0);
}

/* Closed inside the tap on a continuation delivery of a relayed stream:
 * that delivery and a third reach no subscriber. */
static void test_mthk_close_inside_tap_continuation(void) {
  mthk_tap_setup(2);
  mthk_feed_objs(1, 1);
  CHECK(mthk_calls_to(SESS_B) != 0); /* the first Object went out */
  moqtrun_test_reset();
  mthk_feed_objs(1, 0);
  CHECK(mthk_tap_calls == 2 && moqtrun_test_count_kind(11) == 1);
  CHECK(mthk_calls_to(SESS_B) == 0);
  mthk_feed_objs(1, 0);
  CHECK(mthk_tap_calls == 2);
  CHECK(mthk_calls_to(SESS_B) == 0);
}

/* The first close stands: a later one, the app's or the hub's own, sends
 * nothing and keeps the first code and reason. */
static void test_mthk_first_close_stands(void) {
  wired_moqtrun_peer* p;
  mthk_init();
  mthk_join_tok(SESS_A);
  p = moqtrun_find_by_wt(&mtst_hub, SESS_A);
  CHECK(wired_moqt_close(&mtst_hub, SESS_A, 0, wired_span_cstr("room-ended")));
  CHECK(!moqtrun_peer_close(
      &mtst_hub, p, WIRED_MOQTRUN_CLOSE_PROTOCOL_VIOLATION));
  CHECK(!moqtrun_peer_close_r(&mtst_hub, p, 0x2, wired_span_cstr("x")));
  CHECK(moqtrun_test_count_kind(11) == 1 && moqtrun_test_close_code() == 0);
}

/* An authorizer that closes the session yet grants is a refusal: no
 * subscription is made. */
static void test_mthk_close_then_grant_refuses(void) {
  moqctl_ftn f = mtst_ftn("chat", "room1", "alice");
  mthk_init();
  mthk_join_tok(SESS_A);
  mthk_join_tok(SESS_B);
  mtst_publish(SESS_A, MTRQ_ID(1), &f, 1);
  mthk_auth_closes = 2;
  mtst_subscribe_p(SESS_B, MTRQ_S1, &f, mtst_rid += 4, 0);
  CHECK(mthk_auth_calls == 2);
  CHECK(mtst_sub(SESS_A, SESS_B) == 0);
}

/* With every peer slot taken, a WT session is closed at once with
 * INTERNAL_ERROR (-22 6.6), like a raw one; no SETUP goes to it. */
static void test_mthk_full_hub_closes_wt(void) {
  mtst_init();
  for (usz i = 0; i < WIRED_MOQTRUN_MAX_SESSIONS; i++) {
    wired_moqt_on_session(
        &mtst_hub, (wired_wt_session*)(usz)(100 + i), wired_span_of(0, 0),
        moqtrun_test_proto("moqt-22"));
  }
  CHECK(moqtrun_test_count_kind(11) == 0);
  moqtrun_test_reset();
  wired_moqt_on_session(
      &mtst_hub, SESS_A, wired_span_of(0, 0), moqtrun_test_proto("moqt-22"));
  const moqtrun_test_call* c = moqtrun_test_last_kind(11);
  CHECK(c && c->s == SESS_A);
  CHECK(moqtrun_test_close_code() == WIRED_MOQTRUN_CLOSE_INTERNAL_ERROR);
  CHECK(moqtrun_find_by_wt(&mtst_hub, SESS_A) == 0);
  CHECK(moqtrun_test_count_kind(5) == 0 && moqtrun_test_count_kind(1) == 0);
}

/* ===================== legacy sessions under admit ===================== */

static int mthk_enc_fetch(wired_mspan buf, usz* off, const void* m) {
  return moqfetch_fetch_encode(buf, off, m);
}

/* With admit set, a legacy session (no subprotocol: it need never send a
 * SETUP) is closed UNAUTHORIZED at once and never registered, so its
 * SUBSCRIBE, PUBLISH and FETCH are not read. */
static void test_mthk_admit_closes_legacy(void) {
  static moqfetch_fetch fe;
  u8                    buf[MTST_MSG_MAX];
  usz                   n;
  mthk_init();
  mtst_hub.admit  = mthk_admit;
  mthk_admit_code = 0;
  wired_moqt_on_session(
      &mtst_hub, SESS_A, wired_span_of(0, 0), wired_span_of(0, 0));
  CHECK(moqtrun_test_close_code() == WIRED_MOQTRUN_CLOSE_UNAUTHORIZED);
  CHECK(moqtrun_find_by_wt(&mtst_hub, SESS_A) == 0);
  moqtrun_test_reset();
  mt_feed(
      &mtst_hub, SESS_A, MTRQ_S1,
      wired_span_of(g_moqt_ctl_subscribe_basic, G_MOQT_CTL_SUBSCRIBE_BASIC_LEN),
      0);
  mt_feed(
      &mtst_hub, SESS_A, MTRQ_S2,
      wired_span_of(g_moqt_ctl_publish_basic, G_MOQT_CTL_PUBLISH_BASIC_LEN), 0);
  fe.fetch_type = MOQFETCH_STANDALONE;
  fe.track      = mtst_ftn("chat", "room1", "alice");
  n             = moqtrun_envelope_put(
      MOQVER_D22, wired_mspan_of(buf, sizeof buf), MOQFETCH_T_FETCH,
      mthk_enc_fetch, &fe);
  CHECK(n != 0);
  mt_feed(&mtst_hub, SESS_A, MTRQ_ID(3), wired_span_of(buf, n), 0);
  CHECK(mthk_auth_calls == 0);
  CHECK(g_n_calls == 0);
}

static void test_moqtrun_hooks(void) {
  test_mthk_setup_keeps_first_token();
  test_mthk_admit_refuses_with_reason();
  test_mthk_setup_token_alias_types();
  test_mthk_admit_accepts();
  test_mthk_tap_prefix_and_cap();
  test_mthk_close_any_session();
  test_mthk_close_drops_new_requests();
  test_mthk_close_drops_objects();
  test_mthk_admit_refusal_drops_requests();
  test_mthk_close_inside_authorize();
  test_mthk_close_inside_admit();
  test_mthk_close_inside_tap();
  test_mthk_close_inside_tap_second_obj();
  test_mthk_close_inside_tap_continuation();
  test_mthk_first_close_stands();
  test_mthk_close_then_grant_refuses();
  test_mthk_full_hub_closes_wt();
  test_mthk_admit_closes_legacy();
}
