/* Hub namespace discovery (draft-ietf-moq-transport-19 6.1-6.2, 10.15-10.18):
 * PUBLISH_NAMESPACE and SUBSCRIBE_NAMESPACE on request streams, NAMESPACE /
 * NAMESPACE_DONE pushed on the SUBSCRIBE_NAMESPACE's stream. Shares the
 * recording io stubs (moqtrun_test.c) and the request-stream fixtures
 * (moqtrun_sub_test.c) of the same unity TU. */

/* Track Namespace from "a/b/c" ("" = zero fields); views into z. */
static moqctl_ns mtns_ns(const char* z) {
  moqctl_ns ns = {0};
  usz       at = 0;
  while (z[at]) {
    usz from = at;
    while (z[at] && z[at] != '/') at++;
    ns.fields[ns.n++] = wired_span_of((const u8*)z + from, at - from);
    at += z[at] == '/';
  }
  return ns;
}

static int mtns_enc(wired_mspan buf, usz* off, const void* m) {
  return moqns_req_encode(buf, off, m);
}

static void mtns_req(wired_wt_session* s, u64 sid, u64 type, const char* z) {
  static moqns_req m;
  m.request_id = mtst_rid += 2;
  m.ns         = mtns_ns(z);
  m.params.n   = 0;
  mtst_send(s, sid, type, mtns_enc, &m);
}

static void mtns_pub(wired_wt_session* s, u64 sid, const char* z) {
  mtns_req(s, sid, MOQNS_T_PUBLISH_NAMESPACE, z);
}

static void mtns_sub(wired_wt_session* s, u64 sid, const char* z) {
  mtns_req(s, sid, MOQNS_T_SUBSCRIBE_NAMESPACE, z);
}

static char mtns_text[1024];
static usz  mtns_at;

static void mtns_put(const char* z) {
  while (*z) mtns_text[mtns_at++] = *z++;
}

static void mtns_put_ns(wired_span body) {
  moqctl_ns ns;
  CHECK(moqns_suffix_take(body, &ns) == MOQCTL_OK);
  for (usz i = 0; i < ns.n; i++) {
    usz n = ns.fields[i].n < 8 ? ns.fields[i].n : 8; /* long fields: 8 */
    if (i) mtns_put("/");
    for (usz k = 0; k < n; k++) mtns_text[mtns_at++] = (char)ns.fields[i].p[k];
  }
}

static void mtns_put_err(wired_span body) {
  static const char    hex[] = "0123456789abcdef";
  moqctl_request_error e;
  usz                  off = 0;
  CHECK(moqctl_request_error_take(body, &off, &e) == MOQCTL_OK);
  mtns_put("ERR:");
  mtns_text[mtns_at++] = hex[(e.error_code >> 4) & 0xF];
  mtns_text[mtns_at++] = hex[e.error_code & 0xF];
}

static void mtns_put_msg(u64 type, wired_span body) {
  if (type == MOQCTL_T_REQUEST_OK) mtns_put("OK");
  if (type == MOQCTL_T_REQUEST_ERROR) mtns_put_err(body);
  if (type == MOQNS_T_NAMESPACE) mtns_put("NS:");
  if (type == MOQNS_T_NAMESPACE_DONE) mtns_put("DONE:");
  if (type == MOQNS_T_NAMESPACE || type == MOQNS_T_NAMESPACE_DONE)
    mtns_put_ns(body);
  mtns_put("|");
}

static void mtns_put_call(const moqtrun_test_call* c) {
  wired_span all = wired_span_of(c->payload, c->payload_len);
  usz        off = 0;
  u64        type;
  wired_span body;
  while (off < all.n) {
    CHECK(moqctl_peek_type(all, &off, &type, &body) != MOQCTL_INSUFFICIENT);
    mtns_put_msg(type, body);
  }
}

/* Every message the hub delivered on s's stream sid, rendered "OK|NS:a/b|"
 * (refused sends were not delivered and are skipped). */
static const char* mtns_log(wired_wt_session* s, u64 sid) {
  mtns_at = 0;
  for (usz i = 0; i < g_n_calls; i++) {
    const moqtrun_test_call* c  = &g_calls[i];
    int                      on = (c->kind == 12 || c->kind == 3) && c->s == s;
    if (on && c->stream_id == sid && !c->refused) mtns_put_call(c);
  }
  mtns_text[mtns_at] = 0;
  return mtns_text;
}

static int mtns_is(wired_wt_session* s, u64 sid, const char* want) {
  const char* got = mtns_log(s, sid);
  usz         i   = 0;
  while (got[i] && got[i] == want[i]) i++;
  if (got[i] != want[i]) printf("  got \"%s\" want \"%s\"\n", got, want);
  return got[i] == want[i];
}

static void mtns_init(void) {
  mtst_init();
  mtst_join(SESS_A);
  mtst_join(SESS_B);
}

/* 10.15 / 6.2: a PUBLISH_NAMESPACE on its request stream is accepted with
 * REQUEST_OK and stays open (withdrawn only by cancelling it); on the
 * control stream there is no stream to hold it, so NOT_SUPPORTED. */
static void test_moqtrun_ns_publish_accepted(void) {
  mtns_init();
  mtns_pub(SESS_A, MTRQ_S1, "chat/room1");
  CHECK(mtns_is(SESS_A, MTRQ_S1, "OK|"));
  CHECK(mtrq_fin_on(MTRQ_S1) == 0);
  CHECK(mtrq_used() == 1);
  u64 cb = moqtrun_find_by_wt(&mtst_hub, SESS_B)->control_stream_id;
  mtns_pub(SESS_B, cb, "chat/room2");
  CHECK(mtns_is(SESS_B, cb, "ERR:03|"));
}

/* 10.18: REQUEST_OK, then one NAMESPACE per published namespace under the
 * prefix, carrying only the fields after it; others are filtered out. */
static void test_moqtrun_ns_initial_set(void) {
  mtns_init();
  mtns_pub(SESS_A, MTRQ_S1, "chat/room1");
  mtns_pub(SESS_A, MTRQ_S2, "chat/room2");
  mtns_pub(SESS_A, MTRQ_ID(5), "video/x");
  mtns_pub(SESS_A, MTRQ_ID(6), "chatroom");
  mtns_sub(SESS_B, MTRQ_S1, "chat");
  CHECK(mtns_is(SESS_B, MTRQ_S1, "OK|NS:room1|NS:room2|"));
  CHECK(mtrq_fin_on(MTRQ_S1) == 0);
}

/* 6.1: a zero-field prefix matches every namespace, so the suffix is the
 * whole namespace; an exact-match prefix yields an empty suffix. */
static void test_moqtrun_ns_empty_prefix(void) {
  mtns_init();
  mtns_pub(SESS_A, MTRQ_S1, "chat/room1");
  mtns_pub(SESS_A, MTRQ_S2, "video/x");
  mtns_sub(SESS_B, MTRQ_S1, "");
  CHECK(mtns_is(SESS_B, MTRQ_S1, "OK|NS:chat/room1|NS:video/x|"));
  mtns_sub(SESS_B, MTRQ_S2, "video/x");
  CHECK(mtns_is(SESS_B, MTRQ_S2, "ERR:30|"));
  mtst_join(SESS_C);
  mtns_sub(SESS_C, MTRQ_S1, "video/x");
  CHECK(mtns_is(SESS_C, MTRQ_S1, "OK|NS:|"));
}

/* 10.18: later matching publications are pushed as NAMESPACE, a
 * withdrawal (request cancelled, 6.2) as NAMESPACE_DONE. */
static void test_moqtrun_ns_live_join_and_cancel(void) {
  mtns_init();
  mtns_sub(SESS_B, MTRQ_S1, "chat");
  mtns_pub(SESS_A, MTRQ_S1, "chat/room1");
  mtns_pub(SESS_A, MTRQ_S2, "video/x");
  CHECK(mtns_is(SESS_B, MTRQ_S1, "OK|NS:room1|"));
  wired_moqt_on_stream_reset(&mtst_hub, SESS_A, MTRQ_S1, 0, 0);
  CHECK(mtns_is(SESS_B, MTRQ_S1, "OK|NS:room1|DONE:room1|"));
  wired_moqt_on_stream_reset(&mtst_hub, SESS_A, MTRQ_S2, 0, 0);
  CHECK(mtns_is(SESS_B, MTRQ_S1, "OK|NS:room1|DONE:room1|"));
}

/* A publisher's session ending withdraws all its namespaces; a subscriber's
 * session ending holds nothing back. */
static void test_moqtrun_ns_publisher_leaves(void) {
  mtns_init();
  mtns_pub(SESS_A, MTRQ_S1, "chat/room1");
  mtns_pub(SESS_A, MTRQ_S2, "chat/room2");
  mtns_sub(SESS_B, MTRQ_S1, "chat");
  wired_moqt_on_session_close(&mtst_hub, SESS_A);
  CHECK(
      mtns_is(SESS_B, MTRQ_S1, "OK|NS:room1|NS:room2|DONE:room1|DONE:room2|"));
  mtns_init();
  mtns_pub(SESS_A, MTRQ_S1, "chat/room1");
  mtns_sub(SESS_B, MTRQ_S1, "chat");
  wired_moqt_on_session_close(&mtst_hub, SESS_B);
  wired_moqt_on_stream_reset(&mtst_hub, SESS_A, MTRQ_S1, 0, 0);
  CHECK(mtrq_used() == 0);
}

/* Cancelling a SUBSCRIBE_NAMESPACE stops its pushes. */
static void test_moqtrun_ns_subscriber_cancels(void) {
  mtns_init();
  mtns_sub(SESS_B, MTRQ_S1, "chat");
  wired_moqt_on_stream_reset(&mtst_hub, SESS_B, MTRQ_S1, 0, 0);
  mtns_pub(SESS_A, MTRQ_S1, "chat/room1");
  CHECK(mtns_is(SESS_B, MTRQ_S1, "OK|"));
  CHECK(mtrq_used() == 1);
}

/* 6.1: namespaces the subscriber itself published are echoed back. */
static void test_moqtrun_ns_own_echoed(void) {
  mtns_init();
  mtns_pub(SESS_A, MTRQ_S1, "chat/room1");
  mtns_sub(SESS_A, MTRQ_S2, "chat");
  CHECK(mtns_is(SESS_A, MTRQ_S2, "OK|NS:room1|"));
}

/* 10.18 PREFIX_OVERLAP, read strictly: within a session two prefixes
 * overlap when either is empty or their first fields are equal. The
 * refusal FINs the stream; other sessions are independent. */
static void test_moqtrun_ns_prefix_overlap(void) {
  mtns_init();
  mtns_sub(SESS_B, MTRQ_S1, "chat/room1");
  mtns_sub(SESS_B, MTRQ_S2, "chat/room2");
  CHECK(mtns_is(SESS_B, MTRQ_S2, "ERR:30|"));
  CHECK(mtrq_fin_on(MTRQ_S2) == 1);
  mtns_sub(SESS_B, MTRQ_ID(5), "video");
  CHECK(mtns_is(SESS_B, MTRQ_ID(5), "OK|"));
  mtns_sub(SESS_B, MTRQ_ID(6), "");
  CHECK(mtns_is(SESS_B, MTRQ_ID(6), "ERR:30|"));
  mtns_sub(SESS_A, MTRQ_S1, "chat");
  CHECK(mtns_is(SESS_A, MTRQ_S1, "OK|"));
}

/* A namespace already published (by any session) is refused UNINTERESTED
 * until its holder withdraws it. */
static void test_moqtrun_ns_duplicate_refused(void) {
  mtns_init();
  mtns_pub(SESS_A, MTRQ_S1, "chat/room1");
  mtns_pub(SESS_B, MTRQ_S1, "chat/room1");
  CHECK(mtns_is(SESS_B, MTRQ_S1, "ERR:20|"));
  CHECK(mtrq_fin_on(MTRQ_S1) == 1);
  wired_moqt_on_stream_reset(&mtst_hub, SESS_A, MTRQ_S1, 0, 0);
  mtns_pub(SESS_B, MTRQ_S2, "chat/room1");
  CHECK(mtns_is(SESS_B, MTRQ_S2, "OK|"));
}

/* A namespace past WIRED_MOQTRUN_MAX_NS encoded bytes is refused, never
 * truncated. */
static void test_moqtrun_ns_oversized_refused(void) {
  static char big[201];
  for (usz i = 0; i < 200; i++) big[i] = 'a';
  mtns_init();
  mtns_pub(SESS_A, MTRQ_S1, big);
  CHECK(mtns_is(SESS_A, MTRQ_S1, "ERR:00|"));
}

/* Each namespace holds a request stream: one session publishes at most
 * WIRED_MOQTRUN_MAX_REQS_PER_SESSION, the next stream is reset with
 * EXCESSIVE_LOAD (draft 3.3.4). */
static void test_moqtrun_ns_per_session_cap(void) {
  static char names[WIRED_MOQTRUN_MAX_REQS_PER_SESSION + 1][4];
  mtns_init();
  for (usz i = 0; i <= WIRED_MOQTRUN_MAX_REQS_PER_SESSION; i++) {
    names[i][0] = 'n';
    names[i][1] = (char)('a' + i);
    mtns_pub(SESS_A, MTRQ_ID(i), names[i]);
  }
  CHECK(mtrq_used() == WIRED_MOQTRUN_MAX_REQS_PER_SESSION);
  CHECK(mtrq_reset_code(MTRQ_ID(WIRED_MOQTRUN_MAX_REQS_PER_SESSION)) == 0x9);
  mtns_sub(SESS_B, MTRQ_S1, "");
  CHECK(mtns_is(
      SESS_B, MTRQ_S1,
      "OK|NS:na|NS:nb|NS:nc|NS:nd|NS:ne|NS:nf|NS:ng|NS:nh|NS:ni|NS:nj|NS:nk|"
      "NS:nl|NS:nm|NS:nn|NS:no|NS:np|"));
}

/* A push that does not fit the subscriber's queue waits for a later round
 * (wired_moqt_tick), in order, never dropped; a withdrawn namespace whose
 * NAMESPACE_DONE is still owed keeps its slot, so a new publication cannot
 * take it over and swallow both messages. */
static void test_moqtrun_ns_backpressure(void) {
  static char x[4][101];
  for (usz i = 0; i < 4; i++) {
    for (usz k = 0; k < 100; k++) x[i][k] = 'a';
    x[i][0] = 'x';
    x[i][1] = (char)('1' + i);
  }
  mtns_init();
  mtns_sub(SESS_B, MTRQ_S1, "");
  g_stream_send_reject_n = 1000;
  for (usz i = 0; i < 3; i++) mtns_pub(SESS_A, MTRQ_ID(i), x[i]);
  wired_moqt_on_stream_reset(&mtst_hub, SESS_A, MTRQ_ID(0), 0, 0);
  mtns_pub(SESS_A, MTRQ_ID(3), x[3]);
  g_stream_send_reject_n = 0;
  for (usz i = 0; i < 4; i++) wired_moqt_tick(&mtst_hub, 0);
  CHECK(mtns_is(
      SESS_B, MTRQ_S1,
      "OK|NS:x1aaaaaa|NS:x2aaaaaa|DONE:x1aaaaaa|NS:x3aaaaaa|NS:x4aaaaaa|"));
}

void test_moqtrun_ns(void) {
  test_moqtrun_ns_publish_accepted();
  test_moqtrun_ns_initial_set();
  test_moqtrun_ns_empty_prefix();
  test_moqtrun_ns_live_join_and_cancel();
  test_moqtrun_ns_publisher_leaves();
  test_moqtrun_ns_subscriber_cancels();
  test_moqtrun_ns_own_echoed();
  test_moqtrun_ns_prefix_overlap();
  test_moqtrun_ns_duplicate_refused();
  test_moqtrun_ns_oversized_refused();
  test_moqtrun_ns_per_session_cap();
  test_moqtrun_ns_backpressure();
}
