/* Hub subscription state and Full Track Name matching
 * (draft-ietf-moq-transport-19 1.5, 9.3.1, 10.2.7-10.2.17). Shares the
 * recording io stubs and fixtures of moqtrun_test.c (same unity TU). */

static wired_moqt_hub mtst_hub;
static u64            mtst_rid;

#define MTST_MSG_MAX (WIRED_MOQTRUN_CTL_MSG_MAX + WIRED_MOQTRUN_CTL_HDR_MAX)

static wired_span mtst_z(const char* z) {
  usz n = 0;
  while (z[n]) n++;
  return wired_span_of((const u8*)z, n);
}

/* Full Track Name {ns0, ns1} / name. */
static moqctl_ftn mtst_ftn(const char* ns0, const char* ns1, const char* name) {
  moqctl_ftn f   = {0};
  f.ns.fields[0] = mtst_z(ns0);
  f.ns.fields[1] = mtst_z(ns1);
  f.ns.n         = 2;
  f.name         = mtst_z(name);
  return f;
}

static int mtst_enc_publish(wired_mspan buf, usz* off, const void* m) {
  return moqctl_publish_encode(buf, off, m);
}

static int mtst_enc_subscribe(wired_mspan buf, usz* off, const void* m) {
  return moqctl_subscribe_encode(buf, off, m);
}

static void mtst_send(
    wired_wt_session*      s,
    u64                    ctrl,
    u64                    type,
    moqtrun_body_encode_fn fn,
    const void*            m) {
  u8  buf[MTST_MSG_MAX];
  usz n = moqtrun_envelope_put(wired_mspan_of(buf, sizeof buf), type, fn, m);
  CHECK(n != 0);
  wired_moqt_on_stream_data(&mtst_hub, s, ctrl, wired_span_of(buf, n), 0);
}

static void mtst_publish_p(
    wired_wt_session*    s,
    u64                  ctrl,
    const moqctl_ftn*    f,
    u64                  alias,
    const moqctl_params* params) {
  static moqctl_publish m;
  m.request_id  = mtst_rid += 2;
  m.name        = *f;
  m.track_alias = alias;
  m.params.n    = 0;
  if (params) m.params = *params;
  mtst_send(s, ctrl, MOQCTL_T_PUBLISH, mtst_enc_publish, &m);
}

static void mtst_publish(
    wired_wt_session* s, u64 ctrl, const moqctl_ftn* f, u64 alias) {
  mtst_publish_p(s, ctrl, f, alias, 0);
}

static void mtst_subscribe_p(
    wired_wt_session*    s,
    u64                  ctrl,
    const moqctl_ftn*    f,
    u64                  rid,
    const moqctl_params* params) {
  static moqctl_subscribe m;
  m.request_id = rid;
  m.name       = *f;
  m.params.n   = 0;
  if (params) m.params = *params;
  mtst_send(s, ctrl, MOQCTL_T_SUBSCRIBE, mtst_enc_subscribe, &m);
}

static void mtst_subscribe(wired_wt_session* s, u64 ctrl, const moqctl_ftn* f) {
  mtst_subscribe_p(s, ctrl, f, mtst_rid += 2, 0);
}

static u64 mtst_join(wired_wt_session* s) {
  return moqtrun_test_join(&mtst_hub, s);
}

static void mtst_init(void) {
  moqtrun_test_reset();
  wired_moqt_init(&mtst_hub, moqtrun_test_io());
}

/* ===================== Full Track Name matching ===================== */

/* Same Track Name under another namespace is another track (1.5): no
 * match, DOES_NOT_EXIST; the exact Full Track Name matches. */
static void test_moqtrun_sub_ns_must_match(void) {
  mtst_init();
  u64        ca    = mtst_join(SESS_A);
  u64        cb    = mtst_join(SESS_B);
  moqctl_ftn pub   = mtst_ftn("chat", "room1", "alice");
  moqctl_ftn other = mtst_ftn("chat", "room2", "alice");
  mtst_publish(SESS_A, ca, &pub, 1);
  mtst_subscribe(SESS_B, cb, &other);
  CHECK(mtsub_last_reply_type() == MOQCTL_T_REQUEST_ERROR);
  mtst_subscribe(SESS_B, cb, &pub);
  CHECK(mtsub_last_reply_type() == MOQCTL_T_SUBSCRIBE_OK);
}

/* A namespace with the maximum MOQCTL_MAX_NS_FIELDS fields is stored
 * whole: exact match succeeds, a difference in the last field does not. */
static void test_moqtrun_sub_ns_max_fields(void) {
  static const char* const F = "abcdefghijklmnopqrstuvwxyzABCDEF";
  moqctl_ftn               f = {0};
  mtst_init();
  u64 ca = mtst_join(SESS_A);
  u64 cb = mtst_join(SESS_B);
  for (usz i = 0; i < MOQCTL_MAX_NS_FIELDS; i++)
    f.ns.fields[i] = wired_span_of((const u8*)F + i, 1);
  f.ns.n = MOQCTL_MAX_NS_FIELDS;
  f.name = mtst_z("alice");
  mtst_publish(SESS_A, ca, &f, 1);
  CHECK(mtsub_last_reply_type() == MOQCTL_T_REQUEST_OK);
  mtst_subscribe(SESS_B, cb, &f);
  CHECK(mtsub_last_reply_type() == MOQCTL_T_SUBSCRIBE_OK);
  f.ns.fields[MOQCTL_MAX_NS_FIELDS - 1] = mtst_z("z");
  mtst_subscribe(SESS_B, cb, &f);
  CHECK(mtsub_last_reply_type() == MOQCTL_T_REQUEST_ERROR);
}

/* Two publishers of one Track Name under different namespaces are two
 * tracks: the newer does not supersede the older, whose Objects still
 * reach its subscriber. */
static void test_moqtrun_sub_same_name_other_ns_coexist(void) {
  mtst_init();
  u64        ca = mtst_join(SESS_A);
  u64        cc = mtst_join(SESS_C);
  u64        cb = mtst_join(SESS_B);
  moqctl_ftn r1 = mtst_ftn("chat", "room1", "alice");
  moqctl_ftn r2 = mtst_ftn("chat", "room2", "alice");
  mtst_publish(SESS_A, ca, &r1, 1);
  mtst_publish(SESS_C, cc, &r2, 1);
  mtst_subscribe(SESS_B, cb, &r1);
  CHECK(mtsub_last_reply_type() == MOQCTL_T_SUBSCRIBE_OK);
  CHECK(moqtrun_test_relay_alice_chat(&mtst_hub) == 1);
  CHECK(moqtrun_test_last_kind(4)->s == SESS_B);
}

/* A namespace longer than the hub stores (WIRED_MOQTRUN_MAX_NS) is
 * refused, never truncated into a false match. */
static void test_moqtrun_sub_ns_over_cap_refused(void) {
  static u8  big[WIRED_MOQTRUN_MAX_NS];
  moqctl_ftn f = mtst_ftn("chat", "room1", "alice");
  mtst_init();
  u64 ca = mtst_join(SESS_A);
  for (usz i = 0; i < sizeof big; i++) big[i] = 'x';
  f.ns.fields[1] = wired_span_of(big, sizeof big);
  mtst_publish(SESS_A, ca, &f, 1);
  CHECK(mtsub_last_reply_type() == MOQCTL_T_REQUEST_ERROR);
}

void test_moqtrun_sub(void) {
  test_moqtrun_sub_ns_must_match();
  test_moqtrun_sub_ns_max_fields();
  test_moqtrun_sub_same_name_other_ns_coexist();
  test_moqtrun_sub_ns_over_cap_refused();
}
